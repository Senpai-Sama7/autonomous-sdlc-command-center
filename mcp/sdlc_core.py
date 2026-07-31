"""Portable, safety-gated SDLC diagnostics used by the CLI and MCP server.

This module is the shared, dependency-free core. It runs identically on
Windows, Linux, and macOS with Python 3.9+ and no third-party packages.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


VERSION = "1.2.0"
MAX_FILES_LIMIT = 2_000
MAX_READ_BYTES = 1_048_576
DEFAULT_READ_BYTES = 65_536
DEFAULT_READ_LINES = 2_000
MAX_READ_LINES = 100_000
MAX_BATCH_FILES = 20
BINARY_SNIFF_BYTES = 8_192
MAX_TREE_DEPTH = 10
DEFAULT_TREE_DEPTH = 4
MAX_TREE_ENTRIES = 2_000
DEFAULT_TREE_ENTRIES = 500
ENV_ALLOW_NETWORK_PATHS = "SDLC_ALLOW_NETWORK_PATHS"
IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "coverage",
        "target",
        "__pycache__",
        ".sdlc",
    }
)
MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "pnpm-workspace.yaml",
        "pyproject.toml",
        "requirements.txt",
        "Pipfile",
        "poetry.lock",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "composer.json",
        "Dockerfile",
        "docker-compose.yml",
        "compose.yml",
        "Makefile",
    }
)
LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "go.sum",
        "Gemfile.lock",
        "composer.lock",
        "gradle.lockfile",
    }
)
# Filenames that look sensitive by convention but are intentional public templates (E15).
NON_SENSITIVE_ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template", ".env.defaults"})
SECRET_SIGNATURES = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("url-basic-auth", re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE)),
    ("generic-secret-assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"\s]{16,}['\"]")),
)
DANGEROUS_COMMAND_SIGNATURES = (
    ("dynamic-code-execution", re.compile(r"\b(?:Invoke-Expression|iex)\b", re.IGNORECASE)),
    ("encoded-powershell", re.compile(r"-EncodedCommand\b", re.IGNORECASE)),
    (
        "pipe-to-shell",
        re.compile(r"(?:curl|Invoke-WebRequest|iwr).{0,200}\|\s*(?:sh|bash|iex|Invoke-Expression)", re.IGNORECASE),
    ),
    (
        "force-recursive-delete",
        re.compile(r"Remove-Item\b[^\r\n]*-Recurse\b[^\r\n]*-Force\b", re.IGNORECASE),
    ),
)
SEMVER_PATTERN = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"


class InputError(ValueError):
    """Raised for safe, user-correctable input errors."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_text(value: str) -> str:
    """Replace lone surrogates (from non-UTF-8 filesystem paths) with U+FFFD (E3)."""

    if not isinstance(value, str):
        return value
    if not any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        return value
    return "".join("\ufffd" if 0xD800 <= ord(char) <= 0xDFFF else char for char in value)


def has_surrogates(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def redact_secret_values(text: str) -> str:
    """Mask anything matching a known secret signature. Values are never echoed."""

    redacted = text
    for identifier, pattern in SECRET_SIGNATURES:
        redacted = pattern.sub(f"[REDACTED:{identifier}]", redacted)
    return redacted


def is_probably_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    # Heuristic: >30% control characters (excluding common whitespace) means binary.
    control = sum(1 for byte in sample if byte < 0x09 or (0x0E <= byte < 0x20))
    return control / len(sample) > 0.30


def _reject_network_path(raw: str, resolved: Path) -> None:
    """E7: refuse UNC/network paths unless explicitly overridden."""

    if os.environ.get(ENV_ALLOW_NETWORK_PATHS) == "1":
        return
    candidates = [raw, str(resolved)]
    for candidate in candidates:
        normalized = candidate.replace("/", "\\")
        if normalized.startswith("\\\\"):
            raise InputError(
                "network (UNC) paths are not scanned by default; "
                f"set {ENV_ALLOW_NETWORK_PATHS}=1 to override"
            )


def _resolve_directory(candidate: str) -> Path:
    if not isinstance(candidate, str) or not candidate.strip() or "\x00" in candidate:
        raise InputError("path must be a non-empty directory path")

    try:
        resolved = Path(candidate).expanduser().resolve(strict=True)
    except OSError as exc:
        raise InputError("path could not be resolved") from exc

    if not resolved.is_dir():
        raise InputError("path must identify a directory")
    if resolved == resolved.parent:
        raise InputError("refusing to scan a filesystem root; provide a repository directory")
    _reject_network_path(candidate.strip(), resolved)
    return resolved


def resolve_within_root(root: Path, file_path: str) -> Path:
    """Resolve a user-supplied file path and prove it stays inside ``root``.

    Accepts paths relative to ``root`` or absolute paths contained by it.
    Rejects traversal, escapes, and symlinks anywhere in the existing chain.
    """

    if not isinstance(file_path, str) or not file_path.strip() or "\x00" in file_path:
        raise InputError("filePath must be a non-empty string")
    if len(file_path) > 4096:
        raise InputError("filePath exceeds the maximum length")

    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise InputError("filePath could not be resolved") from exc

    try:
        common = os.path.commonpath([str(root), str(resolved)])
    except ValueError as exc:
        raise InputError("filePath must stay inside the target directory") from exc
    if common != str(root):
        raise InputError("filePath must stay inside the target directory")

    # Reject symlinks anywhere along the path between root and target.
    check = resolved
    while check != root and check != check.parent:
        if check.is_symlink():
            raise InputError("filePath must not traverse a symlink")
        check = check.parent
    if resolved.is_symlink():
        raise InputError("filePath must not be a symlink")
    return resolved


def _read_max_files(value: Any, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError("maxFiles must be an integer")
    if not 1 <= value <= MAX_FILES_LIMIT:
        raise InputError(f"maxFiles must be between 1 and {MAX_FILES_LIMIT}")
    return value


def _read_bool(value: Any, default: bool, name: str = "includeGit") -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise InputError(f"{name} must be a boolean")
    return value


def _read_int_range(value: Any, default: int, minimum: int, maximum: int, name: str) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise InputError(f"{name} must be between {minimum} and {maximum}")
    return value


def walk_repository(root: Path, limit: int) -> dict[str, Any]:
    """Return a deterministic, bounded file sample without following symlinks."""

    files: list[str] = []
    inaccessible_directories = 0
    skipped_symlinks = 0
    non_utf8_paths = 0
    pending = [root]

    while pending and len(files) < limit:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except (OSError, PermissionError):
            inaccessible_directories += 1
            continue

        children: list[Path] = []
        for entry in entries:
            if len(files) >= limit:
                break
            if entry.name in IGNORED_DIRECTORY_NAMES:
                continue
            try:
                if entry.is_symlink():
                    skipped_symlinks += 1  # E2: count instead of silently skipping
                    continue
                if entry.is_dir(follow_symlinks=False):
                    children.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    relative = Path(entry.path).relative_to(root).as_posix()
                    if has_surrogates(relative):
                        non_utf8_paths += 1  # E3: count and sanitize, never crash
                        relative = sanitize_text(relative)
                    files.append(relative)
            except OSError:
                continue

        pending.extend(reversed(children))

    return {
        "files": files,
        "inaccessibleDirectories": inaccessible_directories,
        "skippedSymlinks": skipped_symlinks,
        "nonUtf8Paths": non_utf8_paths,
    }


def _run_git(root: Path, arguments: list[str], timeout_seconds: float = 5.0) -> subprocess.CompletedProcess[str] | None:
    git_path = shutil.which("git")
    if git_path is None:
        return None
    try:
        return subprocess.run(
            [git_path, "-C", str(root), *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def git_executable() -> str | None:
    return shutil.which("git")


def run_git(root: Path, arguments: list[str], timeout_seconds: float = 5.0) -> subprocess.CompletedProcess[str] | None:
    """Public wrapper for sibling modules (analyze/write)."""

    return _run_git(root, arguments, timeout_seconds)


def _git_summary(root: Path) -> dict[str, Any]:
    if shutil.which("git") is None:
        return {"available": False, "repository": False}

    inside = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.returncode != 0 or inside.stdout.strip() != "true":
        return {"available": True, "repository": False}

    branch = _run_git(root, ["branch", "--show-current"])
    head = _run_git(root, ["rev-parse", "--short", "HEAD"])
    status = _run_git(root, ["status", "--porcelain=v1"])
    changed_file_count = len(status.stdout.splitlines()) if status and status.returncode == 0 else None
    return {
        "available": True,
        "repository": True,
        "branch": branch.stdout.strip() if branch and branch.returncode == 0 else None,
        "head": head.stdout.strip() if head and head.returncode == 0 else None,
        "workingTreeClean": changed_file_count == 0 if changed_file_count is not None else None,
        "changedFileCount": changed_file_count,
    }


def repo_snapshot(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 250)
    include_git = _read_bool(arguments.get("includeGit"), False)
    walk = walk_repository(root, max_files)
    files = walk["files"]

    manifests = [path for path in files if Path(path).name in MANIFEST_NAMES]
    lockfiles = [path for path in files if Path(path).name in LOCKFILE_NAMES]
    ci_files = [
        path
        for path in files
        if re.search(r"(^|/)(?:\.github/workflows/|\.circleci/)|\.gitlab-ci|azure-pipelines|Jenkinsfile|buildkite", path, re.IGNORECASE)
    ]
    test_files = [
        path
        for path in files
        if re.search(r"(^|/)(?:test|tests|spec|__tests__)(?:/|$)|\.(?:test|spec)\.[^.]+$", path, re.IGNORECASE)
    ][:50]
    infrastructure_files = [
        path
        for path in files
        if re.search(r"(^|/)(?:terraform|k8s|kubernetes|helm|ansible|\.github/workflows)(?:/|$)|(^|/)(?:Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)$", path, re.IGNORECASE)
    ][:50]
    sensitive_path_indicators = [
        path
        for path in files
        if re.search(r"(^|/)\.env(?:$|\.)|(^|/)(?:secrets?|credentials?)(?:/|[_.-]|$)", path, re.IGNORECASE)
        and Path(path).name not in NON_SENSITIVE_ENV_TEMPLATES  # E15
    ][:20]

    return {
        "schemaVersion": "1.0",
        "generatedAtUtc": _utc_now(),
        "scanRoot": str(root),
        "fileCountSampled": len(files),
        "sampleLimit": max_files,
        "sampleLimitReached": len(files) >= max_files,
        "inaccessibleDirectoryCount": walk["inaccessibleDirectories"],
        "skippedSymlinkCount": walk["skippedSymlinks"],
        "nonUtf8PathCount": walk["nonUtf8Paths"],
        "manifests": manifests,
        "lockfiles": lockfiles,
        "ciFiles": ci_files,
        "testFiles": test_files,
        "infrastructureFiles": infrastructure_files,
        "sensitivePathIndicators": sensitive_path_indicators,
        "git": _git_summary(root) if include_git else None,
    }


def read_file_content(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bounded, symlink-safe file read with binary detection and secret redaction."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    file_path = arguments.get("filePath")
    if file_path is None:
        raise InputError("filePath is required")
    target = resolve_within_root(root, file_path)

    if not target.exists():
        raise InputError("filePath does not exist")
    if not target.is_file():
        raise InputError("filePath must identify a regular file")

    max_bytes = _read_int_range(arguments.get("maxBytes"), DEFAULT_READ_BYTES, 1, MAX_READ_BYTES, "maxBytes")
    max_lines = _read_int_range(arguments.get("maxLines"), DEFAULT_READ_LINES, 1, MAX_READ_LINES, "maxLines")
    redact = _read_bool(arguments.get("redactSecrets"), True, "redactSecrets")

    size_bytes = target.stat().st_size
    with target.open("rb") as handle:
        sniff = handle.read(BINARY_SNIFF_BYTES)
        if is_probably_binary(sniff):
            return {
                "status": "ok",
                "path": str(root),
                "filePath": target.relative_to(root).as_posix(),
                "sizeBytes": size_bytes,
                "isBinary": True,
                "content": None,
                "note": "Binary content is never returned. Hash and size are provided for identification.",
            }
        handle.seek(0)
        raw = handle.read(max_bytes + 1)

    truncated_bytes = len(raw) > max_bytes
    raw = raw[:max_bytes]
    decoded = raw.decode("utf-8", errors="replace")
    replaced_characters = decoded.count("\ufffd")

    lines = decoded.splitlines(keepends=True)
    truncated_lines = len(lines) > max_lines
    lines = lines[:max_lines]
    content = "".join(lines)
    if redact:
        content = redact_secret_values(content)

    return {
        "status": "ok",
        "path": str(root),
        "filePath": target.relative_to(root).as_posix(),
        "sizeBytes": size_bytes,
        "isBinary": False,
        "encoding": "utf-8",
        "replacedCharacterCount": replaced_characters,
        "truncatedBytes": truncated_bytes,
        "truncatedLines": truncated_lines,
        "lineCountReturned": len(lines),
        "secretsRedacted": redact,
        "content": content,
    }


def read_multiple_files(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Batch-read up to MAX_BATCH_FILES files. Each file gets its own result entry."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))

    file_paths = arguments.get("filePaths")
    if not isinstance(file_paths, list) or not file_paths:
        raise InputError("filePaths must be a non-empty array of strings")
    if len(file_paths) > MAX_BATCH_FILES:
        raise InputError(f"filePaths must contain at most {MAX_BATCH_FILES} entries")
    for file_path in file_paths:
        if not isinstance(file_path, str):
            raise InputError("each entry in filePaths must be a string")

    max_bytes = _read_int_range(arguments.get("maxBytes"), DEFAULT_READ_BYTES, 1, MAX_READ_BYTES, "maxBytes")
    max_lines = _read_int_range(arguments.get("maxLines"), DEFAULT_READ_LINES, 1, MAX_READ_LINES, "maxLines")
    redact = _read_bool(arguments.get("redactSecrets"), True, "redactSecrets")

    results: list[dict[str, Any]] = []
    for file_path in file_paths:
        try:
            single = read_file_content(
                {
                    "path": str(root),
                    "filePath": file_path,
                    "maxBytes": max_bytes,
                    "maxLines": max_lines,
                    "redactSecrets": redact,
                }
            )
            single["filePath"] = file_path
            results.append(single)
        except InputError as exc:
            results.append({"status": "error", "filePath": file_path, "error": str(exc)})

    succeeded = sum(1 for result in results if result["status"] == "ok")
    errored = sum(1 for result in results if result["status"] == "error")
    return {
        "status": "ok" if errored == 0 else ("error" if succeeded == 0 else "partial"),
        "path": str(root),
        "fileCount": len(results),
        "succeeded": succeeded,
        "errored": errored,
        "results": results,
    }


def directory_tree(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bounded recursive directory listing with depth and entry caps.

    Returns a flat array of {path, type, depth} entries. Depth 0 is the root's
    direct children; depth increases by 1 per level of nesting.
    """

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_depth = _read_int_range(arguments.get("maxDepth"), DEFAULT_TREE_DEPTH, 1, MAX_TREE_DEPTH, "maxDepth")
    max_entries = _read_int_range(arguments.get("maxEntries"), DEFAULT_TREE_ENTRIES, 1, MAX_TREE_ENTRIES, "maxEntries")
    show_files = _read_bool(arguments.get("includeFiles"), True, "includeFiles")
    show_dirs = _read_bool(arguments.get("includeDirs"), True, "includeDirs")

    entries: list[dict[str, Any]] = []
    skipped_depth_limited = 0

    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    while queue and len(entries) < max_entries:
        directory, depth = queue.popleft()
        if depth > max_depth:
            skipped_depth_limited += 1
            continue
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except (OSError, PermissionError):
            continue

        subdirs: list[Path] = []
        for child in children:
            if len(entries) >= max_entries:
                break
            if child.name in IGNORED_DIRECTORY_NAMES:
                continue
            try:
                relative = Path(child.path).relative_to(root).as_posix()
                if has_surrogates(relative):
                    relative = sanitize_text(relative)
                if child.is_symlink():
                    continue
                if child.is_dir(follow_symlinks=False):
                    if show_dirs:
                        entries.append({"path": relative, "type": "directory", "depth": depth})
                    subdirs.append(Path(child.path))
                elif child.is_file(follow_symlinks=False):
                    if show_files:
                        entries.append({"path": relative, "type": "file", "depth": depth})
            except OSError:
                continue

        if depth < max_depth:
            queue.extend((subdir, depth + 1) for subdir in subdirs)

    return {
        "status": "ok",
        "path": str(root),
        "maxDepth": max_depth,
        "entryCount": len(entries),
        "entryLimitReached": len(entries) >= max_entries,
        "depthLimitedCount": skipped_depth_limited,
        "entries": entries,
    }


def _check(identifier: str, status: str, detail: str) -> dict[str, str]:
    return {"id": identifier, "status": status, "detail": detail}


def release_readiness(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    snapshot = repo_snapshot(
        {
            "path": arguments.get("path", os.getcwd()),
            "maxFiles": arguments.get("maxFiles", 500),
            "includeGit": True,
        }
    )
    root = Path(snapshot["scanRoot"])
    checks: list[dict[str, str]] = []

    checks.append(
        _check(
            "inventory-completeness",
            "warning" if snapshot["sampleLimitReached"] else "pass",
            (
                f"The snapshot reached its {snapshot['sampleLimit']}-file limit; inspect targeted paths before relying on absence claims."
                if snapshot["sampleLimitReached"]
                else "The bounded snapshot did not reach its sample limit."
            ),
        )
    )
    checks.append(
        _check(
            "build-manifests",
            "pass" if snapshot["manifests"] else "warning",
            f"Detected {len(snapshot['manifests'])} build or runtime manifest(s)."
            if snapshot["manifests"]
            else "No common build manifest was found in the sampled files.",
        )
    )
    checks.append(
        _check(
            "dependency-lockfiles",
            "pass" if snapshot["lockfiles"] else ("warning" if snapshot["manifests"] else "unknown"),
            f"Detected {len(snapshot['lockfiles'])} dependency lockfile(s)."
            if snapshot["lockfiles"]
            else (
                "A manifest was found but no common lockfile was detected in the sample."
                if snapshot["manifests"]
                else "No dependency-manifest evidence was available."
            ),
        )
    )
    checks.append(
        _check(
            "test-evidence",
            "pass" if snapshot["testFiles"] else "warning",
            f"Detected {len(snapshot['testFiles'])} test-related file(s) in the sample."
            if snapshot["testFiles"]
            else "No test-related files were detected; inspect the test strategy manually.",
        )
    )
    checks.append(
        _check(
            "ci-evidence",
            "pass" if snapshot["ciFiles"] else "warning",
            f"Detected {len(snapshot['ciFiles'])} CI configuration file(s)."
            if snapshot["ciFiles"]
            else "No CI configuration was detected in the sample.",
        )
    )
    checks.append(
        _check(
            "documentation",
            "pass" if (root / "README.md").is_file() else "warning",
            "README.md is present." if (root / "README.md").is_file() else "README.md was not found at the repository root.",
        )
    )
    checks.append(
        _check(
            "changelog",
            "pass" if (root / "CHANGELOG.md").is_file() else "warning",
            "CHANGELOG.md is present." if (root / "CHANGELOG.md").is_file() else "CHANGELOG.md was not found at the repository root.",
        )
    )

    git = snapshot["git"]
    if git["available"] and git["repository"]:
        checks.append(
            _check(
                "working-tree",
                "pass" if git["workingTreeClean"] else "warning",
                "Working tree is clean."
                if git["workingTreeClean"]
                else f"Working tree has {git['changedFileCount']} changed path(s); confirm intended release contents.",
            )
        )
        diff_check = _run_git(root, ["diff", "--check"], timeout_seconds=10.0)
        checks.append(
            _check(
                "diff-whitespace",
                "pass" if diff_check and diff_check.returncode == 0 else "fail",
                "git diff --check found no whitespace errors in tracked changes."
                if diff_check and diff_check.returncode == 0
                else "git diff --check found whitespace errors or did not complete; inspect locally before release.",
            )
        )
    elif git["available"]:
        checks.append(_check("working-tree", "unknown", "Git is available but the target is not a Git worktree."))
    else:
        checks.append(_check("working-tree", "unknown", "Git is not available; working-tree state was not assessed."))

    summary = {status: sum(check["status"] == status for check in checks) for status in ("pass", "warning", "fail", "unknown")}
    recommendation = "blocked" if summary["fail"] else ("needs-review" if summary["warning"] else "ready-for-verification")
    return {
        "status": recommendation,
        "scanRoot": str(root),
        "generatedAtUtc": _utc_now(),
        "checks": checks,
        "summary": summary,
        "note": "This is read-only evidence collection. It does not run tests, query remote CI, scan vulnerabilities, or authorize a release.",
    }


def _iter_skill_files(skills_root: Path) -> Iterable[Path]:
    for directory, directory_names, file_names in os.walk(skills_root, followlinks=False):
        directory_names[:] = [name for name in directory_names if name not in IGNORED_DIRECTORY_NAMES]
        if "SKILL.md" in file_names:
            yield Path(directory) / "SKILL.md"


def _finding(severity: str, identifier: str, message: str, file: Path | None = None) -> dict[str, str | None]:
    return {"severity": severity, "id": identifier, "message": message, "file": str(file) if file else None}


def _validate_skill_contract(skill_dir: Path, skill_name: str | None, findings: list[dict[str, str | None]]) -> None:
    """Validate the machine-readable skill contract (E13)."""

    contract_path = skill_dir / "contract.json"
    if not contract_path.is_file():
        findings.append(_finding("warning", "contract-missing", "Skill has no machine-readable contract.json.", skill_dir))
        return

    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        if not isinstance(contract, dict):
            raise ValueError("contract root must be an object")
    except (OSError, json.JSONDecodeError, ValueError):
        findings.append(_finding("error", "contract-invalid-json", "Skill contract is not a valid JSON object.", contract_path))
        return

    for field in ("schemaVersion", "name", "version", "summary"):
        if field not in contract:
            findings.append(_finding("error", "contract-field", f"Skill contract is missing required field '{field}'.", contract_path))

    contract_name = contract.get("name")
    if isinstance(contract_name, str) and contract_name != skill_dir.name:
        findings.append(_finding("error", "contract-name", "Contract name must match the skill directory.", contract_path))
    if skill_name is not None and isinstance(contract_name, str) and contract_name != skill_name:
        findings.append(_finding("error", "contract-name-mismatch", "Contract name must match SKILL.md frontmatter name.", contract_path))

    contract_version = contract.get("version")
    if "version" in contract and (not isinstance(contract_version, str) or not re.fullmatch(SEMVER_PATTERN, contract_version)):
        findings.append(_finding("error", "contract-version", "Contract version is not semantic-version compatible.", contract_path))

    tools_used = contract.get("toolsUsed")
    if tools_used is not None and not (isinstance(tools_used, list) and all(isinstance(tool, str) for tool in tools_used)):
        findings.append(_finding("error", "contract-tools", "contract.toolsUsed must be an array of tool-name strings.", contract_path))

    safety = contract.get("safety")
    if safety is not None and not isinstance(safety, dict):
        findings.append(_finding("error", "contract-safety", "contract.safety must be an object.", contract_path))

    eval_prompts = contract.get("evalPrompts")
    if eval_prompts is not None:
        if not isinstance(eval_prompts, list) or not all(isinstance(item, str) for item in eval_prompts):
            findings.append(_finding("error", "contract-eval", "contract.evalPrompts must be an array of relative file paths.", contract_path))
        else:
            for relative in eval_prompts:
                if not (skill_dir / relative).is_file():
                    findings.append(_finding("warning", "contract-eval-missing", f"Eval prompt file '{relative}' is missing.", contract_path))


def plugin_preflight(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")
    default_plugin_path = Path(__file__).resolve().parent.parent
    root = _resolve_directory(arguments.get("pluginPath", str(default_plugin_path)))
    findings: list[dict[str, str | None]] = []
    manifest_path = root / ".codex-plugin" / "plugin.json"
    manifest: dict[str, Any] | None = None

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.append(_finding("error", "manifest-missing", "Required plugin manifest is missing.", manifest_path))
    except (OSError, json.JSONDecodeError):
        findings.append(_finding("error", "manifest-invalid-json", "Plugin manifest is not valid JSON.", manifest_path))

    if manifest is not None:
        if manifest.get("name") != root.name:
            findings.append(_finding("error", "manifest-name", "Manifest name must match the plugin directory.", manifest_path))
        version = manifest.get("version")
        if not isinstance(version, str) or not re.fullmatch(SEMVER_PATTERN, version):
            findings.append(_finding("error", "manifest-version", "Manifest version is missing or is not semantic-version compatible.", manifest_path))
        interface = manifest.get("interface")
        if not isinstance(interface, dict) or not interface.get("displayName") or not interface.get("shortDescription"):
            findings.append(_finding("error", "manifest-interface", "Manifest interface metadata is incomplete.", manifest_path))
        prompts = interface.get("defaultPrompt", []) if isinstance(interface, dict) else []
        prompts = prompts if isinstance(prompts, list) else [prompts]
        if len(prompts) > 3:
            findings.append(_finding("warning", "prompt-count", "Only the first three default prompts are surfaced by Codex.", manifest_path))
        if any(isinstance(prompt, str) and len(prompt) > 128 for prompt in prompts):
            findings.append(_finding("warning", "prompt-length", "A default prompt exceeds 128 characters and may be truncated.", manifest_path))

    skills_root = root / "skills"
    if not skills_root.is_dir():
        findings.append(_finding("error", "skills-missing", "The declared skills directory is missing.", skills_root))
    else:
        skill_files = list(_iter_skill_files(skills_root))
        if not skill_files:
            findings.append(_finding("error", "skills-empty", "No SKILL.md files were found.", skills_root))
        seen_skill_names: set[str] = set()
        for skill_file in skill_files:
            content = skill_file.read_text(encoding="utf-8", errors="replace")
            if re.search(r"\[TODO:\s*", content):
                findings.append(_finding("error", "skill-todo", "Skill contains an unresolved TODO placeholder.", skill_file))
            front_matter = re.match(r"\A---\s*\r?\n(?P<body>.*?)\r?\n---", content, re.DOTALL)
            if front_matter is None:
                findings.append(_finding("error", "skill-frontmatter", "Skill is missing YAML frontmatter.", skill_file))
                continue
            front_matter_body = front_matter.group("body")
            name_match = re.search(r'^name:\s*["\']?(?P<name>[a-z0-9-]+)["\']?\s*$', front_matter_body, re.MULTILINE)
            description_match = re.search(r'^description:\s*["\']?(?P<description>.+?)["\']?\s*$', front_matter_body, re.MULTILINE)
            if name_match is None or description_match is None:
                findings.append(_finding("error", "skill-metadata", "Skill frontmatter requires name and description.", skill_file))
                continue
            skill_name = name_match.group("name")
            if skill_name in seen_skill_names:
                findings.append(_finding("error", "skill-duplicate-name", f"Skill name '{skill_name}' is duplicated.", skill_file))
            seen_skill_names.add(skill_name)
            if skill_name != skill_file.parent.name:
                findings.append(_finding("warning", "skill-directory-name", "Skill name does not match its directory.", skill_file))
            _validate_skill_contract(skill_file.parent, skill_name, findings)

    code_root = root / "scripts" / "commands"
    if code_root.is_dir():
        for code_file in code_root.rglob("*"):
            # The PowerShell preflight command embeds the same detection rules and would
            # otherwise match its own rule literals. It is validated separately by tests.
            if code_file.name == "plugin_preflight.ps1" or not code_file.is_file() or code_file.stat().st_size > 1_048_576:
                continue
            content = code_file.read_text(encoding="utf-8", errors="replace")
            for identifier, pattern in DANGEROUS_COMMAND_SIGNATURES:
                if pattern.search(content):
                    findings.append(_finding("error", identifier, "Bundled command violates the local read-only safety policy.", code_file))
            for identifier, pattern in SECRET_SIGNATURES:
                if pattern.search(content):
                    findings.append(_finding("error", "potential-secret", f"Potential {identifier} signature detected; value intentionally omitted.", code_file))

    errors = sum(finding["severity"] == "error" for finding in findings)
    warnings = sum(finding["severity"] == "warning" for finding in findings)
    infos = sum(finding["severity"] == "info" for finding in findings)
    return {
        "status": "pass" if errors == 0 else "fail",
        "pluginPath": str(root),
        "coreVersion": VERSION,
        "summary": {"errors": errors, "warnings": warnings, "info": infos},
        "findings": findings,
    }
