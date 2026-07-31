"""Read-only repository intelligence: search, secrets, languages, dependencies, git, risk.

Dependency-free and cross-platform (Windows/Linux/macOS, Python 3.9+).
All findings redact secret values; raw secrets are never returned.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from sdlc_core import (
    InputError,
    SECRET_SIGNATURES,
    VERSION,
    _read_bool,
    _read_int_range,
    _read_max_files,
    _resolve_directory,
    _utc_now,
    git_executable,
    is_probably_binary,
    plugin_preflight,
    redact_secret_values,
    release_readiness,
    repo_snapshot,
    run_git,
    walk_repository,
)


MAX_SEARCH_PATTERN_LENGTH = 500
MAX_SEARCH_RESULTS = 500
DEFAULT_SEARCH_FILE_BYTES = 262_144
MAX_SCAN_FILE_BYTES = 1_048_576
MAX_LINE_PREVIEW = 300

LANGUAGE_BY_EXTENSION = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    ".go": "Go", ".rs": "Rust", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".cs": "C#", ".fs": "F#", ".vb": "Visual Basic",
    ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".m": "Objective-C",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".sql": "SQL", ".r": "R", ".lua": "Lua", ".pl": "Perl", ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".clj": "Clojure", ".hs": "Haskell", ".dart": "Dart",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "SCSS", ".less": "Less",
    ".json": "JSON", ".jsonc": "JSON", ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML",
    ".xml": "XML", ".md": "Markdown", ".rst": "reStructuredText", ".tex": "TeX",
    ".tf": "Terraform", ".hcl": "HCL", ".dockerfile": "Dockerfile",
    ".proto": "Protocol Buffers", ".graphql": "GraphQL", ".gql": "GraphQL",
}


def _iter_text_file_lines(target: Path, max_file_bytes: int):
    """Yield (line_number, decoded_line) for a text file; returns None if binary/too large."""

    try:
        size = target.stat().st_size
    except OSError:
        return None
    if size > max_file_bytes:
        return None
    try:
        with target.open("rb") as handle:
            sniff = handle.read(8_192)
            if is_probably_binary(sniff):
                return None
            handle.seek(0)
            raw = handle.read(max_file_bytes)
    except OSError:
        return None
    decoded = raw.decode("utf-8", errors="replace")
    return list(enumerate(decoded.splitlines(), start=1))


def search_code(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bounded regex search with context lines and secret redaction."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    pattern_value = arguments.get("pattern")
    if not isinstance(pattern_value, str) or not pattern_value:
        raise InputError("pattern is required and must be a non-empty string")
    if len(pattern_value) > MAX_SEARCH_PATTERN_LENGTH:
        raise InputError(f"pattern exceeds {MAX_SEARCH_PATTERN_LENGTH} characters")
    try:
        pattern = re.compile(pattern_value)
    except re.error as exc:
        raise InputError(f"pattern is not a valid regular expression: {exc}") from exc

    file_filter = None
    file_pattern = arguments.get("filePattern")
    if file_pattern is not None:
        if not isinstance(file_pattern, str) or len(file_pattern) > MAX_SEARCH_PATTERN_LENGTH:
            raise InputError("filePattern must be a string within the length limit")
        try:
            file_filter = re.compile(file_pattern)
        except re.error as exc:
            raise InputError(f"filePattern is not a valid regular expression: {exc}") from exc

    max_results = _read_int_range(arguments.get("maxResults"), 50, 1, MAX_SEARCH_RESULTS, "maxResults")
    context_lines = _read_int_range(arguments.get("contextLines"), 1, 0, 10, "contextLines")
    max_files = _read_max_files(arguments.get("maxFiles"), 1_000)
    max_file_bytes = _read_int_range(arguments.get("maxFileBytes"), DEFAULT_SEARCH_FILE_BYTES, 1_024, MAX_SCAN_FILE_BYTES, "maxFileBytes")
    redact = _read_bool(arguments.get("redactSecrets"), True, "redactSecrets")

    files = walk_repository(root, max_files)["files"]
    matches: list[dict[str, Any]] = []
    files_searched = 0

    for relative in files:
        if len(matches) >= max_results:
            break
        if file_filter is not None and not file_filter.search(relative):
            continue
        target = root / relative
        lines = _iter_text_file_lines(target, max_file_bytes)
        if lines is None:
            continue
        files_searched += 1
        for index, (line_number, line_text) in enumerate(lines):
            if len(matches) >= max_results:
                break
            if not pattern.search(line_text):
                continue
            before = [lines[i][1][:MAX_LINE_PREVIEW] for i in range(max(0, index - context_lines), index)]
            after = [lines[i][1][:MAX_LINE_PREVIEW] for i in range(index + 1, min(len(lines), index + 1 + context_lines))]
            preview = line_text[:MAX_LINE_PREVIEW]
            if redact:
                preview = redact_secret_values(preview)
                before = [redact_secret_values(item) for item in before]
                after = [redact_secret_values(item) for item in after]
            matches.append(
                {
                    "file": relative,
                    "line": line_number,
                    "text": preview,
                    "context": {"before": before, "after": after},
                }
            )

    return {
        "status": "ok",
        "scanRoot": str(root),
        "pattern": pattern_value,
        "matchCount": len(matches),
        "resultsLimit": max_results,
        "resultsLimitReached": len(matches) >= max_results,
        "filesSearched": files_searched,
        "secretsRedacted": redact,
        "matches": matches,
    }


def secret_scan(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Scan text files for secret signatures. Values are always redacted."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 1_000)
    max_file_bytes = _read_int_range(arguments.get("maxFileBytes"), MAX_SCAN_FILE_BYTES, 1_024, MAX_SCAN_FILE_BYTES, "maxFileBytes")
    max_findings = _read_int_range(arguments.get("maxFindings"), 500, 1, 5_000, "maxFindings")

    files = walk_repository(root, max_files)["files"]
    findings: list[dict[str, Any]] = []
    files_scanned = 0

    for relative in files:
        if len(findings) >= max_findings:
            break
        name = Path(relative).name.lower()
        if re.search(r"(^|/)\.env$|(^|/)(?:secrets?|credentials?)(?:/|[_.-]|$)", relative, re.IGNORECASE) and name not in {
            ".env.example", ".env.sample", ".env.template", ".env.defaults",
        }:
            findings.append(
                {
                    "file": relative,
                    "line": None,
                    "signature": "sensitive-file",
                    "preview": "File path matches a sensitive-location convention; contents not opened.",
                }
            )
            continue
        lines = _iter_text_file_lines(root / relative, max_file_bytes)
        if lines is None:
            continue
        files_scanned += 1
        for line_number, line_text in lines:
            if len(findings) >= max_findings:
                break
            for identifier, pattern in SECRET_SIGNATURES:
                if pattern.search(line_text):
                    findings.append(
                        {
                            "file": relative,
                            "line": line_number,
                            "signature": identifier,
                            "preview": redact_secret_values(line_text.strip())[:MAX_LINE_PREVIEW],
                        }
                    )
                    break

    return {
        "status": "pass" if not findings else "warning",
        "scanRoot": str(root),
        "scannedAtUtc": _utc_now(),
        "filesScanned": files_scanned,
        "findingCount": len(findings),
        "findingsLimitReached": len(findings) >= max_findings,
        "findings": findings,
        "note": "Findings are signature-based and redacted. Confirm true positives with a secrets manager before rotation.",
    }


def language_stats(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Language breakdown by file count and bounded line counting."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 2_000)
    max_file_bytes = _read_int_range(arguments.get("maxFileBytes"), MAX_SCAN_FILE_BYTES, 1_024, 4 * MAX_SCAN_FILE_BYTES, "maxFileBytes")

    files = walk_repository(root, max_files)["files"]
    by_language: dict[str, dict[str, int]] = {}
    total_lines = 0
    line_counted_files = 0

    for relative in files:
        suffix = Path(relative).suffix.lower()
        name = Path(relative).name.lower()
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language is None and name in {"dockerfile", "makefile", "jenkinsfile"}:
            language = {"dockerfile": "Dockerfile", "makefile": "Makefile", "jenkinsfile": "Groovy"}[name]
        if language is None:
            language = "Other"
        bucket = by_language.setdefault(language, {"files": 0, "lines": 0})
        bucket["files"] += 1

        if language not in {"Other"}:
            target = root / relative
            try:
                size = target.stat().st_size
            except OSError:
                continue
            if size > max_file_bytes:
                continue
            try:
                with target.open("rb") as handle:
                    sniff = handle.read(8_192)
                    if is_probably_binary(sniff):
                        continue
                    # Full accurate line count
                    handle.seek(0)
                    nl = 0
                    last = None
                    while True:
                        chunk = handle.read(1_048_576)
                        if not chunk:
                            break
                        nl += chunk.count(b"\n")
                        last = chunk[-1:]
                    if size == 0:
                        line_count = 0
                    else:
                        line_count = nl + (0 if last == b"\n" else 1)
            except OSError:
                continue
            bucket["lines"] += line_count
            total_lines += line_count
            line_counted_files += 1

    total_files = len(files)
    languages = sorted(
        (
            {
                "language": language,
                "files": data["files"],
                "lines": data["lines"],
                "filesPct": round(100 * data["files"] / total_files, 2) if total_files else 0.0,
                "linesPct": round(100 * data["lines"] / total_lines, 2) if total_lines else 0.0,
            }
            for language, data in by_language.items()
        ),
        key=lambda item: (item["lines"], item["files"]),
        reverse=True,
    )
    primary = next((entry["language"] for entry in languages if entry["language"] != "Other"), None)

    return {
        "status": "ok",
        "scanRoot": str(root),
        "totalFilesSampled": total_files,
        "lineCountedFiles": line_counted_files,
        "totalLines": total_lines,
        "primaryLanguage": primary,
        "languages": languages,
    }


def _parse_package_json(target: Path) -> tuple[str, list[dict[str, str]]]:
    data = json.loads(target.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError("package.json root is not an object")
    dependencies: list[dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        entries = data.get(section)
        if isinstance(entries, dict):
            for name, version in entries.items():
                dependencies.append({"name": str(name), "version": str(version), "scope": section})
    return "npm", dependencies


def _parse_requirements_txt(target: Path) -> tuple[str, list[dict[str, str]]]:
    dependencies = []
    for raw_line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(.*)", line)
        if match:
            dependencies.append({"name": match.group(1), "version": match.group(2).strip() or None})
    return "pypi", dependencies


def _parse_pyproject_toml(target: Path) -> tuple[str, list[dict[str, str]]]:
    text = target.read_text(encoding="utf-8", errors="replace")
    dependencies: list[dict[str, str]] = []
    project_deps = re.search(r"(?ms)^\[project\].*?^dependencies\s*=\s*\[(.*?)\]", text)
    if project_deps:
        for entry in re.finditer(r"""["']([A-Za-z0-9_.-]+)([^"']*)["']""", project_deps.group(1)):
            dependencies.append({"name": entry.group(1), "version": entry.group(2).strip() or None})
    poetry = re.search(r"(?ms)^\[tool\.poetry\.dependencies\](.*?)(?=^\[|\Z)", text)
    if poetry:
        for entry in re.finditer(r"(?m)^([A-Za-z0-9_.-]+)\s*=\s*[\"']?([^\s\"']+)", poetry.group(1)):
            if entry.group(1).lower() != "python":
                dependencies.append({"name": entry.group(1), "version": entry.group(2)})
    return "pypi", dependencies


def _parse_go_mod(target: Path) -> tuple[str, list[dict[str, str]]]:
    dependencies = []
    in_block = False
    for raw_line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        candidate = line if in_block else (line[len("require "):] if line.startswith("require ") else None)
        if candidate:
            match = re.match(r"(\S+)\s+(v\S+)", candidate)
            if match:
                dependencies.append({"name": match.group(1), "version": match.group(2)})
    return "go", dependencies


def _parse_cargo_toml(target: Path) -> tuple[str, list[dict[str, str]]]:
    dependencies = []
    in_deps = False
    for raw_line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("["):
            in_deps = line in {"[dependencies]", "[dev-dependencies]", "[build-dependencies]"}
            continue
        if in_deps:
            match = re.match(r"([A-Za-z0-9_-]+)\s*=\s*(.+)", line)
            if match:
                dependencies.append({"name": match.group(1), "version": match.group(2).strip().strip('"')})
    return "cargo", dependencies


_MANIFEST_PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "go.mod": _parse_go_mod,
    "Cargo.toml": _parse_cargo_toml,
}


def dependency_inventory(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Best-effort dependency extraction from common manifests."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 500)
    max_dependencies = _read_int_range(arguments.get("maxDependenciesPerManifest"), 200, 1, 2_000, "maxDependenciesPerManifest")

    files = walk_repository(root, max_files)["files"]
    manifests: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
    unique_names: set[str] = set()
    total = 0

    for relative in files:
        parser = _MANIFEST_PARSERS.get(Path(relative).name)
        if parser is None:
            continue
        target = root / relative
        try:
            ecosystem, dependencies = parser(target)
        except Exception as exc:  # best-effort: record and continue
            parse_errors.append({"file": relative, "error": exc.__class__.__name__})
            continue
        capped = dependencies[:max_dependencies]
        for dependency in capped:
            unique_names.add(f"{ecosystem}:{dependency['name'].lower()}")
        total += len(dependencies)
        manifests.append(
            {
                "file": relative,
                "ecosystem": ecosystem,
                "dependencyCount": len(dependencies),
                "dependencyLimitReached": len(dependencies) > len(capped),
                "dependencies": capped,
            }
        )

    return {
        "status": "ok",
        "scanRoot": str(root),
        "manifestCount": len(manifests),
        "totalDependencies": total,
        "uniqueDependencyCount": len(unique_names),
        "manifests": manifests,
        "parseErrors": parse_errors,
        "note": "Extraction is best-effort and offline; it does not resolve transitive or registry data.",
    }


def git_history(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recent commit history and churn hotspots from local git (read-only)."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_commits = _read_int_range(arguments.get("maxCommits"), 20, 1, 100, "maxCommits")
    include_churn = _read_bool(arguments.get("includeChurn"), True, "includeChurn")

    if git_executable() is None:
        return {"status": "unknown", "available": False, "detail": "git is not available on PATH."}
    inside = run_git(root, ["rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.returncode != 0 or inside.stdout.strip() != "true":
        return {"status": "unknown", "available": True, "repository": False, "detail": "Target is not a git worktree."}

    log = run_git(root, ["log", f"-n{max_commits}", "--date=iso-strict", "--pretty=format:%h%x1f%an%x1f%ae%x1f%ad%x1f%s"], timeout_seconds=10.0)
    commits: list[dict[str, Any]] = []
    authors: set[str] = set()
    if log is not None and log.returncode == 0 and log.stdout.strip():
        for line in log.stdout.splitlines():
            parts = line.split("\x1f")
            if len(parts) < 5:
                continue
            commits.append(
                {
                    "hash": parts[0],
                    "author": parts[1],
                    "authorEmail": parts[2],
                    "date": parts[3],
                    "subject": parts[4][:200],
                }
            )
            authors.add(parts[2].lower())

    top_changed: list[dict[str, Any]] = []
    if include_churn:
        churn = run_git(root, ["log", f"-n{max_commits}", "--pretty=format:", "--name-only"], timeout_seconds=10.0)
        counts: dict[str, int] = {}
        if churn is not None and churn.returncode == 0:
            for line in churn.stdout.splitlines():
                name = line.strip()
                if name:
                    counts[name] = counts.get(name, 0) + 1
        top_changed = [
            {"file": name, "changes": count}
            for name, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:20]
        ]

    return {
        "status": "ok",
        "available": True,
        "repository": True,
        "scanRoot": str(root),
        "commitCount": len(commits),
        "distinctAuthorCount": len(authors),
        "commits": commits,
        "topChangedFiles": top_changed,
        "note": "Local history only; it does not query remotes or prove deployment state.",
    }


def risk_score(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Heuristic composite delivery-risk score from read-only signals."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    path = arguments.get("path", os.getcwd())
    max_files = _read_max_files(arguments.get("maxFiles"), 500)
    snapshot = repo_snapshot({"path": path, "maxFiles": max_files, "includeGit": True})
    readiness = release_readiness({"path": path, "maxFiles": max_files})
    secrets = secret_scan({"path": path, "maxFiles": max_files})

    factors: list[dict[str, Any]] = []

    def add(condition: bool, identifier: str, weight: int, detail: str) -> None:
        if condition:
            factors.append({"id": identifier, "weight": weight, "detail": detail})

    add(secrets["findingCount"] > 0, "secret-findings", 40, f"{secrets['findingCount']} redacted secret-signature finding(s).")
    add(bool(snapshot["manifests"]) and not snapshot["lockfiles"], "missing-lockfile", 15, "Build manifest present without a detected lockfile.")
    add(not snapshot["testFiles"], "no-test-evidence", 15, "No test-related files detected in the sample.")
    add(not snapshot["ciFiles"], "no-ci-evidence", 10, "No CI configuration detected in the sample.")
    git = snapshot["git"] or {}
    add(git.get("repository") is True and git.get("workingTreeClean") is False, "dirty-working-tree", 10, f"Working tree has {git.get('changedFileCount')} changed path(s).")
    add(snapshot["sampleLimitReached"], "sample-limit-reached", 5, "Inventory sampling limit reached; absence claims are weaker.")
    add(readiness["summary"]["fail"] > 0, "readiness-failures", 20, f"{readiness['summary']['fail']} release-readiness check(s) failing.")
    add(not (Path(snapshot["scanRoot"]) / "README.md").is_file(), "no-readme", 5, "README.md missing at repository root.")
    add(snapshot["inaccessibleDirectoryCount"] > 0, "inaccessible-dirs", 2, f"{snapshot['inaccessibleDirectoryCount']} director(y/ies) could not be read.")
    add(snapshot["nonUtf8PathCount"] > 0, "non-utf8-paths", 2, f"{snapshot['nonUtf8PathCount']} path(s) contained non-UTF-8 names.")

    score = min(100, sum(factor["weight"] for factor in factors))
    if score < 10:
        grade, level = "A", "low"
    elif score < 25:
        grade, level = "B", "low"
    elif score < 45:
        grade, level = "C", "moderate"
    elif score < 70:
        grade, level = "D", "elevated"
    else:
        grade, level = "F", "high"

    return {
        "status": "ok",
        "scanRoot": snapshot["scanRoot"],
        "generatedAtUtc": _utc_now(),
        "score": score,
        "grade": grade,
        "riskLevel": level,
        "factors": sorted(factors, key=lambda factor: factor["weight"], reverse=True),
        "inputs": {
            "readinessStatus": readiness["status"],
            "secretFindingCount": secrets["findingCount"],
            "fileCountSampled": snapshot["fileCountSampled"],
        },
        "note": "Heuristic signal for prioritization, not a security certification.",
    }


def _executable_version(name: str, arguments: list[str]) -> str | None:
    path = shutil.which(name)
    if path is None:
        return None
    try:
        result = subprocess.run(
            [path, *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    first_line = (result.stdout or "").splitlines()
    return first_line[0].strip()[:120] if first_line else None


def doctor(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Environment and capability probe for harness-agnostic deployments."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    temp_writable = False
    try:
        with tempfile.TemporaryFile():
            temp_writable = True
    except OSError:
        temp_writable = False

    # Resolve plugin root with fallbacks for pip-installed locations
    candidate_roots = []
    env_root = os.environ.get("SDLC_PLUGIN_ROOT")
    if env_root:
        candidate_roots.append(Path(env_root))
    # Original file location (source checkout)
    candidate_roots.append(Path(__file__).resolve().parent.parent)
    # Common global install locations
    candidate_roots.extend([
        Path.home() / "Projects" / "autonomous-sdlc-command-center",
        Path.home() / ".local" / "share" / "autonomous-sdlc-command-center" / "autonomous-sdlc-command-center",
        Path.home() / ".local" / "share" / "autonomous-sdlc-command-center",
        Path.cwd(),
    ])
    plugin_root = None
    preflight_status = None
    for candidate in candidate_roots:
        try:
            if (candidate / ".codex-plugin" / "plugin.json").is_file():
                plugin_root = candidate
                break
        except OSError:
            continue
    if plugin_root is None:
        plugin_root = Path(__file__).resolve().parent.parent
    if (plugin_root / ".codex-plugin" / "plugin.json").is_file():
        try:
            preflight = plugin_preflight({"pluginPath": str(plugin_root)})
            preflight_status = {"status": preflight["status"], "errors": preflight["summary"]["errors"], "warnings": preflight["summary"]["warnings"]}
        except InputError:
            preflight_status = None
    else:
        # If installed via pip and no plugin.json found, still report core healthy with null preflight
        preflight_status = None

    return {
        "status": "ok",
        "coreVersion": VERSION,
        "python": {"version": platform.python_version(), "implementation": platform.python_implementation(), "executable": sys.executable},
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "executables": {
            "git": _executable_version("git", ["--version"]),
            "rg": _executable_version("rg", ["--version"]),
            "pwsh": _executable_version("pwsh", ["--version"]),
        },
        "capabilities": {
            "mcpStdio": True,
            "mcpHttp": True,
            "readDiagnostics": True,
            "writeEngine": True,
            "rollback": True,
            "auditLog": True,
            "sarifOutput": True,
            "networkPathsAllowed": os.environ.get("SDLC_ALLOW_NETWORK_PATHS") == "1",
        },
        "filesystem": {"tempWritable": temp_writable},
        "plugin": {"root": str(plugin_root), "preflight": preflight_status},
    }
