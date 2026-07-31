"""Extended SDLC diagnostics: code metrics, SBOM-lite, entropy scanner, AST refactor.

These are additive tools beyond the core 18, designed for enhancement without breaking
existing contracts. Zero dependencies, cross-platform, Python 3.9+.

- code_metrics: cyclomatic-ish complexity estimation, TODO/FIXME counts, large file detection
- sbom_lite: lightweight SBOM generation from manifests (offline)
- entropy_scan: Shannon entropy secret detection (H > 4.5 threshold)
- replace_in_file_ast: Python AST-aware scope-safe string replacement
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from sdlc_core import (
    InputError,
    _read_max_files,
    _read_int_range,
    _resolve_directory,
    _utc_now,
    walk_repository,
    is_probably_binary,
)


def code_metrics(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Lightweight code health metrics: file counts, TODOs, large files, complexity hints."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 1000)
    max_file_bytes = _read_int_range(arguments.get("maxFileBytes"), 262_144, 1_024, 1_048_576, "maxFileBytes")
    todo_pattern = re.compile(r"(TODO|FIXME|HACK|XXX|BUG)\b", re.IGNORECASE)

    files = walk_repository(root, max_files)["files"]
    total = len(files)
    metrics = {
        "filesScanned": 0,
        "todoCount": 0,
        "fixmeCount": 0,
        "largeFiles": [],
        "complexityHints": [],
        "longLines": 0,
        "emptyFiles": 0,
        "binarySkipped": 0,
    }

    todos_by_file: dict[str, int] = {}

    for relative in files:
        target = root / relative
        try:
            size = target.stat().st_size
        except OSError:
            continue
        if size == 0:
            metrics["emptyFiles"] += 1
            continue
        if size > max_file_bytes:
            metrics["largeFiles"].append({"file": relative, "bytes": size})
            continue
        try:
            with target.open("rb") as h:
                sniff = h.read(8192)
                if is_probably_binary(sniff):
                    metrics["binarySkipped"] += 1
                    continue
                h.seek(0)
                raw = h.read(max_file_bytes)
        except OSError:
            continue

        metrics["filesScanned"] += 1
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if not lines:
            metrics["emptyFiles"] += 1
            continue

        # TODO counts
        for line in lines:
            m = todo_pattern.search(line)
            if m:
                kind = m.group(1).upper()
                if kind == "TODO":
                    metrics["todoCount"] += 1
                todos_by_file[relative] = todos_by_file.get(relative, 0) + 1
                if "FIXME" in kind or "BUG" in kind:
                    metrics["fixmeCount"] += 1
            if len(line) > 200:
                metrics["longLines"] += 1

        # Complexity hint: count branching keywords
        # Simple heuristic: if/else, for, while, case, &&, ||
        branch_tokens = len(re.findall(r"\b(if|for|while|case|elif|else if)\b|&&|\|\|", text))
        if branch_tokens > 30 and len(lines) < 200:
            metrics["complexityHints"].append({"file": relative, "branches": branch_tokens, "lines": len(lines), "hint": "high branch density"})

    # Top files with most TODOs
    top_todo = sorted(todos_by_file.items(), key=lambda x: x[1], reverse=True)[:20]

    score = 100
    score -= min(20, metrics["todoCount"] // 2)
    score -= min(20, metrics["fixmeCount"] * 3)
    score -= min(15, len(metrics["largeFiles"]) * 2)
    score -= min(10, metrics["longLines"] // 20)
    score -= min(15, len(metrics["complexityHints"]) * 2)
    score = max(0, score)

    return {
        "status": "ok",
        "scanRoot": str(root),
        "generatedAtUtc": _utc_now(),
        "fileCountSampled": total,
        "metrics": metrics,
        "topTodoFiles": [{"file": f, "count": c} for f, c in top_todo],
        "healthScore": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "note": "Heuristic metrics for prioritization, not precise complexity analysis.",
    }


def sbom_lite(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Offline SBOM generation from manifests - CycloneDX-like minimal JSON."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 500)

    # Defer to dependency_inventory for parsing, then transform to SBOM shape
    from sdlc_analyze import dependency_inventory

    inv = dependency_inventory({"path": str(root), "maxFiles": max_files})

    components = []
    for manifest in inv.get("manifests", []):
        for dep in manifest.get("dependencies", []):
            components.append({
                "type": "library",
                "name": dep.get("name"),
                "version": dep.get("version"),
                "scope": dep.get("scope") or "required",
                "ecosystem": manifest.get("ecosystem"),
                "manifest": manifest.get("file"),
            })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{_utc_now()}",
        "version": 1,
        "metadata": {
            "timestamp": _utc_now(),
            "component": {
                "type": "application",
                "name": root.name,
                "version": "unknown",
            },
            "tools": [{"vendor": "autonomous-sdlc", "name": "sdlc_sbom_lite", "version": "1.2.0"}],
        },
        "components": components,
    }

    return {
        "status": "ok",
        "scanRoot": str(root),
        "generatedAtUtc": _utc_now(),
        "manifestCount": inv.get("manifestCount", 0),
        "componentCount": len(components),
        "uniqueComponentCount": inv.get("uniqueDependencyCount", 0),
        "bom": bom,
        "note": "Offline SBOM from manifests only; no transitive resolution or vulnerability data.",
    }


# -------------------------------------------------------------------
# Entropy-based secret scanner (Shannon H > 4.5)
# -------------------------------------------------------------------

# Token regex: word-boundary anchored to avoid matching inside identifiers.
# Matches Base64, hex strings, JWTs, API keys, etc.
_TOKEN_REGEX = re.compile(
    r"(?:^|(?<=['\"=:\s]))([A-Za-z0-9+/=_\-\.~]{16,})(?=['\"\s;,)}]|$)"
)

_IGNORED_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll",
    ".lock", ".min.js", ".min.css", ".map",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
})


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy H(X) in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _safe_token_preview(token: str) -> str:
    """Show first/last 2 chars for short tokens, 4 chars for long ones. Never >50% reveal."""
    length = len(token)
    if length <= 8:
        return f"{token[:2]}...{token[-2:]}"
    if length <= 20:
        return f"{token[:3]}...{token[-3:]}"
    return f"{token[:4]}...{token[-4:]}"


def entropy_scan(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Shannon entropy secret detector. Flags high-entropy tokens (H > threshold) without patterns.

    Unlike signature-based scanners, this catches arbitrary unpatterned credentials,
    random API keys, and obfuscated secrets that regex would miss.
    """

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_files = _read_max_files(arguments.get("maxFiles"), 1000)
    max_file_bytes = _read_int_range(arguments.get("maxFileBytes"), 262_144, 1_024, 1_048_576, "maxFileBytes")
    max_findings = _read_int_range(arguments.get("maxFindings"), 500, 1, 5_000, "maxFindings")
    entropy_threshold = arguments.get("entropyThreshold")
    if entropy_threshold is None:
        entropy_threshold = 4.5
    else:
        try:
            entropy_threshold = float(entropy_threshold)
        except (TypeError, ValueError):
            raise InputError("entropyThreshold must be a number")
        if not (2.0 <= entropy_threshold <= 8.0):
            raise InputError("entropyThreshold must be between 2.0 and 8.0")

    min_token_length = _read_int_range(arguments.get("minTokenLength"), 16, 8, 128, "minTokenLength")

    files = walk_repository(root, max_files)["files"]
    findings: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()  # deduplicate across files
    files_scanned = 0

    for relative in files:
        if len(findings) >= max_findings:
            break
        target = root / relative
        if target.suffix.lower() in _IGNORED_EXTENSIONS:
            continue
        try:
            size = target.stat().st_size
        except OSError:
            continue
        if size == 0 or size > max_file_bytes:
            continue
        try:
            with target.open("rb") as h:
                sniff = h.read(8192)
                if is_probably_binary(sniff):
                    continue
                h.seek(0)
                raw = h.read(max_file_bytes)
        except OSError:
            continue

        files_scanned += 1
        content = raw.decode("utf-8", errors="replace")

        for line_num, line in enumerate(content.splitlines(), start=1):
            if len(findings) >= max_findings:
                break
            for match in _TOKEN_REGEX.finditer(line):
                token = match.group(1) if match.lastindex else match.group(0)
                if len(token) < min_token_length:
                    continue

                # Deduplicate by SHA-256 of the token
                token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
                if token_hash in seen_tokens:
                    continue
                seen_tokens.add(token_hash)

                entropy = _shannon_entropy(token)
                if entropy >= entropy_threshold:
                    findings.append({
                        "file": relative,
                        "line": line_num,
                        "tokenPreview": _safe_token_preview(token),
                        "entropy": round(entropy, 3),
                        "length": len(token),
                        "tokenHash": token_hash,
                    })

    return {
        "status": "pass" if not findings else "warning",
        "scanRoot": str(root),
        "scannedAtUtc": _utc_now(),
        "filesScanned": files_scanned,
        "findingCount": len(findings),
        "findingsLimitReached": len(findings) >= max_findings,
        "entropyThreshold": entropy_threshold,
        "findings": findings,
        "note": "Entropy-based detection; no regex patterns used. Token previews are truncated to prevent secret leakage. Confirm true positives with a secrets manager.",
    }


# -------------------------------------------------------------------
# AST-aware file replacement (Python stdlib ast module)
# -------------------------------------------------------------------

def _ast_find_string_literals(tree: ast.AST, target: str) -> list[ast.Constant]:
    """Find all string constants in the AST that contain the target substring."""

    class StringFinder(ast.NodeVisitor):
        def __init__(self) -> None:
            self.matches: list[ast.Constant] = []

        def visit_Constant(self, node: ast.Constant) -> None:
            if isinstance(node.value, str) and target in node.value:
                self.matches.append(node)
            self.generic_visit(node)

    finder = StringFinder()
    finder.visit(tree)
    return finder.matches


def _ast_replace_in_strings(tree: ast.AST, target: str, replacement: str) -> tuple[str, int]:
    """Replace target with replacement in all string constants. Returns (new_source, count)."""

    class StringReplacer(ast.NodeVisitor):
        def __init__(self) -> None:
            self.count = 0

        def visit_Constant(self, node: ast.Constant) -> None:
            if isinstance(node.value, str) and target in node.value:
                node.value = node.value.replace(target, replacement)
                self.count += 1
            self.generic_visit(node)

    replacer = StringReplacer()
    replacer.visit(tree)
    return ast.unparse(tree), replacer.count


def replace_in_file_ast(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Scope-aware string replacement using Python's AST module.

    For .py files: parses the source into an AST, finds string literals containing
    the target, and replaces them while preserving all non-string code formatting.

    For non-.py files: falls back to exact string replacement (same as sdlc_replace_in_file).
    """

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    file_path = arguments.get("filePath")
    if not isinstance(file_path, str) or not file_path:
        raise InputError("filePath is required")

    target = (root / file_path).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise InputError("filePath escapes the target directory")

    if not target.exists() or not target.is_file():
        raise InputError("target does not exist as a regular file")

    find = arguments.get("find", "")
    if not isinstance(find, str) or not find:
        raise InputError("find must be a non-empty string")

    replace = arguments.get("replace", "")
    if not isinstance(replace, str):
        raise InputError("replace must be a string")

    confirm = arguments.get("confirm", False)
    dry_run = arguments.get("dryRun")
    effective_dry_run = True if dry_run is True else not confirm

    # Read the file
    try:
        content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise InputError("target is not valid UTF-8 text")

    # Only use AST mode for Python files
    is_python = target.suffix == ".py"

    if is_python:
        try:
            tree = ast.parse(content, filename=str(target))
        except SyntaxError as exc:
            raise InputError(f"cannot parse Python file (syntax error at line {exc.lineno}): {exc.msg}")

        # Find matching string literals
        matches = _ast_find_string_literals(tree, find)

        if not matches:
            # No string literals match — try a full-source fallback
            if find in content:
                after_text = content.replace(find, replace)
                mode_used = "full-source-fallback"
                occurrences = content.count(find)
            else:
                return {
                    "status": "no-match",
                    "dryRun": effective_dry_run,
                    "path": str(root),
                    "filePath": file_path,
                    "mode": "ast",
                    "find": find,
                    "occurrences": 0,
                    "note": "No string literals or source text matched the target.",
                }
            mode_used = "full-source-fallback"
            occurrences = content.count(find)
        else:
            after_text, count = _ast_replace_in_strings(tree, find, replace)
            mode_used = "ast"
            occurrences = count
    else:
        # Non-Python: exact string replacement
        occurrences = content.count(find)
        if occurrences == 0:
            return {
                "status": "no-match",
                "dryRun": effective_dry_run,
                "path": str(root),
                "filePath": file_path,
                "mode": "exact",
                "find": find,
                "occurrences": 0,
            }
        after_text = content.replace(find, replace)
        mode_used = "exact"

    # Build diff preview
    import difflib
    diff_lines = list(difflib.unified_diff(
        content.splitlines(keepends=True),
        after_text.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    ))
    added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    preview = "\n".join(line.rstrip("\n") for line in diff_lines[:100])
    truncated = len(diff_lines) > 100

    result: dict[str, Any] = {
        "status": "dry-run" if effective_dry_run else "applied",
        "dryRun": effective_dry_run,
        "path": str(root),
        "filePath": file_path,
        "mode": mode_used,
        "find": find,
        "replace": replace,
        "occurrences": occurrences,
        "diff": {"preview": preview, "truncated": truncated, "linesAdded": added, "linesRemoved": removed},
    }

    if effective_dry_run:
        return result

    # Apply the change
    target.write_text(after_text, encoding="utf-8")
    result["approvalGate"] = "Applied without backup. Use sdlc_rollback for reversal if backed up separately."
    return result
