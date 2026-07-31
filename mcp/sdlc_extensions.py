"""Extended SDLC diagnostics: code metrics and SBOM-lite.

These are additive tools beyond the core 18, designed for enhancement without breaking
existing contracts. Zero dependencies, cross-platform, Python 3.9+.

- code_metrics: cyclomatic-ish complexity estimation, TODO/FIXME counts, large file detection
- sbom_lite: lightweight SBOM generation from manifests (offline)
"""

from __future__ import annotations

import json
import os
import re
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
            "tools": [{"vendor": "autonomous-sdlc", "name": "sdlc_sbom_lite", "version": "1.1.0"}],
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
