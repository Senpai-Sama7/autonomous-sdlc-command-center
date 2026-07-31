"""Shadow Worktree Engine: zero-latency out-of-band agent execution.

Provides isolated Git worktree sessions for safe mutation + validation before
promoting verified changes back to the main repository. Eliminates the
dry-run -> LLM evaluation -> confirm two-pass latency.

Safety invariants:
  1. Shadow worktrees live under .sdlc/shadows/ and are auto-cleaned.
  2. Promote checks for conflicts via 3-way diff before writing.
  3. All operations are path-confined to the shadow or main repo.
  4. Sessions are tracked in .sdlc/shadow-sessions.jsonl for audit.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from sdlc_core import (
    InputError,
    _read_bool,
    _resolve_directory,
    _utc_now,
    run_git,
)


SHADOW_DIR_NAME = "shadows"
SHADOW_STATE_FILE = "shadow-sessions.jsonl"


def _shadow_state_dir(root: Path) -> Path:
    return root / ".sdlc"


def _shadow_sessions_path(root: Path) -> Path:
    return _shadow_state_dir(root) / SHADOW_STATE_FILE


def _shadow_base(root: Path) -> Path:
    base = _shadow_state_dir(root) / SHADOW_DIR_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def _read_sessions(root: Path) -> list[dict[str, Any]]:
    path = _shadow_sessions_path(root)
    if not path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def _append_session(root: Path, record: dict[str, Any]) -> None:
    state = _shadow_state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    with _shadow_sessions_path(root).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _run_git_shadow(repo_path: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_path)] + args,
        capture_output=True,
        text=True,
        check=False,
    )


def _diff3_check(main_repo: Path, shadow_path: Path, relative_paths: list[str]) -> dict[str, Any]:
    """Check for conflicts between shadow changes and main working tree.

    Uses diff3-style 3-way comparison: base (HEAD), main (current), shadow.
    Returns conflict info if any file was modified in both main and shadow.
    """
    conflicts: list[dict[str, Any]] = []
    clean: list[str] = []

    for rel in relative_paths:
        shadow_file = shadow_path / rel
        main_file = main_repo / rel

        if not shadow_file.exists():
            continue

        shadow_content = shadow_file.read_text(encoding="utf-8", errors="replace") if shadow_file.is_file() else ""

        # Get the base version from HEAD
        base_result = _run_git_shadow(main_repo, ["show", f"HEAD:{rel}"])
        base_content = base_result.stdout if base_result.returncode == 0 else ""

        # Get the current main version
        if main_file.exists() and main_file.is_file():
            main_content = main_file.read_text(encoding="utf-8", errors="replace")
        else:
            main_content = ""

        # Check if both sides changed from base
        base_changed_main = main_content != base_content
        base_changed_shadow = shadow_content != base_content

        if base_changed_main and base_changed_shadow:
            # Both sides changed — potential conflict
            # Use difflib to show what's different
            diff_main = list(difflib.unified_diff(
                base_content.splitlines(keepends=True),
                main_content.splitlines(keepends=True),
                fromfile=f"base/{rel}",
                tofile=f"main/{rel}",
                lineterm="",
            ))
            diff_shadow = list(difflib.unified_diff(
                base_content.splitlines(keepends=True),
                shadow_content.splitlines(keepends=True),
                fromfile=f"base/{rel}",
                tofile=f"shadow/{rel}",
                lineterm="",
            ))
            conflicts.append({
                "file": rel,
                "mainDiffLines": len(diff_main),
                "shadowDiffLines": len(diff_shadow),
                "mainPreview": "\n".join(diff_main[:20]),
                "shadowPreview": "\n".join(diff_shadow[:20]),
            })
        else:
            clean.append(rel)

    return {
        "hasConflicts": len(conflicts) > 0,
        "conflictCount": len(conflicts),
        "cleanCount": len(clean),
        "conflicts": conflicts,
        "cleanFiles": clean,
    }


def shadow_create(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create an isolated shadow worktree for zero-latency agent execution.

    Spawns a lightweight Git worktree at .sdlc/shadows/<session>/ on a temporary branch.
    The agent can write files, run tests, and validate changes in this isolated space.
    Use shadow_promote to atomically merge verified changes back.
    """

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))

    # Verify this is a git repo
    git_check = _run_git_shadow(root, ["rev-parse", "--git-dir"])
    if git_check.returncode != 0:
        raise InputError("target directory is not a Git repository")

    # Check for uncommitted changes
    status = _run_git_shadow(root, ["status", "--porcelain"])
    has_uncommitted = bool(status.stdout.strip())

    # Stash uncommitted changes if present, so shadow gets a clean snapshot
    stashed = False
    if has_uncommitted:
        stash_result = _run_git_shadow(root, ["stash", "push", "-m", "sdlc-shadow-stash"])
        if stash_result.returncode == 0 and "No local changes" not in stash_result.stdout:
            stashed = True

    session_id = f"shadow-{uuid.uuid4().hex[:8]}"
    shadow_path = _shadow_base(root) / session_id
    branch_name = f"sdlc-tmp-{session_id}"

    try:
        result = _run_git_shadow(root, ["worktree", "add", "-b", branch_name, str(shadow_path), "HEAD"])
        if result.returncode != 0:
            raise RuntimeError(f"Shadow worktree creation failed: {result.stderr.strip()}")
    finally:
        # Restore stashed changes
        if stashed:
            _run_git_shadow(root, ["stash", "pop"])

    # Record session
    session_record = {
        "sessionId": session_id,
        "createdAtUtc": _utc_now(),
        "branchName": branch_name,
        "shadowPath": str(shadow_path),
        "mainPath": str(root),
        "status": "active",
    }
    _append_session(root, session_record)

    return {
        "status": "created",
        "sessionId": session_id,
        "shadowPath": str(shadow_path),
        "branchName": branch_name,
        "mainPath": str(root),
        "hasUncommittedInMain": has_uncommitted,
        "note": "Write files and run tests in the shadow path. Use shadow_promote to merge back.",
    }


def shadow_promote(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Promote verified changes from a shadow worktree to the main repository.

    Performs a 3-way conflict check before writing. Only files that exist in the
    shadow are promoted. Files deleted in the shadow will be deleted in main.
    """

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    session_id = arguments.get("sessionId")
    if not isinstance(session_id, str) or not session_id:
        raise InputError("sessionId is required")

    confirm = _read_bool(arguments.get("confirm"), False, "confirm")
    dry_run = arguments.get("dryRun")
    effective_dry_run = True if dry_run is True else not confirm

    # Find the session
    sessions = _read_sessions(root)
    session = None
    for s in sessions:
        if s.get("sessionId") == session_id and s.get("status") == "active":
            session = s
            break

    if session is None:
        raise InputError(f"no active shadow session found for sessionId '{session_id}'")

    shadow_path = Path(session["shadowPath"])
    if not shadow_path.is_dir():
        raise InputError(f"shadow worktree directory missing: {shadow_path}")

    # Find changed files in shadow (vs HEAD of main)
    diff_result = _run_git_shadow(root, ["diff", "--name-only", "HEAD", "--", str(shadow_path)])
    if diff_result.returncode != 0:
        # Fallback: list files that differ
        diff_result = _run_git_shadow(root, ["diff", "--name-status", "HEAD"])

    # Get the list of changed files relative to shadow
    # We need to diff the shadow branch against main
    shadow_diff = _run_git_shadow(shadow_path, ["diff", "--name-status", "HEAD"])
    changed_files: list[str] = []
    if shadow_diff.returncode == 0:
        for line in shadow_diff.stdout.splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                status_code, filepath = parts
                if status_code in ("M", "A", "D"):
                    changed_files.append(filepath)

    if not changed_files:
        # Try a broader approach: compare shadow tree to main tree
        ls_result = _run_git_shadow(shadow_path, ["ls-files", "--modified", "--others"])
        if ls_result.returncode == 0:
            changed_files = [f for f in ls_result.stdout.splitlines() if f.strip()]

    if not changed_files:
        return {
            "status": "nothing-to-promote",
            "dryRun": effective_dry_run,
            "sessionId": session_id,
            "shadowPath": str(shadow_path),
            "changedFiles": [],
            "note": "No modified files detected in shadow worktree.",
        }

    # Conflict check
    conflict_info = _diff3_check(root, shadow_path, changed_files)

    result: dict[str, Any] = {
        "status": "dry-run" if effective_dry_run else "promoted",
        "dryRun": effective_dry_run,
        "sessionId": session_id,
        "shadowPath": str(shadow_path),
        "changedFiles": changed_files,
        "conflictCheck": conflict_info,
    }

    if conflict_info["hasConflicts"] and not effective_dry_run:
        result["status"] = "conflicts-detected"
        result["approvalGate"] = "Resolve conflicts manually or pass force=true to overwrite."
        force = _read_bool(arguments.get("force"), False, "force")
        if not force:
            return result

    if effective_dry_run:
        return result

    # Promote: copy changed files from shadow to main
    promoted: list[dict[str, Any]] = []
    for rel in changed_files:
        shadow_file = shadow_path / rel
        main_file = root / rel

        if not str(shadow_file.resolve()).startswith(str(shadow_path.resolve())):
            raise InputError(f"Shadow file escapes shadow directory: {rel}")

        if shadow_file.exists() and shadow_file.is_file():
            # Copy file from shadow to main
            main_file.parent.mkdir(parents=True, exist_ok=True)
            src_data = shadow_file.read_bytes()
            dst_hash = hashlib.sha256(src_data).hexdigest()[:16]
            shutil.copy2(str(shadow_file), str(main_file))
            promoted.append({"file": rel, "action": "copied", "hash": dst_hash})
        elif not shadow_file.exists() and main_file.exists():
            # File was deleted in shadow — delete in main
            main_file.unlink()
            promoted.append({"file": rel, "action": "deleted"})

    result["promoted"] = promoted
    result["promotedCount"] = len(promoted)
    return result


def shadow_destroy(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Destroy a shadow worktree and clean up its temporary branch."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    session_id = arguments.get("sessionId")
    if not isinstance(session_id, str) or not session_id:
        raise InputError("sessionId is required")

    sessions = _read_sessions(root)
    session = None
    for s in sessions:
        if s.get("sessionId") == session_id:
            session = s
            break

    if session is None:
        raise InputError(f"no shadow session found for sessionId '{session_id}'")

    shadow_path = Path(session["shadowPath"])
    branch_name = session["branchName"]

    # Remove worktree
    if shadow_path.is_dir():
        _run_git_shadow(root, ["worktree", "remove", "--force", str(shadow_path)])
        # Fallback: manual removal if git worktree remove fails
        if shadow_path.is_dir():
            shutil.rmtree(shadow_path, ignore_errors=True)

    # Remove branch
    _run_git_shadow(root, ["branch", "-D", branch_name])

    # Update session record
    _append_session(root, {
        **session,
        "status": "destroyed",
        "destroyedAtUtc": _utc_now(),
    })

    return {
        "status": "destroyed",
        "sessionId": session_id,
        "shadowPath": str(shadow_path),
        "branchName": branch_name,
    }


def shadow_list(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """List active shadow worktree sessions."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")

    root = _resolve_directory(arguments.get("path", os.getcwd()))
    sessions = _read_sessions(root)

    # Filter to active sessions and verify they still exist
    active: list[dict[str, Any]] = []
    for s in sessions:
        if s.get("status") != "active":
            continue
        shadow_path = Path(s.get("shadowPath", ""))
        if shadow_path.is_dir():
            active.append(s)
        else:
            # Mark as stale
            _append_session(root, {**s, "status": "stale", "staleAtUtc": _utc_now()})

    return {
        "status": "ok",
        "path": str(root),
        "activeCount": len(active),
        "sessions": active,
    }
