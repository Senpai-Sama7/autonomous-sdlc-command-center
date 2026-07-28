"""Safety-gated write engine: dry-run by default, explicit confirm, atomic writes,
content-addressed backups, reversible rollback, and a hash-chained audit log.

Safety invariants (enforced here, not by callers):
  1. Every mutation runs as a dry-run unless ``confirm: true`` is passed.
  2. Writes never escape the approved root (traversal, symlinks, and UNC rejected).
  3. Sensitive locations (.env, keys, credentials, .git, the .sdlc state dir) require
     an explicit ``allowSensitive: true`` override.
  4. Every real mutation is backed up first and recorded in the audit log.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sdlc_core import (
    InputError,
    _read_bool,
    _read_int_range,
    _resolve_directory,
    _utc_now,
    resolve_within_root,
)


MAX_WRITE_BYTES = 1_048_576
MAX_DIFF_PREVIEW_CHARS = 10_000
STATE_DIRECTORY_NAME = ".sdlc"
AUDIT_FILE_NAME = "audit.jsonl"
BACKUPS_DIRECTORY_NAME = "backups"

SENSITIVE_BASENAME_PATTERN = re.compile(
    r"(?i)^(?:\.env(?:\..+)?|.*\.(?:pem|key|pfx|p12|jks|keystore)|id_(?:rsa|dsa|ecdsa|ed25519)(?:\..+)?|"
    r"(?:.*[_.-])?(?:credentials?|secrets?)(?:[_.-].*)?)$"
)
NON_SENSITIVE_ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template", ".env.defaults"})
PROTECTED_PATH_PARTS = frozenset({".git", STATE_DIRECTORY_NAME})


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _new_change_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def _state_dir(root: Path) -> Path:
    return root / STATE_DIRECTORY_NAME


def _audit_path(root: Path) -> Path:
    return _state_dir(root) / AUDIT_FILE_NAME


def _canonical(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _read_audit_entries(root: Path) -> list[dict[str, Any]]:
    path = _audit_path(root)
    if not path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                entries.append({"corrupt": True, "raw": None})
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)
    return entries


def _append_audit(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    """Append one hash-chained entry. Returns the stored entry."""

    state = _state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    entries = _read_audit_entries(root)
    previous_hash = entries[-1].get("entryHash") if entries and isinstance(entries[-1], dict) else None
    entry = {
        "seq": len(entries) + 1,
        "timestampUtc": _utc_now(),
        "prevHash": previous_hash,
        **record,
    }
    entry["entryHash"] = _sha256_text((previous_hash or "GENESIS") + "|" + _canonical(entry))
    with _audit_path(root).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return entry


def verify_audit_chain(entries: list[dict[str, Any]]) -> tuple[bool, int | None]:
    previous_hash: str | None = None
    for position, entry in enumerate(entries, start=1):
        if entry.get("corrupt"):
            return False, position
        stored_hash = entry.get("entryHash")
        body = {key: value for key, value in entry.items() if key != "entryHash"}
        if body.get("seq") != position or body.get("prevHash") != previous_hash:
            return False, position
        expected = _sha256_text((previous_hash or "GENESIS") + "|" + _canonical(body))
        if stored_hash != expected:
            return False, position
        previous_hash = stored_hash
    return True, None


def _guard_target(root: Path, file_path: str, allow_sensitive: bool) -> Path:
    target = resolve_within_root(root, file_path)
    relative = target.relative_to(root)
    if any(part in PROTECTED_PATH_PARTS for part in relative.parts):
        raise InputError("writes into VCS metadata or the .sdlc state directory are not allowed")
    if not allow_sensitive:
        name = target.name
        if name not in NON_SENSITIVE_ENV_TEMPLATES and SENSITIVE_BASENAME_PATTERN.match(name):
            raise InputError(
                "target matches a sensitive-file convention; pass allowSensitive: true to override intentionally"
            )
    return target


def _atomic_write_bytes(target: Path, data: bytes, preserve_mode_from: Path | None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = None
    if preserve_mode_from is not None:
        try:
            mode = preserve_mode_from.stat().st_mode & 0o777
        except OSError:
            mode = None
    fd, temp_name = tempfile.mkstemp(prefix=".sdlc-tmp-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temp_name, mode)
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _unified_preview(before: str, after: str, relative: str) -> tuple[str, bool, dict[str, int]]:
    diff_lines = list(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
            lineterm="",
        )
    )
    added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    preview = "\n".join(line.rstrip("\n") for line in diff_lines)
    truncated = len(preview) > MAX_DIFF_PREVIEW_CHARS
    if truncated:
        preview = preview[:MAX_DIFF_PREVIEW_CHARS]
    return preview, truncated, {"linesAdded": added, "linesRemoved": removed}


def _read_text_argument(arguments: dict[str, Any], key: str, maximum: int = MAX_WRITE_BYTES) -> str:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise InputError(f"{key} must be a string")
    if not _is_valid_utf8(value):
        raise InputError(f"{key} must be valid UTF-8 text")
    if len(value.encode("utf-8")) > maximum:
        raise InputError(f"{key} exceeds the {maximum}-byte limit")
    return value


def _is_valid_utf8(value: str) -> bool:
    try:
        value.encode("utf-8", errors="strict")
        return True
    except UnicodeEncodeError:
        return False


def _parse_common(arguments: dict[str, Any] | None, require_file_path: bool = True) -> tuple[dict[str, Any], Path, bool]:
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")
    root = _resolve_directory(arguments.get("path", os.getcwd()))
    confirm = _read_bool(arguments.get("confirm"), False, "confirm")
    dry_run = _read_bool(arguments.get("dryRun"), None, "dryRun")
    # Gate semantics: an explicit dryRun=true always wins; otherwise confirm=true applies.
    effective_dry_run = True if dry_run is True else not confirm
    if require_file_path and arguments.get("filePath") is None:
        raise InputError("filePath is required")
    return arguments, root, effective_dry_run


def _record_operation(
    root: Path,
    change_id: str,
    backup_dir: Path,
    operation: str,
    target: Path,
    before_bytes: bytes | None,
    after_bytes: bytes | None,
    dry_run: bool,
) -> dict[str, Any]:
    relative = target.relative_to(root).as_posix()
    record: dict[str, Any] = {
        "operation": operation,
        "path": relative,
        "existedBefore": before_bytes is not None,
        "sha256Before": _sha256_bytes(before_bytes) if before_bytes is not None else None,
        "bytesBefore": len(before_bytes) if before_bytes is not None else None,
        "sha256After": _sha256_bytes(after_bytes) if after_bytes is not None else None,
        "bytesAfter": len(after_bytes) if after_bytes is not None else None,
        "backupFile": None,
    }
    if not dry_run and before_bytes is not None:
        backup_file = backup_dir / relative
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        backup_file.write_bytes(before_bytes)
        record["backupFile"] = str(backup_file.relative_to(_state_dir(root)))
    return record


def _finalize_change(
    root: Path,
    change_id: str,
    backup_dir: Path,
    operations: list[dict[str, Any]],
    dry_run: bool,
) -> None:
    if dry_run or not operations:
        return
    backup_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "changeId": change_id,
        "createdAtUtc": _utc_now(),
        "root": str(root),
        "operations": operations,
    }
    manifest_path = backup_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_file(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create/overwrite/append a UTF-8 text file with backup + audit.

    Default behavior is a dry-run: nothing changes unless ``confirm: true``.
    """

    arguments, root, effective_dry_run = _parse_common(arguments)
    allow_sensitive = _read_bool(arguments.get("allowSensitive"), False, "allowSensitive")
    target = _guard_target(root, str(arguments["filePath"]), allow_sensitive)
    relative = target.relative_to(root).as_posix()

    mode = arguments.get("mode", "overwrite")
    if mode not in {"create", "overwrite", "append"}:
        raise InputError("mode must be one of: create, overwrite, append")
    content = _read_text_argument(arguments, "content")
    expected_sha = arguments.get("expectedSha256")
    if expected_sha is not None and (not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha)):
        raise InputError("expectedSha256 must be a lowercase hex SHA-256 digest")

    exists = target.exists()
    if mode == "create" and exists:
        raise InputError("mode 'create' refused: target already exists")
    before_bytes: bytes | None = None
    before_text = ""
    if exists:
        if not target.is_file():
            raise InputError("target exists and is not a regular file")
        before_bytes = target.read_bytes()
        if len(before_bytes) > MAX_WRITE_BYTES:
            raise InputError("target exceeds the maximum manageable size")
        before_text = before_bytes.decode("utf-8", errors="strict") if _bytes_valid_utf8(before_bytes) else None
        if before_text is None:
            raise InputError("target is not UTF-8 text; refusing to overwrite binary content")
        if expected_sha is not None and _sha256_bytes(before_bytes) != expected_sha:
            raise InputError("expectedSha256 does not match the current file; refusing to write over unknown changes")

    if mode == "append":
        after_text = before_text + content
    else:
        after_text = content
    after_bytes = after_text.encode("utf-8")
    if len(after_bytes) > MAX_WRITE_BYTES:
        raise InputError("resulting content exceeds the maximum write size")

    preview, diff_truncated, counts = _unified_preview(before_text, after_text, relative)
    change_id = _new_change_id()
    backup_dir = _state_dir(root) / BACKUPS_DIRECTORY_NAME / change_id

    result: dict[str, Any] = {
        "status": "dry-run" if effective_dry_run else "written",
        "dryRun": effective_dry_run,
        "changeId": change_id,
        "path": str(root),
        "filePath": relative,
        "mode": mode,
        "existedBefore": exists,
        "diff": {"preview": preview, "truncated": diff_truncated, **counts},
        "sha256Before": _sha256_bytes(before_bytes) if before_bytes is not None else None,
        "sha256After": _sha256_bytes(after_bytes),
        "approvalGate": "Pass confirm: true to apply. A backup and audit entry are created on apply.",
    }

    if effective_dry_run:
        return result

    operation_record = _record_operation(root, change_id, backup_dir, "write_file", target, before_bytes, after_bytes, dry_run=False)
    _atomic_write_bytes(target, after_bytes, preserve_mode_from=target if exists else None)
    _finalize_change(root, change_id, backup_dir, [operation_record], dry_run=False)
    audit_entry = _append_audit(
        root,
        {
            "changeId": change_id,
            "operation": "write_file",
            "path": relative,
            "mode": mode,
            "sha256Before": operation_record["sha256Before"],
            "sha256After": operation_record["sha256After"],
            "bytesBefore": operation_record["bytesBefore"],
            "bytesAfter": operation_record["bytesAfter"],
        },
    )
    result["auditSeq"] = audit_entry["seq"]
    result["rollbackHint"] = f"Rollback with changeId '{change_id}'."
    return result


def _bytes_valid_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        return False


def replace_in_file(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Exact-string replacement with occurrence verification, backup, and audit."""

    arguments, root, effective_dry_run = _parse_common(arguments)
    allow_sensitive = _read_bool(arguments.get("allowSensitive"), False, "allowSensitive")
    target = _guard_target(root, str(arguments["filePath"]), allow_sensitive)
    relative = target.relative_to(root).as_posix()

    find = _read_text_argument(arguments, "find")
    if not find:
        raise InputError("find must be a non-empty string")
    replace = arguments.get("replace", "")
    if not isinstance(replace, str):
        raise InputError("replace must be a string")
    if not _is_valid_utf8(replace):
        raise InputError("replace must be valid UTF-8 text")
    expected_occurrences = _read_int_range(arguments.get("expectedOccurrences"), 1, 1, 10_000, "expectedOccurrences")

    if not target.exists() or not target.is_file():
        raise InputError("target does not exist as a regular file")
    before_bytes = target.read_bytes()
    if len(before_bytes) > MAX_WRITE_BYTES or not _bytes_valid_utf8(before_bytes):
        raise InputError("target is not manageable UTF-8 text")
    before_text = before_bytes.decode("utf-8")

    occurrences = before_text.count(find)
    if occurrences != expected_occurrences:
        raise InputError(f"expected {expected_occurrences} occurrence(s) of 'find' but found {occurrences}; no changes made")
    after_text = before_text.replace(find, replace)
    after_bytes = after_text.encode("utf-8")
    if len(after_bytes) > MAX_WRITE_BYTES:
        raise InputError("resulting content exceeds the maximum write size")

    preview, diff_truncated, counts = _unified_preview(before_text, after_text, relative)
    change_id = _new_change_id()
    backup_dir = _state_dir(root) / BACKUPS_DIRECTORY_NAME / change_id

    result: dict[str, Any] = {
        "status": "dry-run" if effective_dry_run else "written",
        "dryRun": effective_dry_run,
        "changeId": change_id,
        "path": str(root),
        "filePath": relative,
        "occurrences": occurrences,
        "diff": {"preview": preview, "truncated": diff_truncated, **counts},
        "sha256Before": _sha256_bytes(before_bytes),
        "sha256After": _sha256_bytes(after_bytes),
        "approvalGate": "Pass confirm: true to apply. A backup and audit entry are created on apply.",
    }
    if effective_dry_run:
        return result

    operation_record = _record_operation(root, change_id, backup_dir, "replace_in_file", target, before_bytes, after_bytes, dry_run=False)
    _atomic_write_bytes(target, after_bytes, preserve_mode_from=target)
    _finalize_change(root, change_id, backup_dir, [operation_record], dry_run=False)
    audit_entry = _append_audit(
        root,
        {
            "changeId": change_id,
            "operation": "replace_in_file",
            "path": relative,
            "occurrences": occurrences,
            "sha256Before": operation_record["sha256Before"],
            "sha256After": operation_record["sha256After"],
        },
    )
    result["auditSeq"] = audit_entry["seq"]
    result["rollbackHint"] = f"Rollback with changeId '{change_id}'."
    return result


def list_changes(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """List recorded change sets available for rollback."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")
    root = _resolve_directory(arguments.get("path", os.getcwd()))
    backups_root = _state_dir(root) / BACKUPS_DIRECTORY_NAME
    changes: list[dict[str, Any]] = []
    if backups_root.is_dir():
        for entry in sorted(os.scandir(backups_root), key=lambda item: item.name, reverse=True):
            if not entry.is_dir(follow_symlinks=False):
                continue
            manifest_path = Path(entry.path) / "manifest.json"
            if not manifest_path.is_file():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                changes.append({"changeId": entry.name, "corrupt": True})
                continue
            operations = manifest.get("operations", []) if isinstance(manifest, dict) else []
            changes.append(
                {
                    "changeId": manifest.get("changeId", entry.name),
                    "createdAtUtc": manifest.get("createdAtUtc"),
                    "operationCount": len(operations),
                    "paths": [operation.get("path") for operation in operations if isinstance(operation, dict)],
                }
            )
    return {"status": "ok", "path": str(root), "changeCount": len(changes), "changes": changes[:100]}


def rollback(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Restore a recorded change set. Dry-run by default; requires confirm to apply."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")
    root = _resolve_directory(arguments.get("path", os.getcwd()))
    confirm = _read_bool(arguments.get("confirm"), False, "confirm")
    dry_run = _read_bool(arguments.get("dryRun"), None, "dryRun")
    effective_dry_run = True if dry_run is True else not confirm
    change_id = arguments.get("changeId")
    if not isinstance(change_id, str) or not re.fullmatch(r"[0-9A-Za-z-]{1,64}", change_id):
        raise InputError("changeId is required and must be a recorded change identifier")

    backup_dir = _state_dir(root) / BACKUPS_DIRECTORY_NAME / change_id
    manifest_path = backup_dir / "manifest.json"
    if not manifest_path.is_file():
        raise InputError("no recorded change set exists for that changeId")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError("change set manifest is unreadable") from exc
    if not isinstance(manifest, dict) or manifest.get("root") != str(root):
        raise InputError("change set does not belong to this target directory")
    operations = manifest.get("operations")
    if not isinstance(operations, list) or not all(isinstance(item, dict) for item in operations):
        raise InputError("change set manifest is malformed")

    plan: list[dict[str, Any]] = []
    for operation in operations:
        relative = operation.get("path")
        if not isinstance(relative, str):
            raise InputError("change set manifest contains an invalid path entry")
        target = _guard_target(root, relative, allow_sensitive=True)
        existed_before = operation.get("existedBefore") is True
        backup_file = operation.get("backupFile")
        plan.append(
            {
                "path": target.relative_to(root).as_posix(),
                "action": "restore-original" if existed_before else "delete-created-file",
                "sha256Before": operation.get("sha256Before"),
            }
        )

    result: dict[str, Any] = {
        "status": "dry-run" if effective_dry_run else "rolled-back",
        "dryRun": effective_dry_run,
        "changeId": change_id,
        "path": str(root),
        "plan": plan,
        "approvalGate": "Pass confirm: true to apply the rollback. The rollback itself is audited.",
    }
    if effective_dry_run:
        return result

    applied: list[dict[str, Any]] = []
    for operation in reversed(operations):
        relative = operation["path"]
        target = _guard_target(root, relative, allow_sensitive=True)
        if operation.get("existedBefore") is True:
            backup_file = operation.get("backupFile")
            if not isinstance(backup_file, str):
                raise InputError("change set is missing its backup payload")
            backup_source = _state_dir(root) / backup_file
            if not backup_source.is_file():
                raise InputError("backup payload is missing; cannot complete a safe rollback")
            data = backup_source.read_bytes()
            _atomic_write_bytes(target, data, preserve_mode_from=target if target.exists() else None)
            applied.append({"path": relative, "action": "restored", "sha256": _sha256_bytes(data)})
        else:
            if target.exists() and target.is_file() and not target.is_symlink():
                target.unlink()
                applied.append({"path": relative, "action": "deleted-created-file"})
            else:
                applied.append({"path": relative, "action": "already-absent"})

    audit_entry = _append_audit(
        root,
        {
            "changeId": change_id,
            "operation": "rollback",
            "path": None,
            "applied": applied,
        },
    )
    result["applied"] = applied
    result["auditSeq"] = audit_entry["seq"]
    return result


def audit_log(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read the audit log and verify its tamper-evident hash chain."""

    arguments = arguments or {}
    if not isinstance(arguments, dict):
        raise InputError("arguments must be an object")
    root = _resolve_directory(arguments.get("path", os.getcwd()))
    max_entries = _read_int_range(arguments.get("maxEntries"), 50, 1, 1_000, "maxEntries")
    entries = _read_audit_entries(root)
    valid, first_invalid_seq = verify_audit_chain(entries)
    return {
        "status": "ok" if valid else "fail",
        "path": str(root),
        "entryCount": len(entries),
        "chainValid": valid,
        "firstInvalidSeq": first_invalid_seq,
        "entries": entries[-max_entries:],
    }
