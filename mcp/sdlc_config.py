"""Zero-dependency configuration engine for autonomous-sdlc-command-center.

Loads sdlc.config.json from the workspace root with schema-validated defaults.
Every tunable parameter in the server flows through ConfigManager so operators
can override behaviour without touching Python source.

Usage:
    from sdlc_config import ConfigManager
    cfg = ConfigManager(Path("."))
    threshold = cfg.entropy_threshold
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


DEFAULTS: dict[str, Any] = {
    "version": "1.0.0",
    "security": {
        "entropyThreshold": 4.5,
        "blockSensitiveByDefault": True,
        "customBlockedPatterns": [
            r"^.*\.pem$",
            r"^.*\.pfx$",
            r"^.*\.key$",
            r"^\.env.*$",
        ],
        "maxTokenPreviewLength": 8,
    },
    "mutations": {
        "maxFileSizeBytes": 1_048_576,  # 1 MiB
        "maxDiffLines": 5_000,
        "requireConfirmation": True,
        "backupRetentionCount": 50,
    },
    "audit": {
        "logFile": ".sdlc/audit.jsonl",
        "strictHashChecking": True,
    },
    "rateLimiting": {
        "enabled": True,
        "maxRequestsPerMinute": 120,
    },
    "auth": {
        "mode": "bearer",            # "bearer" | "none"
        "tokenFile": ".sdlc/server.token",
        "tokensFile": ".sdlc/tokens.json",
        "allowUnauthenticatedHealth": True,
        "allowUnauthenticatedToolsRead": False,
    },
    "http": {
        "sessionTimeoutSeconds": 3600,
        "maxSessions": 100,
        "corsOrigins": ["*"],
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


class ConfigManager:
    """Loads, validates, and provides typed access to sdlc.config.json."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.config_path = self.workspace_root / "sdlc.config.json"
        self._raw = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return dict(DEFAULTS)
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            if not isinstance(user_cfg, dict):
                print("[sdlc_config] config file is not a JSON object, using defaults", file=sys.stderr)
                return dict(DEFAULTS)
            return _deep_merge(DEFAULTS, user_cfg)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[sdlc_config] failed to load config ({exc}), using defaults", file=sys.stderr)
            return dict(DEFAULTS)

    def reload(self) -> None:
        """Re-read sdlc.config.json from disk."""
        self._raw = self._load()

    def write_default(self) -> Path:
        """Write the default config file if it doesn't exist. Returns path."""
        if self.config_path.exists():
            return self.config_path
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULTS, f, indent=2, ensure_ascii=False)
            f.write("\n")
        return self.config_path

    # ── Security ──────────────────────────────────────────────────────

    @property
    def entropy_threshold(self) -> float:
        return float(self._raw["security"]["entropyThreshold"])

    @property
    def block_sensitive_by_default(self) -> bool:
        return bool(self._raw["security"]["blockSensitiveByDefault"])

    @property
    def custom_blocked_patterns(self) -> list[str]:
        return list(self._raw["security"]["customBlockedPatterns"])

    @property
    def max_token_preview_length(self) -> int:
        return int(self._raw["security"]["maxTokenPreviewLength"])

    # ── Mutations ─────────────────────────────────────────────────────

    @property
    def max_file_size_bytes(self) -> int:
        return int(self._raw["mutations"]["maxFileSizeBytes"])

    @property
    def max_diff_lines(self) -> int:
        return int(self._raw["mutations"]["maxDiffLines"])

    @property
    def require_confirmation(self) -> bool:
        return bool(self._raw["mutations"]["requireConfirmation"])

    @property
    def backup_retention_count(self) -> int:
        return int(self._raw["mutations"]["backupRetentionCount"])

    # ── Audit ─────────────────────────────────────────────────────────

    @property
    def audit_log_file(self) -> str:
        return str(self._raw["audit"]["logFile"])

    @property
    def strict_hash_checking(self) -> bool:
        return bool(self._raw["audit"]["strictHashChecking"])

    # ── Rate Limiting ─────────────────────────────────────────────────

    @property
    def rate_limiting_enabled(self) -> bool:
        return bool(self._raw["rateLimiting"]["enabled"])

    @property
    def max_requests_per_minute(self) -> int:
        return int(self._raw["rateLimiting"]["maxRequestsPerMinute"])

    # ── Auth ──────────────────────────────────────────────────────────

    @property
    def auth_mode(self) -> str:
        return str(self._raw["auth"]["mode"])

    @property
    def auth_token_file(self) -> str:
        return str(self._raw["auth"]["tokenFile"])

    @property
    def auth_tokens_file(self) -> str:
        return str(self._raw["auth"]["tokensFile"])

    @property
    def allow_unauthenticated_health(self) -> bool:
        return bool(self._raw["auth"]["allowUnauthenticatedHealth"])

    @property
    def allow_unauthenticated_tools_read(self) -> bool:
        return bool(self._raw["auth"]["allowUnauthenticatedToolsRead"])

    # ── HTTP ──────────────────────────────────────────────────────────

    @property
    def session_timeout_seconds(self) -> int:
        return int(self._raw["http"]["sessionTimeoutSeconds"])

    @property
    def max_sessions(self) -> int:
        return int(self._raw["http"]["maxSessions"])

    @property
    def cors_origins(self) -> list[str]:
        return list(self._raw["http"]["corsOrigins"])

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a serialisable snapshot of the active config."""
        return dict(self._raw)
