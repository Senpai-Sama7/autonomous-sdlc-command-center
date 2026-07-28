#!/bin/sh
# POSIX update hook (Linux/macOS). Usage: on_update.sh <PluginPath> <PreviousVersion>
set -eu

PLUGIN_PATH="${1:?PluginPath argument required}"
PREVIOUS_VERSION="${2:-unknown}"

echo "[autonomous-sdlc-command-center] Updating from v$PREVIOUS_VERSION..."

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ] || [ ! -f "$PLUGIN_PATH/mcp/sdlc_cli.py" ]; then
  echo "[WARNING] Portable CLI not available for verification."
  exit 0
fi

if "$PY" "$PLUGIN_PATH/mcp/sdlc_cli.py" plugin-preflight --plugin-path "$PLUGIN_PATH" >/dev/null; then
  echo "[autonomous-sdlc-command-center] Update verified."
else
  echo "[WARNING] Update completed with preflight findings."
fi
