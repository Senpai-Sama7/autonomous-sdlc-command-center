#!/bin/sh
# POSIX install hook (Linux/macOS). Usage: on_install.sh <PluginPath>
set -eu

PLUGIN_PATH="${1:?PluginPath argument required}"

echo "[autonomous-sdlc-command-center] Verifying plugin integrity..."

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "[ERROR] Python 3.9+ is required but was not found on PATH." >&2
  exit 1
fi

if [ ! -f "$PLUGIN_PATH/mcp/sdlc_cli.py" ]; then
  echo "[ERROR] Portable CLI not found; installation may be incomplete." >&2
  exit 1
fi

if "$PY" "$PLUGIN_PATH/mcp/sdlc_cli.py" plugin-preflight --plugin-path "$PLUGIN_PATH" >/dev/null; then
  echo "[autonomous-sdlc-command-center] Plugin verified. Run smoke tests with:"
  echo "  python3 scripts/tests/smoke.py"
else
  echo "[ERROR] Plugin preflight failed. Review findings above." >&2
  exit 1
fi
