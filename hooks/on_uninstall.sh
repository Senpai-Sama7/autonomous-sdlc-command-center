#!/bin/sh
# POSIX uninstall hook (Linux/macOS). Usage: on_uninstall.sh <PluginPath>
set -eu

PLUGIN_PATH="${1:?PluginPath argument required}"
: "$PLUGIN_PATH"

echo "[autonomous-sdlc-command-center] Uninstalling."
echo "Note: per-repository .sdlc/ state (backups and audit logs created by the gated"
echo "write engine inside scanned repositories) is left intact for recovery purposes."
