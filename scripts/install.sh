#!/usr/bin/env bash
# Universal installer for Autonomous SDLC Command Center
# Installs CLI, MCP server, and configures for any AI coding CLI agent
# Supports: opencode, Claude Code/Desktop, Cursor, Gemini CLI, Cline, Windsurf, VSCode, Continue.dev
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "=== Autonomous SDLC Command Center Universal Installer ==="
echo "Source: $PROJECT_DIR"
echo "Version: $(grep '^version' "$PROJECT_DIR/pyproject.toml" | head -n1 || echo '1.1.0')"
echo ""

# Check python
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found"
  exit 1
fi

echo "[1/6] Installing Python package (pip)..."
python3 -m pip install -e "$PROJECT_DIR" --break-system-packages --user 2>&1 | tail -n 5 || python3 -m pip install "$PROJECT_DIR" --break-system-packages | tail -n 5
echo "  -> Installed sdlc and sdlc-mcp to ~/.local/bin"
ls -lh ~/.local/bin/sdlc* 2>/dev/null || true

echo ""
echo "[2/6] Verifying CLI..."
~/.local/bin/sdlc --version
~/.local/bin/sdlc doctor --format text | head -n 20

echo ""
echo "[3/6] Installing ripgrep (rg) if missing (required for PowerShell commands)..."
if ! command -v rg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "  -> Attempting apt-get install ripgrep (needs sudo)"
    sudo apt-get update && sudo apt-get install -y ripgrep || echo "  WARN: could not install rg automatically"
  else
    echo "  WARN: rg not found and no apt-get; please install ripgrep manually"
  fi
else
  echo "  -> rg found: $(rg --version)"
fi

echo ""
echo "[4/6] Configuring AI CLI agents..."

MCP_BIN="$HOME/.local/bin/sdlc-mcp"
# Ensure absolute path
MCP_BIN_ABS="$(realpath "$MCP_BIN" 2>/dev/null || echo "$MCP_BIN")"

# Helper to write JSON if missing
ensure_dir() { mkdir -p "$(dirname "$1")"; }

# 4a OpenCode
OPENCODE_CFG="$HOME/.config/opencode/opencode.jsonc"
ensure_dir "$OPENCODE_CFG"
python3 << PY
import json, pathlib
cfg_path = pathlib.Path("$OPENCODE_CFG")
existing = {}
if cfg_path.exists():
    try:
        existing = json.loads(cfg_path.read_text())
    except:
        existing = {"\$schema": "https://opencode.ai/config.json"}
existing.setdefault("\$schema", "https://opencode.ai/config.json")
existing.setdefault("mcp", {})["autonomous-sdlc-command-center"] = {
    "type": "local",
    "command": ["$MCP_BIN_ABS"],
    "enabled": True,
    "timeout": 10000
}
cfg_path.write_text(json.dumps(existing, indent=2))
print(f"  -> OpenCode: {cfg_path}")
PY

# 4b Skills for opencode
SKILLS_SRC="$PROJECT_DIR/skills"
SKILLS_DEST="$HOME/.config/opencode/skills"
mkdir -p "$SKILLS_DEST"
for d in "$SKILLS_SRC"/*; do
  [ -d "$d" ] || continue
  name=$(basename "$d")
  mkdir -p "$SKILLS_DEST/$name"
  cp "$d/SKILL.md" "$SKILLS_DEST/$name/" 2>/dev/null || true
  [ -f "$d/contract.json" ] && cp "$d/contract.json" "$SKILLS_DEST/$name/" || true
  echo "  -> Skill $name -> $SKILLS_DEST/$name"
done

# 4c Claude Desktop
CLAUDE_DESKTOP="$HOME/.config/Claude/claude_desktop_config.json"
ensure_dir "$CLAUDE_DESKTOP"
python3 << PY
import json, pathlib
p = pathlib.Path("$CLAUDE_DESKTOP")
cfg = {}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
    except:
        cfg = {}
cfg.setdefault("mcpServers", {})["autonomous-sdlc-command-center"] = {"command": "$MCP_BIN_ABS", "args": []}
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> Claude Desktop: {p}")
PY

# 4d Claude Code .claude.json
CLAUDE_CODE="$HOME/.claude.json"
python3 << PY
import json, pathlib
p = pathlib.Path("$CLAUDE_CODE")
cfg = {}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
    except:
        cfg = {}
cfg.setdefault("mcpServers", {})["autonomous-sdlc-command-center"] = {"command": "$MCP_BIN_ABS"}
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> Claude Code: {p}")
PY

# 4e Cursor
CURSOR_CFG="$HOME/.cursor/mcp.json"
ensure_dir "$CURSOR_CFG"
python3 << PY
import json, pathlib
p = pathlib.Path("$CURSOR_CFG")
cfg = {"mcpServers": {}}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
    except:
        cfg = {"mcpServers": {}}
cfg.setdefault("mcpServers", {})["autonomous-sdlc-command-center"] = {"command": "$MCP_BIN_ABS", "args": [], "env": {}}
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> Cursor: {p}")
PY

# 4f Gemini CLI
GEMINI_CFG="$HOME/.gemini/settings.json"
ensure_dir "$GEMINI_CFG"
python3 << PY
import json, pathlib
p = pathlib.Path("$GEMINI_CFG")
cfg = {}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
    except:
        cfg = {}
cfg.setdefault("mcpServers", {})["autonomous-sdlc-command-center"] = {"command": "$MCP_BIN_ABS"}
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> Gemini: {p}")
PY

# 4g Windsurf
WINDSURF_CFG="$HOME/.codeium/windsurf/mcp_config.json"
ensure_dir "$WINDSURF_CFG"
python3 << PY
import json, pathlib
p = pathlib.Path("$WINDSURF_CFG")
cfg = {"mcpServers": {"autonomous-sdlc-command-center": {"command": "$MCP_BIN_ABS", "args": []}}}
if p.exists():
    try:
        existing = json.loads(p.read_text())
        existing.setdefault("mcpServers", {})["autonomous-sdlc-command-center"] = {"command": "$MCP_BIN_ABS", "args": []}
        cfg = existing
    except:
        pass
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> Windsurf: {p}")
PY

# 4h VSCode generic
VSCODE_CFG="$HOME/.vscode/mcp.json"
ensure_dir "$VSCODE_CFG"
python3 << PY
import json, pathlib
p = pathlib.Path("$VSCODE_CFG")
cfg = {"servers": {"autonomous-sdlc-command-center": {"type": "stdio", "command": "$MCP_BIN_ABS"}}}
if p.exists():
    try:
        existing = json.loads(p.read_text())
        existing.setdefault("servers", {})["autonomous-sdlc-command-center"] = {"type": "stdio", "command": "$MCP_BIN_ABS"}
        cfg = existing
    except:
        pass
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> VSCode: {p}")
PY

# 4i Cline
CLINE_CFG="$HOME/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
ensure_dir "$CLINE_CFG"
python3 << PY
import json, pathlib
p = pathlib.Path("$CLINE_CFG")
cfg = {"mcpServers": {"autonomous-sdlc-command-center": {"command": "$MCP_BIN_ABS", "disabled": False, "autoApprove": []}}}
if p.exists():
    try:
        existing = json.loads(p.read_text())
        existing.setdefault("mcpServers", {})["autonomous-sdlc-command-center"] = {"command": "$MCP_BIN_ABS", "disabled": False, "autoApprove": []}
        cfg = existing
    except:
        pass
p.write_text(json.dumps(cfg, indent=2))
print(f"  -> Cline: {p}")
PY

echo ""
echo "[5/6] Creating global share directory..."
SHARE_DIR="$HOME/.local/share/autonomous-sdlc-command-center"
mkdir -p "$SHARE_DIR"
cat > "$SHARE_DIR/README.md" << README
# Autonomous SDLC Command Center - Global Installation

- Source: $PROJECT_DIR
- MCP: $MCP_BIN_ABS
- CLI: $HOME/.local/bin/sdlc
- Version: 1.1.0

## Usage
sdlc doctor
sdlc snapshot --path /repo --include-git --format text
sdlc risk --path /repo --format text
sdlc secret-scan --path /repo --format sarif
sdlc-mcp --http 8765

## MCP Tools (18)
Read-only: snapshot, release-readiness, plugin-preflight, read_file, read_files, directory_tree, search_code, secret_scan, language_stats, dependency_inventory, git_history, risk_score, doctor, list_changes, audit_log
Gated writes: write_file, replace_in_file, rollback

## AI Agent Configs Installed
- OpenCode: ~/.config/opencode/opencode.jsonc
- Skills: ~/.config/opencode/skills/*
- Agents: ~/.config/opencode/agents/*
- Claude Desktop: ~/.config/Claude/claude_desktop_config.json
- Claude Code: ~/.claude.json
- Cursor: ~/.cursor/mcp.json
- Gemini: ~/.gemini/settings.json
- Windsurf: ~/.codeium/windsurf/mcp_config.json
- VSCode: ~/.vscode/mcp.json
- Cline: ~/.config/Code/User/.../cline_mcp_settings.json
README
echo "  -> $SHARE_DIR/README.md"

echo ""
echo "[6/6] Creating wrapper and symlink for universal access..."
cat > "$HOME/.local/bin/sdlc-universal" << WRAPPER
#!/usr/bin/env bash
# Universal wrapper
set -e
MCP_SERVER="$MCP_BIN_ABS"
CLI="$HOME/.local/bin/sdlc"
if [[ "\$1" == "mcp" ]]; then
  shift
  exec "\$MCP_SERVER" "\$@"
else
  exec "\$CLI" "\$@"
fi
WRAPPER
chmod +x "$HOME/.local/bin/sdlc-universal"

# Try /usr/local/bin symlink (needs sudo)
if command -v pkexec >/dev/null 2>&1; then
  pkexec ln -sf "$MCP_BIN_ABS" /usr/local/bin/sdlc-mcp 2>/dev/null || true
  pkexec ln -sf "$HOME/.local/bin/sdlc" /usr/local/bin/sdlc 2>/dev/null || true
  pkexec ln -sf "$HOME/.local/bin/sdlc-universal" /usr/local/bin/sdlc-universal 2>/dev/null || true
  echo "  -> Symlinks in /usr/local/bin created (if authorized)"
fi

echo ""
echo "=== Installation Complete ==="
echo "Test: sdlc doctor --format text"
echo "Test MCP: echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}' | sdlc-mcp"
echo ""
echo "OpenCode: opencode mcp list  (should show connected)"
echo ""
~/.local/bin/sdlc doctor --format text | head -n 15
