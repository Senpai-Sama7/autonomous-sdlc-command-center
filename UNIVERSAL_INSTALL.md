# Universal AI CLI Installation - Autonomous SDLC Command Center

This document explains where the SDLC Command Center is installed for universal AI CLI agent access.

## Installation Locations

### Core Binaries (via pip, user install)
- **sdlc CLI**: `/home/donovan/.local/bin/sdlc` (also `/usr/local/bin/sdlc` if authorized)
- **sdlc-mcp MCP Server**: `/home/donovan/.local/bin/sdlc-mcp` (also `/usr/local/bin/sdlc-mcp`)
- **Universal wrapper**: `/home/donovan/.local/bin/sdlc-universal`
- **Python modules**: `/home/donovan/.local/lib/python3.13/site-packages/sdlc_*.py`
- **Source**: `/home/donovan/Projects/autonomous-sdlc-command-center`
- **Global share**: `~/.local/share/autonomous-sdlc-command-center/`
- **Completions**: `~/.local/share/autonomous-sdlc-command-center/completions/sdlc.bash|zsh`

### Version
- Installed: 1.1.1 (upgraded from 1.1.0)
- Python: 3.13.12
- Tools: 20 (18 original + 2 new: code_metrics, sbom)
- Status: `opencode mcp list` shows 2 servers connected ✓
- Tests: 38 passed, 0 failed, 1 skipped (UNC is Windows-specific)

## AI Agent Configurations

All configs use absolute path `/home/donovan/.local/bin/sdlc-mcp` for reliability.

### OpenCode (primary)
- **Config**: `~/.config/opencode/opencode.jsonc`
- **MCP entry**:
```json
{
  "mcp": {
    "autonomous-sdlc-command-center": {
      "type": "local",
      "command": ["/home/donovan/.local/bin/sdlc-mcp"],
      "enabled": true,
      "timeout": 10000
    }
  }
}
```
- **Skills**: `~/.config/opencode/skills/*` (7 skills copied)
  - sdlc-orchestrator, repo-intelligence, ci-release, incident-triage, security-reliability, performance-reliability, change-governance
- **Agents**: `~/.config/opencode/agents/*` (4 new agents)
  - sdlc-orchestrator.md, sdlc-security.md, sdlc-release.md, sdlc-incident.md
- **Verify**: `~/.opencode/bin/opencode mcp list`

### Claude Desktop
- **Config**: `~/.config/Claude/claude_desktop_config.json`
```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "/home/donovan/.local/bin/sdlc-mcp",
      "args": []
    }
  }
}
```

### Claude Code
- **Config**: `~/.claude.json`
```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "/home/donovan/.local/bin/sdlc-mcp"
    }
  }
}
```

### Cursor
- **Config**: `~/.cursor/mcp.json`
```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "/home/donovan/.local/bin/sdlc-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

### Gemini CLI
- **Config**: `~/.gemini/settings.json`
```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "/home/donovan/.local/bin/sdlc-mcp"
    }
  }
}
```

### Windsurf (Codeium)
- **Config**: `~/.codeium/windsurf/mcp_config.json`
```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "/home/donovan/.local/bin/sdlc-mcp",
      "args": []
    }
  }
}
```

### VS Code (Generic MCP)
- **Config**: `~/.vscode/mcp.json` or `.vscode/mcp.json` in project
```json
{
  "servers": {
    "autonomous-sdlc-command-center": {
      "type": "stdio",
      "command": "/home/donovan/.local/bin/sdlc-mcp"
    }
  }
}
```

### Cline (VSCode extension)
- **Config**: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "/home/donovan/.local/bin/sdlc-mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Continue.dev
- Add to `~/.continue/config.json`:
```json
{
  "mcpServers": [
    {"name": "autonomous-sdlc", "command": "/home/donovan/.local/bin/sdlc-mcp"}
  ]
}
```

### Codex
- **Plugin root**: `/home/donovan/Projects/autonomous-sdlc-command-center/.codex-plugin/plugin.json`
- **MCP**: Same binary, configure via `.codex/config.toml` if needed

### Any CLI Agent
```bash
# STDIO (default)
sdlc-mcp

# HTTP transport (for agents without stdio support)
sdlc-mcp --http 8765 --host 127.0.0.1
curl http://127.0.0.1:8765/health
curl http://127.0.0.1:8765/tools
```

## CLI Usage

```bash
sdlc --version
sdlc doctor --format text
sdlc snapshot --path /repo --include-git --format text
sdlc tree --path /repo --max-depth 3 --format text
sdlc read --path /repo --file README.md --format text
sdlc read-batch --path /repo --file README.md --file src/main.py
sdlc search --path /repo --pattern "TODO" --format text
sdlc secret-scan --path /repo --format sarif
sdlc languages --path /repo --format text
sdlc deps --path /repo --format text
sdlc git-history --path /repo --format text
sdlc risk --path /repo --format text
sdlc metrics --path /repo --format text      # NEW
sdlc sbom --path /repo --format text         # NEW

# Gated writes (dry-run by default)
sdlc write --path /repo --file config.txt --content "v2"           # preview diff
sdlc write --path /repo --file config.txt --content "v2" --confirm # apply with backup + audit
sdlc replace --path /repo --file app.txt --find "v1" --replace "v2" --confirm
sdlc changes --path /repo
sdlc rollback --path /repo --change-id <id> --confirm
sdlc audit --path /repo

# Shell completions
sdlc completion --shell bash >> ~/.bashrc
sdlc completion --shell zsh >> ~/.zshrc
sdlc completion --shell fish > ~/.config/fish/completions/sdlc.fish

# Install script (re-run anytime)
bash /home/donovan/Projects/autonomous-sdlc-command-center/scripts/install.sh
```

## MCP Tools (20)

**Original 18:**
- Read-only: `sdlc_repo_snapshot`, `sdlc_release_readiness`, `sdlc_plugin_preflight`, `sdlc_read_file`, `sdlc_read_files`, `sdlc_directory_tree`, `sdlc_search_code`, `sdlc_secret_scan`, `sdlc_language_stats`, `sdlc_dependency_inventory`, `sdlc_git_history`, `sdlc_risk_score`, `sdlc_doctor`, `sdlc_list_changes`, `sdlc_audit_log`
- Gated writes: `sdlc_write_file`, `sdlc_replace_in_file`, `sdlc_rollback`

**New 2 (enhancement):**
- `sdlc_code_metrics` - TODO/FIXME counts, large files, long lines, complexity hints, health score A-F
- `sdlc_sbom` - Offline SBOM CycloneDX from manifests (no network)

## Verification

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | sdlc-mcp | jq '.result.tools | length'
# Should output 20

sdlc doctor --format json | jq .
opencode mcp list
```

## Uninstall

```bash
python3 -m pip uninstall autonomous-sdlc-command-center
rm -rf ~/.local/share/autonomous-sdlc-command-center
# Then remove MCP entries from configs above
```
