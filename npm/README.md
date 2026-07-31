# sdlc-mcp (npm wrapper)

Run the **autonomous-sdlc-command-center** MCP server and CLI from the Node ecosystem —
no `pip install` required. The package bundles the complete dependency-free Python
implementation and only needs **Python 3.9+** on your `PATH`.

## Quick start

```bash
# MCP server (stdio) — point your AI assistant at this command
npx sdlc-mcp

# Human CLI — repo health in one shot
npx sdlc-mcp doctor --path .
```

> The package exposes two binaries: **`sdlc-mcp`** (MCP server) and **`sdlc`** (CLI).
> With `npx <pkg>`, the first binary is used; for the CLI use `npx -p sdlc-mcp sdlc ...`
> or install globally: `npm i -g sdlc-mcp`.

## Configure your AI assistant

Add to your MCP client config (Claude Desktop, Cursor, OpenCode, Windsurf, VS Code, …):

```json
{
  "mcpServers": {
    "sdlc": {
      "command": "npx",
      "args": ["-y", "sdlc-mcp"]
    }
  }
}
```

You get 26 tools: repo snapshot, risk scoring, secret + entropy scanning, release
readiness, gated writes with rollback, hash-chained audit log, shadow worktrees, SBOM,
and more.

## Other entry points

```bash
npx -p sdlc-mcp sdlc risk --path .            # composite risk score (A-F)
npx -p sdlc-mcp sdlc release-readiness        # go/no-go evidence checks
npx -p sdlc-mcp sdlc dashboard --open         # web dashboard at http://127.0.0.1:8420
npx -p sdlc-mcp sdlc write --help             # safety-gated write engine (dry-run default)
sdlc-mcp --http-streamable 8080               # 2026 Streamable HTTP transport + Bearer auth
```

## Requirements

- **Node.js ≥ 14** (for npx itself)
- **Python 3.9+** on `PATH` (`python3`, `python`, or the Windows `py` launcher)

Environment overrides:

| Variable | Purpose |
|---|---|
| `SDLC_PYTHON` | Explicit Python interpreter path |
| `SDLC_PYTHON_HOME` | Explicit directory containing the `sdlc_*.py` modules |

## Links

- GitHub: https://github.com/Senpai-Sama7/autonomous-sdlc-command-center
- Issues: https://github.com/Senpai-Sama7/autonomous-sdlc-command-center/issues
- License: MIT
