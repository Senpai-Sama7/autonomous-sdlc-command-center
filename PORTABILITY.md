# Portability

The installation wrapper is Codex-specific because it uses `.codex-plugin/plugin.json` and the Codex marketplace. The operational core is provider-neutral, OS-neutral (Windows/Linux/macOS), and model-agnostic.

| Component | Portability | Requirement |
| --- | --- | --- |
| `skills/*/SKILL.md` | Portable workflow text | A harness that can load Markdown skills, or a user who attaches the file as instructions |
| `skills/*/contract.json` | Machine-readable skill contracts (inputs, outputs, tools, safety gates) for any orchestrator | Any JSON consumer |
| `skills/*/tests.md` | Behavioral eval prompts for model/harness evaluation | Any agent runner |
| `mcp/sdlc_mcp_server.py` | Standard MCP over stdio **or** localhost HTTP (`--http PORT`) | Python 3.9+ and an MCP-capable host or any HTTP client |
| `mcp/sdlc_cli.py` | Any shell or automation runner (JSON/text/SARIF output) | Python 3.9+ |
| `mcp/sdlc_core.py`, `sdlc_analyze.py`, `sdlc_write.py` | Embeddable library modules | Python 3.9+ |
| `scripts/commands/*.ps1` | Windows/PowerShell automation | PowerShell and `rg` |
| `scripts/tests/smoke.py` | Cross-platform test suite (39 tests incl. error paths, batch reads, tree, rate limiting) | Python 3.9+ |
| `scripts/tests/smoke.ps1` | PowerShell test suite (20 tests) | pwsh |
| `hooks/*.ps1` / `hooks/*.sh` | Lifecycle hooks | pwsh / POSIX sh |
| `.codex-plugin/` | Codex installation only | Codex or ChatGPT plugin host |

Use the MCP server for the most interoperable integration. It exposes narrow tools with JSON Schema inputs, structured JSON outputs, explicit read-only/destructive annotations, and no model-specific prompts or API calls. The `sdlc_doctor` tool reports the runtime capability matrix so any harness can verify its environment before relying on features.

Do not assume every harness supports the same MCP protocol revision (the server negotiates `DRAFT-2026-v1`, `2025-11-25`, and `2025-06-18`), approval UI, or plugin format. Configure the MCP command with an absolute local path, review the host's tool-permission settings, and keep the write tools' `confirm` gate mapped to your harness's human-approval flow.

## Linux notes

- Everything under `mcp/` and `scripts/tests/smoke.py` runs unchanged: `python3 mcp/sdlc_cli.py doctor`.
- Lifecycle hooks have POSIX equivalents: `hooks/on_install.sh`, `on_update.sh`, `on_uninstall.sh`.
- The PowerShell commands and `smoke.ps1` are optional and only needed for Windows parity; the Python CLI covers the same diagnostics cross-platform.
- UNC/network path guarding is a no-op on Linux; scanning network mounts can be allowed explicitly with `SDLC_ALLOW_NETWORK_PATHS=1` (off by default).
