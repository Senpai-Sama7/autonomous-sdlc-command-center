# Autonomous SDLC Command Center

A local-first, safety-gated engineering control plane. It maps repositories, triages incidents, diagnoses CI failures, reviews security and reliability, scores delivery risk, measures release readiness — and can apply **approval-gated** file changes with backup, rollback, and a tamper-evident audit log.

## What is in the box

| Layer | Contents | Platform |
| --- | --- | --- |
| Skills | 7 workflow skills, each with a machine-readable `contract.json` and behavioral `tests.md` | Any harness that loads Markdown skills |
| MCP server | `mcp/sdlc_mcp_server.py` — 18 tools over stdio **or** localhost HTTP | Windows / Linux / macOS, Python 3.9+ |
| CLI | `mcp/sdlc_cli.py` — the full tool surface for any shell or CI runner | Windows / Linux / macOS, Python 3.9+ |
| PowerShell commands | `scripts/commands/*.ps1` — snapshot, readiness, preflight | Windows PowerShell / pwsh, `rg` |
| Tests | `scripts/tests/smoke.py` (cross-platform, 39 tests) and `scripts/tests/smoke.ps1` (20 tests) | Python 3.9+ / pwsh |
| Lifecycle hooks | `hooks/*.ps1` and `hooks/*.sh` | pwsh / POSIX sh |

No third-party packages. No network calls against targets. No telemetry.

## Quick start

```bash
# Cross-platform CLI (Windows, Linux, macOS)
python mcp/sdlc_cli.py doctor
python mcp/sdlc_cli.py snapshot --path /repo --include-git
python mcp/sdlc_cli.py tree --path /repo --max-depth 3
python mcp/sdlc_cli.py read-batch --path /repo --file README.md --file src/main.py
python mcp/sdlc_cli.py secret-scan --path /repo --format sarif
python mcp/sdlc_cli.py risk --path /repo

# MCP over stdio (any MCP host)
python mcp/sdlc_mcp_server.py

# MCP over localhost HTTP
python mcp/sdlc_mcp_server.py --http 8765   # POST /mcp, GET /health, GET /tools
```

```powershell
# PowerShell commands (Windows)
.\scripts\commands\repo_snapshot.ps1 -Path <repository> -IncludeGit
.\scripts\commands\release_readiness.ps1 -Path <repository>
.\scripts\commands\plugin_preflight.ps1
.\scripts\tests\smoke.ps1
```

## The gated write engine

Read tools are side-effect free. The three write tools (`sdlc_write_file`, `sdlc_replace_in_file`, `sdlc_rollback`) enforce safety **in the engine**, not in the prompt:

1. **Dry-run by default.** Every call returns a unified-diff preview and changes nothing unless `confirm: true` is passed.
2. **Confinement.** Paths cannot escape the approved directory; traversal, symlinks, UNC/network paths, `.git`, and the `.sdlc` state directory are rejected. Sensitive names (`.env`, keys, credentials) need `allowSensitive: true`.
3. **Backup first.** Existing content is copied into `.sdlc/backups/<changeId>/` before any mutation. Writes are atomic (temp file + rename).
4. **Rollback.** `sdlc_rollback` restores originals (or deletes created files) by `changeId`.
5. **Audit.** Every mutation appends to `.sdlc/audit.jsonl`, a hash-chained log whose integrity is verified by `sdlc_audit_log`.

```bash
python mcp/sdlc_cli.py write --path /repo --file config.txt --content "v2"           # dry-run diff
python mcp/sdlc_cli.py write --path /repo --file config.txt --content "v2" --confirm # apply (backup + audit)
python mcp/sdlc_cli.py changes --path /repo                                          # list change sets
python mcp/sdlc_cli.py rollback --path /repo --change-id <changeId> --confirm        # revert
python mcp/sdlc_cli.py audit --path /repo                                            # verify the chain
```

## Tool surface (18 MCP tools)

Read-only: `sdlc_repo_snapshot`, `sdlc_release_readiness`, `sdlc_plugin_preflight`, `sdlc_read_file`, `sdlc_read_files`, `sdlc_directory_tree`, `sdlc_search_code`, `sdlc_secret_scan`, `sdlc_language_stats`, `sdlc_dependency_inventory`, `sdlc_git_history`, `sdlc_risk_score`, `sdlc_doctor`, `sdlc_list_changes`, `sdlc_audit_log`.
Gated writes: `sdlc_write_file`, `sdlc_replace_in_file`, `sdlc_rollback`.

**Rate limiting:** The MCP server enforces a fixed-window per-tool rate limit (default 60 calls per 60 seconds per tool). Configurable via `SDLC_RATE_LIMIT_CALLS` and `SDLC_RATE_LIMIT_WINDOW_SECONDS`. Violations return as tool errors.

See [Operating model](docs/OPERATING_MODEL.md), [security notes](SECURITY.md), [portability](PORTABILITY.md), and the [MCP server guide](mcp/README.md).

Start with: `Inspect this repository and produce a decision-ready SDLC control report.`
