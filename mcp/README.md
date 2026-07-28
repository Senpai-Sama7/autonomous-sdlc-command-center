# Portable MCP server

`sdlc_mcp_server.py` is a dependency-free, tools-only MCP server for local SDLC diagnostics and safety-gated writes. Python 3.9+, Windows/Linux/macOS, no package installation.

## Transports

**stdio (default)** — newline-delimited JSON-RPC, one message per line:

```json
{
  "mcpServers": {
    "autonomous-sdlc-command-center": {
      "command": "python",
      "args": ["/absolute/path/to/autonomous-sdlc-command-center/mcp/sdlc_mcp_server.py"]
    }
  }
}
```

**localhost HTTP** — request/response JSON-RPC for harnesses without stdio MCP:

```bash
python mcp/sdlc_mcp_server.py --http 8765 [--host 127.0.0.1]
# POST /mcp        JSON-RPC dispatch (single messages, no batch)
# GET  /health     liveness
# GET  /tools      tool catalog
```

Supported protocol versions: `DRAFT-2026-v1`, `2025-11-25`, `2025-06-18`. The server also answers the `server/discover` capability probe with its version matrix, transports, and tool names.

## Tools

Read-only tools (`readOnlyHint: true`, side-effect free):

| Tool | Purpose |
| --- | --- |
| `sdlc_repo_snapshot` | Bounded inventory: manifests, lockfiles, CI, tests, infra, sensitive-path indicators, symlink/non-UTF-8 counts, optional git summary |
| `sdlc_release_readiness` | Release evidence checks with pass/warning/fail/unknown statuses |
| `sdlc_plugin_preflight` | Validate a plugin: manifest, skills, machine-readable contracts, command-safety signatures |
| `sdlc_read_file` | Bounded, symlink-safe read; binary detection; secret redaction on by default |
| `sdlc_read_files` | Batch read of up to 20 files; per-file error isolation; same safety as `sdlc_read_file` |
| `sdlc_directory_tree` | Bounded recursive listing with depth (1–10) and entry (1–2000) caps; returns flat `{path, type, depth}` entries |
| `sdlc_search_code` | Regex search with context lines, result bounds, redaction |
| `sdlc_secret_scan` | Secret-signature scan; findings always redacted (CLI also emits SARIF 2.1.0) |
| `sdlc_language_stats` | Language breakdown by files and lines; primary-language detection |
| `sdlc_dependency_inventory` | Offline dependency extraction (package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml) |
| `sdlc_git_history` | Recent commits, distinct authors, churn hotspots (local only, never contacts remotes) |
| `sdlc_risk_score` | Heuristic 0–100 composite risk with letter grade and weighted factors |
| `sdlc_doctor` | Environment/capability probe for harness-agnostic setup checks |
| `sdlc_list_changes` | Recorded change sets available for rollback |
| `sdlc_audit_log` | Audit log read with hash-chain verification |

Gated write tools (`readOnlyHint: false`, `destructiveHint: true`):

| Tool | Purpose |
| --- | --- |
| `sdlc_write_file` | Create/overwrite/append UTF-8 text. Dry-run unless `confirm: true`. Optional `expectedSha256` optimistic-concurrency guard |
| `sdlc_replace_in_file` | Exact-string replacement with occurrence verification. Dry-run unless `confirm: true` |
| `sdlc_rollback` | Restore a change set by `changeId` (or delete files it created). Dry-run unless `confirm: true` |

## Write-tool safety contract

- **Dry-run by default** — a unified-diff preview is returned; nothing changes without `confirm: true`. An explicit `dryRun: true` always wins.
- **Confinement** — targets must stay inside the approved directory. Traversal, symlinks, `.git`, the `.sdlc` state dir, and UNC/network paths are rejected (network paths require `SDLC_ALLOW_NETWORK_PATHS=1`). Sensitive basenames (`.env`, private keys, credentials) require `allowSensitive: true`.
- **Backup + atomicity** — existing bytes are saved to `.sdlc/backups/<changeId>/` before mutation; writes complete via temp file + rename.
- **Audit** — applied mutations append a hash-chained entry to `.sdlc/audit.jsonl`; `sdlc_audit_log` verifies the chain.
- **Bounds** — content ≤ 1 MiB, UTF-8 only, binary targets refused.

The server emits JSON-RPC only on stdout in stdio mode (HTTP logs go to stderr). It makes no network calls against targets, does not execute target-repository code, installs nothing, and redacts secret values in every output.

## Rate limiting

The server enforces a fixed-window per-tool rate limit (default 60 calls per 60 seconds per tool). When exceeded, the tool call returns an error result with `isError: true`. Configurable via environment variables:

```bash
SDLC_RATE_LIMIT_CALLS=60          # max calls per window per tool (default 60)
SDLC_RATE_LIMIT_WINDOW_SECONDS=60 # window duration in seconds (default 60)
```
