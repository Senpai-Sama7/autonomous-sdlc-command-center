# Security notes

## Read tools

The read-only tools (snapshot, readiness, search, secret scan, language stats, dependency inventory, git history, risk score, doctor, batch read, directory tree) are local and side-effect free. They make no network calls, install nothing, and never execute target-repository code. Secret values are redacted from every output by construction: findings report file, line, and signature type — never the matched value. The preflight reports potential secret signatures by file path and rule identifier only.

## Rate limiting

The MCP server enforces a fixed-window per-tool rate limit (default 60 calls per 60 seconds per tool name). Exceeded limits return a tool error result (`isError: true`), not a transport error. Configurable via `SDLC_RATE_LIMIT_CALLS` and `SDLC_RATE_LIMIT_WINDOW_SECONDS`. The limiter is in-memory per server process; it resets on restart.

## Write tools

The write engine (`sdlc_write_file`, `sdlc_replace_in_file`, `sdlc_rollback`) enforces its safety policy in code, not in prompts:

- **Approval gate** — mutations are dry-runs unless `confirm: true`; an explicit `dryRun: true` always wins. Map this gate to your harness's human-approval mechanism.
- **Confinement** — targets must resolve inside the approved directory. `..` traversal, absolute escapes, symlinks (target or ancestor), `.git`, and the `.sdlc` state directory are rejected. Filesystem roots and UNC/network paths are rejected (`SDLC_ALLOW_NETWORK_PATHS=1` overrides intentionally).
- **Sensitive-file guard** — `.env`, private keys, certificate stores, and credential-style names require `allowSensitive: true`; intentional templates (`.env.example` etc.) are not treated as sensitive.
- **Integrity** — existing content is backed up before mutation; writes are atomic (temp file + `fsync` + rename); `expectedSha256` provides optimistic concurrency against unknown changes.
- **Accountability** — every applied mutation appends to `.sdlc/audit.jsonl`, a SHA-256 hash-chained log. `sdlc_audit_log` re-verifies the chain and reports the first invalid sequence number on tampering.
- **Bounds** — UTF-8 text only, ≤ 1 MiB per write, binary targets refused, replacement occurrence counts verified before applying.

Rollback restores original bytes (or removes created files) and is itself audited. Backups and audit logs live inside the target repository's `.sdlc/` directory — treat that directory as sensitive operational data and do not commit it to shared remotes without review.

## Operational guidance

Do not place credentials in prompts, issue descriptions, terminal output, or plugin files. Treat repository paths and file names as potentially sensitive. Review structured command output before sharing it outside the trusted workspace. The HTTP transport binds localhost by default — do not expose it on a network interface without adding your own authentication layer.
