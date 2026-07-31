# SDLc MCP — Tools & Prompt Reference

> The SDLc server is a safety-gated read/write engine. All write tools are **dry-run by default** and require explicit confirmation.

## Read Tools

| Tool | Trigger Prompt |
|------|---------------|
| `sdlc_sdlc_read_file` | "read `<file>`" |
| `sdlc_sdlc_read_files` | "read these files: `<list>`" |
| `sdlc_sdlc_directory_tree` | "directory listing" / "tree of this repo" |
| `sdlc_sdlc_search_code` | "search code for `<regex>`" / "find `<pattern>` in code" |

## Inventory & Metrics

| Tool | Trigger Prompt |
|------|---------------|
| `sdlc_sdlc_repo_snapshot` | "repo snapshot" / "bounded repo inventory" |
| `sdlc_sdlc_language_stats` | "language breakdown" / "what languages are used?" |
| `sdlc_sdlc_dependency_inventory` | "list dependencies" / "extract package inventory" |
| `sdlc_sdlc_code_metrics` | "code health check" / "find large files and long lines" |
| `sdlc_sdlc_sbom` | "generate SBOM" / "cyclonedx from manifests" |
| `sdlc_sdlc_git_history` | "git history" / "churn hotspots" |

## Risk & Release Readiness

| Tool | Trigger Prompt |
|------|---------------|
| `sdlc_sdlc_risk_score` | "risk score this repo" / "delivery risk assessment" |
| `sdlc_sdlc_release_readiness` | "release readiness check" / "is this shippable?" |
| `sdlc_sdlc_plugin_preflight` | "validate plugin manifest" |
| `sdlc_sdlc_doctor` | "run doctor" / "platform diagnostics" |

## Security Scanning

| Tool | Trigger Prompt | Notes |
|------|---------------|-------|
| `sdlc_sdlc_secret_scan` | "scan for secrets" / "secret scan with redaction" | Signature-based, redacts by construction |
| `sdlc_sdlc_entropy_scan` | "entropy scan" / "shannon entropy detection" | Flags high-entropy tokens (H > 4.5) |

## Safety-Gated Write Tools

> **All dry-run by default.** Add `confirm=true` to apply. Every applied change creates a backup + hash-chained audit log entry.

| Tool | Trigger Prompt |
|------|---------------|
| `sdlc_sdlc_write_file` | "write `<file>` with content `<X>`" |
| `sdlc_sdlc_replace_in_file` | "replace `<old>` with `<new>` in `<file>`" |
| `sdlc_sdlc_replace_in_file_ast` | "AST-aware replace in Python file `<file>`" |

## Rollback & Audit

| Tool | Trigger Prompt |
|------|---------------|
| `sdlc_sdlc_rollback` | "rollback changeSet `<id>`" / "undo my last edit" |
| `sdlc_sdlc_audit_log` | "show audit log" / "list all changes made" |
| `sdlc_sdlc_list_changes` | "list recorded changes" / "what change sets exist?" |

## Isolated Worktrees (Shadow Sessions)

| Tool | Trigger Prompt |
|------|---------------|
| `sdlc_sdlc_shadow_create` | "create isolated worktree" / "shadow git worktree" |
| `sdlc_sdlc_shadow_destroy` | "destroy shadow `<session-id>`" |
| `sdlc_sdlc_shadow_promote` | "promote shadow changes" / "merge shadow to main" |

---

## Safety Model

```
write_file / replace_in_file → dry-run diff shown first
                             → confirm=true to apply
                             → backup + hash-chained audit entry on apply
rollback                     → restore from recorded change set (with diff check)
```

Key guarantees:
- **Dry-run by default**: no mutation without `confirm=true`.
- **Backups**: every applied change saves the original content.
- **Audit log**: hash-chained record of all mutations (`audit_log`).
- **Rollback**: any change set can be reversed (`rollback`).
- **Shadow isolation**: test changes in isolated Git worktrees without touching the main working tree (`shadow_create` / `shadow_promote`).
