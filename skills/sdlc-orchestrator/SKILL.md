---
name: sdlc-orchestrator
description: Coordinate repository analysis, incident triage, CI diagnosis, performance review, security assessment, change control, and release readiness into an evidence-backed engineering workflow.
---

# SDLC Orchestrator

Use this as the entry point for broad engineering requests. Treat the repository, runtime evidence, and stated operating constraints as the source of truth.

## Operating loop

1. Establish scope: repository, branch, environment, requested outcome, success signal, and destructive-action boundaries.
2. Classify the work: map, investigate, change, release, or incident. Use the narrowest matching skill after initial discovery.
3. Run read-only discovery first. Use the portable tooling — MCP tools (`sdlc_repo_snapshot`, `sdlc_language_stats`, `sdlc_dependency_inventory`, `sdlc_git_history`, `sdlc_risk_score`), the cross-platform CLI (`python mcp/sdlc_cli.py snapshot|languages|deps|risk`), or `scripts/commands/repo_snapshot.ps1` on PowerShell.
4. State a falsifiable hypothesis and the evidence needed to confirm or reject it.
5. Separate observations from inferences and label unknowns explicitly.
6. For changes, propose the smallest reversible patch, a verification command, rollback conditions, and blast radius.
7. Ask for approval immediately before mutations, publishing, deployment, credential use, or external communication.
8. Verify after every mutation and report exact commands and outcomes.

## Safety gates

- Never expose secrets, tokens, private keys, or sensitive logs.
- Do not infer that a green test suite proves production safety.
- Do not merge, deploy, delete, rotate credentials, or contact third parties without explicit authorization.
- Prefer reversible changes and narrow file scope.
- If evidence is missing, label the result `unknown` instead of guessing.
- Keep external data egress out of diagnostic steps unless the user explicitly authorizes it.

## Output contract

Return: `status`, `scope`, `evidence`, `findings`, `confidence`, `recommended next action`, `approval required`, `verification`, `rollback`, and `residual risk`.

Machine-readable contract: `contract.json` (inputs, outputs, tools, safety gates). Behavioral evals: `tests.md`. Mutations go through the gated write engine (`sdlc_write_file` / `sdlc_replace_in_file` / `sdlc_rollback`): dry-run diff first, `confirm` to apply, backup + hash-chained audit entry on every change.
