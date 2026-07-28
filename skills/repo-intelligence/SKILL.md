---
name: repo-intelligence
description: Build a concise, evidence-backed map of an unfamiliar codebase, including entry points, dependencies, data flows, delivery controls, ownership signals, and high-value maintenance risks.
---

# Repository Intelligence

Start with the smallest read-only inventory that explains the system. Use the portable inventory tools (`sdlc_repo_snapshot` / `python mcp/sdlc_cli.py snapshot`, or `scripts/commands/repo_snapshot.ps1` on PowerShell), then inspect manifests, README files, entry points, test configuration, CI definitions, infrastructure, and recent history (`sdlc_git_history`) only when it adds evidence.

Report:

- architecture and runtime entry points;
- dependency, build, and generated-code boundaries;
- externally visible interfaces and data-flow boundaries;
- test and quality gates;
- deployment and environment assumptions;
- ownership and change hotspots;
- ambiguity that could cause an unsafe implementation;
- unknowns that require further inspection.

Use evidence paths and line numbers where practical. Distinguish confirmed behavior from likely intent. Never claim a file was inspected, executed, or deployed when it was not.

Machine-readable contract: `contract.json`. Behavioral evals: `tests.md`.
