---
name: ci-release
description: Diagnose build and CI failures, assess release readiness, and create a minimal, reversible verification plan with clear evidence boundaries.
---

# CI and Release Engineering

Normalize failures into: symptom, first failing boundary, likely cause, confirming evidence, smallest fix, regression test, and rollback condition. Use the portable readiness tooling (`sdlc_release_readiness` MCP tool, `python mcp/sdlc_cli.py release-readiness`, or `scripts/commands/release_readiness.ps1` on PowerShell) to collect read-only delivery evidence before claiming a release is ready.

For release readiness, check versioning, changelog, tests, static analysis, dependency and license changes, migration safety, observability, rollback, and environment parity. Separate local evidence from remote CI evidence. A release recommendation must state what was not verified and whether a human approval is still required.

Do not retry blindly, suppress a failing check, weaken a quality gate, or publish artifacts without approval. Preserve useful logs while redacting secrets and unneeded customer data.

Machine-readable contract: `contract.json`. Behavioral evals: `tests.md`.
