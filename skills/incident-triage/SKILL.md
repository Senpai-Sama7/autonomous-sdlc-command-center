---
name: incident-triage
description: Triage service failures, production degradation, error spikes, and operational anomalies using a safety-first evidence loop that stabilizes impact before making changes.
---

# Incident Triage

Establish the incident scope, user impact, affected systems, start time, and recent changes. Preserve evidence before changing state.

1. State the current severity and the evidence supporting it.
2. Check health signals, error boundaries, dependencies, capacity, and recent deployments using read-only evidence first.
3. Form and rank hypotheses by impact, likelihood, and time-to-confirm.
4. Prefer containment and reversible mitigations. Request approval before any production write, rollback, restart, traffic shift, or external notification.
5. Record the timeline, commands run, observations, decisions, owner, and next update time.

Return `severity`, `impact`, `timeline`, `confirmed evidence`, `ranked hypotheses`, `mitigation options`, `approval required`, and `next checkpoint`. Do not claim root cause until the evidence excludes credible alternatives.

Machine-readable contract: `contract.json`. Behavioral evals: `tests.md`.
