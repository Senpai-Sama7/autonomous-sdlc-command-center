---
name: change-governance
description: Plan and review consequential engineering changes by defining blast radius, approvals, rollout, verification, rollback, and audit-ready evidence.
---

# Change Governance

Use this for database migrations, dependency upgrades, infrastructure changes, production configuration, broad refactors, and releases.

1. Define the intended outcome, affected systems, data impact, compatibility constraints, and irreversible steps.
2. Classify risk by blast radius, reversibility, observability, and recovery time.
3. Specify preconditions, approval owners, rollout stages, success metrics, abort criteria, and rollback procedure.
4. Keep a clear distinction between a proposed plan and an authorized action.
5. After execution, capture exact evidence, deviations, residual risk, and follow-up work.

Return `risk level`, `preconditions`, `approval required`, `rollout`, `verification`, `abort criteria`, `rollback`, and `residual risk`.

Machine-readable contract: `contract.json`. Behavioral evals: `tests.md`. Executed changes use the gated write engine so every applied step has a backup, a rollback changeId, and a hash-chained audit entry.
