---
name: security-reliability
description: Perform repository-grounded threat modeling and reliability review, prioritize actionable controls, and preserve strict secret-handling and approval boundaries.
---

# Security and Reliability Gate

Identify assets, trust boundaries, identities, data flows, privileged operations, failure domains, and recovery paths. Review authentication, authorization, input handling, secret management, dependency exposure, logging, supply chain, availability, timeouts, retries, idempotency, circuit breaking, and backup/restore assumptions.

Prioritize findings by exploitability, impact, evidence, remediation cost, and detectability. Include a minimal reproduction or confirming check only when safe. Never access or print secret values — use `sdlc_secret_scan`, which redacts by construction. Treat scanners as evidence, not proof of absence. Do not recommend broad access, data collection, or security-control bypasses merely to speed delivery.

Machine-readable contract: `contract.json`. Behavioral evals: `tests.md`.
