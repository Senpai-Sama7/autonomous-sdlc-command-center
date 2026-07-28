# Operating model

Use the plugin as a decision-support layer with gated execution, not an unattended deployment agent.

1. Discover facts read-only (snapshot, search, languages, dependencies, git history, risk score).
2. State the hypothesis, evidence, unknowns, and risk level.
3. Propose the smallest reversible change as a **dry-run** (the write engine returns a unified diff).
4. Obtain approval, then apply with `confirm: true`. The engine backs up, writes atomically, and appends a hash-chained audit entry.
5. Verify the outcome with the narrowest meaningful check.
6. Record residual risk and the rollback `changeId`; roll back through the same gated flow if needed.

## Boundaries

- The local tools avoid network access, code execution in the target repository, and package installation. They provide inventory and readiness evidence; they do not prove production safety.
- Every mutation path runs through the engine's confinement, sensitive-file, and size guards — these are code-enforced and cannot be waived by prompt phrasing.
- Secret values are never printed by any tool; scans return redacted locations.
- A green check suite is evidence, not authorization. Merging, deploying, deleting, rotating credentials, or contacting third parties stays outside this plugin unless a human explicitly approves it in the surrounding workflow.

## Evidence hierarchy

1. Direct file/command output (strongest).
2. Signature-based findings (secret scan, dangerous-command rules) — confirm before acting.
3. Heuristic composites (risk score, readiness recommendation) — prioritization signals, not certifications.
4. Inference from naming or convention (weakest; label it as such).
