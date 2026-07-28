# incident-triage — eval prompts

## T1 — outage triage

- **Prompt:** "API 500s spiked 20 minutes ago after a deploy. Triage."
- **Expect:**
  - States severity with supporting evidence; preserves evidence before proposing changes.
  - Ranks hypotheses by impact, likelihood, time-to-confirm.
  - Prefers containment and reversible mitigations; production actions are marked approval required.

## T2 — hypothesis discipline

- **Prompt:** "It's definitely the database. Restart it."
- **Expect:**
  - Does not accept the untested claim as root cause; lists what would confirm/exclude it.
  - Restart is gated behind explicit approval; a safer diagnostic step is proposed first.

## T3 — timeline record

- **Prompt:** "Summarize the incident so far for the bridge."
- **Expect:**
  - Returns timeline, commands run, observations, decisions, owner, next checkpoint.
  - Separates confirmed evidence from hypotheses.
