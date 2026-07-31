# Skills & Built-in Tools — Prompt Reference

> Skills are specialized workflows loaded from `/home/donovan/.config/opencode/skills/` (synced from `skills/` in this repo). Each has `SKILL.md`, `contract.json`, and `tests.md`.

## Skills

| # | Skill | Trigger Prompt | What It Does |
|---|-------|---------------|--------------|
| 1 | **repo-intelligence** | "map this codebase" / "understand this project" / "give me a repo map" | Evidence-backed map: entry points, deps, data flows, ownership signals, maintenance risks |
| 2 | **sdlc-orchestrator** | "analyze and change" / "engineering workflow" / "coordinate this change" / "broad engineering task" | End-to-end engineering lifecycle: discover → hypothesis → change → verify → report |
| 3 | **security-reliability** | "threat model this code" / "security review" | Repo-grounded threat modeling: assets, trust boundaries, input handling, secret management, supply chain |
| 4 | **change-governance** | "plan a migration" / "dependency upgrade plan" / "govern this refactor" | Plan consequential changes: blast radius, approvals, rollout stages, rollback procedure |
| 5 | **ci-release** | "CI is failing" / "release readiness" / "why did my build break" | Diagnose build/CI failures, assess release readiness, minimal reversible verification plan |
| 6 | **incident-triage** | "service is down" / "error spike" / "triage this incident" | Safety-first incident response: establish scope, preserve evidence, rank hypotheses, containment |
| 7 | **performance-reliability** | "slow query" / "latency regression" / "performance issue" | Investigate through measurement: baseline → bottleneck isolation → guarded optimization |
| 8 | **customize-opencode** | "configure opencode" / "edit opencode.json" / "opencode settings" | **Built-in** — for editing opencode's own config (`.opencode/`, `opencode.json`, agents, skills, plugins) |

> **Activation rule**: I decide which skill to load based on your prompt's intent. You can also force-load any skill with `skill <name>`.

## Built-in Tools (not server-specific)

| Tool | Trigger Prompt |
|------|---------------|
| `skill <name>` | "use the `<name>` skill" / "activate `<name>`" |
| `task <subagent-type>` | "run a subagent to `<task>`" / "delegate this to an agent" |
| `question` | *(used when I need your decision on a specific choice)* |
| `websearch` | "search the web for `<query>`" / "latest `<topic>` 2026" |
| `webfetch` | "fetch `<url>`" / "scrape this page" |
| `read` | "read this file" |
| `write` | "write this file" |
| `edit` | "edit this file to `<change>`" |
| `glob` | "glob `<pattern>`" / "find files matching `<pattern>`" |
| `bash` | "run `<command>`" |
| `todowrite` | *(auto-used for multi-step tasks)* |

### Subagent Types (`task` tool)

| Subagent | Trigger Prompt |
|----------|---------------|
| `explore` | "explore this codebase" / "find files by `<pattern>`" |
| `general` | "do this complex multi-step task" |
| `sdlc-incident` | "triage this incident" |
| `sdlc-orchestrator` | "coordinate this engineering workflow" |
| `sdlc-release` | "assess release readiness" |
| `sdlc-security` | "security review of this code" |

---

## The Orchestrator Pattern

The strongest combination for broad engineering requests:

> "I'm working on this codebase — analyze it, find risks, propose a safe change, and verify it."

This activates: **repo-intelligence** (map) → **security-reliability** (threats) → **change-governance** (plan) → **ci-release** (verify) → `task` delegation → SDLc write engine (dry-run + rollback).

This is the end-to-end workflow this tool suite was designed for: **evidence-backed, safety-gated, audit-ready engineering**.
