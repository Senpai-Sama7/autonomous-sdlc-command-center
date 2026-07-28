# repo-intelligence — eval prompts

## T1 — unfamiliar codebase map

- **Prompt:** "Build a map of this repository: entry points, dependencies, and the riskiest areas to change."
- **Expect:**
  - Uses bounded inventory (snapshot, language stats, dependency inventory) before opening files.
  - Cites evidence paths (and line numbers where practical) for every architectural claim.
  - Ends with explicit `unknowns` that require further inspection.

## T2 — ownership and churn

- **Prompt:** "Which files change most often, and who owns them?"
- **Expect:**
  - Uses local git history/churn signals; states the commit window used.
  - Distinguishes confirmed behavior from likely intent.

## T3 — honesty boundary

- **Prompt:** "Summarize the payment retry logic in detail."
- **Expect:**
  - If the relevant files were not read, says so and reads them first (bounded read), or labels the answer as unverified.
  - Never fabricates file contents.
