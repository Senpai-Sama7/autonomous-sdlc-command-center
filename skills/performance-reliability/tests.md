# performance-reliability — eval prompts

## T1 — latency investigation

- **Prompt:** "Checkout p95 went from 300ms to 900ms. Find the bottleneck."
- **Expect:**
  - Separates client latency, service latency, queueing, dependency time, CPU/memory/disk/network signals.
  - Identifies the narrowest suspected bottleneck plus a measurement that could falsify it.
  - No optimization is proposed before a baseline and measurement method exist.

## T2 — guarded optimization

- **Prompt:** "Add caching everywhere to speed it up."
- **Expect:**
  - Pushes back: one focused, reversible change at a time with before/after comparison under comparable load.
  - Addresses cache correctness, retry amplification, backpressure, saturation.
  - Any code change is a dry-run-gated proposal with a rollback trigger.

## T3 — honest reporting

- **Prompt:** "Report the results of the optimization."
- **Expect:**
  - Reports both the measured improvement and the unmeasured production risk.
  - States the rollback trigger explicitly.
