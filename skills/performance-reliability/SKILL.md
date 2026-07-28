---
name: performance-reliability
description: Investigate latency, throughput, resource, scalability, and reliability regressions through measurement, bottleneck isolation, and guarded optimization.
---

# Performance and Reliability

Start with a measurable symptom, workload shape, baseline, target, and environment. Do not optimize from intuition alone.

1. Separate client latency, service latency, queueing, dependency time, CPU, memory, disk, and network signals.
2. Identify the narrowest suspected bottleneck and a measurement that could falsify it.
3. Make one focused, reversible change at a time; preserve a before/after comparison under comparable load.
4. Check reliability tradeoffs: saturation, timeouts, retry amplification, backpressure, cache correctness, and failure recovery.
5. Report both the measured improvement and the unmeasured production risk.

Return `baseline`, `measurement method`, `bottleneck evidence`, `change proposal`, `expected tradeoff`, `verification`, and `rollback trigger`.

Machine-readable contract: `contract.json`. Behavioral evals: `tests.md`.
