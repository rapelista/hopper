---
description: Probe the local environment for security tool readiness
agent: security
---

Run the `doctor` tool, then:

1. Summarize which tools are available, missing, or degraded.
2. For each missing tool that matters to the operator's current task, give the exact `brew install` (or `apt install`) line.
3. Note that missing tools never fail the probe — Hopper degrades and the agent works with what is present.

Keep it short: a readiness table and the install lines. No preamble.
