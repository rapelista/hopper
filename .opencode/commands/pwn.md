---
description: Bootstrap a scoped pentest operation for a target
agent: pentest
---

The operator just pointed you at a target: `$ARGUMENTS`.

Work through this bootstrap in order, showing each result before moving on:

1. Write the operation scope to `.opencode/scope.json` with exactly:
   `{"targets": ["$ARGUMENTS"], "strict": true, "created": "<current ISO timestamp>"}`
   If `$ARGUMENTS` is empty or is not a concrete host/IP/URL the operator owns or is authorized to test, stop and ask.
2. Run the `doctor` tool and summarize which local tooling is available, missing, or degraded.
3. If the target is a public domain and passive recon is appropriate, load the `passive-osint` skill and run its standard opening.
4. Lay out the engagement plan as PTES phases (PTES-01..07) scoped to this target only, and name the first concrete action you will take.

Authorized engagement only. The target boundary written in step 1 is the fence for everything that follows.
