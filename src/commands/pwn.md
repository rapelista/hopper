---
description: Bootstrap a scoped pentest operation for a target
agent: pentest
---

The operator just pointed you at a target: `$ARGUMENTS`.

Work through this bootstrap in order, showing each result before moving on:

1. Extract the **host** from `$ARGUMENTS` — strip any scheme and port (e.g. `http://localhost:3000` → `localhost`, `https://app.lab.test` → `app.lab.test`). If `$ARGUMENTS` is empty or is not a concrete host/IP/URL the operator owns or is authorized to test, stop and ask.
2. If the target is a public domain, load the `passive-osint` skill FIRST and run its standard opening — passive sources are consulted before the scope fence goes up.
3. Write the operation scope to `.opencode/scope.json` with exactly:
   `{"targets": ["<the host from step 1>"], "strict": true, "created": "<current ISO timestamp>"}`
4. Run the `doctor` tool and summarize which local tooling is available, missing, or degraded.
5. Lay out the engagement plan as PTES phases (PTES-01..07) scoped to this target only, and name the first concrete action you will take.

Authorized engagement only. The target boundary written in step 3 is the fence for everything that follows.
