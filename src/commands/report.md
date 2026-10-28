---
description: Generate the engagement report from operation state
agent: pentest
---

Generate the deliverable for the active engagement:

1. Run the `report` tool to build the markdown report from operation state (findings ledger + evidence, severity-ordered).
2. Summarize the report to the operator in 5 lines max: counts by status, top severity, and the report path.
3. Remind: findings that never reached `reportable` are listed as context, not as confirmed issues — do not present them as such.

Do not fabricate report content in chat; the file is the deliverable.
