---
description: Load and execute a security runbook
agent: pentest
---

The operator asked for a runbook: `$ARGUMENTS`.

1. Parse `$ARGUMENTS`: first token is the runbook name, the rest is its target (e.g. `/runbook appsec-web-triage https://lab.test`).
2. Available runbooks:
   - `appsec-web-triage <url>` — evidence-first DAST triage of a live web app
   - `web-surface <url> [domain]` — attack surface map (passive-first)
   - `passive-osint <domain|email|handle>` — passive recon kit
   - `forensics-kit` — forensic artifact triage
   With bare `list` (or an unknown name), print this list and stop.
3. Load the skill with the `skill` tool, then execute its steps **one per assistant message** — wait for each result before continuing. Do not re-run the runbook, do not batch steps, do not stop while declared steps are pending.
4. Record every signal as `finding action=add` candidates and attach proof with `evidence action=capture`.

Authorized targets only — the active scope is the fence.
