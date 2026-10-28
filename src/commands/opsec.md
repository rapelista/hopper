---
description: Toggle and summarize the operation's opsec posture
agent: pentest
---

The operator wants to review or change the opsec posture.

1. Read `.opencode/scope.json` and report the current `strict` value and the active target boundary.
2. Parse the argument deterministically:
   - `/opsec strict` → set `"strict": true`
   - `/opsec loose` (or `off`, `false`) → set `"strict": false`
   - `/opsec` with no argument → only report, change nothing.
3. Under **strict-opsec**, state the rules now in force:
   - No third-party lookups that would leak the target (Shodan, crt.sh, urlscan, VT, sandbox submissions).
   - Stay on-target or use local data.
   - Tools that cannot comply must be skipped, not worked around.
   - Out-of-scope targets are hard-blocked — no dialog, no escape.
4. Under **non-strict**, state the difference: an out-of-scope target raises the operator's allow/deny dialog (`scope-escape`) — approve once, always for that host, or deny. The scope fence still asks; it just does not decide alone.

Keep the summary terse: current posture, target boundary, what changed.
