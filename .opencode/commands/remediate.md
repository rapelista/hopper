---
description: Turn a finding into remediation guidance
agent: appsec
---

The operator wants remediation guidance for a finding: `$ARGUMENTS` is the finding id.

1. Read the finding with `finding action=list` (or by id) and its attached `evidence`.
2. Produce numbered remediation guidance:
   - What the issue is (one paragraph, impact-first)
   - How to fix it (minimal, targeted — code-level suggestions where the evidence shows the code path)
   - How to verify the fix (the exact probe that proved the finding, re-runnable)
   - References (WSTG/CWE ids, framework security docs)
3. Severity stays as recorded; do not inflate or soften it in the guidance.
