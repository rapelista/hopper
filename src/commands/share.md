---
description: Export a redacted, tamper-evident operation bundle
agent: pentest
---

Export the engagement so it can be reviewed, resumed, or handed off:

1. Run the `share` tool for the active operation.
2. Report the bundle path and the manifest sha256 — the recipient can re-derive the manifest to verify nothing was edited after export.
3. State what was redacted (authorization, cookie, set-cookie, x-api-key, token values) and that evidence hashes refer to the original, pre-redaction content.

Keep it terse: path, manifest, redaction note.
