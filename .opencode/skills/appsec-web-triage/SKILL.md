---
name: appsec-web-triage
description: Run an evidence-first DAST triage against a live web application - environment readiness, AppSec methodology context, surface inventory, and semantic candidate-finding probes. Argument is the root HTTP(S) URL to triage. Execute one runbook step per assistant message.
---

# AppSec Web Triage runbook

Evidence-first DAST triage. Each step produces material for the findings ledger — nothing is a finding until probed by hand and backed by evidence.

**Arguments:** `target` — root HTTP(S) URL to triage (must be inside the active operation scope).

## Steps

1. **Refresh local cyber tool readiness** — run the `doctor` tool and note what is available, missing, or degraded.
2. **Anchor to AppSec methodology** — recall the WSTG map for SQL injection (WSTG-INPV-05), XSS (WSTG-INPV-02), JWT auth (WSTG-SESS-10), IDOR (WSTG-ATHZ-04), CORS (WSTG-CLNT-07). [fallback: knowledge broker pending — verify ids with `websearch` when unsure]
3. **Inventory the surface** — with `http-request`, fetch the root page, `robots.txt`, and `sitemap.xml`; note frameworks, headers, forms, and entry points. [fallback: scanner crawl mode pending]
4. **Extract JavaScript endpoints and secret-shaped values** — pull the main JS bundles with `http-request` and `bash` (`curl -s <url> | grep -oE '"/[a-z0-9/_-]+"' | sort -u`); look for API routes, keys, tokens. [fallback: scanner js mode pending]
5. **Run semantic AppSec DAST candidate probes** — for each check below, craft the probe by hand with `http-request` and record every interesting response with `evidence action=capture`:
   - `sqli_search` — inject `'` / `1' OR '1'='1` into search/filter params
   - `xss_search` — inject `<script>alert(1)</script>` / `"><img src=x>` into reflected params
   - `broken_auth_jwt` — decode JWTs (`bash`: `base64 -d`), check `alg: none`, weak secrets, missing expiry
   - `idor_basket` — request object ids belonging to another user pattern (`/api/orders/1` → `/api/orders/2`)
   - `weak_cors` — send `Origin: https://evil.test` and inspect `Access-Control-Allow-*` echoes
6. **Record candidates** — every probe with signal becomes `finding action=add` (candidate, with severity + confidence in notes); attach the captured evidence with `evidence action=attach`.
7. **Exit criteria** — summary of candidates by severity, evidence attached for each, and a prioritized drill list for the `pentest` lane.

Do not promote anything past `candidate` inside this runbook — promotion to `observed`/`verified` happens after hands-on confirmation in the engagement lane.
