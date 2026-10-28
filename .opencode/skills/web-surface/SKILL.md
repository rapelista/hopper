---
name: web-surface
description: Map the attack surface of a URL - page inventory, JS endpoint extraction, light dir-fuzz, and subdomain enumeration via passive OSINT. Produces endpoints, forms, JS secrets, subdomains. Arguments are the root URL to survey and optionally the apex domain for subdomain enumeration. Execute one runbook step per assistant message.
---

# Web Surface Map runbook

Passive-first surface mapping. Active steps (dirfuzz) stay inside the operation scope; OSINT is strictly passive.

**Arguments:** `target` — root URL to survey (e.g. `https://example.com`); optional `domain` — apex domain for subdomain enumeration.

## Steps

1. **(if `domain` given) Passive subdomain enumeration** — load the `passive-osint` skill and enumerate subdomains of `{{domain}}` using crt.sh, wayback, theHarvester, holehe. No active probes; passive only.
2. **Inventory the target** — with `http-request`, fetch the root page, `robots.txt`, `sitemap.xml`; list forms, links, and entry points. [fallback: scanner crawl mode pending]
3. **JavaScript endpoint extraction** — pull the main JS bundles with `http-request` and extract API routes and secret-shaped values via `bash` (`grep -oE '"/[a-z0-9/_-]+"' | sort -u`). [fallback: scanner js mode pending]
4. **Light web dir-fuzz** — run `scanner` mode `dirfuzz` with target `{{target}}/FUZZ` (ffuf, common wordlist); triage interesting status codes (200, 301/302, 401, 403).
5. **Technology fingerprint** — run `scanner` mode `techscan` (whatweb) on `{{target}}`; note observed components.
6. **Browser passive findings** — [fallback: browser tool pending] skip; note DOM-heavy areas for manual follow-up with `http-request`.
7. **Record the map** — summarize endpoints, forms, JS secrets, and subdomains as `finding action=add` candidates (severity `info`/`low`, confidence in notes) with `evidence action=capture` for each source artifact.

The output of this runbook is a working inventory — drill deeper where signal is strongest, in the engagement lane.
