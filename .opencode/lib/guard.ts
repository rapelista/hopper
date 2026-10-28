import { isInScope, isFenceableHost, type Scope } from "./scope"

export type GuardResult = { ok: true } | { ok: false; reason: string; violations: string[] }

const URL_RE = /https?:\/\/[^\s"'`]+/g
const DOMAIN_RE = /\b((?:[a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,63})\b/gi

const FILE_EXT_RE =
  /\.(php|m?js|html?|css|png|jpe?g|gif|svg|ico|log|xml|json|csv|map|env|bak|old|ya?ml|conf|ini|sh|py|pyc|rb|go|ts|txt|md|pdf|tar|gz|zip|lock|db)$/i

/**
 * IP-literal checking was removed intentionally along with the SSRF guard:
 * dotted quads, encoded integers, localhost, and single-label names are never
 * extracted or judged here. The operator is responsible for every address
 * they engage. Only DNS-style domain names are fence-checked against the
 * operation scope.
 */
function extractDomains(command: string): string[] {
  const hosts: string[] = []
  let work = command

  for (const m of command.matchAll(URL_RE)) {
    try {
      const u = new URL(m[0])
      if (isFenceableHost(u.hostname)) hosts.push(u.hostname.toLowerCase())
    } catch {
      // unparsable URL — leave for token scan
    }
    work = work.split(m[0]).join(" ")
  }

  // A token immediately preceded by "/" is a path segment, never a host:
  // hostnames cannot contain "/", so `ftp/eastere.gg`, `./encrypt.pyc` are
  // filenames in an argument list or shell loop, not targets.
  // A dotted token immediately followed by "(" is a method call in inline code
  // (`json.load(`, `d.get(`), never a host.
  const isPathSegment = (idx: number) => idx > 0 && work[idx - 1] === "/"
  const isCallSite = (endIdx: number) => work[endIdx] === "("

  for (const m of work.matchAll(DOMAIN_RE)) {
    if (isPathSegment(m.index)) continue
    if (isCallSite(m.index + m[0].length)) continue
    const token = m[1]!
    if (FILE_EXT_RE.test(token)) continue
    hosts.push(token.toLowerCase())
  }

  return [...new Set(hosts)]
}

export function bashScopeGuard(scope: Scope | null, command: string): GuardResult {
  if (scope === null) return { ok: true } // the permission system still gates every call
  const violations: string[] = []
  for (const host of extractDomains(command)) {
    if (isInScope(scope, host)) continue
    violations.push(host)
  }
  if (violations.length > 0) {
    return {
      ok: false,
      violations,
      reason: `scope guard: refusing out-of-scope target(s) ${violations.join(", ")} — allowed: ${scope.targets.join(", ")}`,
    }
  }
  return { ok: true }
}
