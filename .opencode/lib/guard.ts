import { isInScope, type Scope } from "./scope"

export type GuardResult = { ok: true } | { ok: false; reason: string; violations: string[] }

const IPV4_RE = /(?<![:\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])/g
const URL_RE = /https?:\/\/[^\s"'`]+/g
const DOMAIN_RE = /\b((?:[a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,63})\b/gi

const FILE_EXT_RE =
  /\.(php|m?js|html?|css|png|jpe?g|gif|svg|ico|log|xml|json|csv|map|env|bak|old|ya?ml|conf|ini|sh|py|pyc|rb|go|ts|txt|md|pdf|tar|gz|zip|lock|db)$/i

/**
 * Parse a plain decimal dotted-quad IPv4 to a 32-bit value; null otherwise.
 * NOTE (intentional): encoded-IP detection (bare decimal/hex integers, octal
 * parts like 010.0.0.1) was removed together with the SSRF guard — the
 * operator is responsible for what their commands connect to.
 */
export function parseIpToken(token: string): number | null {
  const parts = token.split(".")
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const p = Number(part)
    if (p > 255) return null
    value = value * 256 + p
  }
  return value >>> 0
}

/**
 * Auto-allowed networks without a scope entry: loopback, RFC1918, and
 * link-local (169.254/16 — cloud metadata). The SSRF guard that used to
 * special-case the metadata range was removed intentionally: pentest tool,
 * the operator is responsible.
 */
function isAutoAllowedPrivateIp(n: number): boolean {
  const within = (cidr: number, bits: number) => (n >>> (32 - bits)) === (cidr >>> (32 - bits))
  return (
    within(0x7f000000, 8) ||
    within(0x0a000000, 8) ||
    within(0xac100000, 12) ||
    within(0xc0a80000, 16) ||
    within(0xa9fe0000, 16)
  )
}

function isAutoAllowedHost(host: string): boolean {
  if (host === "localhost") return true
  const n = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? parseIpToken(host) : null
  return n !== null && isAutoAllowedPrivateIp(n)
}

interface Extracted {
  ips: string[]
  hosts: string[]
}

function extractTargets(command: string): Extracted {
  const ips: string[] = []
  const hosts: string[] = []
  let work = command

  for (const m of command.matchAll(URL_RE)) {
    try {
      const u = new URL(m[0])
      hosts.push(u.hostname.toLowerCase())
    } catch {
      // unparsable URL — leave for token scan
    }
    work = work.split(m[0]).join(" ")
  }

  // A token immediately preceded by "/" is a path segment, never a host:
  // hostnames cannot contain "/", so `ftp/eastere.gg`, `./encrypt.pyc`, or
  // `conf/8.8.8.8` are filenames in an argument list or shell loop, not targets.
  // A dotted token immediately followed by "(" is a method call in inline code
  // (`json.load(`, `d.get(`), never a host.
  const isPathSegment = (idx: number) => idx > 0 && work[idx - 1] === "/"
  const isCallSite = (endIdx: number) => work[endIdx] === "("

  for (const m of work.matchAll(IPV4_RE)) {
    if (isPathSegment(m.index)) continue
    ips.push(m[1]!)
  }

  for (const m of work.matchAll(DOMAIN_RE)) {
    if (isPathSegment(m.index)) continue
    if (isCallSite(m.index + m[0].length)) continue
    const token = m[1]!
    if (FILE_EXT_RE.test(token)) continue
    if (/^\d/.test(token)) continue
    hosts.push(token.toLowerCase())
  }

  return { ips: [...new Set(ips)], hosts: [...new Set(hosts)] }
}

export function bashScopeGuard(scope: Scope | null, command: string): GuardResult {
  if (scope === null) return { ok: true } // the permission system still gates every call
  const { ips, hosts } = extractTargets(command)
  const violations: string[] = []
  for (const ip of ips) {
    const n = parseIpToken(ip)
    if (isInScope(scope, ip)) continue
    if (n !== null && isAutoAllowedPrivateIp(n)) continue
    violations.push(ip)
  }
  for (const host of hosts) {
    if (isInScope(scope, host)) continue
    if (isAutoAllowedHost(host)) continue
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
