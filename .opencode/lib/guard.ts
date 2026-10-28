import { isInScope, type Scope } from "./scope"

export type GuardResult = { ok: true } | { ok: false; reason: string; violations: string[] }

const IPV4_RE = /(?<![:\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])/g
const URL_RE = /https?:\/\/[^\s"'`]+/g
const DOMAIN_RE = /\b((?:[a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,63})\b/gi
const BARE_INT_RE = /(?<![:\w.])(?:0x[0-9a-fA-F]{7,10}|\d{7,10})(?![\w.])/g

const FILE_EXT_RE =
  /\.(php|m?js|html?|css|png|jpe?g|gif|svg|ico|log|xml|json|csv|map|env|bak|old|ya?ml|conf|ini|sh|py|rb|go|ts|txt|md|pdf|tar|gz|zip|lock|db)$/i

/** inet_aton-style part parse: 0x… → hex, leading 0 → octal, else decimal. */
function parsePart(part: string): number | null {
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) return parseInt(part.slice(2), 16)
  if (/^0[0-7]+$/.test(part) && part.length > 1) return parseInt(part.slice(1), 8)
  if (/^\d{1,10}$/.test(part)) return parseInt(part, 10)
  return null
}

/** Decode dotted (2-4 parts) or bare/hex integer encodings to a 32-bit IPv4 value; null if not an IP. */
export function parseIpToken(token: string): number | null {
  if (/^0x[0-9a-fA-F]{7,10}$/.test(token) || /^\d{7,10}$/.test(token)) {
    const v = parsePart(token)
    return v !== null && v <= 0xffffffff ? v : null
  }
  const parts = token.split(".")
  if (parts.length < 2 || parts.length > 4) return null
  let value = 0
  for (let i = 0; i < parts.length; i++) {
    const p = parsePart(parts[i]!)
    if (p === null || p > 0xffffffff) return null
    const shift = (3 - i) * 8
    if (parts.length === 4 && p > 255) return null
    value += p * 2 ** shift
  }
  return value >>> 0
}

export function ipToString(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".")
}

/** Loopback + RFC1918 only. Cloud metadata 169.254/16 is deliberately NOT here. */
function isAutoAllowedPrivateIp(n: number): boolean {
  const within = (cidr: number, bits: number) => (n >>> (32 - bits)) === (cidr >>> (32 - bits))
  return within(0x7f000000, 8) || within(0x0a000000, 8) || within(0xac100000, 12) || within(0xc0a80000, 16)
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
      const asIp =
        /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) || /^\d{7,10}$/.test(u.hostname) || /^0x/.test(u.hostname)
          ? parseIpToken(u.hostname)
          : null
      if (asIp !== null) ips.push(ipToString(asIp))
      else hosts.push(u.hostname.toLowerCase())
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
  for (const m of work.matchAll(BARE_INT_RE)) {
    if (isPathSegment(m.index)) continue
    const v = parseIpToken(m[0])
    if (v !== null) ips.push(ipToString(v))
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
