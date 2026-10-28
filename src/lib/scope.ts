import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"

export class ScopeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "ScopeError"
  }
}

export interface Scope {
  targets: string[]
  strict: boolean
  created: string
}

export function parseScope(raw: string): Scope {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new ScopeError("scope.json is not valid JSON")
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new ScopeError("scope.json must be an object")
  }
  const obj = parsed as Record<string, unknown>
  if (!Array.isArray(obj.targets) || obj.targets.length === 0 || !obj.targets.every((t) => typeof t === "string" && t.length > 0)) {
    throw new ScopeError("scope.json must contain a non-empty targets array of strings")
  }
  return {
    targets: obj.targets as string[],
    strict: typeof obj.strict === "boolean" ? obj.strict : true,
    created: typeof obj.created === "string" ? obj.created : new Date().toISOString(),
  }
}

export function loadScope(configDir: string): Scope | null {
  const path = join(configDir, "scope.json")
  if (!existsSync(path)) return null
  return parseScope(readFileSync(path, "utf8"))
}

/** Normalize a scope target: URL → hostname, lowercase, port stripped. */
function normalizeTarget(target: string): string {
  const t = target.trim().toLowerCase()
  if (/^https?:\/\//.test(t)) {
    try {
      return new URL(t).hostname
    } catch {
      return t
    }
  }
  return t
}

export function saveScope(configDir: string, scope: Scope): void {
  mkdirSync(configDir, { recursive: true })
  const normalized: Scope = { ...scope, targets: scope.targets.map(normalizeTarget) }
  writeFileSync(join(configDir, "scope.json"), JSON.stringify(normalized, null, 2) + "\n")
}

/** Normalize a host: lowercase, strip :port (IPv4/hostname), unwrap [v6]. */
function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase()
  if (h.startsWith("[")) {
    const end = h.indexOf("]")
    if (end === -1) throw new ScopeError(`malformed host: ${host}`)
    return h.slice(1, end)
  }
  if (h.split(":").length === 2) h = h.split(":")[0]! // host:port
  return h
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".")
  if (parts.length !== 4) return null
  let n = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const v = Number(part)
    if (v > 255) return null
    n = n * 256 + v
  }
  return n
}

function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsRaw] = cidr.split("/")
  if (!base || bitsRaw === undefined) return false
  const bits = Number(bitsRaw)
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false
  const baseInt = ipv4ToInt(base)
  const ipInt = ipv4ToInt(ip)
  if (baseInt === null || ipInt === null) return false
  if (bits === 0) return true
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (baseInt & mask) === (ipInt & mask)
}

/**
 * Only DNS-style domain names (multi-label, alphabetic TLD) are scope-fence-checked.
 * Numeric hosts (dotted-quad IPv4, bare integers, hex) and single-label local
 * names (localhost, container names) are never checked — the SSRF guard was
 * removed intentionally: pentest tool, the operator is responsible for every
 * address they consciously engage.
 */
export function isFenceableHost(host: string): boolean {
  return /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,63}$/i.test(host)
}

export function isInScope(scope: Scope, host: string): boolean {
  const h = normalizeHost(host)
  for (const rawTarget of scope.targets) {
    const t = normalizeTarget(rawTarget)
    if (t === h) return true
    if (t.startsWith("*.")) {
      const domain = t.slice(2)
      if (h === domain || h.endsWith("." + domain)) return true
    }
    if (t.includes("/") && cidrContains(t, h)) return true
  }
  return false
}

/** Pure dialog-always policy: which fenceable hosts fall outside the scope (or any scope). */
export function scopeViolations(scope: Scope | null, hosts: string[]): string[] {
  const out: string[] = []
  for (const host of hosts) {
    const h = normalizeHost(host)
    if (!isFenceableHost(h)) continue
    if (scope !== null && isInScope(scope, h)) continue
    out.push(h)
  }
  return [...new Set(out)]
}

/**
 * Advisory only (operator decision B): hosts that, when engaged, carry the target
 * identity to a third party. They never block anything — they only enrich the
 * scope-escape dialog reason so the operator decides informed.
 */
export const OPSEC_ADVISORY_HOSTS: readonly string[] = [
  "shodan.io",
  "crt.sh",
  "virustotal.com",
  "urlscan.io",
  "otx.alienvault.com",
  "web.archive.org",
]
