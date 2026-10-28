import type { FindingSummary, FindingsCounts, OperationStatusResult } from "../rpc"

/**
 * Pure presentation helpers for the TUI part — no imports beyond the rpc
 * contract types, so they unit-test without any TUI/plugin runtime.
 */

const STATUS_SUFFIX: Array<[keyof FindingsCounts, string]> = [
  ["candidate", "c"],
  ["observed", "o"],
  ["verified", "v"],
  ["reportable", "r"],
  ["rejected", "x"],
  ["stale", "s"],
]

export const LIFECYCLE = ["candidate", "observed", "verified", "reportable", "rejected", "stale"] as const

/** Next/previous lifecycle tab, wrapping around. */
export function cycleStatus(current: string, direction: 1 | -1): string {
  const idx = LIFECYCLE.indexOf(current as (typeof LIFECYCLE)[number])
  const base = idx === -1 ? 0 : idx
  return LIFECYCLE[(base + direction + LIFECYCLE.length) % LIFECYCLE.length]!
}

/** `3c/1v` — nonzero statuses only, lifecycle order; "" when the ledger is empty. */
export function compactCounts(c: FindingsCounts): string {
  return STATUS_SUFFIX.filter(([key]) => c[key] > 0)
    .map(([key, suffix]) => `${c[key]}${suffix}`)
    .join("/")
}

const STATUS_INITIAL: Record<string, string> = { candidate: "C", observed: "O", verified: "V", reportable: "R", rejected: "X", stale: "S" }

/** Panel tab initial — rejected takes X so it never collides with reportable. */
export function statusInitial(status: string): string {
  return STATUS_INITIAL[status] ?? (status[0]?.toUpperCase() || "?")
}

/** Uniform 3-letter severity badge: cri/hig/med/low/inf — keeps the ledger column aligned. */
export function severityShort(severity: string): string {
  return severity.slice(0, 3).toLowerCase()
}

/** The operation banner: `hop · <name> → <target> · <opsec>` (+ counts when any exist). */
export function bannerText(m: {
  operation: OperationStatusResult["operation"]
  opsec: OperationStatusResult["opsec"]
  counts: FindingsCounts
}): string {
  if (m.operation === null) return "hop · no operation"
  const base = `hop · ${m.operation.name} → ${m.operation.target} · ${m.opsec}`
  const counts = compactCounts(m.counts)
  return counts === "" ? base : `${base} · ${counts}`
}

/** Group findings by lifecycle status, lifecycle order, empty groups omitted. */
export function groupFindings(items: FindingSummary[]): Array<{ status: string; items: FindingSummary[] }> {
  const out: Array<{ status: string; items: FindingSummary[] }> = []
  for (const status of LIFECYCLE) {
    const group = items.filter((f) => f.status === status)
    if (group.length > 0) out.push({ status, items: group })
  }
  return out
}

/** Map a finding severity onto a theme token name (verified against context.theme at the panel). */
export function severityToken(s: string): "error" | "warning" | "base" | "muted" {
  if (s === "critical" || s === "high") return "error"
  if (s === "medium") return "warning"
  if (s === "low") return "base"
  return "muted" // info + unknown
}

/** `/pwn` name default: the hostname's leftmost label, or the whole dotless target. */
export function defaultOperationName(target: string): string {
  let host = target.trim().toLowerCase()
  if (/^https?:\/\//.test(host)) {
    try {
      host = new URL(host).hostname
    } catch {
      /* fall through to label logic */
    }
  }
  host = host.split(":")[0]!
  const first = host.split(".")[0]!
  return first === "" ? host : first
}
