export type FindingStatus = "candidate" | "observed" | "verified" | "reportable" | "rejected" | "stale"

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export const TRANSITIONS: Record<FindingStatus, readonly FindingStatus[]> = {
  candidate: ["observed", "rejected"],
  observed: ["verified", "rejected", "stale"],
  verified: ["reportable", "stale"],
  reportable: ["stale"],
  rejected: [],
  stale: [],
}

export class FindingError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "FindingError"
  }
}

export function canTransition(from: FindingStatus, to: FindingStatus): boolean {
  return TRANSITIONS[from].includes(to)
}

export function assertTransition(from: FindingStatus, to: FindingStatus): void {
  if (from === to) throw new FindingError(`finding is already ${from}`)
  if (!canTransition(from, to)) {
    throw new FindingError(`illegal lifecycle jump: ${from} → ${to} (allowed: ${TRANSITIONS[from].join(", ") || "none"})`)
  }
}
