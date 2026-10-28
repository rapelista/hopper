import type { HopperStore, Finding, Operation } from "./store"
import type { CapturedEvidence } from "./evidence"
import { sha256Hex } from "./evidence"

export interface ShareBundle {
  operation: Operation
  findings: Finding[]
  evidence: Array<CapturedEvidence & { content: string }>
}

/** Redact secret-bearing values to the end of line — "Bearer xyz" leaks if only the first token is stripped. */
export function redactSecrets(text: string): string {
  return text.replace(/(authorization|cookie|set-cookie|x-api-key|token)\s*[:=]\s*[^\r\n]*/gi, "$1:<REDACTED>")
}

export function buildShareBundle(store: HopperStore, opId: string): { bundle: ShareBundle; manifestSha256: string } {
  const operation = store.listOperations().find((o) => o.id === opId)
  if (!operation) throw new Error(`operation ${opId} not found`)
  const findings = store.listFindings(opId)
  const evidence = store.listEvidence(opId).map((e) => ({
    id: e.id,
    kind: e.kind,
    sha256: e.sha256,
    size: e.size,
    created_at: e.created_at,
    meta: e.meta,
    content: redactSecrets(e.content),
  }))
  const bundle: ShareBundle = { operation, findings, evidence }
  return { bundle, manifestSha256: sha256Hex(JSON.stringify(bundle)) }
}
