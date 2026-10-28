import type { HopperStore, Finding, Operation } from "./store"
import type { CapturedEvidence } from "./evidence"
import { sha256Hex } from "./evidence"

export interface ShareBundle {
  operation: Operation
  findings: Finding[]
  evidence: Array<CapturedEvidence & { content: string }>
}

const SECRET_RE =
  /(authorization|cookie|set-cookie|api[-_]?key|token|password|passwd|secret|bearer|private[-_]?key|access[-_]?token|client[-_]?secret)["']?\s*[:=]\s*["']?[^\r\n"']*/gi
const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g

/** Redact secret-bearing values to the end of line — quoted-JSON and key=value shapes included. */
export function redactSecrets(text: string): string {
  return text.replace(PEM_RE, "<REDACTED PEM>").replace(SECRET_RE, "$1:<REDACTED>")
}

export function buildShareBundle(store: HopperStore, opId: string): { bundle: ShareBundle; manifestSha256: string } {
  const operation = store.listOperations().find((o) => o.id === opId)
  if (!operation) throw new Error(`operation ${opId} not found`)
  const findings = store.listFindings(opId).map((f) => ({ ...f, notes: redactSecrets(f.notes) }))
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
