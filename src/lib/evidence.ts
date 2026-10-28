export type EvidenceKind = "request" | "response" | "command" | "file" | "note"

export interface CapturedEvidence {
  id: string
  kind: EvidenceKind
  sha256: string
  size: number
  created_at: string
  meta: Record<string, string>
}

export function sha256Hex(data: string | Uint8Array): string {
  const hasher = new Bun.CryptoHasher("sha256")
  hasher.update(data)
  return hasher.digest("hex")
}

export function captureEvidence(
  kind: EvidenceKind,
  content: string | Uint8Array,
  meta: Record<string, string> = {},
): CapturedEvidence {
  const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content
  return {
    id: crypto.randomUUID(),
    kind,
    sha256: sha256Hex(bytes),
    size: bytes.byteLength,
    created_at: new Date().toISOString(),
    meta,
  }
}

export function verifyEvidence(data: string | Uint8Array, expectedSha256: string): boolean {
  return sha256Hex(data) === expectedSha256
}
