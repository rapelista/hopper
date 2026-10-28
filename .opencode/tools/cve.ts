import { tool } from "@opencode-ai/plugin"

export class OsvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "OsvError"
  }
}

export interface VulnInfo {
  id: string
  summary: string
  severity: string
  url: string
}

export interface OsvQuery {
  package?: string
  ecosystem?: string
  cve?: string
}

const MAX_VULNS = 20

interface OsvVuln {
  id: string
  summary?: string
  database_specific?: { severity?: string }
  ecosystem_specific?: { severity?: string }
  references?: Array<{ url?: string }>
}

export async function queryOsv(q: OsvQuery, fetchImpl: typeof fetch = fetch): Promise<VulnInfo[]> {
  let url: string
  if (q.cve) {
    url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(q.cve)}`
  } else if (q.package && q.ecosystem) {
    url = `https://api.osv.dev/v1/query/${encodeURIComponent(q.ecosystem)}/${encodeURIComponent(q.package)}`
  } else if (q.package) {
    url = `https://api.osv.dev/v1/query/npm/${encodeURIComponent(q.package)}`
  } else {
    throw new OsvError("provide cve, or package (+ ecosystem)")
  }

  const res = await fetchImpl(url)
  if (!res.ok) throw new OsvError(`OSV API ${res.status} for ${url}`)

  const data = (await res.json()) as OsvVuln | { vulns: OsvVuln[] }
  const vulns: OsvVuln[] = "vulns" in data ? data.vulns : [data]

  return vulns.slice(0, MAX_VULNS).map((v) => ({
    id: v.id,
    summary: v.summary ?? "",
    severity: v.database_specific?.severity ?? v.ecosystem_specific?.severity ?? "UNKNOWN",
    url: v.references?.find((r) => r.url)?.url ?? `https://osv.dev/vulnerability/${v.id}`,
  }))
}

export default tool({
  description:
    "Vulnerability intelligence via the public OSV API (no key required). Look up a CVE id, or a package within an ecosystem (defaults to npm), and get advisory ids, summaries, and severity. Public sources may rate-limit unauthenticated requests. Important: CVE intelligence is not a finding — it prioritizes validation and never proves applicability to the target. Enrich observed components with `cve`, then verify by hand before creating or promoting a Hopper finding.",
  args: {
    cve: tool.schema.string().optional().describe("CVE or GHSA id to look up directly"),
    package: tool.schema.string().optional().describe("Package name (e.g. react, requests)"),
    ecosystem: tool.schema.string().optional().describe("OSV ecosystem (npm, PyPI, Go, crates.io…); defaults to npm"),
  },
  async execute(args) {
    const vulns = await queryOsv({
      cve: args.cve,
      package: args.package,
      ecosystem: args.ecosystem,
    })
    if (vulns.length === 0) return "No advisories found for this query."
    return vulns
      .map((v) => `- [${v.severity}] ${v.id}: ${v.summary}\n  ${v.url}`)
      .join("\n")
  },
})
