import { loadScope, checkUrl, assertInScope, ScopeError } from "./scope"
import { HopperStore } from "./store"
import { captureEvidence } from "./evidence"
import { writeReport } from "./report"
import { buildShareBundle } from "./share"
import { mkdirSync } from "node:fs"
import { join } from "node:path"

// ---------------------------------------------------------------------------
// pure logic (ported from the retired file-tools layer)
// ---------------------------------------------------------------------------

/** doctor: local security tool availability */
export const TOOLS = ["nmap", "nuclei", "ffuf", "gobuster", "nikto", "whatweb", "sqlmap", "httpx"]

export interface DoctorReport {
  available: string[]
  missing: string[]
}

export function checkTools(
  names: string[],
  whichFn: (cmd: string) => string | null = (c) => Bun.which(c),
): DoctorReport {
  const available: string[] = []
  const missing: string[] = []
  for (const name of names) {
    if (whichFn(name) !== null) available.push(name)
    else missing.push(name)
  }
  return { available, missing }
}

/** http-request: scope-enforced HTTP client */
export interface RequestResult {
  url: string
  status: number
  headers: Record<string, string>
  body: string
  sha256: string
  hops: string[]
}

export interface RequestOpts {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string
  timeoutMs?: number
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>

const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"])
const MAX_HOPS = 5
const MAX_BODY_CHARS = 64 * 1024

export function sha256Hex(data: string | Uint8Array): string {
  const hasher = new Bun.CryptoHasher("sha256")
  hasher.update(data)
  return hasher.digest("hex")
}

function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    out[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? "<REDACTED>" : value
  }
  return out
}

export async function request(
  configDir: string,
  opts: RequestOpts,
  fetchImpl: FetchLike = fetch,
): Promise<RequestResult> {
  const hops: string[] = []
  let currentUrl = opts.url
  let response: Response | null = null

  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    // Fail-closed: re-load scope every hop so a deleted scope blocks mid-operation redirects too.
    const scope = loadScope(configDir)
    checkUrl(scope, currentUrl)

    response = await fetchImpl(currentUrl, {
      method: opts.method ?? "GET",
      headers: opts.headers,
      body: opts.body,
      redirect: "manual",
      signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
    })

    const location = response.headers.get("location")
    if (response.status >= 300 && response.status < 400 && location) {
      if (hop === MAX_HOPS) throw new Error(`too many redirects (>${MAX_HOPS})`)
      currentUrl = new URL(location, currentUrl).toString()
      hops.push(currentUrl)
      continue
    }
    break
  }

  if (!response) throw new Error("no response")

  const raw = new Uint8Array(await response.arrayBuffer())
  const text = new TextDecoder().decode(raw)
  const headerRecord: Record<string, string> = {}
  response.headers.forEach((value, key) => {
    headerRecord[key] = value
  })

  return {
    url: currentUrl,
    status: response.status,
    headers: redactHeaders(headerRecord),
    body: text.length > MAX_BODY_CHARS ? text.slice(0, MAX_BODY_CHARS) + "\n…[truncated]" : text,
    sha256: sha256Hex(raw),
    hops,
  }
}

/** cve: OSV advisory lookup */
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

export async function queryOsv(q: OsvQuery, fetchImpl: FetchLike = fetch): Promise<VulnInfo[]> {
  let url: string
  if (q.cve) {
    url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(q.cve)}`
  } else if (q.package) {
    url = `https://api.osv.dev/v1/query`
  } else {
    throw new OsvError("provide cve, or package (+ ecosystem)")
  }

  const init: RequestInit | undefined = q.cve
    ? undefined
    : {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ package: { name: q.package, ecosystem: q.ecosystem ?? "npm" } }),
      }

  const res = await fetchImpl(url, init)
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

/** scanner: scope-checked nmap/ffuf/whatweb wrappers */
export type ScannerMode = "portscan" | "dirfuzz" | "techscan"

export const COMMON_WORDLIST = `${process.env.HOME ?? "~"}/.cache/hopper/wordlists/common.txt`

export function buildCommand(mode: ScannerMode, target: string, extra: string[] = []): {
  bin: string
  argv: string[]
} {
  switch (mode) {
    case "portscan":
      return { bin: "nmap", argv: ["-sV", "-T4", target, ...extra] }
    case "dirfuzz":
      return { bin: "ffuf", argv: ["-w", COMMON_WORDLIST, "-u", target, ...extra] }
    case "techscan":
      return { bin: "whatweb", argv: [target, ...extra] }
  }
}

async function defaultSpawn(cmd: { bin: string; argv: string[] }): Promise<{ exitCode: number; stdout: string }> {
  const proc = Bun.spawn([cmd.bin, ...cmd.argv], { stdout: "pipe", stderr: "pipe", stdin: "ignore" })
  const timer = setTimeout(() => proc.kill(), 300_000)
  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  clearTimeout(timer)
  const combined = (stdout + (stderr ? `\n${stderr}` : "")).slice(0, 128 * 1024)
  return { exitCode, stdout: combined }
}

function scopeTarget(mode: ScannerMode, target: string): string {
  if (mode === "portscan" && /^[a-z]+:\/\//i.test(target)) return new URL(target).hostname
  return target
}

export async function runScan(
  configDir: string,
  args: { mode: ScannerMode; target: string; extra?: string[] },
  run: (cmd: { bin: string; argv: string[] }) => Promise<{ exitCode: number; stdout: string }> = defaultSpawn,
): Promise<{ command: string; exitCode: number; stdout: string }> {
  const scope = loadScope(configDir)
  if (args.mode === "portscan") {
    assertInScope(scope, scopeTarget("portscan", args.target))
  } else {
    checkUrl(scope, scopeTarget(args.mode, args.target))
  }

  const cmd = buildCommand(args.mode, scopeTarget(args.mode, args.target), args.extra)
  for (let i = 0; i < cmd.argv.length; i++) {
    const a = cmd.argv[i]!
    if (a === "-iL" || a === "--input-file") {
      throw new ScopeError(`scope guard: input-file lists cannot be scope-verified (${cmd.argv[i + 1] ?? ""})`)
    }
    if (/^https?:\/\//.test(a)) checkUrl(scope, a)
  }
  if (Bun.which(cmd.bin) === null) {
    return {
      command: `${cmd.bin} ${cmd.argv.join(" ")}`,
      exitCode: 127,
      stdout: `${cmd.bin} is not installed. Install it first:\n  brew install ${cmd.bin}\n  # or: apt install ${cmd.bin}`,
    }
  }
  const result = await run(cmd)
  return { command: `${cmd.bin} ${cmd.argv.join(" ")}`, exitCode: result.exitCode, stdout: result.stdout.slice(0, 128 * 1024) }
}

/** portscan targets are bare hosts, not URLs */

// ---------------------------------------------------------------------------
// tool definitions (v2 plugin shape: plain JSON Schema inputs, content results)
// ---------------------------------------------------------------------------

export interface ToolDef {
  name: string
  description: string
  input: Record<string, unknown>
  execute: (input: any, context?: any) => Promise<{ content: string }>
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"]
const FINDING_STATUSES = ["candidate", "observed", "verified", "reportable", "rejected", "stale"]

export function buildTools(configDir: string): ToolDef[] {
  return [
    {
      name: "doctor",
      description:
        "Run a local environment probe for Hopper. Reports the bun runtime, OS/arch, and which security tools are on PATH (nmap, nuclei, ffuf, gobuster, nikto, whatweb, sqlmap, httpx). Missing tools are listed with install hints but never fail the probe. Use when the operator runs /doctor, reports environment issues, or before promising a scan that depends on a specific binary.",
      input: { type: "object", properties: {}, additionalProperties: false },
      async execute() {
        const report = checkTools(TOOLS)
        const lines: string[] = []
        lines.push("# Doctor — environment probe", "")
        lines.push(`- runtime: bun ${Bun.version} on ${process.platform}/${process.arch}`)
        lines.push(`- tools available (${report.available.length}): ${report.available.join(", ") || "none"}`)
        lines.push(`- tools missing (${report.missing.length}): ${report.missing.join(", ") || "none"}`)
        if (report.missing.length > 0) {
          lines.push("", "Install the missing toolbelt (pick what you need):", "", "```bash", `brew install ${report.missing.join(" ")}`, "```", "", "Missing tools never fail the probe — Hopper degrades and tells the agent what is unavailable.")
        }
        return { content: lines.join("\n") }
      },
    },
    {
      name: "http-request",
      description:
        "Precision instrument for manual web testing: injections, auth bypass, IDOR, SSRF probes. Performs one HTTP request with exact method/headers/body and returns status, headers, body, a SHA256 over the raw bytes (evidence-grade), and the redirect hops followed. Every hop is re-checked against the active operation scope — out-of-scope redirects (including cloud metadata IPs) are refused, and with no active scope the tool fails closed. Sensitive response headers are redacted in the echo.",
      input: {
        type: "object",
        properties: {
          url: { type: "string", description: "Absolute http(s) URL to request (checked against scope)" },
          method: { type: "string", description: "HTTP method (default GET)" },
          headers: { type: "object", additionalProperties: { type: "string" }, description: "Request headers" },
          body: { type: "string", description: "Request body" },
          timeoutMs: { type: "number", description: "Timeout in ms (default 30000)" },
        },
        required: ["url"],
        additionalProperties: false,
      },
      async execute(input: { url: string; method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number }) {
        const result = await request(configDir, {
          url: input.url,
          method: input.method,
          headers: input.headers,
          body: input.body,
          timeoutMs: input.timeoutMs,
        })
        return { content: JSON.stringify(result, null, 2) }
      },
    },
    {
      name: "cve",
      description:
        "Vulnerability intelligence via the public OSV API (no key required). Look up a CVE id, or a package within an ecosystem (defaults to npm), and get advisory ids, summaries, and severity. Important: CVE intelligence is not a finding — it prioritizes validation and never proves applicability to the target. Enrich observed components with `cve`, then verify by hand before creating or promoting a Hopper finding.",
      input: {
        type: "object",
        properties: {
          cve: { type: "string", description: "CVE or GHSA id to look up directly" },
          package: { type: "string", description: "Package name (e.g. react, requests)" },
          ecosystem: { type: "string", description: "OSV ecosystem (npm, PyPI, Go, crates.io…); defaults to npm" },
        },
        additionalProperties: false,
      },
      async execute(input: { cve?: string; package?: string; ecosystem?: string }) {
        const vulns = await queryOsv({ cve: input.cve, package: input.package, ecosystem: input.ecosystem })
        if (vulns.length === 0) return { content: "No advisories found for this query." }
        return { content: vulns.map((v) => `- [${v.severity}] ${v.id}: ${v.summary}\n  ${v.url}`).join("\n") }
      },
    },
    {
      name: "scanner",
      description:
        "Active web/network recon: portscan (nmap service scan), dirfuzz (ffuf directory brute-force with FUZZ placeholder in the target URL), and techscan (whatweb fingerprinting). Targets are checked against the active operation scope — an out-of-scope target or a missing scope refuses the scan (fail-closed). Non-zero exit codes are returned as signal, not errors. Use before drilling with http-request or shell.",
      input: {
        type: "object",
        properties: {
          mode: { type: "string", enum: ["portscan", "dirfuzz", "techscan"], description: "Recon mode" },
          target: { type: "string", description: "Host or CIDR (portscan) or absolute URL (dirfuzz/techscan); must be in scope" },
          extra: { type: "array", items: { type: "string" }, description: "Extra CLI flags for the wrapped binary" },
        },
        required: ["mode", "target"],
        additionalProperties: false,
      },
      async execute(input: { mode: ScannerMode; target: string; extra?: string[] }, context?: { signal?: AbortSignal }) {
        void context
        const res = await runScan(configDir, { mode: input.mode, target: input.target, extra: input.extra })
        return { content: [`$ ${res.command}`, `exit: ${res.exitCode}`, "", res.stdout || "(no output)"].join("\n") }
      },
    },
    {
      name: "operation",
      description:
        "Ground truth for 'what am I working on'. Creates, lists, or reports the active operation: a named engagement against one target boundary. Creating an operation archives the previous one and writes the active scope (fail-closed for every scoped tool). action=status returns the active operation; action=list returns the operation history; action=create needs name and target (host, wildcard domain, or CIDR — URLs are normalized to their hostname).",
      input: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["create", "status", "list"], description: "What to do" },
          name: { type: "string", description: "Operation name (create)" },
          target: { type: "string", description: "Target boundary (create); URLs normalized to hostname" },
        },
        required: ["action"],
        additionalProperties: false,
      },
      async execute(input: { action: "create" | "status" | "list"; name?: string; target?: string }) {
        const store = HopperStore.open(configDir)
        try {
          if (input.action === "create") {
            if (!input.name || !input.target) return { content: "create needs both name and target." }
            const op = store.createOperation(input.name, input.target)
            return { content: `Active operation: ${op.name} (target: ${op.target})\nScope file written — every scoped tool now enforces this boundary.` }
          }
          if (input.action === "status") {
            const op = store.getActiveOperation()
            return {
              content: op
                ? `Active operation: ${op.name}\nTarget: ${op.target}\nStarted: ${op.created_at}`
                : "No active operation. Create one with action=create (name + target), or /pwn <target>.",
            }
          }
          const ops = store.listOperations()
          if (ops.length === 0) return { content: "No operations recorded yet." }
          return { content: ops.map((o) => `- [${o.status}] ${o.name} → ${o.target} (${o.created_at.slice(0, 10)})`).join("\n") }
        } finally {
          store.close()
        }
      },
    },
    {
      name: "finding",
      description:
        "The findings ledger — findings do not live in chat. action=add records a candidate (severity critical|high|medium|low|info, target, notes); action=status promotes along the lifecycle candidate → observed → verified → reportable (illegal jumps are refused; rejected/stale close a finding); action=list filters by status/operation; action=update patches title/severity/notes. Attach proof with the evidence tool before promoting. The workflow is not allowed to pretend every idea is reportable.",
      input: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["add", "list", "update", "status"], description: "What to do" },
          operationId: { type: "string", description: "Operation id (defaults to active)" },
          title: { type: "string", description: "Finding title (add/update)" },
          severity: { type: "string", enum: SEVERITIES, description: "Severity (add/update)" },
          target: { type: "string", description: "Affected host/URL (add)" },
          notes: { type: "string", description: "Context, confidence, remediation pointers (add/update)" },
          findingId: { type: "string", description: "Finding id (update/status)" },
          status: { type: "string", enum: FINDING_STATUSES, description: "Target status (status)" },
          patch: { type: "object", description: "Alternative patch object for update: {title?, severity?, notes?}" },
        },
        required: ["action"],
        additionalProperties: false,
      },
      async execute(input: Record<string, any>) {
        const store = HopperStore.open(configDir)
        try {
          const opId = input.operationId ?? store.getActiveOperation()?.id ?? null
          if (input.action === "add") {
            if (!opId) return { content: "No active operation — create one first (operation action=create or /pwn)." }
            if (!input.title || !input.severity || !input.target) return { content: "add needs title, severity, and target." }
            const f = store.addFinding(opId, { title: input.title, severity: input.severity, target: input.target, notes: input.notes })
            return { content: `Finding ${f.id} recorded as candidate: [${f.severity}] ${f.title}` }
          }
          if (input.action === "list") {
            const findings = store.listFindings(opId ?? undefined)
            if (findings.length === 0) return { content: "No findings recorded." }
            return { content: findings.map((f) => `- [${f.status}/${f.severity}] ${f.title} (${f.target}) id=${f.id}`).join("\n") }
          }
          if (input.action === "status") {
            if (!input.findingId || !input.status) return { content: "status needs findingId and status." }
            try {
              const f = store.updateFindingStatus(input.findingId, input.status)
              return { content: `Finding ${f.id} → ${f.status}` }
            } catch (err) {
              return { content: err instanceof Error ? err.message : String(err) }
            }
          }
          if (!input.findingId) return { content: "update needs findingId." }
          const patch = input.patch ?? {}
          const f = store.updateFinding(input.findingId, {
            title: patch.title ?? input.title,
            severity: patch.severity ?? input.severity,
            notes: patch.notes ?? input.notes,
          })
          return { content: `Finding ${f.id} updated.` }
        } finally {
          store.close()
        }
      },
    },
    {
      name: "evidence",
      description:
        "Attach proof to the operation — chain of custody for everything the operator may later report. action=capture stores content (a raw request/response, command output, file excerpt, or note) with kind + SHA256 + size + optional meta, and returns the evidence id; action=attach links evidence to a finding; action=list shows evidence for the operation, optionally filtered by finding. Promote findings to verified/reportable only with evidence attached.",
      input: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["capture", "list", "attach"], description: "What to do" },
          kind: { type: "string", enum: ["request", "response", "command", "file", "note"], description: "Evidence kind (capture)" },
          content: { type: "string", description: "The evidence payload verbatim (capture)" },
          meta: { type: "object", additionalProperties: { type: "string" }, description: "Optional metadata (url, command, source)" },
          operationId: { type: "string", description: "Operation id (defaults to active)" },
          findingId: { type: "string", description: "Finding id (attach, or filter list)" },
          evidenceId: { type: "string", description: "Evidence id (attach)" },
        },
        required: ["action"],
        additionalProperties: false,
      },
      async execute(input: Record<string, any>) {
        const store = HopperStore.open(configDir)
        try {
          const opId = input.operationId ?? store.getActiveOperation()?.id ?? null
          if (input.action === "capture") {
            if (!opId) return { content: "No active operation — create one first." }
            if (!input.kind || input.content === undefined) return { content: "capture needs kind and content." }
            const cap = captureEvidence(input.kind, input.content, input.meta ?? {})
            store.saveEvidence(opId, cap, input.content)
            return { content: `Evidence ${cap.id} captured (${cap.kind}, ${cap.size} bytes, sha256 ${cap.sha256.slice(0, 16)}…)` }
          }
          if (input.action === "attach") {
            if (!input.findingId || !input.evidenceId) return { content: "attach needs findingId and evidenceId." }
            store.attachEvidence(input.findingId, input.evidenceId)
            return { content: `Evidence ${input.evidenceId} attached to finding ${input.findingId}.` }
          }
          if (!opId) return { content: "No active operation." }
          const items = store.listEvidence(opId, input.findingId)
          if (items.length === 0) return { content: "No evidence recorded." }
          return { content: items.map((e) => `- ${e.kind} ${e.id} (${e.size}B, sha256 ${e.sha256.slice(0, 16)}…) ${e.created_at}`).join("\n") }
        } finally {
          store.close()
        }
      },
    },
    {
      name: "report",
      description:
        "Produce the signed deliverable for the engagement: a markdown report generated from operation state — never fabricated in chat. Includes the operation summary, findings table ordered by severity, reportable findings with their attached evidence (ids + sha256 prefixes), and a timestamp. Writes to reports/ and returns the path.",
      input: {
        type: "object",
        properties: { operationId: { type: "string", description: "Operation id (defaults to active)" } },
        additionalProperties: false,
      },
      async execute(input: { operationId?: string }) {
        try {
          const path = writeReport(configDir, input.operationId)
          return { content: `Report written: ${path}` }
        } catch (err) {
          return { content: err instanceof Error ? err.message : String(err) }
        }
      },
    },
    {
      name: "share",
      description:
        "Export a redacted, tamper-evident bundle of the operation so it can be reviewed, resumed, or handed off: the operation record, every finding with its lifecycle state, and all evidence with secret-bearing values (authorization, cookies, api keys, tokens) redacted. Returns the bundle path and a SHA256 manifest over the canonical JSON — any later edit to the operation changes the manifest.",
      input: {
        type: "object",
        properties: { operationId: { type: "string", description: "Operation id (defaults to active)" } },
        additionalProperties: false,
      },
      async execute(input: { operationId?: string }) {
        const store = HopperStore.open(configDir)
        try {
          const opId = input.operationId ?? store.getActiveOperation()?.id
          if (!opId) return { content: "No active operation to share." }
          const { bundle, manifestSha256 } = buildShareBundle(store, opId)
          const shareDir = join(configDir, "share")
          mkdirSync(shareDir, { recursive: true })
          const path = join(shareDir, `${opId}.json`)
          const { writeFileSync } = await import("node:fs")
          writeFileSync(path, JSON.stringify({ manifestSha256, bundle }, null, 2))
          return { content: `Share bundle written: ${path}\nManifest sha256: ${manifestSha256}` }
        } finally {
          store.close()
        }
      },
    },
  ]
}
