import { scopeViolations, normalizeTarget, type Scope } from "./scope"
import { HopperStore, type SessionResolution } from "./store"
import { captureEvidence } from "./evidence"
import { writeReport } from "./report"
import { buildShareBundle } from "./share"
import type { HopperNotify } from "../rpc"
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

/** Session/tool-call identity a mid-tool confirm (e.g. a redirect hop) needs to raise the operator dialog. */
export interface ToolSessionContext {
  sessionID?: string
  agent?: string
  messageID?: string
  id?: string
}

/** Ask the operator about a scope escape — allow resolves, deny rejects. Never blocks by itself. */
export type ConfirmScopeEscape = (violations: string[], reason: string, context?: ToolSessionContext) => Promise<void>

export interface RequestHandlers {
  fetch?: FetchLike
  confirm?: ConfirmScopeEscape
  context?: ToolSessionContext
}

const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"])
const MAX_HOPS = 5
const MAX_BODY_CHARS = 64 * 1024

export function sha256Hex(data: string | Uint8Array): string {
  const hasher = new Bun.CryptoHasher("sha256")
  hasher.update(data)
  return hasher.digest("hex")
}

/**
 * What the tool's execution context says about the calling session. No
 * sessionID (or an unreadable store) reads as unbound — ask, never block.
 */
function resolveToolSession(configDir: string, context: ToolSessionContext | undefined): SessionResolution {
  const sessionID = context?.sessionID
  if (typeof sessionID !== "string" || sessionID === "") return { mode: "unbound" }
  try {
    const store = HopperStore.open(configDir)
    try {
      return store.resolveSession(sessionID)
    } finally {
      store.close()
    }
  } catch {
    return { mode: "unbound" } // unreadable store behaves like unbound: dialogs, never blocks
  }
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
  handlers: RequestHandlers = {},
): Promise<RequestResult> {
  const doFetch = handlers.fetch ?? fetch
  const hops: string[] = []
  let currentUrl = opts.url
  let response: Response | null = null

  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    // Dialog-always on redirect hops only — hop 0 is the initial target the
    // execute.before hook already owns. The confirm resolves by the calling
    // session's binding: bound ⇒ fence against the bound operation's store
    // scope row; free ⇒ pass silently; unbound (or an unreadable store) ⇒
    // the binary confirm for every fenceable hop host. Never blocks alone.
    if (hop > 0) {
      const resolution = resolveToolSession(configDir, handlers.context)
      if (resolution.mode !== "free") {
        const scope: Scope | null =
          resolution.mode === "bound"
            ? {
                targets: resolution.scope.targets,
                strict: resolution.scope.strict,
                created: resolution.operation.created_at,
              }
            : null
        const violations = scopeViolations(scope, [new URL(currentUrl).hostname])
        if (violations.length > 0 && handlers.confirm) {
          await handlers.confirm(
            violations,
            resolution.mode === "bound"
              ? `redirect hop → ${violations.join(", ")} is outside the operation scope`
              : `no operation bound — allow redirect to ${violations.join(", ")}?`,
            handlers.context,
          )
        }
      }
    }

    response = await doFetch(currentUrl, {
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
  void configDir // scope policy lives in the execute.before hook; the tool body is scope-blind
  const cmd = buildCommand(args.mode, scopeTarget(args.mode, args.target), args.extra)
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

/**
 * Informational no-binding content (spec §5b): the guard stays the only
 * fence — this tells the agent how to get an operation, it never refuses a
 * call the guard would allow.
 */
const NO_OPERATION_BOUND = "no operation bound to this session — bind one (/op) or pass operationId"

/**
 * Session-scoped operation default: an explicit operationId always wins and
 * works for any operation; without one, the calling session's bound
 * operation is the default. Free/unbound sessions get the no-binding
 * content (content, never a throw — that is the tool contract).
 */
function sessionOperation(
  store: HopperStore,
  operationId: unknown,
  context: unknown,
): { ok: true; opId: string } | { ok: false; content: string } {
  if (typeof operationId === "string" && operationId !== "") return { ok: true, opId: operationId }
  const sessionID = (context as ToolSessionContext | undefined)?.sessionID
  if (typeof sessionID === "string" && sessionID !== "") {
    const resolution = store.resolveSession(sessionID)
    if (resolution.mode === "bound") return { ok: true, opId: resolution.operation.id }
  }
  return { ok: false, content: NO_OPERATION_BOUND }
}

export function buildTools(
  configDir: string,
  opts?: { confirm?: ConfirmScopeEscape; notify?: HopperNotify },
): ToolDef[] {
  const confirm = opts?.confirm
  const notify = opts?.notify
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
        "Precision instrument for manual web testing: injections, auth bypass, IDOR, SSRF probes. Performs one HTTP request with exact method/headers/body and returns status, headers, body, a SHA256 over the raw bytes (evidence-grade), and the redirect hops followed. The URL and every redirect hop are checked against the active operation scope — an out-of-scope target raises the operator dialog (allow once / always / deny) instead of refusing. Sensitive response headers are redacted in the echo.",
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
      async execute(
        input: { url: string; method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number },
        context?: unknown,
      ) {
        const result = await request(
          configDir,
          {
            url: input.url,
            method: input.method,
            headers: input.headers,
            body: input.body,
            timeoutMs: input.timeoutMs,
          },
          { confirm, context: context as ToolSessionContext | undefined },
        )
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
        "Active web/network recon: portscan (nmap service scan), dirfuzz (ffuf directory brute-force with FUZZ placeholder in the target URL), and techscan (whatweb fingerprinting). Targets are checked against the active operation scope — an out-of-scope target or a missing scope raises the operator dialog (allow once / always / deny) instead of refusing. Non-zero exit codes are returned as signal, not errors. Use before drilling with http-request or shell.",
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
      async execute(input: { mode: ScannerMode; target: string; extra?: string[] }) {
        const res = await runScan(configDir, { mode: input.mode, target: input.target, extra: input.extra })
        return { content: [`$ ${res.command}`, `exit: ${res.exitCode}`, "", res.stdout || "(no output)"].join("\n") }
      },
    },
    {
      name: "operation",
      description:
        "Ground truth for 'what am I working on'. Creates, lists, or reports this session's bound operation: a named engagement against one target boundary. action=status reports the session's bound operation (or how to get one); action=list returns the whole operation history; action=create needs name and target (host, wildcard domain, or CIDR — URLs are normalized to their hostname). Creating is additive — no other operation is archived or touched — and it never binds this session: the operator binds via /op (or the unbound-scope dialog), and until a binding exists the ledger tools need an explicit operationId. Scoped tools confirm with the operator when a target falls outside the bound operation's scope.",
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
      async execute(input: { action: "create" | "status" | "list"; name?: string; target?: string }, context?: unknown) {
        const store = HopperStore.open(configDir)
        try {
          if (input.action === "create") {
            if (!input.name || !input.target) return { content: "create needs both name and target." }
            const op = store.createOperation(input.name, normalizeTarget(input.target))
            try {
              notify?.({ type: "operation.changed", data: { operationId: op.id } })
            } catch {
              // best-effort — a missed notification never blocks the tool
            }
            return {
              content: `Operation ${op.name} created (target: ${op.target}, id: ${op.id}).\nNo session is bound to it yet — the operator binds this session via /op or the unbound-scope dialog; until then pass this id as operationId to the ledger tools.`,
            }
          }
          if (input.action === "status") {
            const sessionID = (context as ToolSessionContext | undefined)?.sessionID
            const resolution = typeof sessionID === "string" && sessionID !== "" ? store.resolveSession(sessionID) : null
            return {
              content:
                resolution?.mode === "bound"
                  ? `Bound operation: ${resolution.operation.name} (id: ${resolution.operation.id})\nTarget: ${resolution.operation.target}\nStarted: ${resolution.operation.created_at}`
                  : NO_OPERATION_BOUND,
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
        "The findings ledger — findings do not live in chat. action=add records a candidate (severity critical|high|medium|low|info, target, notes); action=status promotes along the lifecycle candidate → observed → verified → reportable (illegal jumps are refused; rejected/stale close a finding); action=list shows an operation's findings; action=update patches title/severity/notes. operationId defaults to the session's bound operation — with none bound, pass operationId explicitly. Attach proof with the evidence tool before promoting. The workflow is not allowed to pretend every idea is reportable.",
      input: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["add", "list", "update", "status"], description: "What to do" },
          operationId: { type: "string", description: "Operation id (defaults to the session's bound operation)" },
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
      async execute(input: Record<string, any>, context?: unknown) {
        const store = HopperStore.open(configDir)
        try {
          if (input.action === "add") {
            const resolved = sessionOperation(store, input.operationId, context)
            if (!resolved.ok) return { content: resolved.content }
            if (!input.title || !input.severity || !input.target) return { content: "add needs title, severity, and target." }
            const f = store.addFinding(resolved.opId, { title: input.title, severity: input.severity, target: input.target, notes: input.notes })
            try {
              notify?.({ type: "finding.changed", data: { operationId: f.operation_id, findingId: f.id, status: f.status } })
            } catch {
              // best-effort
            }
            return { content: `Finding ${f.id} recorded as candidate: [${f.severity}] ${f.title}` }
          }
          if (input.action === "list") {
            const resolved = sessionOperation(store, input.operationId, context)
            if (!resolved.ok) return { content: resolved.content }
            const findings = store.listFindings(resolved.opId)
            if (findings.length === 0) return { content: "No findings recorded." }
            return { content: findings.map((f) => `- [${f.status}/${f.severity}] ${f.title} (${f.target}) id=${f.id}`).join("\n") }
          }
          if (input.action === "status") {
            if (!input.findingId || !input.status) return { content: "status needs findingId and status." }
            try {
              const f = store.updateFindingStatus(input.findingId, input.status)
              try {
                notify?.({ type: "finding.changed", data: { operationId: f.operation_id, findingId: f.id, status: f.status } })
              } catch {
                // best-effort
              }
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
        "Attach proof to the operation — chain of custody for everything the operator may later report. action=capture stores content (a raw request/response, command output, file excerpt, or note) with kind + SHA256 + size + optional meta, and returns the evidence id; action=attach links evidence to a finding; action=list shows evidence for the operation, optionally filtered by finding. operationId defaults to the session's bound operation — with none bound, pass operationId explicitly. Promote findings to verified/reportable only with evidence attached.",
      input: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["capture", "list", "attach"], description: "What to do" },
          kind: { type: "string", enum: ["request", "response", "command", "file", "note"], description: "Evidence kind (capture)" },
          content: { type: "string", description: "The evidence payload verbatim (capture)" },
          meta: { type: "object", additionalProperties: { type: "string" }, description: "Optional metadata (url, command, source)" },
          operationId: { type: "string", description: "Operation id (defaults to the session's bound operation)" },
          findingId: { type: "string", description: "Finding id (attach, or filter list)" },
          evidenceId: { type: "string", description: "Evidence id (attach)" },
        },
        required: ["action"],
        additionalProperties: false,
      },
      async execute(input: Record<string, any>, context?: unknown) {
        const store = HopperStore.open(configDir)
        try {
          if (input.action === "capture") {
            const resolved = sessionOperation(store, input.operationId, context)
            if (!resolved.ok) return { content: resolved.content }
            if (!input.kind || input.content === undefined) return { content: "capture needs kind and content." }
            const cap = captureEvidence(input.kind, input.content, input.meta ?? {})
            store.saveEvidence(resolved.opId, cap, input.content)
            return { content: `Evidence ${cap.id} captured (${cap.kind}, ${cap.size} bytes, sha256 ${cap.sha256.slice(0, 16)}…)` }
          }
          if (input.action === "attach") {
            if (!input.findingId || !input.evidenceId) return { content: "attach needs findingId and evidenceId." }
            store.attachEvidence(input.findingId, input.evidenceId)
            return { content: `Evidence ${input.evidenceId} attached to finding ${input.findingId}.` }
          }
          const resolved = sessionOperation(store, input.operationId, context)
          if (!resolved.ok) return { content: resolved.content }
          const items = store.listEvidence(resolved.opId, input.findingId)
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
        "Produce the signed deliverable for the engagement: a markdown report generated from operation state — never fabricated in chat. Includes the operation summary, findings table ordered by severity, reportable findings with their attached evidence (ids + sha256 prefixes), and a timestamp. operationId defaults to the session's bound operation — with none bound, pass operationId explicitly. Writes to reports/ and returns the path.",
      input: {
        type: "object",
        properties: { operationId: { type: "string", description: "Operation id (defaults to the session's bound operation)" } },
        additionalProperties: false,
      },
      async execute(input: { operationId?: string }, context?: unknown) {
        let opId: string
        const store = HopperStore.open(configDir)
        try {
          const resolved = sessionOperation(store, input.operationId, context)
          if (!resolved.ok) return { content: resolved.content }
          opId = resolved.opId
        } finally {
          store.close()
        }
        try {
          const path = writeReport(configDir, opId)
          return { content: `Report written: ${path}` }
        } catch (err) {
          return { content: err instanceof Error ? err.message : String(err) }
        }
      },
    },
    {
      name: "share",
      description:
        "Export a redacted, tamper-evident bundle of the operation so it can be reviewed, resumed, or handed off: the operation record, every finding with its lifecycle state, and all evidence with secret-bearing values (authorization, cookies, api keys, tokens) redacted. operationId defaults to the session's bound operation — with none bound, pass operationId explicitly. Returns the bundle path and a SHA256 manifest over the canonical JSON — any later edit to the operation changes the manifest.",
      input: {
        type: "object",
        properties: { operationId: { type: "string", description: "Operation id (defaults to the session's bound operation)" } },
        additionalProperties: false,
      },
      async execute(input: { operationId?: string }, context?: unknown) {
        const store = HopperStore.open(configDir)
        try {
          const resolved = sessionOperation(store, input.operationId, context)
          if (!resolved.ok) return { content: resolved.content }
          const { bundle, manifestSha256 } = buildShareBundle(store, resolved.opId)
          const shareDir = join(configDir, "share")
          mkdirSync(shareDir, { recursive: true })
          const path = join(shareDir, `${resolved.opId}.json`)
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
