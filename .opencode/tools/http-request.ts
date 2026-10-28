import { tool } from "@opencode-ai/plugin"
import { checkUrl, loadScope } from "../lib/scope"

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

const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"])
const MAX_HOPS = 5
const MAX_BODY_CHARS = 64 * 1024

function sha256Hex(data: string | Uint8Array): string {
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
  fetchImpl: typeof fetch = fetch,
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

export default tool({
  description:
    "Precision instrument for manual web testing: injections, auth bypass, IDOR, SSRF probes. Performs one HTTP request with exact method/headers/body and returns status, headers, body, a SHA256 over the raw bytes (evidence-grade), and the redirect hops followed. Every hop is re-checked against the active operation scope — out-of-scope redirects (including cloud metadata IPs) are refused, and with no active scope the tool fails closed. Sensitive request headers are redacted in the echo.",
  args: {
    url: tool.schema.string().describe("Absolute http(s) URL to request (checked against scope)"),
    method: tool.schema.string().optional().describe("HTTP method (default GET)"),
    headers: tool.schema.record(tool.schema.string()).optional().describe("Request headers"),
    body: tool.schema.string().optional().describe("Request body"),
    timeoutMs: tool.schema.number().optional().describe("Timeout in ms (default 30000)"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    const result = await request(configDir, {
      url: args.url,
      method: args.method,
      headers: args.headers,
      body: args.body,
      timeoutMs: args.timeoutMs,
    })
    return JSON.stringify(result, null, 2)
  },
})
