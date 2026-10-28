import type { Plugin } from "@opencode-ai/plugin"
import { loadScope, isInScope, checkUrl, type Scope } from "../lib/scope"
import { HopperStore } from "../lib/store"

export type GuardResult = { ok: true } | { ok: false; reason: string }

const IPV4_RE = /(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])/g
const DOMAIN_RE = /\b((?:[a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,63})\b/gi

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".")
  if (parts.length !== 4 || parts.some((p) => Number(p) > 255)) return null
  return parts.reduce((n, p) => n * 256 + Number(p), 0)
}

/** Networks auto-allowed without a scope entry (loopback + RFC1918). Cloud metadata 169.254/16 is NOT here. */
function isAutoAllowedPrivate(host: string): boolean {
  const n = ipv4ToInt(host)
  if (n === null) return host === "localhost"
  const within = (cidr: number, bits: number) => (n >>> (32 - bits)) === (cidr >>> (32 - bits))
  return within(0x7f000000, 8) || within(0x0a000000, 8) || within(0xac100000, 12) || within(0xc0a80000, 16)
}

function extractHosts(command: string): string[] {
  const hosts = new Set<string>()
  for (const m of command.matchAll(IPV4_RE)) hosts.add(m[1]!)
  for (const m of command.matchAll(DOMAIN_RE)) {
    const token = m[1]!
    // skip files and version-like fragments; pure numbers belong to the IPv4 pass
    if (/\.(md|txt|json|pdf|tar|gz|zip)$/i.test(token)) continue
    if (/^\d/.test(token)) continue
    hosts.add(token.toLowerCase())
  }
  return [...hosts]
}

export function bashScopeGuard(scope: Scope | null, command: string): GuardResult {
  if (scope === null) return { ok: true } // permission `bash: ask` still gates every call
  const violations: string[] = []
  for (const host of extractHosts(command)) {
    if (isInScope(scope, host)) continue
    if (isAutoAllowedPrivate(host)) continue
    violations.push(host)
  }
  if (violations.length > 0) {
    return {
      ok: false,
      reason: `scope guard: refusing out-of-scope target(s) ${violations.join(", ")} — allowed: ${scope.targets.join(", ")}`,
    }
  }
  return { ok: true }
}

function configDirFor(ctx: { directory?: string; worktree?: string }): string {
  return `${ctx.worktree ?? ctx.directory}/.opencode`
}

export const HopperKernel: Plugin = async (ctx) => {
  const configDir = configDirFor(ctx)
  const client = (ctx as { client?: { app?: { log: (x: unknown) => Promise<unknown> } } }).client

  const log = async (message: string, extra: Record<string, unknown> = {}) => {
    try {
      await client?.app?.log({ body: { service: "hopper-kernel", level: "warn", message, extra } })
    } catch {
      // logging must never break the host
    }
  }

  return {
    "tool.execute.before": async (input: { tool: string }, output: { args?: Record<string, unknown> }) => {
      try {
        const scope = loadScope(configDir)
        if (input.tool === "bash" && typeof output.args?.command === "string") {
          const guard = bashScopeGuard(scope, output.args.command)
          if (!guard.ok) {
            await log("blocked bash by scope guard", { reason: guard.reason })
            throw new Error(guard.reason) // tool.execute.before failure rejects the call
          }
        }
        if (input.tool === "webfetch" && typeof output.args?.url === "string" && scope !== null) {
          checkUrl(scope, output.args.url)
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith("scope guard:")) throw err
        if ((err as { name?: string })?.name === "ScopeError") throw err
        // unexpected guard errors are logged and swallowed — never crash opencode
        await log("scope guard internal error", { error: String(err) })
      }
    },

    "experimental.session.compacting": async (_input: unknown, output: { context?: string[] }) => {
      try {
        const store = HopperStore.open(configDir)
        try {
          const op = store.getActiveOperation()
          if (!op) return
          const findings = store.listFindings(op.id)
          const counts = new Map<string, number>()
          for (const f of findings) counts.set(f.status, (counts.get(f.status) ?? 0) + 1)
          const summary = [...counts.entries()].map(([status, n]) => `${n} ${status}`).join(", ") || "none yet"
          output.context?.push(
            [
              "## Hopper Operation Context",
              "",
              `- Active operation: ${op.name} (target: ${op.target}, started ${op.created_at})`,
              `- Findings ledger: ${summary}`,
              "- Preserve the operation target boundary and the findings lifecycle when summarizing.",
            ].join("\n"),
          )
        } finally {
          store.close()
        }
      } catch (err) {
        await log("compaction context injection failed", { error: String(err) })
      }
    },
  } as unknown as Awaited<ReturnType<Plugin>>
}
