import { Plugin, Skill } from "@opencode/plugin"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { bashScopeGuard } from "./lib/guard"
import { buildTools, type ConfirmScopeEscape } from "./lib/tools"
import { loadScope, saveScope, normalizeTarget, scopeViolations, OPSEC_ADVISORY_HOSTS } from "./lib/scope"
import { HopperStore } from "./lib/store"
import { Hopper, type HopperNotify } from "./rpc"

export { bashScopeGuard } from "./lib/guard"
export { buildTools } from "./lib/tools"

/** Repo root = one level up from this file (src/index.ts). */
const repoRoot = join(import.meta.dir, "..")

interface BundledSkill {
  id: string
  name: string
  description?: string
  path: string
  content: string
}

/**
 * Bundle the runbook skills with the plugin so they are available wherever it
 * is registered — no config `skills` entry or symlink needed. Mirrors the
 * native loader's semantics (skill-file.ts): id = directory name, name and
 * description from frontmatter, content = body with frontmatter stripped.
 */
export function loadBundledSkills(skillsDir = join(repoRoot, "src", "skills")): BundledSkill[] {
  if (!existsSync(skillsDir)) return []
  const out: BundledSkill[] = []
  for (const entry of readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const file = join(skillsDir, entry.name, "SKILL.md")
    if (!existsSync(file)) continue
    const raw = readFileSync(file, "utf8")
    const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/)
    if (!m) continue
    const front = m[1]!
    out.push({
      id: entry.name,
      name: front.match(/^name:\s*(.+)$/m)?.[1]?.trim() ?? entry.name,
      description: front.match(/^description:\s*(.+)$/m)?.[1]?.trim(),
      path: file,
      content: m[2] ?? "",
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// bundled personas — the plugin ships the 5 Hopper agents itself
// ---------------------------------------------------------------------------

export interface PermissionRule {
  action: string
  resource: string
  effect: "allow" | "ask" | "deny"
}

const EFFECTS = new Set(["allow", "ask", "deny"])

export interface BundledAgent {
  id: string
  description?: string
  mode: "primary" | "subagent" | "all"
  color?: string
  system: string
  permissions: PermissionRule[]
}

function splitFrontmatter(raw: string): { front: string[]; body: string } | null {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/)
  if (!m) return null
  return { front: m[1]!.split(/\r?\n/), body: m[2] ?? "" }
}

const unquote = (s: string) => s.replace(/^["']|["']$/g, "").trim()

/**
 * Convert the v1 `permission:` object frontmatter into ordered v2 rules.
 * v2 evaluates last-match-wins, so file order ("*" first, exceptions after)
 * is preserved. The v1 `bash` action maps to the v2 `shell` action.
 */
export function permissionRules(lines: string[]): PermissionRule[] {
  const rules: PermissionRule[] = []
  let action: string | null = null
  for (const raw of lines) {
    if (!raw.trim()) continue
    const indent = raw.length - raw.trimStart().length
    if (indent === 0) break // next top-level frontmatter key — permission block ended
    const kv = raw.trim().match(/^(.+?):\s*(.*)$/)
    if (!kv) continue
    const key = unquote(kv[1]!)
    const value = unquote(kv[2] ?? "")
    if (value === "") {
      action = key === "bash" ? "shell" : key
      continue
    }
    if (!EFFECTS.has(value)) continue // not a permission line — skip defensively
    const effect = value as PermissionRule["effect"]
    if (indent <= 2) rules.push({ action: key === "bash" ? "shell" : key, resource: "*", effect })
    else if (action) rules.push({ action, resource: key, effect })
  }
  return rules
}

/**
 * Bundle the personas with the plugin. Registered through ctx.agent.transform:
 * the editor's update() upserts (creates the agent when the id is absent),
 * which is how new agents are introduced through the plugin API.
 */
export function loadBundledAgents(agentsDir = join(repoRoot, "src", "agents")): BundledAgent[] {
  if (!existsSync(agentsDir)) return []
  const out: BundledAgent[] = []
  for (const entry of readdirSync(agentsDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".md")) continue
    const parsed = splitFrontmatter(readFileSync(join(agentsDir, entry.name), "utf8"))
    if (!parsed) continue
    const fm = (key: string) => {
      const raw = parsed.front.find((l) => l.startsWith(key + ":"))?.slice(key.length + 1).trim()
      return raw === undefined ? undefined : unquote(raw) // strip YAML quotes: color: "#hex" → #hex
    }
    const permIdx = parsed.front.findIndex((l) => /^permission:/.test(l))
    const mode = fm("mode")
    out.push({
      id: entry.name.replace(/\.md$/, ""),
      description: fm("description"),
      mode: mode === "subagent" || mode === "all" ? mode : "primary",
      color: fm("color"),
      system: parsed.body,
      permissions: permIdx === -1 ? [] : permissionRules(parsed.front.slice(permIdx + 1)),
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// bundled commands — the plugin ships the slash commands itself
// ---------------------------------------------------------------------------

export interface BundledCommand {
  name: string
  description?: string
  agent?: string
  template: string
}

export function loadBundledCommands(commandsDir = join(repoRoot, "src", "commands")): BundledCommand[] {
  if (!existsSync(commandsDir)) return []
  const out: BundledCommand[] = []
  for (const entry of readdirSync(commandsDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".md")) continue
    const parsed = splitFrontmatter(readFileSync(join(commandsDir, entry.name), "utf8"))
    if (!parsed) continue
    const fm = (key: string) =>
      parsed.front.find((l) => l.startsWith(key + ":"))?.slice(key.length + 1).trim()
    out.push({
      name: entry.name.replace(/\.md$/, ""),
      description: fm("description"),
      agent: fm("agent"),
      template: parsed.body,
    })
  }
  return out
}

interface ToolBeforeEvent {
  tool: string
  sessionID: string
  agent: string
  messageID: string
  id: string
  input: unknown
}

interface SystemBlock {
  type: string
  text: string
}

interface ContextEvent {
  system: SystemBlock[]
}

/** v2 renamed the bash tool to "shell" — guard both names. */
const SHELL_TOOLS = new Set(["shell", "bash"])

function operationContextBlock(configDir: string): string | null {
  const store = HopperStore.open(configDir)
  try {
    const op = store.getActiveOperation()
    if (!op) return null
    const findings = store.listFindings(op.id)
    const counts = new Map<string, number>()
    for (const f of findings) counts.set(f.status, (counts.get(f.status) ?? 0) + 1)
    const summary = [...counts.entries()].map(([status, n]) => `${n} ${status}`).join(", ") || "none yet"
    return [
      "## Hopper Operation Context",
      "",
      `- Active operation: ${op.name} (target: ${op.target}, started ${op.created_at})`,
      `- Findings ledger: ${summary}`,
      "- Preserve the operation target boundary and the findings lifecycle (candidate → observed → verified → reportable).",
    ].join("\n")
  } catch {
    return null
  } finally {
    store.close()
  }
}

export default Plugin.define({
  id: "hopper-kernel",
  async setup(ctx) {
    const configDir = `${ctx.location.directory}/.opencode`

    // Operator dialog API (defensive: absent in some hosts → tools fail-open).
    const permissionAssert = (ctx as { permission?: { assert?: (input: unknown) => Promise<void> } }).permission?.assert

    // 0. RPC surface: operation/findings/opsec state for the TUI part and any client.
    const rpcReg = await ctx.rpc.register(Hopper, {
      operationStatus: async () => {
        const store = HopperStore.open(configDir)
        try {
          const op = store.getActiveOperation()
          let opsec: "normal" | "strict" = "normal"
          try {
            opsec = loadScope(configDir)?.strict ? "strict" : "normal"
          } catch {
            opsec = "normal" // unreadable scope behaves like no scope — never throw
          }
          const counts: Record<string, number> = { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 }
          if (op) for (const f of store.listFindings(op.id)) counts[f.status] = (counts[f.status] ?? 0) + 1
          return {
            operation: op ? { id: op.id, name: op.name, target: op.target, createdAt: op.created_at } : null,
            opsec,
            findings: counts,
          }
        } finally {
          store.close()
        }
      },
      findings: async (input: unknown) => {
        const { operationId } = input as { operationId?: string }
        const store = HopperStore.open(configDir)
        try {
          const opId = operationId ?? store.getActiveOperation()?.id
          const items = store
            .listFindings(opId)
            .map((f) => ({ id: f.id, title: f.title, severity: f.severity, status: f.status, target: f.target, createdAt: f.created_at }))
          return { items }
        } finally {
          store.close()
        }
      },
      createOperation: async (input: unknown) => {
        const { name, target } = input as { name: string; target: string }
        const store = HopperStore.open(configDir)
        try {
          const op = store.createOperation(name, normalizeTarget(target))
          // emit failure must not fail a mutation that landed
          void rpcReg.events.emit("operation.changed", { operationId: op.id }).catch(() => {})
          return { operation: { id: op.id, name: op.name, target: op.target, createdAt: op.created_at } }
        } finally {
          store.close()
        }
      },
      setOpsec: async (input: unknown, context: { error: (type: "no_scope", message: string, data: { message: string }) => unknown; signal: AbortSignal }) => {
        const { level } = input as { level: "normal" | "strict" }
        let scope: ReturnType<typeof loadScope> = null
        try {
          scope = loadScope(configDir)
        } catch {
          scope = null // unreadable scope cannot be adjusted — typed error, never a crash
        }
        if (scope === null) {
          return context.error("no_scope", "no active scope to adjust — create an operation first (/pwn)", {
            message: "no active scope to adjust — create an operation first (/pwn)",
          })
        }
        saveScope(configDir, { ...scope, strict: level === "strict" })
        const store = HopperStore.open(configDir)
        let operationId: string | null = null
        try {
          operationId = store.getActiveOperation()?.id ?? null
        } finally {
          store.close()
        }
        // emit failure must not fail a mutation that landed
        void rpcReg.events.emit("operation.changed", { operationId }).catch(() => {})
        return { opsec: level }
      },
    })
    const notify: HopperNotify = (event) => {
      if (event.type === "operation.changed") void rpcReg.events.emit("operation.changed", { ...event.data }).catch(() => {})
      else void rpcReg.events.emit("finding.changed", { ...event.data }).catch(() => {})
    }

    // Mid-tool confirm (redirect hops): same allow/deny dialog, fed from the
    // tool's own execution context (sessionID/messageID/call id).
    const confirm: ConfirmScopeEscape | undefined =
      typeof permissionAssert === "function"
        ? (violations, reason, context) =>
            Promise.resolve(
              permissionAssert.call(ctx.permission, {
                sessionID: context?.sessionID,
                agent: context?.agent,
                source: { type: "tool", messageID: context?.messageID, id: context?.id },
                action: "scope-escape",
                resources: violations,
                save: violations,
                metadata: { reason },
              }),
            )
        : undefined

    // 1. security tools (plain names — personas/commands/skills reference them bare)
    await ctx.tool.transform((editor) => {
      for (const tool of buildTools(configDir, { confirm, notify })) editor.add(tool)
    })

    // 1b. runbook skills bundled with the plugin (travel with it everywhere)
    const bundledSkills = loadBundledSkills()
    if (bundledSkills.length > 0) {
      await ctx.skill.transform((editor) => {
        for (const s of bundledSkills) {
          editor.add({
            id: Skill.ID.make(s.id),
            name: Skill.Name.make(s.name),
            ...(s.description ? { description: s.description } : {}),
            path: Skill.Info.fields.path.make(s.path),
            content: s.content,
          })
        }
      })
    }

    // 1c. personas bundled with the plugin. editor.update() upserts — creating
    //     the agent when the id is absent — which is how the plugin API
    //     introduces new agents.
    const bundledAgents = loadBundledAgents()
    if (bundledAgents.length > 0) {
      await ctx.agent.transform((editor) => {
        for (const a of bundledAgents) {
          editor.update(a.id, (agent) => {
            agent.description = a.description
            agent.mode = a.mode
            agent.color = a.color
            agent.system = a.system
            agent.permissions = a.permissions
          })
        }
      })
    }

    // 1d. slash commands bundled with the plugin, mirroring the native
    //     file-based loader: switch to the frontmatter agent, then submit the
    //     template with $ARGUMENTS substituted.
    const bundledCommands = loadBundledCommands()
    if (bundledCommands.length > 0) {
      await ctx.command.transform((editor) => {
        for (const c of bundledCommands) {
          editor.add({
            name: c.name,
            ...(c.description ? { description: c.description } : {}),
            execute: async ({ sessionID, prompt, delivery }) => {
              if (c.agent) {
                const session = await ctx.session.get({ sessionID })
                if (session.agent !== c.agent) await ctx.session.switchAgent({ sessionID, agent: c.agent })
              }
              await ctx.session.prompt({
                ...prompt,
                sessionID,
                text: c.template.replaceAll("$ARGUMENTS", prompt.text ?? ""),
                delivery,
              })
            },
          })
        }
      })
    }

    // 2. runtime guard — dialog-always: every scope escape (shell, webfetch,
    //    http-request, scanner target/extras) raises the operator dialog and
    //    nothing else. A dialog deny is the only rejection path; with no dialog
    //    API we warn and proceed (fail-open). `strict` changes nothing here —
    //    opsec is advisory (operator decision B).
    await ctx.tool.hook("execute.before", async (event: ToolBeforeEvent) => {
      let scope: ReturnType<typeof loadScope> = null
      try {
        scope = loadScope(configDir)
      } catch {
        scope = null // unreadable scope behaves like no scope: dialogs, never blocks
      }

      const violations: string[] = []
      let inputFile = ""
      const input = (event.input ?? {}) as Record<string, unknown>

      try {
        if (SHELL_TOOLS.has(event.tool)) {
          const command = input.command
          if (typeof command === "string") {
            const guard = bashScopeGuard(scope, command)
            if (!guard.ok) violations.push(...guard.violations)
          }
        } else if (event.tool === "webfetch" || event.tool === "http-request") {
          const url = input.url
          if (typeof url === "string") {
            try {
              violations.push(...scopeViolations(scope, [new URL(url).hostname]))
            } catch {
              // malformed url — the tool itself will fail
            }
          }
        } else if (event.tool === "scanner") {
          const { mode, target } = input as { mode?: unknown; target?: unknown }
          if (typeof mode === "string" && typeof target === "string") {
            try {
              const host = mode === "portscan" && !/^[a-z]+:\/\//i.test(target) ? target : new URL(target).hostname
              violations.push(...scopeViolations(scope, [host]))
            } catch {
              // malformed target — the tool itself will fail
            }
          }
          const extra = input.extra
          if (Array.isArray(extra)) {
            for (let i = 0; i < extra.length; i++) {
              const arg = extra[i]
              if (arg === "-iL" || arg === "--input-file") {
                inputFile = `input-file list ${extra[i + 1] ?? ""}`
              } else if (typeof arg === "string" && /^https?:\/\//.test(arg)) {
                try {
                  violations.push(...scopeViolations(scope, [new URL(arg).hostname]))
                } catch {
                  // malformed extra url — ignored
                }
              }
            }
          }
        }
      } catch (err) {
        // unexpected guard errors must never crash the host
        console.error("[hopper-kernel] guard error:", err)
        return
      }

      if (violations.length === 0 && inputFile === "") return

      const parts: string[] = []
      if (violations.length > 0) {
        parts.push(
          scope === null
            ? `no active operation scope — confirm engaging ${violations.join(", ")}`
            : `target(s) ${violations.join(", ")} outside the operation scope (${scope.targets.join(", ")})`,
        )
      }
      if (inputFile !== "") parts.push(`${inputFile} cannot be scope-verified`)
      for (const host of violations) {
        if (OPSEC_ADVISORY_HOSTS.some((entry) => host === entry || host.endsWith("." + entry))) {
          parts.push(`opsec advisory: engaging ${host} may leak the target identity to a third party`)
        }
      }
      const reason = parts.join("; ")

      if (typeof permissionAssert !== "function") {
        console.warn("[hopper-kernel] scope escape without dialog api, proceeding:", reason)
        return
      }

      // Operator decision. Deny rejects with a Tool.Error the model sees; allow proceeds.
      await permissionAssert.call(ctx.permission, {
        sessionID: event.sessionID,
        agent: event.agent,
        source: { type: "tool", messageID: event.messageID, id: event.id },
        action: "scope-escape",
        resources: violations.length > 0 ? violations : [inputFile],
        save: violations.length > 0 ? violations : [inputFile],
        metadata: { reason },
      })
    })

    // 3. operation context on every agent-loop model call (system block)
    await ctx.session.hook("context", async (event: ContextEvent) => {
      try {
        const block = operationContextBlock(configDir)
        if (block) event.system.push({ type: "text", text: block })
      } catch (err) {
        console.error("[hopper-kernel] context hook error:", err)
      }
    })
  },
})
