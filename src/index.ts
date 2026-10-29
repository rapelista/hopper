import { Plugin, Skill } from "@opencode/plugin"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { bashScopeGuard } from "./lib/guard"
import { buildTools, type ConfirmScopeEscape } from "./lib/tools"
import { normalizeTarget, scopeViolations, OPSEC_ADVISORY_HOSTS, type Scope } from "./lib/scope"
import { HopperStore, type SessionResolution } from "./lib/store"
import { createUnboundGate, type GuardAsk, type UnboundGate } from "./lib/unbound-gate"
import { Hopper, type GuardAnswerChoice, type HopperNotify } from "./rpc"

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
  sessionID: string
  system: SystemBlock[]
}

/** v2 renamed the bash tool to "shell" — guard both names. */
const SHELL_TOOLS = new Set(["shell", "bash"])

/**
 * Synthetic empty scope for UNBOUND shell extraction (controller amendment
 * R6): `bashScopeGuard(null, …)` extracts nothing, which let an unbound
 * session shell `nmap … evil.test` straight past the gate while a webfetch
 * to the same host triggered it. Extracting against an empty target list
 * turns every host the command references into a gate target. Bound-branch
 * extraction is unaffected.
 */
const UNBOUND_EXTRACT_SCOPE: Scope = { targets: [], strict: false, created: "" }

/** Handler-context subset used by the typed-error handlers (matches Rpc.ErrorFactory over the contract's error names). */
interface RpcErrCtx<E extends string> {
  error: (type: E, message: string, data: { message: string }) => unknown
  signal: AbortSignal
}


// ---------------------------------------------------------------------------
// unbound-session gate — one instance per setup; the guard asks through it,
// the guardAnswer RPC (Task 6) answers through it.
// ---------------------------------------------------------------------------

/** Builds the plugin's unbound gate; receives the production ask forwarder (the rpc `guard.ask` emitter). */
export type UnboundGateFactory = (emit: (ask: GuardAsk) => void) => UnboundGate

const defaultGateFactory: UnboundGateFactory = (emit) => createUnboundGate({ emit, log: console.warn })

let unboundGateFactory: UnboundGateFactory = defaultGateFactory

/**
 * Embedding/testing seam: replace how setup builds its unbound gate (e.g. a
 * small fail-open timeout or a capturing emit). Pass null to restore the
 * production gate.
 */
export function setUnboundGateFactory(factory: UnboundGateFactory | null): void {
  unboundGateFactory = factory ?? defaultGateFactory
}

/**
 * Operation context block for a session's BOUND operation (spec §5): same
 * content shape as the active-operation era, fed from the resolved operation
 * and its scope/store rows. Free/unbound sessions (and any store error) push
 * nothing.
 */
function operationContextBlock(configDir: string, sessionID: string): string | null {
  const store = HopperStore.open(configDir)
  try {
    const resolution = store.resolveSession(sessionID)
    if (resolution.mode !== "bound") return null
    const findings = store.listFindings(resolution.operation.id)
    const counts = new Map<string, number>()
    for (const f of findings) counts.set(f.status, (counts.get(f.status) ?? 0) + 1)
    const summary = [...counts.entries()].map(([status, n]) => `${n} ${status}`).join(", ") || "none yet"
    return [
      "## Hopper Operation Context",
      "",
      `- Active operation: ${resolution.operation.name} (target: ${resolution.operation.target}, started ${resolution.operation.created_at})`,
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

    // Unbound-session gate (spec §4): ONE instance for the plugin lifetime —
    // the guard asks through it and the guardAnswer RPC (Task 6) answers
    // through it. The ask forwarder is late-bound: rpcReg exists only after
    // registration below, and no ask can happen before the hooks exist.
    let forwardAsk: (ask: GuardAsk) => void = () => {}
    const gate = unboundGateFactory((ask) => forwardAsk(ask))

    // 0. RPC surface: per-session bindings + the operation ledger for the
    //    TUI part and any client (spec §6). Mutations land first; events
    //    fire-and-forget — an emit failure must never fail a landed mutation.
    const rpcReg = await ctx.rpc.register(Hopper, {
      // Deprecated compatibility shape: with a sessionID, the session's BOUND
      // operation + its opsec + its counts; free/unbound/missing sessionID
      // reads as no-operation.
      operationStatus: async (input: unknown) => {
        const { sessionID } = input as { sessionID?: string }
        const counts = { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 }
        const store = HopperStore.open(configDir)
        try {
          const resolution = sessionID === undefined ? null : store.resolveSession(sessionID)
          if (resolution === null || resolution.mode !== "bound") {
            return { operation: null, opsec: "normal", findings: counts }
          }
          for (const f of store.listFindings(resolution.operation.id)) counts[f.status] = (counts[f.status] ?? 0) + 1
          return {
            operation: {
              id: resolution.operation.id,
              name: resolution.operation.name,
              target: resolution.operation.target,
              createdAt: resolution.operation.created_at,
            },
            opsec: resolution.scope.strict ? "strict" : "normal",
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
        const { name, target, sessionID } = input as { name: string; target: string; sessionID?: string }
        const store = HopperStore.open(configDir)
        try {
          const op = store.createOperation(name, normalizeTarget(target))
          if (sessionID !== undefined) store.upsertBinding(sessionID, op.id)
          // emit failure must not fail a mutation that landed
          void rpcReg.events.emit("operation.changed", { operationId: op.id }).catch(() => {})
          if (sessionID !== undefined) void rpcReg.events.emit("binding.changed", { sessionID }).catch(() => {})
          return { operation: { id: op.id, name: op.name, target: op.target, createdAt: op.created_at } }
        } finally {
          store.close()
        }
      },
      setOpsec: async (input: unknown, context: RpcErrCtx<"no_operation">) => {
        const { operationId, level } = input as { operationId?: string; level: "normal" | "strict" }
        if (operationId === undefined) {
          // controller ruling: no implicit active-op pick — an opsec level is
          // always written to a named operation
          return context.error("no_operation", "setOpsec requires an operationId", {
            message: "setOpsec requires an operationId",
          })
        }
        const store = HopperStore.open(configDir)
        let written = false
        try {
          written = store.setScopeStrict(operationId, level === "strict")
        } finally {
          store.close()
        }
        if (!written) {
          return context.error("no_operation", `unknown operation ${operationId}`, {
            message: `unknown operation ${operationId}`,
          })
        }
        // emit failure must not fail a mutation that landed
        void rpcReg.events.emit("operation.changed", { operationId }).catch(() => {})
        return { opsec: level }
      },
      operationsList: async () => {
        const store = HopperStore.open(configDir)
        try {
          const items = store.listOperationsWithCounts().map((op) => ({
            id: op.id,
            name: op.name,
            target: op.target,
            createdAt: op.created_at,
            status: op.status,
            findings: op.findings,
          }))
          return { items }
        } finally {
          store.close()
        }
      },
      bind: async (input: unknown, context: RpcErrCtx<"no_operation" | "not_active">) => {
        const { sessionID, operationId } = input as { sessionID: string; operationId: string }
        const store = HopperStore.open(configDir)
        try {
          const op = store.listOperations().find((o) => o.id === operationId)
          if (!op) {
            return context.error("no_operation", `unknown operation ${operationId}`, {
              message: `unknown operation ${operationId}`,
            })
          }
          if (op.status !== "active") {
            // terminal operations are read-only history — they can never be re-entered
            return context.error("not_active", `operation ${operationId} is ${op.status}, not active`, {
              message: `operation ${operationId} is ${op.status}, not active`,
            })
          }
          store.upsertBinding(sessionID, operationId)
        } finally {
          store.close()
        }
        // emit failure must not fail a mutation that landed
        void rpcReg.events.emit("binding.changed", { sessionID }).catch(() => {})
        return { operationId }
      },
      unbind: async (input: unknown) => {
        const { sessionID } = input as { sessionID: string }
        const store = HopperStore.open(configDir)
        try {
          store.clearBinding(sessionID)
        } finally {
          store.close()
        }
        // emit failure must not fail a mutation that landed
        void rpcReg.events.emit("binding.changed", { sessionID }).catch(() => {})
        return { operationId: null }
      },
      setOperationStatus: async (input: unknown, context: RpcErrCtx<"no_operation">) => {
        const { operationId, status } = input as { operationId: string; status: "completed" | "archived" }
        const store = HopperStore.open(configDir)
        let affected: string[] = []
        let updated = false
        try {
          // capture BEFORE the call: the store flips the status and unbinds these sessions in one transaction
          affected = store.listBoundSessions(operationId)
          updated = store.setOperationStatus(operationId, status) !== null
        } finally {
          store.close()
        }
        if (!updated) {
          return context.error("no_operation", `unknown operation ${operationId}`, {
            message: `unknown operation ${operationId}`,
          })
        }
        for (const sid of affected) void rpcReg.events.emit("binding.changed", { sessionID: sid }).catch(() => {})
        return { status }
      },
      deleteOperation: async (input: unknown, context: RpcErrCtx<"no_operation">) => {
        const { operationId } = input as { operationId: string }
        const store = HopperStore.open(configDir)
        let affected: string[] = []
        let deleted = false
        try {
          // same fan-out as setOperationStatus: deletion unbinds these sessions
          affected = store.listBoundSessions(operationId)
          deleted = store.deleteOperation(operationId)
        } finally {
          store.close()
        }
        if (!deleted) {
          return context.error("no_operation", `unknown operation ${operationId}`, {
            message: `unknown operation ${operationId}`,
          })
        }
        for (const sid of affected) void rpcReg.events.emit("binding.changed", { sessionID: sid }).catch(() => {})
        return { ok: true }
      },
      guardAnswer: async (input: unknown) => {
        const { askId, choice, operationId } = input as { askId: string; choice: GuardAnswerChoice; operationId?: string }
        if (choice === "bind" && operationId === undefined) {
          // controller ruling: never write a NULL-op bound row. The contract
          // exposes no error shape on guardAnswer, so the type-safe refusal
          // is { accepted: false } — the ask stays pending for a well-formed answer.
          return { accepted: false }
        }
        return { accepted: gate.answer(askId, choice, operationId) }
      },
    })
    // The gate's asks ride the rpc event bus to the operator (TUI); a missing
    // listener simply times out fail-open inside the gate.
    forwardAsk = (ask) => {
      void rpcReg.events.emit("guard.ask", { ...ask }).catch(() => {})
    }
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

    // 2. runtime guard — per-session binding resolution (spec §3): bound ⇒
    //    dialog-always fence against the bound operation's store scope (a
    //    dialog deny is the only rejection; no dialog API ⇒ warn and proceed);
    //    free ⇒ no fence at all; unbound ⇒ rich guard.ask dialog through the
    //    gate (fail-open timeout), never a silent weapon pass. `strict`
    //    changes nothing here — opsec is advisory (operator decision B).
    await ctx.tool.hook("execute.before", async (event: ToolBeforeEvent) => {
      let resolution: SessionResolution = { mode: "unbound" }
      try {
        const store = HopperStore.open(configDir)
        try {
          resolution = store.resolveSession(event.sessionID)
        } finally {
          store.close()
        }
      } catch {
        resolution = { mode: "unbound" } // unreadable store behaves like unbound: dialogs, never blocks
      }
      if (resolution.mode === "free") return

      // The bound operation's scope row is the fence; unbound sessions fence
      // against nothing (every extracted target is a violation ⇒ dialog).
      const scope: Scope | null =
        resolution.mode === "bound"
          ? {
              targets: resolution.scope.targets,
              strict: resolution.scope.strict,
              created: resolution.operation.created_at,
            }
          : null

      const violations: string[] = []
      let inputFile = ""
      const input = (event.input ?? {}) as Record<string, unknown>

      try {
        if (SHELL_TOOLS.has(event.tool)) {
          const command = input.command
          if (typeof command === "string") {
            // R6: unbound sessions extract against a synthetic EMPTY scope so
            // shell commands reach the gate (`bashScopeGuard(null, …)`
            // extracts nothing, which silently bypassed it); bound-branch
            // extraction stays verbatim.
            const guard = bashScopeGuard(resolution.mode === "unbound" ? UNBOUND_EXTRACT_SCOPE : scope, command)
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

      if (resolution.mode === "unbound") {
        // Rich unbound dialog (spec §4): rpc-correlated ask with a fail-open
        // timeout. Deny is the only refusal; every other choice proceeds.
        const answer = await gate.decide({
          askId: "",
          sessionID: event.sessionID,
          messageID: event.messageID,
          tool: event.tool,
          targets: violations.length > 0 ? violations : [inputFile],
          reason,
        })
        if (answer.choice === "deny") throw new Error("[hopper] operator denied: " + reason)
        if (answer.choice === "free") {
          try {
            const store = HopperStore.open(configDir)
            try {
              store.setFree(event.sessionID)
            } finally {
              store.close()
            }
          } catch (err) {
            // the operator allowed the call — a failed free-write must not block it
            console.warn("[hopper-kernel] could not persist free mode, proceeding:", err)
          }
          return
        }
        if (answer.choice === "bind") {
          if (answer.operationId === undefined) {
            // bind without an operation to bind to is a client bug — proceed
            // unbound rather than writing a corrupt binding row
            console.warn("[hopper-kernel] bind answer without operationId, proceeding unbound")
            return
          }
          try {
            const store = HopperStore.open(configDir)
            try {
              store.upsertBinding(event.sessionID, answer.operationId)
            } finally {
              store.close()
            }
          } catch (err) {
            // the operator eyeballed the target and allowed it — a failed
            // binding write must not block the already-approved call
            console.warn("[hopper-kernel] could not persist binding, proceeding:", err)
          }
          return // the triggering call proceeds; the fence applies from the next one
        }
        return // allow-once: proceed, write nothing
      }

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

    // 3. operation context on every agent-loop model call (system block) —
    //    per session: only a bound operation gets a block (spec §5).
    await ctx.session.hook("context", async (event: ContextEvent) => {
      try {
        const block = operationContextBlock(configDir, event.sessionID)
        if (block) event.system.push({ type: "text", text: block })
      } catch (err) {
        console.error("[hopper-kernel] context hook error:", err)
      }
    })
  },
})
