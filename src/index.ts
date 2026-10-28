import { Plugin, Skill } from "@opencode/plugin"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { bashScopeGuard } from "./lib/guard"
import { buildTools } from "./lib/tools"
import { loadScope, checkUrl } from "./lib/scope"
import { HopperStore } from "./lib/store"

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

    // 1. security tools (plain names — personas/commands/skills reference them bare)
    await ctx.tool.transform((editor) => {
      for (const tool of buildTools(configDir)) editor.add(tool)
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

    // 2. runtime guard: shell commands and webfetch stay inside the operation scope.
    //    strict-opsec (scope.strict) hard-blocks; otherwise an out-of-scope target
    //    raises the native allow/deny dialog via ctx.permission.assert — the operator
    //    decides (once / always-for-this-host / deny). Throwing rejects the call.
    await ctx.tool.hook("execute.before", async (event: ToolBeforeEvent) => {
      let scope: ReturnType<typeof loadScope> = null
      let violation: { reason: string; violations: string[] } | null = null
      try {
        scope = loadScope(configDir)
        if (SHELL_TOOLS.has(event.tool)) {
          const command = (event.input as { command?: unknown } | undefined)?.command
          if (typeof command === "string") {
            const guard = bashScopeGuard(scope, command)
            if (!guard.ok) violation = { reason: guard.reason, violations: guard.violations }
          }
        }
        if (event.tool === "webfetch" && scope !== null) {
          const url = (event.input as { url?: unknown } | undefined)?.url
          if (typeof url === "string") checkUrl(scope, url)
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith("scope guard:")) throw err
        if ((err as { name?: string })?.name === "ScopeError") throw err
        // unexpected guard errors must never crash the host
        console.error("[hopper-kernel] guard error:", err)
        return
      }
      if (!violation) return

      if (scope?.strict) throw new Error(violation.reason) // strict-opsec: no dialog, no escape

      const assert = (ctx as { permission?: { assert?: (input: unknown) => Promise<void> } }).permission?.assert
      if (!assert) throw new Error(violation.reason) // no dialog API available → fail-closed

      // Operator decision. Deny rejects with a Tool.Error the model sees; allow proceeds.
      // Deliberately outside the swallowing try/catch above — a denial must block the call.
      await assert.call(
        ctx.permission,
        {
          sessionID: event.sessionID,
          agent: event.agent,
          source: { type: "tool", messageID: event.messageID, id: event.id },
          action: "scope-escape",
          resources: violation.violations,
          save: violation.violations,
          metadata: { reason: violation.reason },
        },
      )
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
