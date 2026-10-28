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
export function loadBundledSkills(skillsDir = join(repoRoot, ".opencode", "skills")): BundledSkill[] {
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
