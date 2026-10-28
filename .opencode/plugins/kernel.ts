import { Plugin } from "@opencode/plugin"
import { bashScopeGuard } from "../lib/guard"
import { buildTools } from "../lib/tools"
import { loadScope, checkUrl } from "../lib/scope"
import { HopperStore } from "../lib/store"

export { bashScopeGuard } from "../lib/guard"
export { buildTools } from "../lib/tools"

interface ToolBeforeEvent {
  tool: string
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

    // 2. runtime guard: shell commands and webfetch stay inside the operation scope.
    //    Throwing from execute.before rejects the call before it runs.
    await ctx.tool.hook("execute.before", async (event: ToolBeforeEvent) => {
      try {
        const scope = loadScope(configDir)
        if (SHELL_TOOLS.has(event.tool)) {
          const command = (event.input as { command?: unknown } | undefined)?.command
          if (typeof command === "string") {
            const guard = bashScopeGuard(scope, command)
            if (!guard.ok) throw new Error(guard.reason)
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
      }
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
