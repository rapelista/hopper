import { tool } from "@opencode-ai/plugin"
import { HopperStore } from "../lib/store"

export default tool({
  description:
    "Ground truth for 'what am I working on'. Creates, lists, or reports the active operation: a named engagement against one target boundary. Creating an operation archives the previous one and writes the active scope (fail-closed for every scoped tool). action=status returns the active operation; action=list returns the operation history; action=create needs name and target.",
  args: {
    action: tool.schema.enum(["create", "status", "list"]).describe("What to do"),
    name: tool.schema.string().optional().describe("Operation name (create)"),
    target: tool.schema.string().optional().describe("Target boundary: host, CIDR, or URL (create)"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    const store = HopperStore.open(configDir)
    try {
      if (args.action === "create") {
        if (!args.name || !args.target) return "create needs both name and target."
        const op = store.createOperation(args.name, args.target)
        return `Active operation: ${op.name} (target: ${op.target})\nScope file written — every scoped tool now enforces this boundary.`
      }
      if (args.action === "status") {
        const op = store.getActiveOperation()
        return op
          ? `Active operation: ${op.name}\nTarget: ${op.target}\nStarted: ${op.created_at}`
          : "No active operation. Create one with action=create (name + target), or /pwn <target>."
      }
      const ops = store.listOperations()
      if (ops.length === 0) return "No operations recorded yet."
      return ops.map((o) => `- [${o.status}] ${o.name} → ${o.target} (${o.created_at.slice(0, 10)})`).join("\n")
    } finally {
      store.close()
    }
  },
})
