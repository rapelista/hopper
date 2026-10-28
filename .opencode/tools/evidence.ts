import { tool } from "@opencode-ai/plugin"
import { HopperStore } from "../lib/store"
import { captureEvidence } from "../lib/evidence"

export default tool({
  description:
    "Attach proof to the operation — chain of custody for everything the operator may later report. action=capture stores content (a raw request/response, command output, file excerpt, or note) with kind + SHA256 + size + optional meta, and returns the evidence id; action=attach links evidence to a finding; action=list shows evidence for the operation, optionally filtered by finding. Promote findings to verified/reportable only with evidence attached.",
  args: {
    action: tool.schema.enum(["capture", "list", "attach"]).describe("What to do"),
    kind: tool.schema
      .enum(["request", "response", "command", "file", "note"])
      .optional()
      .describe("Evidence kind (capture)"),
    content: tool.schema.string().optional().describe("The evidence payload verbatim (capture)"),
    meta: tool.schema.record(tool.schema.string()).optional().describe("Optional metadata (url, command, source)"),
    operationId: tool.schema.string().optional().describe("Operation id (defaults to active)"),
    findingId: tool.schema.string().optional().describe("Finding id (attach, or filter list)"),
    evidenceId: tool.schema.string().optional().describe("Evidence id (attach)"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    const store = HopperStore.open(configDir)
    try {
      const opId = args.operationId ?? store.getActiveOperation()?.id ?? null

      if (args.action === "capture") {
        if (!opId) return "No active operation — create one first."
        if (!args.kind || args.content === undefined) return "capture needs kind and content."
        const cap = captureEvidence(args.kind, args.content, args.meta)
        store.saveEvidence(opId, cap, args.content)
        return `Evidence ${cap.id} captured (${cap.kind}, ${cap.size} bytes, sha256 ${cap.sha256.slice(0, 16)}…)`
      }

      if (args.action === "attach") {
        if (!args.findingId || !args.evidenceId) return "attach needs findingId and evidenceId."
        store.attachEvidence(args.findingId, args.evidenceId)
        return `Evidence ${args.evidenceId} attached to finding ${args.findingId}.`
      }

      // list
      if (!opId) return "No active operation."
      const items = store.listEvidence(opId, args.findingId)
      if (items.length === 0) return "No evidence recorded."
      return items
        .map((e) => `- ${e.kind} ${e.id} (${e.size}B, sha256 ${e.sha256.slice(0, 16)}…) ${e.created_at}`)
        .join("\n")
    } finally {
      store.close()
    }
  },
})
