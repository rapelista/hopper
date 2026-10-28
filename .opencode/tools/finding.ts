import { tool } from "@opencode-ai/plugin"
import { HopperStore } from "../lib/store"

export default tool({
  description:
    "The findings ledger — findings do not live in chat. action=add records a candidate (severity critical|high|medium|low|info, target, notes); action=status promotes along the lifecycle candidate → observed → verified → reportable (illegal jumps are refused; rejected/stale close a finding); action=list filters by status/operation; action=update patches title/severity/notes. Attach proof with the evidence tool before promoting. The workflow is not allowed to pretend every idea is reportable.",
  args: {
    action: tool.schema.enum(["add", "list", "update", "status"]).describe("What to do"),
    operationId: tool.schema.string().optional().describe("Operation id (defaults to active)"),
    title: tool.schema.string().optional().describe("Finding title (add/update)"),
    severity: tool.schema
      .enum(["critical", "high", "medium", "low", "info"])
      .optional()
      .describe("Severity (add/update)"),
    target: tool.schema.string().optional().describe("Affected host/URL (add)"),
    notes: tool.schema.string().optional().describe("Context, confidence, remediation pointers (add/update)"),
    findingId: tool.schema.string().optional().describe("Finding id (update/status)"),
    status: tool.schema
      .enum(["candidate", "observed", "verified", "reportable", "rejected", "stale"])
      .optional()
      .describe("Target status (status)"),
    patch: tool.schema
      .record(tool.schema.string())
      .optional()
      .describe("Alternative patch object for update: {title?, severity?, notes?}"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    const store = HopperStore.open(configDir)
    try {
      const opId =
        args.operationId ?? store.getActiveOperation()?.id ?? null

      if (args.action === "add") {
        if (!opId) return "No active operation — create one first (operation action=create or /pwn)."
        if (!args.title || !args.severity || !args.target) return "add needs title, severity, and target."
        const f = store.addFinding(opId, {
          title: args.title,
          severity: args.severity,
          target: args.target,
          notes: args.notes,
        })
        return `Finding ${f.id} recorded as candidate: [${f.severity}] ${f.title}`
      }

      if (args.action === "list") {
        const findings = store.listFindings(opId ?? undefined)
        if (findings.length === 0) return "No findings recorded."
        return findings
          .map((f) => `- [${f.status}/${f.severity}] ${f.title} (${f.target}) id=${f.id}`)
          .join("\n")
      }

      if (args.action === "status") {
        if (!args.findingId || !args.status) return "status needs findingId and status."
        try {
          const f = store.updateFindingStatus(args.findingId, args.status)
          return `Finding ${f.id} → ${f.status}`
        } catch (err) {
          return String(err instanceof Error ? err.message : err)
        }
      }

      // update
      if (!args.findingId) return "update needs findingId."
      const patch = args.patch ?? {}
      const f = store.updateFinding(args.findingId, {
        title: patch.title ?? args.title,
        severity: patch.severity ?? args.severity,
        notes: patch.notes ?? args.notes,
      })
      return `Finding ${f.id} updated.`
    } finally {
      store.close()
    }
  },
})
