import { tool } from "@opencode-ai/plugin"
import { writeReport } from "../lib/report"

export default tool({
  description:
    "Produce the signed deliverable for the engagement: a markdown report generated from operation state — never fabricated in chat. Includes the operation summary, findings table ordered by severity, reportable findings with their attached evidence (ids + sha256 prefixes), and a timestamp. Writes to reports/ and returns the path.",
  args: {
    operationId: tool.schema.string().optional().describe("Operation id (defaults to active)"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    try {
      const path = writeReport(configDir, args.operationId)
      return `Report written: ${path}`
    } catch (err) {
      return String(err instanceof Error ? err.message : err)
    }
  },
})
