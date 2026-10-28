import { tool } from "@opencode-ai/plugin"
import { mkdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { HopperStore } from "../lib/store"
import { buildShareBundle } from "../lib/share"

export default tool({
  description:
    "Export a redacted, tamper-evident bundle of the operation so it can be reviewed, resumed, or handed off: the operation record, every finding with its lifecycle state, and all evidence with secret-bearing values (authorization, cookies, api keys, tokens) redacted. Returns the bundle path and a SHA256 manifest over the canonical JSON — any later edit to the operation changes the manifest.",
  args: {
    operationId: tool.schema.string().optional().describe("Operation id (defaults to active)"),
  },
  async execute(args, context) {
    const configDir = `${context.worktree ?? context.directory}/.opencode`
    const store = HopperStore.open(configDir)
    try {
      const opId = args.operationId ?? store.getActiveOperation()?.id
      if (!opId) return "No active operation to share."
      const { bundle, manifestSha256 } = buildShareBundle(store, opId)
      const shareDir = join(configDir, "share")
      mkdirSync(shareDir, { recursive: true })
      const path = join(shareDir, `${opId}.json`)
      writeFileSync(path, JSON.stringify({ manifestSha256, bundle }, null, 2))
      return `Share bundle written: ${path}\nManifest sha256: ${manifestSha256}`
    } finally {
      store.close()
    }
  },
})
