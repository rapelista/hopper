// Mirrors @opentui/solid's own preload rewrite (solid-plugin.js) but patches
// the files on disk, so the CLIENT solid build loads under every resolution
// path — including the CJS require("solid-js") the TUI's plugin loader uses
// (dist/server.cjs), which the host's ESM-only rewrite cannot reach.
// Without this, every signal inside a foreign plugin silently stops notifying.
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const pairs = [
  ["node_modules/solid-js/dist/server.js", "node_modules/solid-js/dist/solid.js"],
  ["node_modules/solid-js/dist/server.cjs", "node_modules/solid-js/dist/solid.cjs"],
  ["node_modules/solid-js/store/dist/server.js", "node_modules/solid-js/store/dist/store.js"],
  ["node_modules/solid-js/store/dist/server.cjs", "node_modules/solid-js/store/dist/store.cjs"],
]

for (const [server, client] of pairs) {
  const serverPath = join(root, server)
  const clientPath = join(root, client)
  if (!existsSync(clientPath)) {
    console.warn(`[patch-solid] client build missing, skipped: ${client}`)
    continue
  }
  const marker = "/* hopper-patched-client-build */"
  const current = existsSync(serverPath) ? readFileSync(serverPath, "utf8") : ""
  if (current.startsWith(marker)) continue
  copyFileSync(clientPath, serverPath)
  writeFileSync(serverPath, `${marker}\n${readFileSync(serverPath, "utf8")}`)
  console.log(`[patch-solid] ${server} ← ${client}`)
}
