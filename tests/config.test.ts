import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const root = join(import.meta.dir, "..")

/** Strip // comments and trailing commas so JSONC parses as JSON (string-aware). */
function parseJsonc(path: string): Record<string, unknown> {
  const src = readFileSync(path, "utf8")
  let stripped = ""
  let inString = false
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!
    if (inString) {
      out_append: {
        if (c === "\\") {
          stripped += c + (src[i + 1] ?? "")
          i++
          break out_append
        }
        if (c === '"') inString = false
        stripped += c
      }
      continue
    }
    if (c === '"') {
      inString = true
      stripped += c
      continue
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i++
      stripped += "\n"
      continue
    }
    stripped += c
  }
  stripped = stripped.replace(/,(\s*[}\]])/g, "$1")
  return JSON.parse(stripped) as Record<string, unknown>
}

describe("opencode preset config", () => {
  const cfg = parseJsonc(join(root, "opencode.jsonc"))
  const permission = cfg.permission as Record<string, unknown>

  test("bash defaults to ask", () => {
    const bash = permission.bash as Record<string, string>
    expect(bash["*"]).toBe("ask")
  })

  test("read-only recon git commands allowed", () => {
    const bash = permission.bash as Record<string, string>
    expect(bash["git status*"]).toBe("allow")
    expect(bash["git diff*"]).toBe("allow")
    expect(bash["git log*"]).toBe("allow")
    expect(bash["grep *"]).toBe("allow")
    expect(bash["ls *"]).toBe("allow")
  })

  test("edit, webfetch, external_directory, doom_loop require asking", () => {
    expect(permission.edit).toBe("ask")
    expect(permission.webfetch).toBe("ask")
    expect(permission.external_directory).toBe("ask")
    expect(permission.doom_loop).toBe("ask")
  })

  test("plugins key present as array", () => {
    expect(Array.isArray(cfg.plugins)).toBe(true)
  })
})
