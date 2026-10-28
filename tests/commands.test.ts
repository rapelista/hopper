import { describe, expect, test } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { join } from "node:path"

const commandsDir = join(import.meta.dir, "..", "src", "commands")

function readCommand(name: string) {
  const path = join(commandsDir, `${name}.md`)
  if (!existsSync(path)) return null
  const raw = readFileSync(path, "utf8")
  const m = raw.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/)
  if (!m) return null
  return { frontmatter: m[1]!, body: m[2]! }
}

describe("retired commands (superseded by the interactive tui commands)", () => {
  test("pwn and opsec templates are gone - reintroduction would collide with the tui slash names", () => {
    expect(readCommand("pwn")).toBeNull()
    expect(readCommand("opsec")).toBeNull()
  })
})

describe("command /doctor", () => {
  test("exists with frontmatter", () => {
    const cmd = readCommand("doctor")!
    expect(cmd).not.toBeNull()
    expect(cmd.frontmatter).toMatch(/^description:\s*.+/m)
    expect(cmd.frontmatter).toMatch(/agent:\s*security/)
  })
  test("invokes the doctor tool", () => {
    expect(readCommand("doctor")!.body).toContain("doctor")
  })
})

describe("no upstream branding in commands", () => {
  test("clean of banned strings", () => {
    for (const name of ["doctor", "remediate", "report", "runbook", "share"]) {
      expect(readCommand(name)!.body.toLowerCase()).not.toContain(["numa", "sec"].join(""))
    }
  })
})
