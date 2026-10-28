import { describe, expect, test } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { join } from "node:path"

const commandsDir = join(import.meta.dir, "..", ".opencode", "commands")

function readCommand(name: string) {
  const path = join(commandsDir, `${name}.md`)
  if (!existsSync(path)) return null
  const raw = readFileSync(path, "utf8")
  const m = raw.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/)
  if (!m) return null
  return { frontmatter: m[1]!, body: m[2]! }
}

describe("command /pwn", () => {
  test("exists with frontmatter", () => {
    expect(readCommand("pwn")).not.toBeNull()
  })
  test("targets the pentest agent", () => {
    expect(readCommand("pwn")!.frontmatter).toMatch(/^description:\s*.+/m)
    expect(readCommand("pwn")!.frontmatter).toMatch(/agent:\s*pentest/)
  })
  test("bootstraps scope from $ARGUMENTS", () => {
    const body = readCommand("pwn")!.body
    expect(body).toContain("$ARGUMENTS")
    expect(body).toContain("scope.json")
    expect(body.toLowerCase()).toContain("doctor")
  })
})

describe("command /opsec", () => {
  test("exists with frontmatter and agent", () => {
    const cmd = readCommand("opsec")!
    expect(cmd).not.toBeNull()
    expect(cmd.frontmatter).toMatch(/^description:\s*.+/m)
    expect(cmd.frontmatter).toMatch(/agent:\s*\w+/)
  })
  test("toggles strict posture", () => {
    expect(readCommand("opsec")!.body.toLowerCase()).toContain("strict")
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
    for (const name of ["pwn", "opsec", "doctor"]) {
      expect(readCommand(name)!.body.toLowerCase()).not.toContain(["numa", "sec"].join(""))
    }
  })
})
