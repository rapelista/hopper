import { describe, expect, test } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { join } from "node:path"

const root = join(import.meta.dir, "..")
const skillsDir = join(root, ".opencode", "skills")

const RUNBOOKS = {
  "appsec-web-triage": ["http-request", "finding", "evidence", "doctor"],
  "web-surface": ["passive-osint", "http-request", "dirfuzz"],
} as const

function readSkill(name: string) {
  const path = join(skillsDir, name, "SKILL.md")
  return existsSync(path) ? readFileSync(path, "utf8") : null
}

describe.each(Object.keys(RUNBOOKS))("runbook skill %s", (name) => {
  test("SKILL.md exists with valid frontmatter", () => {
    const raw = readSkill(name)!
    expect(raw).not.toBeNull()
    const m = raw.match(/^---\n([\s\S]*?)\n---/)
    expect(m).not.toBeNull()
    const nameMatch = m![1]!.match(/^name:\s*(.+)$/m)
    expect(nameMatch![1]!.trim()).toBe(name)
    expect(nameMatch![1]!.trim()).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/)
    const desc = m![1]!.match(/^description:\s*([\s\S]+)$/m)![1]!
    expect(desc.length).toBeGreaterThan(10)
    expect(desc.length).toBeLessThanOrEqual(1024)
  })

  test("runbook references the Hopper tool palette", () => {
    const raw = readSkill(name)!
    for (const ref of RUNBOOKS[name as keyof typeof RUNBOOKS]) {
      expect(raw).toContain(ref)
    }
  })

  test("clean of upstream branding", () => {
    expect(readSkill(name)!.toLowerCase()).not.toContain(["numa", "sec"].join(""))
  })
})

describe("/runbook command", () => {
  test("exists with $ARGUMENTS and agent", () => {
    const raw = readFileSync(join(root, ".opencode", "commands", "runbook.md"), "utf8")
    expect(raw).toContain("$ARGUMENTS")
    expect(raw).toMatch(/agent:\s*pentest/)
    expect(raw).toMatch(/^description:\s*.+/m)
  })
})
