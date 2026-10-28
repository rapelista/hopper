import { describe, expect, test } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { join } from "node:path"

const skillsDir = join(import.meta.dir, "..", "src", "skills")

const SKILLS = {
  "passive-osint": ["zero direct traffic"],
  "forensics-kit": ["chain-of-custody", "SHA256"],
} as const

function readSkill(name: string) {
  const path = join(skillsDir, name, "SKILL.md")
  if (!existsSync(path)) return null
  return readFileSync(path, "utf8")
}

describe.each(Object.keys(SKILLS))("skill %s", (name) => {
  test("SKILL.md exists", () => {
    expect(readSkill(name)).not.toBeNull()
  })

  test("frontmatter name matches directory and slug rules", () => {
    const raw = readSkill(name)!
    const m = raw.match(/^---\n([\s\S]*?)\n---/)
    expect(m).not.toBeNull()
    const nameMatch = m![1]!.match(/^name:\s*(.+)$/m)
    expect(nameMatch).not.toBeNull()
    const skillName = nameMatch![1]!.trim()
    expect(skillName).toBe(name)
    expect(skillName).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/)
  })

  test("description present and <= 1024 chars", () => {
    const raw = readSkill(name)!
    const m = raw.match(/^---\n([\s\S]*?)\n---/)
    const descMatch = m![1]!.match(/^description:\s*([\s\S]+)$/m)
    expect(descMatch).not.toBeNull()
    expect(descMatch![1]!.length).toBeGreaterThan(10)
    expect(descMatch![1]!.length).toBeLessThanOrEqual(1024)
  })

  test("key phrases survive adaptation", () => {
    const raw = readSkill(name)!
    for (const phrase of SKILLS[name as keyof typeof SKILLS]) {
      expect(raw).toContain(phrase)
    }
  })

  test("no leftover upstream branding", () => {
    expect(readSkill(name)!.toLowerCase()).not.toContain(["numa", "sec"].join(""))
  })
})
