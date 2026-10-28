import { describe, expect, test } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
import { join } from "node:path"

const agentsDir = join(import.meta.dir, "..", ".opencode", "agents")

const AGENTS = {
  security: { color: "secondary", phrases: ["Jarvis on a Kali box", "authorization"] },
  pentest: { color: "error", phrases: ["Authorized engagement only", "evidence", "PTES"] },
  appsec: { color: "primary", phrases: ["attacker-controlled input", "strict-opsec"] },
  osint: { color: "warning", phrases: ["passive-only", "Provenance"] },
  hacking: { color: "#D16BFF", phrases: ["get to the flag", "authorization"] },
} as const

function parseAgent(name: string) {
  const path = join(agentsDir, `${name}.md`)
  if (!existsSync(path)) return null
  const raw = readFileSync(path, "utf8")
  const m = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/)
  if (!m) return null
  return { frontmatter: m[1]!, body: m[2]! }
}

describe.each(Object.keys(AGENTS))("agent %s", (name) => {
  const spec = AGENTS[name as keyof typeof AGENTS]

  test("file exists with frontmatter and body", () => {
    const agent = parseAgent(name)
    expect(agent).not.toBeNull()
  })

  test("frontmatter: description, mode primary, color", () => {
    const fm = parseAgent(name)!.frontmatter
    expect(fm).toMatch(/^description:\s*.+/m)
    expect(fm).toMatch(/^mode:\s*primary\s*$/m)
    const expectedColor = spec.color.startsWith("#") ? `"${spec.color}"` : spec.color
    expect(fm).toContain(`color: ${expectedColor}`)
  })

  test("body is substantial (>= 1500 chars)", () => {
    expect(parseAgent(name)!.body.length).toBeGreaterThanOrEqual(1500)
  })

  test("persona key phrases survive adaptation (anti fidelity-drift)", () => {
    const body = parseAgent(name)!.body
    for (const phrase of spec.phrases) {
      expect(body).toContain(phrase)
    }
  })

  test("no leftover upstream branding", () => {
    const raw = readFileSync(join(agentsDir, `${name}.md`), "utf8").toLowerCase()
    expect(raw).not.toContain(["numa", "sec"].join(""))
  })
})

describe("agent permission postures", () => {
  test("pentest restricts destructive tooling by default", () => {
    const fm = parseAgent("pentest")!.frontmatter
    expect(fm).toMatch(/edit:\s*ask/)
    expect(fm).toMatch(/"\*":\s*ask/)
  })

  test("osint denies edits", () => {
    expect(parseAgent("osint")!.frontmatter).toMatch(/edit:\s*deny/)
  })

  test("appsec may write fixes", () => {
    expect(parseAgent("appsec")!.frontmatter).toMatch(/edit:\s*allow/)
  })
})
