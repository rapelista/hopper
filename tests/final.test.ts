import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const readme = readFileSync(join(import.meta.dir, "..", "README.md"), "utf8")

describe("README", () => {
  test("introduces Hopper and its quickstart", () => {
    expect(readme).toContain("Hopper")
    expect(readme).toContain("/pwn")
    expect(readme).toContain("/runbook")
    expect(readme).toContain("/report")
    expect(readme).toContain("/share")
  })

  test("documents authorized use and safety design", () => {
    expect(readme.toLowerCase()).toContain("authorized")
    expect(readme.toLowerCase()).toContain("fail-closed")
    // SSRF guard intentionally removed — the README must say so plainly.
    expect(readme.toLowerCase()).toContain("ssrf guard was removed intentionally")
    expect(readme.toLowerCase()).toContain("operator is consciously responsible")
  })

  test("credits opencode", () => {
    expect(readme).toContain("opencode")
  })

  test("clean of upstream branding", () => {
    expect(readme.toLowerCase()).not.toContain(["numa", "sec"].join(""))
  })
})
