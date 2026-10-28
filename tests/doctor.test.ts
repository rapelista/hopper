import { describe, expect, test } from "bun:test"
import doctor, { TOOLS, checkTools, type DoctorReport } from "../.opencode/tools/doctor"

describe("checkTools", () => {
  test("partitions available and missing binaries", () => {
    const stub = (cmd: string) => (cmd === "nmap" || cmd === "nuclei" ? "/opt/bin/" + cmd : null)
    const report: DoctorReport = checkTools(["nmap", "nuclei", "ffuf"], stub)
    expect(report.available.sort()).toEqual(["nmap", "nuclei"])
    expect(report.missing).toEqual(["ffuf"])
  })

  test("tracks the security toolbelt we care about", () => {
    expect(TOOLS).toContain("nmap")
    expect(TOOLS).toContain("nuclei")
    expect(TOOLS).toContain("ffuf")
    expect(TOOLS.length).toBeGreaterThanOrEqual(6)
  })
})

describe("tool shape", () => {
  test("default export is a tool with description and execute", async () => {
    expect(typeof doctor).toBe("object")
    const t = doctor as unknown as { description: string; execute: (args: unknown) => Promise<string> }
    expect(t.description.length).toBeGreaterThan(10)
    const result = await t.execute({})
    expect(result.toLowerCase()).toContain("nmap")
    expect(result.toLowerCase()).toContain("brew install")
  })
})
