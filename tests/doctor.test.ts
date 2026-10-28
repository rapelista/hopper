import { describe, expect, test } from "bun:test"
import { TOOLS, checkTools, buildTools, type DoctorReport } from "../src/lib/tools"

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
  test("tool has description and executable content", async () => {
    const t = buildTools("/tmp").find((x) => x.name === "doctor")!
    expect(t.description.length).toBeGreaterThan(10)
    expect(typeof t.execute).toBe("function")
    const result = await t.execute({})
    expect(result.content.toLowerCase()).toContain("nmap")
    expect(result.content.toLowerCase()).toContain("brew install")
  })
})
