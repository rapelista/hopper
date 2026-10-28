import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { buildCommand, runScan, COMMON_WORDLIST, buildTools } from "../.opencode/lib/tools"
import { saveScope, ScopeError } from "../.opencode/lib/scope"

let configDir: string
let emptyDir: string
let wordlistBackup: string | null = null

beforeAll(() => {
  configDir = join(tmpdir(), "hopper-t8-scoped")
  emptyDir = join(tmpdir(), "hopper-t8-empty")
  rmSync(configDir, { recursive: true, force: true })
  rmSync(emptyDir, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
  mkdirSync(emptyDir, { recursive: true })
  saveScope(configDir, { targets: ["*.example.test", "10.0.0.0/8"], strict: true, created: "x" })
  // ensure a wordlist file exists so buildCommand can default to it
  try {
    writeFileSync(COMMON_WORDLIST, "admin\nbackup\n.git\n")
  } catch {
    wordlistBackup = "absent"
    writeFileSync(COMMON_WORDLIST, "admin\nbackup\n.git\n")
  }
})

afterAll(() => {
  rmSync(configDir, { recursive: true, force: true })
  rmSync(emptyDir, { recursive: true, force: true })
  if (wordlistBackup === "absent") rmSync(COMMON_WORDLIST, { force: true })
})

describe("buildCommand", () => {
  test("portscan wraps nmap service scan", () => {
    const cmd = buildCommand("portscan", "10.0.0.5", ["-p", "1-1000"])
    expect(cmd.bin).toBe("nmap")
    expect(cmd.argv.slice(0, 2)).toEqual(["-sV", "-T4"])
    expect(cmd.argv).toContain("10.0.0.5")
    expect(cmd.argv).toContain("-p")
  })

  test("dirfuzz wraps ffuf with wordlist", () => {
    const cmd = buildCommand("dirfuzz", "https://sub.example.test/FUZZ")
    expect(cmd.bin).toBe("ffuf")
    expect(cmd.argv).toContain("-w")
    expect(cmd.argv).toContain(COMMON_WORDLIST)
    expect(cmd.argv).toContain("-u")
    expect(cmd.argv).toContain("https://sub.example.test/FUZZ")
  })

  test("techscan wraps whatweb", () => {
    const cmd = buildCommand("techscan", "https://sub.example.test")
    expect(cmd.bin).toBe("whatweb")
    expect(cmd.argv[0]).toBe("https://sub.example.test")
  })
})

const okRun = async (cmd: { bin: string; argv: string[] }) => ({
  exitCode: 0,
  stdout: `${cmd.bin} ${cmd.argv.join(" ")}\ndone`,
})

describe("runScan scope enforcement", () => {
  test("in-scope host passes through with command echo", async () => {
    const res = await runScan(configDir, { mode: "portscan", target: "10.0.0.5" }, okRun)
    expect(res.exitCode).toBe(0)
    expect(res.command).toContain("nmap")
    expect(res.stdout).toContain("10.0.0.5")
  })

  test("out-of-scope domain throws ScopeError; IPs are not fence-checked", async () => {
    await expect(
      runScan(configDir, { mode: "portscan", target: "scanme.nmap.org" }, okRun),
    ).rejects.toBeInstanceOf(ScopeError)
    const ip = await runScan(configDir, { mode: "portscan", target: "203.0.113.9" }, okRun)
    expect(ip.command).toContain("203.0.113.9")
  })

  test("missing scope fails closed (RF#5)", () => {
    expect(runScan(emptyDir, { mode: "techscan", target: "https://sub.example.test" }, okRun)).rejects.toBeInstanceOf(
      ScopeError,
    )
  })

  test("non-zero exit is returned, not thrown", async () => {
    const failing = async () => ({ exitCode: 1, stdout: "nmap: command not found" })
    const res = await runScan(configDir, { mode: "portscan", target: "10.0.0.5" }, failing)
    expect(res.exitCode).toBe(1)
    expect(res.stdout).toContain("command not found")
  })
})

describe("extra argv scope enforcement (review fix)", () => {
  test("out-of-scope domain URL smuggled via extra is refused; IP extras pass (operator responsible)", async () => {
    await expect(
      runScan(configDir, { mode: "techscan", target: "https://sub.example.test", extra: ["http://scanme.nmap.org/"] }, okRun),
    ).rejects.toBeInstanceOf(ScopeError)
    const ip = await runScan(
      configDir,
      { mode: "portscan", target: "10.0.0.5", extra: ["http://169.254.169.254/"] },
      okRun,
    )
    expect(ip.exitCode).toBe(0)
  })

  test("input-file list flags are refused", () => {
    expect(
      runScan(configDir, { mode: "portscan", target: "10.0.0.5", extra: ["-iL", "hosts.txt"] }, okRun),
    ).rejects.toBeInstanceOf(ScopeError)
  })

  test("harmless extra flags still pass", async () => {
    const res = await runScan(configDir, { mode: "portscan", target: "10.0.0.5", extra: ["-Pn"] }, okRun)
    expect(res.exitCode).toBe(0)
  })
})

describe("tool shape", () => {
  test("tool has description and executable content", async () => {
    const t = buildTools("/tmp").find((x) => x.name === "scanner")!
    expect(t.description.length).toBeGreaterThan(10)
    expect(typeof t.execute).toBe("function")
  })
})
