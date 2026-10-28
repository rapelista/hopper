import { describe, expect, test } from "bun:test"
import { bashScopeGuard, HopperKernel } from "../.opencode/plugins/kernel"
import type { Scope } from "../.opencode/lib/scope"

const scope = (targets: string[]): Scope => ({ targets, strict: true, created: "x" })

describe("bashScopeGuard", () => {
  test("in-scope host in nmap command passes", () => {
    const res = bashScopeGuard(scope(["*.nmap.org"]), "nmap -p 1-100 scanme.nmap.org")
    expect(res.ok).toBe(true)
  })

  test("out-of-scope host is blocked with the host in the reason", () => {
    const res = bashScopeGuard(scope(["example.test"]), "nmap -p 1-100 scanme.nmap.org")
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.reason).toContain("scanme.nmap.org")
  })

  test("no scope → allowed (permission bash:ask still gates)", () => {
    const res = bashScopeGuard(null, "nmap -p 1-100 scanme.nmap.org")
    expect(res.ok).toBe(true)
  })

  test("cloud metadata IP is blocked even inside a scoped operation", () => {
    const res = bashScopeGuard(scope(["*.example.test"]), "curl http://169.254.169.254/latest/meta-data")
    expect(res.ok).toBe(false)
  })

  test("localhost is auto-allowed", () => {
    const res = bashScopeGuard(scope(["*.example.test"]), "curl http://localhost:3000/api")
    expect(res.ok).toBe(true)
  })

  test("private ranges are auto-allowed", () => {
    expect(bashScopeGuard(scope(["example.test"]), "nmap 10.0.0.5").ok).toBe(true)
    expect(bashScopeGuard(scope(["example.test"]), "curl http://192.168.1.10/").ok).toBe(true)
  })

  test("public out-of-scope IP is blocked", () => {
    const res = bashScopeGuard(scope(["example.test"]), "curl http://203.0.113.9/")
    expect(res.ok).toBe(false)
  })
})

describe("HopperKernel plugin shape", () => {
  test("exports a plugin function returning both hooks", async () => {
    expect(typeof HopperKernel).toBe("function")
    const hooks = (await HopperKernel({
      client: {} as never,
      directory: import.meta.dir,
      worktree: null as unknown as string,
    } as never)) as Record<string, unknown>
    expect(typeof hooks["tool.execute.before"]).toBe("function")
    expect(typeof hooks["experimental.session.compacting"]).toBe("function")
  })

  test("bash violation in tool.execute.before throws (blocks the call)", async () => {
    const { writeFileSync, mkdirSync, rmSync } = await import("node:fs")
    const { tmpdir } = await import("node:os")
    const { join } = await import("node:path")
    const dir = join(tmpdir(), "hopper-t13-" + Date.now())
    mkdirSync(join(dir, ".opencode"), { recursive: true })
    writeFileSync(
      join(dir, ".opencode", "scope.json"),
      JSON.stringify({ targets: ["example.test"], strict: true, created: "x" }),
    )
    const hooks = (await HopperKernel({
      client: {} as never,
      directory: dir,
      worktree: dir,
    } as never)) as { "tool.execute.before": (input: unknown, output: unknown) => Promise<void> }
    const input = { tool: "bash" }
    const output = { args: { command: "curl http://169.254.169.254/" } }
    expect(hooks["tool.execute.before"](input, output)).rejects.toThrow(/169\.254\.169\.254/)
    rmSync(dir, { recursive: true, force: true })
  })
})
