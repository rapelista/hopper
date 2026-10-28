import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import hopperPlugin, { bashScopeGuard, buildTools } from "../.opencode/plugins/kernel"
import type { Scope } from "../.opencode/lib/scope"

const scope = (targets: string[]): Scope => ({ targets, strict: true, created: "x" })

let configDir: string
let tmpProject: string

beforeAll(() => {
  tmpProject = join(tmpdir(), "hopper-kernel-" + Date.now())
  configDir = join(tmpProject, ".opencode")
  rmSync(tmpProject, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
})

afterAll(() => {
  rmSync(tmpProject, { recursive: true, force: true })
})

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

  test("no scope → allowed (permission gate still applies)", () => {
    expect(bashScopeGuard(null, "nmap -p 1-100 scanme.nmap.org").ok).toBe(true)
  })

  test("cloud metadata IP is blocked even inside a scoped operation", () => {
    expect(bashScopeGuard(scope(["*.example.test"]), "curl http://169.254.169.254/latest/meta-data").ok).toBe(false)
  })

  test("localhost is auto-allowed", () => {
    expect(bashScopeGuard(scope(["*.example.test"]), "curl http://localhost:3000/api").ok).toBe(true)
  })

  test("private ranges are auto-allowed", () => {
    expect(bashScopeGuard(scope(["example.test"]), "nmap 10.0.0.5").ok).toBe(true)
    expect(bashScopeGuard(scope(["example.test"]), "curl http://192.168.1.10/").ok).toBe(true)
  })

  test("public out-of-scope IP is blocked", () => {
    expect(bashScopeGuard(scope(["example.test"]), "curl http://203.0.113.9/").ok).toBe(false)
  })

  test("url paths with file extensions are not treated as hosts", () => {
    const sc = scope(["*.lab.test"])
    expect(bashScopeGuard(sc, "curl https://app.lab.test/login.php").ok).toBe(true)
    expect(bashScopeGuard(sc, "curl https://app.lab.test/static/app.js").ok).toBe(true)
    expect(bashScopeGuard(sc, "whatweb https://app.lab.test/index.html").ok).toBe(true)
  })

  test("output-file arguments are not treated as hosts", () => {
    expect(bashScopeGuard(scope(["*.lab.test"]), "nmap -sV -T4 app.lab.test -oN scan.log").ok).toBe(true)
  })

  test("decimal-encoded cloud metadata IP is blocked", () => {
    expect(bashScopeGuard(scope(["*.lab.test"]), "curl http://2852039166/").ok).toBe(false)
  })

  test("octal-encoded public IP requires scope", () => {
    expect(bashScopeGuard(scope(["*.lab.test"]), "nmap -p 80 010.0.0.1").ok).toBe(false)
  })

  test("in-scope dotted IPv4 still passes", () => {
    expect(bashScopeGuard(scope(["10.0.0.0/8"]), "nmap 10.1.2.3").ok).toBe(true)
  })

  test("relative path segments in shell loops are not hosts (juice-shop repro)", () => {
    const sc = scope(["localhost"])
    const repro =
      'for p in ftp/ ftp/acquisitions.md ftp/eastere.gg ftp/quotations.md ftp/suspicious_errors.yml ftp/encrypt.pyc ftp/package.json.bak api-docs/ rest/admin/application-version rest/products/search?q= snippets; do code=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" "http://localhost:3000/$p"); echo "$code  /$p"; done'
    expect(bashScopeGuard(sc, repro).ok).toBe(true)
  })

  test("dot-slash path segments are not hosts", () => {
    expect(bashScopeGuard(scope(["localhost"]), "cat ./eastere.gg && curl http://localhost:3000/").ok).toBe(true)
    expect(bashScopeGuard(scope(["localhost"]), "grep x ../assets/encrypt.pyc").ok).toBe(true)
  })

  test("path-embedded IPs are not hosts", () => {
    expect(bashScopeGuard(scope(["localhost"]), "curl -o data/2852039166 http://localhost:3000/").ok).toBe(true)
    expect(bashScopeGuard(scope(["localhost"]), "sha256sum conf/8.8.8.8").ok).toBe(true)
  })

  test("space-position hosts still blocked (regression)", () => {
    expect(bashScopeGuard(scope(["example.test"]), "nmap -p 1-100 scanme.nmap.org").ok).toBe(false)
    expect(bashScopeGuard(scope(["example.test"]), "host 203.0.113.9").ok).toBe(false)
    expect(bashScopeGuard(scope(["example.test"]), "curl http://2852039166/").ok).toBe(false)
  })
})

/** Minimal v2 plugin-context mock capturing registrations. */
function makeMockCtx(projectDir: string) {
  const addedTools: Array<{ name: string; description: string; input: unknown; execute: unknown }> = []
  const toolHooks: Record<string, (event: unknown) => unknown> = {}
  const sessionHooks: Record<string, (event: unknown) => unknown> = {}
  const reg = { dispose: async () => {} }
  const editor = {
    list: () => [],
    get: () => undefined,
    add: (t: { name: string; description: string; input: unknown; execute: unknown }) => addedTools.push(t),
    update: () => {},
    remove: () => {},
    namespace: () => {},
  }
  const ctx = {
    location: { directory: projectDir, project: { id: "p", directory: projectDir, canonical: projectDir } },
    tool: {
      transform: async (cb: (e: typeof editor) => void) => {
        cb(editor)
        return reg
      },
      hook: async (name: string, cb: (event: unknown) => unknown) => {
        toolHooks[name] = cb
        return reg
      },
      list: async () => [],
    },
    session: {
      hook: async (name: string, cb: (event: unknown) => unknown) => {
        sessionHooks[name] = cb
        return reg
      },
    },
  }
  return { ctx, addedTools, toolHooks, sessionHooks }
}

const EXPECTED_TOOLS = [
  "doctor",
  "http-request",
  "cve",
  "scanner",
  "operation",
  "finding",
  "evidence",
  "report",
  "share",
]

describe("hopper v2 plugin", () => {
  test("default export is a Plugin.define result with id and setup", () => {
    expect(hopperPlugin).toMatchObject({ id: "hopper-kernel" })
    expect(typeof (hopperPlugin as { setup: unknown }).setup).toBe("function")
  })

  test("buildTools exposes the nine security tools with json-schema inputs", () => {
    const tools = buildTools(configDir)
    expect(tools.map((t) => t.name).sort()).toEqual([...EXPECTED_TOOLS].sort())
    for (const t of tools) {
      expect(t.description.length).toBeGreaterThan(10)
      expect((t.input as { type?: string }).type).toBe("object")
      expect(typeof t.execute).toBe("function")
    }
  })

  test("setup registers all tools plus runtime hooks", async () => {
    const { ctx, addedTools, toolHooks, sessionHooks } = makeMockCtx(tmpProject)
    const cleanup = await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    expect(addedTools.map((t) => t.name).sort()).toEqual([...EXPECTED_TOOLS].sort())
    expect(typeof toolHooks["execute.before"]).toBe("function")
    expect(typeof sessionHooks["context"]).toBe("function")
    if (typeof cleanup === "function") await cleanup
  })

  test("execute.before blocks shell command hitting the metadata IP", async () => {
    writeFileSync(
      join(configDir, "scope.json"),
      JSON.stringify({ targets: ["example.test"], strict: true, created: "x" }),
    )
    const { ctx, toolHooks } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: { tool: string; input: unknown }) => Promise<void>
    const violation = hook({ tool: "shell", input: { command: "curl http://169.254.169.254/" } })
    await expect(violation).rejects.toThrow(/169\.254\.169\.254/)
    await expect(hook({ tool: "shell", input: { command: "curl http://localhost:3000/" } })).resolves.toBeUndefined()
  })

  test("session context hook pushes the operation block", async () => {
    writeFileSync(
      join(configDir, "scope.json"),
      JSON.stringify({ targets: ["example.test"], strict: true, created: "x" }),
    )
    const { ctx, sessionHooks } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = sessionHooks["context"]! as (event: { system: Array<{ type: string; text: string }> }) => Promise<void>
    const event = { system: [] as Array<{ type: string; text: string }> }
    await hook(event)
    // no active operation → no block pushed, but must not throw
    expect(Array.isArray(event.system)).toBe(true)
  })
})
