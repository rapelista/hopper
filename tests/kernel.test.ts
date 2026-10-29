import { describe, expect, test, beforeAll, afterAll, beforeEach, afterEach } from "bun:test"
import { mkdirSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import hopperPlugin, { bashScopeGuard, buildTools, setUnboundGateFactory } from "../src/index"
import { request } from "../src/lib/tools"
import type { Scope } from "../src/lib/scope"
import { HopperStore } from "../src/lib/store"
import { createUnboundGate, type GuardAsk, type UnboundGate } from "../src/lib/unbound-gate"
import { makeMockCtx } from "./helpers"

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

  test("metadata IP is auto-allowed like other private ranges (SSRF guard removed)", () => {
    expect(bashScopeGuard(scope(["*.example.test"]), "curl http://169.254.169.254/latest/meta-data").ok).toBe(true)
  })

  test("encoded integers are no longer decoded as IPs (SSRF guard removed)", () => {
    expect(bashScopeGuard(scope(["*.lab.test"]), "curl http://2852039166/").ok).toBe(true)
    expect(bashScopeGuard(scope(["*.lab.test"]), "nmap -p 80 010.0.0.1").ok).toBe(true)
  })

  test("localhost is auto-allowed", () => {
    expect(bashScopeGuard(scope(["*.example.test"]), "curl http://localhost:3000/api").ok).toBe(true)
  })

  test("private ranges are auto-allowed", () => {
    expect(bashScopeGuard(scope(["example.test"]), "nmap 10.0.0.5").ok).toBe(true)
    expect(bashScopeGuard(scope(["example.test"]), "curl http://192.168.1.10/").ok).toBe(true)
  })

  test("public IPs are not fence-checked (operator is responsible)", () => {
    expect(bashScopeGuard(scope(["example.test"]), "curl http://203.0.113.9/").ok).toBe(true)
    expect(bashScopeGuard(scope(["example.test"]), "nmap 8.8.8.8").ok).toBe(true)
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

  test("in-scope dotted IPv4 still passes", () => {
    expect(bashScopeGuard(scope(["10.0.0.0/8"]), "nmap 10.1.2.3").ok).toBe(true)
  })

  test("code tokens with method calls are not hosts (python -c repro)", () => {
    const sc = scope(["localhost"])
    const repro =
      'python3 -c "\nimport json;d=json.load(open(\'/tmp/js-mnt/challenges.json\'));c=d.get(\'data\',d)\nprint(\'total:\',len(c))\nfor x in sorted(c,key=lambda z:z[\'difficulty\']):\n    print(x[\'difficulty\'], \'|\', x[\'name\'], \'| solved:\', x.get(\'solved\'), \'| flag\' if x.get(\'cfFlag\') or (\'ctf\' in str(x).lower()) else \'\')" 2>&1 | head -70'
    expect(bashScopeGuard(sc, repro).ok).toBe(true)
  })

  test("dotted tokens immediately followed by an open paren are skipped", () => {
    expect(bashScopeGuard(scope(["localhost"]), 'python3 -c "import os; print(os.path.join(\'/a\',\'b\'))"').ok).toBe(true)
    expect(bashScopeGuard(scope(["localhost"]), 'python3 -c "import json;print(json.dumps({}))"').ok).toBe(true)
  })

  test("hosts not followed by open paren are still blocked (regression)", () => {
    expect(bashScopeGuard(scope(["example.test"]), "nmap scanme.nmap.org").ok).toBe(false)
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

  test("space-position domains still blocked (regression); IPs unchecked", () => {
    expect(bashScopeGuard(scope(["example.test"]), "nmap -p 1-100 scanme.nmap.org").ok).toBe(false)
    // IPs and encoded integers are never fence-checked (SSRF guard removed intentionally)
    expect(bashScopeGuard(scope(["example.test"]), "host 203.0.113.9").ok).toBe(true)
    expect(bashScopeGuard(scope(["example.test"]), "curl http://2852039166/").ok).toBe(true)
  })
})

const EVENT_BASE = {
  sessionID: "ses_test",
  agent: "pentest",
  messageID: "msg_test",
  id: "call_test",
}

function writeScopeFixure(strict: boolean) {
  writeFileSync(
    join(configDir, "scope.json"),
    JSON.stringify({ targets: ["example.test"], strict, created: "x" }),
  )
}

/** Create an operation (target normalized, strict scope row) and bind sessionID to it. */
function bindSession(sessionID: string, target = "example.test"): { id: string; name: string; target: string } {
  const store = HopperStore.open(configDir)
  try {
    const op = store.createOperation("op-" + sessionID, target)
    store.upsertBinding(sessionID, op.id)
    return { id: op.id, name: op.name, target: op.target }
  } finally {
    store.close()
  }
}

/**
 * Gate injection: replace setup's gate with one the test controls — capturing
 * emits (and forwarding them through the production rpc `guard.ask` emitter),
 * optionally auto-answering, with a test timeout and captured timeout logs.
 */
function injectGate(opts: { timeoutMs?: number; answer?: (ask: GuardAsk, gate: UnboundGate) => void } = {}) {
  const emitted: GuardAsk[] = []
  const logs: string[] = []
  let created: UnboundGate | undefined
  setUnboundGateFactory((forwardAsk) => {
    created = createUnboundGate({
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      emit: (ask) => {
        emitted.push(ask)
        forwardAsk(ask)
        opts.answer?.(ask, created!)
      },
      log: (...args: unknown[]) => {
        logs.push(args.map(String).join(" "))
      },
    })
    return created
  })
  return { emitted, logs, gate: () => created! }
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

  test("setup bundles the runbook skills with the plugin", async () => {
    const { ctx, addedSkills } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    expect(addedSkills.map((s) => s.id).sort()).toEqual(
      ["appsec-web-triage", "forensics-kit", "passive-osint", "web-surface"].sort(),
    )
    for (const s of addedSkills) {
      expect(s.path).toMatch(/src\/skills\/[^/]+\/SKILL\.md$/)
      expect(s.content.length).toBeGreaterThan(100)
      expect(s.content.startsWith("---")).toBe(false) // content is the body, frontmatter stripped
      expect(s.description?.length).toBeGreaterThan(10)
      expect(s.name.length).toBeGreaterThan(2)
    }
    const osint = addedSkills.find((s) => s.id === "passive-osint")!
    expect(osint.content).toContain("# Passive OSINT kit")
    expect(osint.name).toBe("passive-osint")
  })

  test("setup bundles the five personas via agent-transform upsert", async () => {
    const { ctx, agentUpdates } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    expect(agentUpdates.map((u) => u.id).sort()).toEqual(["appsec", "hacking", "osint", "pentest", "security"])

    const apply = (id: string) => {
      const rec = agentUpdates.find((u) => u.id === id)!
      const agent: Record<string, unknown> = {}
      rec.fn(agent)
      return agent
    }

    const pentest = apply("pentest") as {
      mode: string
      system: string
      permissions: Array<{ action: string; resource: string; effect: string }>
    }
    expect(pentest.mode).toBe("primary")
    expect(pentest.system.length).toBeGreaterThan(100)
    const shellRules = pentest.permissions.filter((r) => r.action === "shell")
    expect(shellRules[0]).toMatchObject({ resource: "*", effect: "ask" })
    expect(shellRules).toContainEqual({ action: "shell", resource: "nmap *", effect: "allow" })
    expect(pentest.permissions).toContainEqual({ action: "edit", resource: "*", effect: "ask" })

    const osint = apply("osint") as { permissions: Array<{ action: string; resource: string; effect: string }> }
    expect(osint.permissions).toContainEqual({ action: "edit", resource: "*", effect: "deny" })

    const hacking = apply("hacking") as { permissions: Array<{ action: string; resource: string; effect: string }> }
    expect(hacking.permissions).toContainEqual({ action: "shell", resource: "*", effect: "allow" })

    const security = apply("security") as { permissions: unknown[] }
    expect(security.permissions).toEqual([]) // default posture, no overrides

    // Colors must be bare hex — YAML quotes must be stripped (RGBA.fromHex fails otherwise)
    for (const rec of agentUpdates) {
      const agent = apply(rec.id) as { color?: string }
      expect(agent.color).toMatch(/^#[0-9a-fA-F]{6}$/)
    }
  })

  test("setup bundles the slash commands with agent switch and $ARGUMENTS", async () => {
    const { ctx, addedCommands, agentSwitches, prompts } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    expect(addedCommands.map((c) => c.name).sort()).toEqual(
      ["doctor", "remediate", "report", "runbook", "share"].sort(), // pwn/opsec retired → interactive tui commands
    )

    const runbook = addedCommands.find((c) => c.name === "runbook")!
    expect(runbook.description?.length).toBeGreaterThan(5)
    await runbook.execute({ sessionID: "s1", prompt: { text: "appsec-web-triage" }, delivery: "steer" })

    expect(agentSwitches).toEqual([{ sessionID: "s1", agent: "pentest" }])
    const p = prompts[0] as { text: string; sessionID: string }
    expect(p.sessionID).toBe("s1")
    expect(p.text).toContain("appsec-web-triage")
    expect(p.text).not.toContain("$ARGUMENTS")
  })

  test("bound session: out-of-scope shell resolves through the dialog instead of blocking", async () => {
    bindSession(EVENT_BASE.sessionID)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(hook({ ...EVENT_BASE, tool: "shell", input: { command: "curl http://scanme.nmap.org/" } })).resolves.toBeUndefined()
    expect(asserts.length).toBe(1)
    await expect(hook({ ...EVENT_BASE, tool: "shell", input: { command: "curl http://localhost:3000/" } })).resolves.toBeUndefined()
    expect(asserts.length).toBe(1) // in-scope/loopback: silent pass
  })

  test("guard result carries the violation list for the dialog", () => {
    const res = bashScopeGuard(scope(["example.test"]), "nmap scanme.nmap.org")
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.violations).toContain("scanme.nmap.org")
  })

  test("bound session: violation triggers the allow/deny dialog and proceeds on allow", async () => {
    bindSession(EVENT_BASE.sessionID)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, {
      assert: async (input: unknown) => {
        asserts.push(input)
      },
    })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, tool: "shell", input: { command: "curl http://scanme.nmap.org/whyami" } }),
    ).resolves.toBeUndefined()
    expect(asserts.length).toBe(1)
    const a = asserts[0] as Record<string, unknown>
    expect(a.action).toBe("scope-escape")
    expect(a.resources).toEqual(["scanme.nmap.org"])
    expect(a.save).toEqual(["scanme.nmap.org"])
    expect(a.metadata).toMatchObject({ reason: expect.stringContaining("outside the operation scope") })
  })

  test("bound session: dialog denial rejects the call", async () => {
    bindSession(EVENT_BASE.sessionID)
    const { ctx, toolHooks } = makeMockCtx(tmpProject, {
      assert: async () => {
        throw new Error("denied by operator")
      },
    })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, tool: "shell", input: { command: "curl http://scanme.nmap.org/" } }),
    ).rejects.toThrow(/denied by operator/)
  })

  test("bound session (store scope rows are strict): operator denial still rejects (the deny is the only block left)", async () => {
    bindSession(EVENT_BASE.sessionID)
    const { ctx, toolHooks } = makeMockCtx(tmpProject, {
      assert: async () => {
        throw new Error("denied by operator")
      },
    })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(hook({ ...EVENT_BASE, tool: "shell", input: { command: "nmap scanme.nmap.org" } })).rejects.toThrow(
      /denied by operator/,
    )
  })

  test("bound session without dialog api: warn and proceed (fail-open)", async () => {
    bindSession(EVENT_BASE.sessionID)
    const warnings: string[] = []
    const origWarn = console.warn
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(" "))
    }
    try {
      const { ctx, toolHooks } = makeMockCtx(tmpProject)
      await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
      const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
      await expect(hook({ ...EVENT_BASE, tool: "shell", input: { command: "nmap scanme.nmap.org" } })).resolves.toBeUndefined()
    } finally {
      console.warn = origWarn
    }
    expect(warnings.join(" ")).toContain("scanme.nmap.org")
  })

  test("bound session: out-of-scope webfetch raises the same dialog", async () => {
    bindSession(EVENT_BASE.sessionID)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://evil.test/x" } })
    expect(asserts.length).toBe(1)
    expect((asserts[0] as { metadata: { reason: string } }).metadata.reason).toContain("outside the operation scope")
  })

  test("bound session: http-request url and scanner target/extras route through the same dialog", async () => {
    bindSession(EVENT_BASE.sessionID)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "http-request", input: { url: "https://evil.test/" } })
    await hook({ ...EVENT_BASE, tool: "scanner", input: { mode: "portscan", target: "evil.test" } })
    await hook({ ...EVENT_BASE, tool: "scanner", input: { mode: "portscan", target: "10.0.0.5", extra: ["-iL", "hosts.txt"] } })
    expect(asserts.length).toBe(3)
    expect((asserts[2] as { metadata: { reason: string } }).metadata.reason).toContain("input-file")
  })

  test("malformed url is skipped by the hook (RF#2)", async () => {
    writeScopeFixure(false)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "not a url" } })).resolves.toBeUndefined()
    expect(asserts.length).toBe(0)
  })

  test("leak-advisory host enriches the bound-dialog reason (opsec stays advisory, never blocks)", async () => {
    bindSession(EVENT_BASE.sessionID)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://api.shodan.io/" } })
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://crt.sh/?q=x" } })
    expect(asserts.length).toBe(2) // advisory hosts still dialog - never block
    expect((asserts[0] as { metadata: { reason: string } }).metadata.reason).toContain("opsec advisory")
    expect((asserts[1] as { metadata: { reason: string } }).metadata.reason).toContain("leak the target identity")
  })

  test("bound dialog input carries resources and save for always-allow (RF#5)", async () => {
    bindSession(EVENT_BASE.sessionID)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "shell", input: { command: "curl http://scanme.nmap.org/" } })
    const a = asserts[0] as Record<string, unknown>
    expect(a.resources).toEqual(["scanme.nmap.org"])
    expect(a.save).toEqual(["scanme.nmap.org"])
  })

  test("http-request tool raises the mid-flight redirect dialog through its wired confirm", async () => {
    writeScopeFixure(false)
    const asserts: unknown[] = []
    const { ctx, addedTools } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const tool = addedTools.find((t) => t.name === "http-request")! as {
      execute: (input: unknown, context: unknown) => Promise<{ content: string }>
    }
    let n = 0
    const origFetch = globalThis.fetch
    globalThis.fetch = (async () => {
      n++
      return n === 1
        ? new Response(null, { status: 302, headers: { location: "http://scanme.nmap.org/x" } })
        : new Response("ok")
    }) as unknown as typeof fetch
    try {
      const res = await tool.execute({ url: "https://example.test/" }, { sessionID: "s1", agent: "pentest", messageID: "m1", id: "c1" })
      expect(res.content).toContain("ok")
    } finally {
      globalThis.fetch = origFetch
    }
    expect(asserts.length).toBe(1)
    const a = asserts[0] as Record<string, unknown>
    expect(a.sessionID).toBe("s1")
    expect(a.resources).toEqual(["scanme.nmap.org"])
  })

  test("http-request redirect confirm (wired): bound session fences against the op's store scope row", async () => {
    bindSession("ses_redir_bound") // operation target: example.test
    const asserts: unknown[] = []
    const { ctx, addedTools } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const tool = addedTools.find((t) => t.name === "http-request")! as {
      execute: (input: unknown, context: unknown) => Promise<{ content: string }>
    }
    let n = 0
    const origFetch = globalThis.fetch
    globalThis.fetch = (async () => {
      n++
      return n === 1
        ? new Response(null, { status: 302, headers: { location: "http://scanme.nmap.org/x" } })
        : new Response("ok")
    }) as unknown as typeof fetch
    try {
      const res = await tool.execute(
        { url: "https://example.test/" },
        { sessionID: "ses_redir_bound", agent: "pentest", messageID: "m1", id: "c1" },
      )
      expect(res.content).toContain("ok")
    } finally {
      globalThis.fetch = origFetch
    }
    expect(asserts.length).toBe(1) // hop 0 was in scope: only the redirect hop dialoged
    const a = asserts[0] as { resources: string[]; metadata: { reason: string } }
    expect(a.resources).toEqual(["scanme.nmap.org"])
    expect(a.metadata.reason).toContain("outside the operation scope")
  })

  test("http-request redirect confirm (wired): free session never raises the mid-tool dialog", async () => {
    const store = HopperStore.open(configDir)
    try {
      store.setFree("ses_redir_free")
    } finally {
      store.close()
    }
    const asserts: unknown[] = []
    const { ctx, addedTools } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const tool = addedTools.find((t) => t.name === "http-request")! as {
      execute: (input: unknown, context: unknown) => Promise<{ content: string }>
    }
    let n = 0
    const origFetch = globalThis.fetch
    globalThis.fetch = (async () => {
      n++
      return n === 1
        ? new Response(null, { status: 302, headers: { location: "http://scanme.nmap.org/x" } })
        : new Response("ok")
    }) as unknown as typeof fetch
    try {
      const res = await tool.execute(
        { url: "https://example.test/" },
        { sessionID: "ses_redir_free", agent: "pentest", messageID: "m1", id: "c1" },
      )
      expect(res.content).toContain("ok")
    } finally {
      globalThis.fetch = origFetch
    }
    expect(asserts.length).toBe(0) // free: neither the hook nor the mid-tool confirm dialogs
  })

  test("session context hook pushes the bound operation's block per session", async () => {
    const opA = bindSession("ses_ctx_a", "alpha.test")
    const opB = bindSession("ses_ctx_b", "beta.test") // seeded later: the legacy global-active pick would return this one
    const store = HopperStore.open(configDir)
    let finding: { id: string } | null = null
    try {
      finding = store.addFinding(opA.id, { title: "t", severity: "low", target: "alpha.test" })
    } finally {
      store.close()
    }
    const { ctx, sessionHooks } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = sessionHooks["context"]! as (event: { sessionID: string; system: Array<{ type: string; text: string }> }) => Promise<void>
    const eventA = { sessionID: "ses_ctx_a", system: [] as Array<{ type: string; text: string }> }
    await hook(eventA)
    expect(eventA.system.length).toBe(1)
    expect(eventA.system[0]!.type).toBe("text")
    expect(eventA.system[0]!.text).toContain("## Hopper Operation Context")
    expect(eventA.system[0]!.text).toContain(opA.name)
    expect(eventA.system[0]!.text).toContain("alpha.test")
    expect(eventA.system[0]!.text).not.toContain("beta.test") // per-session, not the latest active op
    expect(eventA.system[0]!.text).toContain("Findings ledger: 1 candidate")
    void finding
    void opB
  })

  test("session context hook pushes nothing for free and unbound sessions", async () => {
    bindSession("ses_ctx_c", "gamma.test")
    const store = HopperStore.open(configDir)
    try {
      store.setFree("ses_ctx_free")
    } finally {
      store.close()
    }
    const { ctx, sessionHooks } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = sessionHooks["context"]! as (event: { sessionID: string; system: Array<{ type: string; text: string }> }) => Promise<void>
    const freeEvent = { sessionID: "ses_ctx_free", system: [] as Array<{ type: string; text: string }> }
    const unboundEvent = { sessionID: "ses_ctx_unbound", system: [] as Array<{ type: string; text: string }> }
    await hook(freeEvent)
    await hook(unboundEvent)
    expect(freeEvent.system).toEqual([])
    expect(unboundEvent.system).toEqual([]) // an active op exists — must NOT leak into unbound sessions
  })
})

describe("guard: free and unbound sessions (binding resolution + gate)", () => {
  afterEach(() => {
    setUnboundGateFactory(null)
  })

  test("free session: no fence at all — same out-of-scope call raises nothing", async () => {
    const store = HopperStore.open(configDir)
    try {
      store.setFree("ses_free1")
    } finally {
      store.close()
    }
    const gate = injectGate()
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(hook({ ...EVENT_BASE, sessionID: "ses_free1", tool: "webfetch", input: { url: "https://evil.test/x" } })).resolves.toBeUndefined()
    expect(asserts.length).toBe(0)
    expect(gate.emitted.length).toBe(0)
  })

  test("unbound session without weapon targets passes silently", async () => {
    const gate = injectGate()
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(hook({ ...EVENT_BASE, sessionID: "ses_unb_silent", tool: "shell", input: { command: "curl http://localhost:3000/" } })).resolves.toBeUndefined()
    expect(asserts.length).toBe(0)
    expect(gate.emitted.length).toBe(0)
  })

  test("unbound session with a weapon target: ask emitted with the right fields, forwarder fires, allow-once proceeds", async () => {
    const gate = injectGate({ answer: (ask, g) => g.answer(ask.askId, "allow-once") })
    const asserts: unknown[] = []
    const { ctx, toolHooks, rpcEvents } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    const event = { ...EVENT_BASE, sessionID: "ses_unb_ask", messageID: "msg_unb", tool: "webfetch", input: { url: "https://evil.test/x" } }
    await expect(hook(event)).resolves.toBeUndefined()
    expect(asserts.length).toBe(0) // the native dialog is not used for unbound sessions
    expect(gate.emitted.length).toBe(1)
    const ask = gate.emitted[0]!
    expect(ask.askId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/) // minted by the gate
    expect(ask.sessionID).toBe("ses_unb_ask")
    expect(ask.messageID).toBe("msg_unb")
    expect(ask.tool).toBe("webfetch")
    expect(ask.targets).toEqual(["evil.test"])
    expect(ask.reason).toContain("no active operation scope")
    expect(ask.reason).toContain("evil.test")
    // the production forwarder relayed the ask onto the rpc event bus
    const rpcAsk = rpcEvents.find((e) => e.name === "guard.ask")
    expect(rpcAsk).toBeDefined()
    expect((rpcAsk!.data as { askId: string }).askId).toBe(ask.askId)
  })

  test("unbound session: shell command referencing an external host reaches the gate (R6)", async () => {
    const gate = injectGate({ answer: (ask, g) => g.answer(ask.askId, "allow-once") })
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, sessionID: "ses_unb_shell", tool: "shell", input: { command: "nmap -p 80 evil.test" } }),
    ).resolves.toBeUndefined() // allow-once: proceeds, but the operator was asked first
    expect(gate.emitted.length).toBe(1)
    expect(gate.emitted[0]!.targets).toEqual(["evil.test"])
    expect(gate.emitted[0]!.reason).toContain("no active operation scope")
    expect(asserts.length).toBe(0) // the native dialog is not used for unbound sessions
  })

  test("answered bind: binding row written and the triggering call proceeds; fence applies from the next call", async () => {
    const op = bindSession("ses_seed_only", "example.test") // creates the op without binding the asking session
    const store = HopperStore.open(configDir)
    try {
      store.clearBinding("ses_seed_only")
    } finally {
      store.close()
    }
    const gate = injectGate({ answer: (ask, g) => g.answer(ask.askId, "bind", op.id) })
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, sessionID: "ses_unb_bind", tool: "webfetch", input: { url: "https://evil.test/x" } }),
    ).resolves.toBeUndefined() // the triggering call proceeds — the operator just eyeballed the target
    expect(gate.emitted.length).toBe(1)
    expect(asserts.length).toBe(0)
    const store2 = HopperStore.open(configDir)
    let binding: { operation_id: string | null; mode: string } | null = null
    try {
      binding = store2.getBinding("ses_unb_bind")
    } finally {
      store2.close()
    }
    expect(binding).toEqual({ operation_id: op.id, mode: "bound" })
    // bound now: in-scope target passes silently (no second ask)
    await expect(
      hook({ ...EVENT_BASE, sessionID: "ses_unb_bind", tool: "webfetch", input: { url: "https://example.test/x" } }),
    ).resolves.toBeUndefined()
    expect(gate.emitted.length).toBe(1)
    expect(asserts.length).toBe(0)
  })

  test("answered free: session marked free and the call proceeds", async () => {
    const gate = injectGate({ answer: (ask, g) => g.answer(ask.askId, "free") })
    const { ctx, toolHooks } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, sessionID: "ses_unb_free", tool: "webfetch", input: { url: "https://evil.test/x" } }),
    ).resolves.toBeUndefined()
    const store = HopperStore.open(configDir)
    let binding: { operation_id: string | null; mode: string } | null = null
    try {
      binding = store.getBinding("ses_unb_free")
    } finally {
      store.close()
    }
    expect(binding).toEqual({ operation_id: null, mode: "free" })
  })

  test("answered deny: the hook rejects with the operator-denied error", async () => {
    const gate = injectGate({ answer: (ask, g) => g.answer(ask.askId, "deny") })
    const { ctx, toolHooks } = makeMockCtx(tmpProject)
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, sessionID: "ses_unb_deny", tool: "webfetch", input: { url: "https://evil.test/x" } }),
    ).rejects.toThrow("[hopper] operator denied:")
    expect(gate.emitted.length).toBe(1)
  })

  test("unanswered ask (timeoutMs 10): fails open, proceeds with the warn log", async () => {
    const gate = injectGate({ timeoutMs: 10 })
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await expect(
      hook({ ...EVENT_BASE, sessionID: "ses_unb_timeout", tool: "webfetch", input: { url: "https://evil.test/x" } }),
    ).resolves.toBeUndefined()
    expect(asserts.length).toBe(0)
    expect(gate.emitted.length).toBe(1)
    expect(gate.logs.join(" ")).toContain("[hopper] guard.ask timed out, proceeding:")
  })

  test("unreadable store (configDir on an unwritable path): unbound path, no crash (RF#2/#3)", async () => {
    const brokenProject = join(tmpdir(), "hopper-kernel-broken-" + Date.now())
    rmSync(brokenProject, { recursive: true, force: true })
    mkdirSync(brokenProject, { recursive: true })
    writeFileSync(join(brokenProject, ".opencode"), "not a directory") // HopperStore.open cannot mkdir through a file
    try {
      const gate = injectGate({ answer: (ask, g) => g.answer(ask.askId, "allow-once") })
      const asserts: unknown[] = []
      const { ctx, toolHooks, sessionHooks } = makeMockCtx(brokenProject, { assert: async (i: unknown) => { asserts.push(i) } })
      await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
      const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
      await expect(
        hook({ ...EVENT_BASE, sessionID: "ses_broken", tool: "webfetch", input: { url: "https://evil.test/x" } }),
      ).resolves.toBeUndefined() // degraded to unbound → gate dialog → allow-once → proceeds
      expect(gate.emitted.length).toBe(1)
      expect((gate.emitted[0] as { reason: string }).reason).toContain("no active operation scope")
      expect(asserts.length).toBe(0)
      const contextHook = sessionHooks["context"]! as (event: { sessionID: string; system: Array<{ type: string; text: string }> }) => Promise<void>
      const ctxEvent = { sessionID: "ses_broken", system: [] as Array<{ type: string; text: string }> }
      const errors: string[] = []
      const origError = console.error
      console.error = (...args: unknown[]) => {
        errors.push(args.map(String).join(" "))
      }
      try {
        await expect(contextHook(ctxEvent)).resolves.toBeUndefined()
      } finally {
        console.error = origError
      }
      expect(ctxEvent.system).toEqual([])
      expect(errors.join(" ")).toContain("context hook error") // degraded via the catch, not a lucky pass
    } finally {
      rmSync(brokenProject, { recursive: true, force: true })
    }
  })
})

// ---------------------------------------------------------------------------
// Task 7: agent tools are session-scoped — the bound operation is the
// default, never an implicit "latest active" pick.
// ---------------------------------------------------------------------------

describe("agent tools: session-scoped operation defaults (Task 7)", () => {
  const NO_BINDING = "no operation bound to this session — bind one (/op) or pass operationId"
  let dir: string

  beforeEach(() => {
    dir = join(tmpdir(), "hopper-t7-tools-" + Date.now() + "-" + crypto.randomUUID().slice(0, 8))
    mkdirSync(dir, { recursive: true })
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  const tool = (name: string) => buildTools(dir).find((t) => t.name === name)!

  /**
   * The discriminating fixture: the session is bound to op1 while op2 was
   * created later (the singleton-era code would default every tool to op2,
   * the most recently updated active operation).
   */
  const bindThenCreateNewer = (sessionID: string) => {
    const store = HopperStore.open(dir)
    try {
      const bound = store.createOperation("bound-one", "one.test")
      store.upsertBinding(sessionID, bound.id)
      const newer = store.createOperation("newer-one", "two.test")
      return { bound, newer }
    } finally {
      store.close()
    }
  }

  test("finding add in a bound session lands on the bound operation, not the newest active one", async () => {
    const { bound } = bindThenCreateNewer("ses_t7_finding")
    const res = await tool("finding").execute(
      { action: "add", title: "XSS in search", severity: "high", target: "one.test" },
      { sessionID: "ses_t7_finding" },
    )
    expect(res.content).toContain("recorded as candidate")
    const store = HopperStore.open(dir)
    try {
      const findings = store.listFindings(bound.id)
      expect(findings).toHaveLength(1)
      expect(findings[0]!.title).toBe("XSS in search")
      expect(store.listFindings()).toHaveLength(1) // nothing landed on the newer op
    } finally {
      store.close()
    }
  })

  test("finding add with no binding (unbound, free, or contextless) returns the no-binding content and writes no row", async () => {
    bindThenCreateNewer("ses_other") // an active op exists — must NOT leak in as a default
    const store = HopperStore.open(dir)
    try {
      store.setFree("ses_t7_free")
    } finally {
      store.close()
    }
    const call = { action: "add", title: "XSS", severity: "high", target: "one.test" } as const
    for (const context of [{ sessionID: "ses_t7_unbound" }, { sessionID: "ses_t7_free" }, undefined]) {
      const res = await tool("finding").execute(call, context)
      expect(res.content).toBe(NO_BINDING)
    }
    const store2 = HopperStore.open(dir)
    try {
      expect(store2.listFindings()).toHaveLength(0)
    } finally {
      store2.close()
    }
  })

  test("finding honors an explicit operationId over the binding (and with no binding at all)", async () => {
    const { bound, newer } = bindThenCreateNewer("ses_t7_explicit")
    const viaOverride = await tool("finding").execute(
      { action: "add", operationId: newer.id, title: "on the newer op", severity: "low", target: "two.test" },
      { sessionID: "ses_t7_explicit" },
    )
    expect(viaOverride.content).toContain("recorded as candidate")
    const withoutBinding = await tool("finding").execute(
      { action: "add", operationId: bound.id, title: "explicit from unbound", severity: "low", target: "one.test" },
      { sessionID: "ses_t7_nobinding" },
    )
    expect(withoutBinding.content).toContain("recorded as candidate")
    const store = HopperStore.open(dir)
    try {
      expect(store.listFindings(newer.id).map((f) => f.title)).toEqual(["on the newer op"])
      expect(store.listFindings(bound.id).map((f) => f.title)).toEqual(["explicit from unbound"])
    } finally {
      store.close()
    }
  })

  test("finding list defaults to the bound op's ledger; no binding reads the same no-binding content", async () => {
    const { bound } = bindThenCreateNewer("ses_t7_list")
    const store = HopperStore.open(dir)
    try {
      store.addFinding(bound.id, { title: "bound-ledger-item", severity: "info", target: "one.test" })
    } finally {
      store.close()
    }
    const boundList = await tool("finding").execute({ action: "list" }, { sessionID: "ses_t7_list" })
    expect(boundList.content).toContain("bound-ledger-item")
    const unboundList = await tool("finding").execute({ action: "list" }, { sessionID: "ses_t7_unbound_list" })
    expect(unboundList.content).toBe(NO_BINDING)
  })

  test("evidence capture lands on the bound op; no binding returns the no-binding content and stores nothing", async () => {
    const { bound } = bindThenCreateNewer("ses_t7_evidence")
    const ok = await tool("evidence").execute(
      { action: "capture", kind: "response", content: "HTTP/1.1 200 OK" },
      { sessionID: "ses_t7_evidence" },
    )
    expect(ok.content).toContain("captured")
    const refused = await tool("evidence").execute(
      { action: "capture", kind: "response", content: "HTTP/1.1 500 KO" },
      { sessionID: "ses_t7_evidence_unbound" },
    )
    expect(refused.content).toBe(NO_BINDING)
    const store = HopperStore.open(dir)
    try {
      const items = store.listEvidence(bound.id)
      expect(items).toHaveLength(1)
      expect(items[0]!.content).toBe("HTTP/1.1 200 OK")
    } finally {
      store.close()
    }
  })

  test("report defaults to the bound op; no binding returns the no-binding content instead of throwing", async () => {
    const { bound } = bindThenCreateNewer("ses_t7_report")
    const res = await tool("report").execute({}, { sessionID: "ses_t7_report" })
    expect(res.content).toContain("Report written:")
    const { readFileSync } = await import("node:fs")
    const path = res.content.replace("Report written: ", "")
    expect(readFileSync(path, "utf8")).toContain("bound-one") // the BOUND op, not the newest active one
    const refused = await tool("report").execute({}, { sessionID: "ses_t7_report_unbound" })
    expect(refused.content).toBe(NO_BINDING)
  })

  test("share defaults to the bound op; no binding returns the no-binding content", async () => {
    const { bound } = bindThenCreateNewer("ses_t7_share")
    const res = await tool("share").execute({}, { sessionID: "ses_t7_share" })
    expect(res.content).toContain("Share bundle written:")
    const { readFileSync } = await import("node:fs")
    const bundle = JSON.parse(readFileSync(res.content.replace("Share bundle written: ", "").split("\n")[0]!, "utf8"))
    expect(bundle.bundle.operation.id).toBe(bound.id)
    const refused = await tool("share").execute({}, { sessionID: "ses_t7_share_unbound" })
    expect(refused.content).toBe(NO_BINDING)
  })

  test("operation create creates WITHOUT binding and describes the binding handoff", async () => {
    const res = await tool("operation").execute(
      { action: "create", name: "nomad", target: "https://nomad.test:8443" },
      { sessionID: "ses_t7_create" },
    )
    expect(res.content).toContain("nomad")
    expect(res.content).not.toContain("archives") // the singleton-era copy is gone
    expect(res.content).not.toContain("Scope file written") // the scope row lives in the store now
    expect(res.content).toContain("bind") // the handoff (operator binds via /op or the dialog) is described
    const desc = tool("operation").description
    expect(desc).not.toContain("archives the previous one")
    const store = HopperStore.open(dir)
    try {
      expect(store.getBinding("ses_t7_create")).toBeNull() // create binds nothing
    } finally {
      store.close()
    }
  })

  test("operation create is additive: a second create leaves the first active", async () => {
    await tool("operation").execute({ action: "create", name: "first", target: "one.test" }, { sessionID: "ses_a" })
    await tool("operation").execute({ action: "create", name: "second", target: "two.test" }, { sessionID: "ses_a" })
    const store = HopperStore.open(dir)
    try {
      const statuses = store.listOperations().map((o) => o.status)
      expect(statuses).toEqual(["active", "active"])
    } finally {
      store.close()
    }
  })

  test("operation status reports the session's bound operation, or the no-binding content", async () => {
    const { bound } = bindThenCreateNewer("ses_t7_status")
    const boundStatus = await tool("operation").execute({ action: "status" }, { sessionID: "ses_t7_status" })
    expect(boundStatus.content).toContain("bound-one")
    expect(boundStatus.content).not.toContain("newer-one") // bound op, not the newest active one
    expect(boundStatus.content).toContain(bound.id)
    const store = HopperStore.open(dir)
    try {
      store.setFree("ses_t7_status_free")
    } finally {
      store.close()
    }
    for (const context of [{ sessionID: "ses_t7_status_unbound" }, { sessionID: "ses_t7_status_free" }]) {
      const res = await tool("operation").execute({ action: "status" }, context)
      expect(res.content).toBe(NO_BINDING)
    }
  })

  test("operation list keeps listing every operation (not session-scoped)", async () => {
    bindThenCreateNewer("ses_t7_listops")
    const res = await tool("operation").execute({ action: "list" }, { sessionID: "ses_t7_listops" })
    expect(res.content).toContain("bound-one")
    expect(res.content).toContain("newer-one")
    const unbound = await tool("operation").execute({ action: "list" }, { sessionID: "ses_nobody" })
    expect(unbound.content).toContain("bound-one")
    expect(unbound.content).toContain("newer-one")
  })
})

// ---------------------------------------------------------------------------
// Task 7: the mid-tool redirect confirm resolves by session binding —
// bound ⇒ fence against the op's store scope row, free ⇒ pass, unbound ⇒
// the binary confirm callback with the no-binding reason.
// ---------------------------------------------------------------------------

describe("http-request redirect confirm: resolved by session binding (Task 7)", () => {
  let dir: string

  beforeEach(() => {
    dir = join(tmpdir(), "hopper-t7-redir-" + Date.now() + "-" + crypto.randomUUID().slice(0, 8))
    mkdirSync(dir, { recursive: true })
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  const ok = (body: string | null, init?: ResponseInit) => new Response(body, init)
  const hopTo = (loc: string) => {
    let n = 0
    return async () => {
      n++
      return n === 1 ? ok(null, { status: 302, headers: { location: loc } }) : ok("landed")
    }
  }

  test("bound session: hops fence against the bound op's scope row (store, not scope.json)", async () => {
    const store = HopperStore.open(dir)
    try {
      const op = store.createOperation("redir", "ok.test")
      store.upsertBinding("ses_r", op.id)
    } finally {
      store.close()
    }
    const confirms: Array<[string[], string]> = []
    const confirm = async (violations: string[], reason: string) => {
      confirms.push([violations, reason])
    }
    // in-scope hop: silent pass
    const inScope = await request(dir, { url: "https://ok.test/" }, {
      fetch: hopTo("https://ok.test/final"),
      confirm,
      context: { sessionID: "ses_r" },
    })
    expect(inScope.body).toBe("landed")
    expect(confirms).toHaveLength(0)
    // out-of-scope hop: confirm against the op's scope row
    const outOfScope = await request(dir, { url: "https://ok.test/" }, {
      fetch: hopTo("https://evil.test/x"),
      confirm,
      context: { sessionID: "ses_r" },
    })
    expect(outOfScope.body).toBe("landed")
    expect(confirms).toEqual([[["evil.test"], expect.stringContaining("outside the operation scope")]])
  })

  test("free session: redirect hops never confirm", async () => {
    const store = HopperStore.open(dir)
    try {
      store.createOperation("free-op", "ok.test")
      store.setFree("ses_r_free")
    } finally {
      store.close()
    }
    let confirmed = 0
    const res = await request(dir, { url: "https://ok.test/" }, {
      fetch: hopTo("https://evil.test/x"),
      confirm: async () => {
        confirmed++
      },
      context: { sessionID: "ses_r_free" },
    })
    expect(confirmed).toBe(0)
    expect(res.body).toBe("landed")
  })

  test("unbound session: binary confirm with the no-binding reason (verbatim)", async () => {
    const confirms: Array<[string[], string]> = []
    const res = await request(dir, { url: "https://ok.test/" }, {
      fetch: hopTo("https://evil.test/x"),
      confirm: async (violations, reason) => {
        confirms.push([violations, reason])
      },
      context: { sessionID: "ses_r_unbound" },
    })
    expect(res.body).toBe("landed")
    expect(confirms).toEqual([[["evil.test"], "no operation bound — allow redirect to evil.test?"]])
  })

  test("no sessionID in the tool context behaves unbound (ask, never block)", async () => {
    const confirms: Array<[string[], string]> = []
    const res = await request(dir, { url: "https://ok.test/" }, {
      fetch: hopTo("https://evil.test/x"),
      confirm: async (violations, reason) => {
        confirms.push([violations, reason])
      },
    })
    expect(res.body).toBe("landed")
    expect(confirms).toEqual([[["evil.test"], "no operation bound — allow redirect to evil.test?"]])
  })

  test("unreadable store degrades to unbound: the confirm is asked, nothing blocks", async () => {
    writeFileSync(join(dir, "data"), "not a directory") // HopperStore.open cannot mkdir through a file
    const confirms: Array<[string[], string]> = []
    const res = await request(dir, { url: "https://ok.test/" }, {
      fetch: hopTo("https://evil.test/x"),
      confirm: async (violations, reason) => {
        confirms.push([violations, reason])
      },
      context: { sessionID: "ses_r_broken" },
    })
    expect(res.body).toBe("landed")
    expect(confirms).toEqual([[["evil.test"], "no operation bound — allow redirect to evil.test?"]])
  })
})
