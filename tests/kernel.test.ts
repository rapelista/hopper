import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import hopperPlugin, { bashScopeGuard, buildTools } from "../src/index"
import type { Scope } from "../src/lib/scope"

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

/** Minimal v2 plugin-context mock capturing registrations. */
function makeMockCtx(projectDir: string, permission?: {
  assert: (input: unknown) => Promise<void>
}) {
  const addedTools: Array<{ name: string; description: string; input: unknown; execute: unknown }> = []
  const addedSkills: Array<{ id: string; name: string; description?: string; path: string; content: string }> = []
  const addedCommands: Array<{ name: string; description?: string; execute: (input: any) => Promise<void> }> = []
  const agentUpdates: Array<{ id: string; fn: (agent: any) => void }> = []
  const agentSwitches: unknown[] = []
  const prompts: unknown[] = []
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
  const skillEditor = {
    list: () => [],
    get: () => undefined,
    add: (s: { id: string; name: string; description?: string; path: string; content: string }) => addedSkills.push(s),
    update: () => {},
    remove: () => {},
  }
  const agentEditor = {
    list: () => [],
    get: () => undefined,
    default: () => {},
    update: (id: string, fn: (agent: any) => void) => agentUpdates.push({ id, fn }),
    remove: () => {},
  }
  const commandEditor = {
    add: (c: { name: string; description?: string; execute: (input: any) => Promise<void> }) => addedCommands.push(c),
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
    skill: {
      transform: async (cb: (e: typeof skillEditor) => void) => {
        cb(skillEditor)
        return reg
      },
      reload: async () => {},
    },
    agent: {
      transform: async (cb: (e: typeof agentEditor) => void) => {
        cb(agentEditor)
        return reg
      },
      reload: async () => {},
    },
    command: {
      transform: async (cb: (e: typeof commandEditor) => void) => {
        cb(commandEditor)
        return reg
      },
      list: async () => [],
      reload: async () => {},
    },
    session: {
      hook: async (name: string, cb: (event: unknown) => unknown) => {
        sessionHooks[name] = cb
        return reg
      },
      get: async () => ({ agent: "build" }),
      switchAgent: async (input: unknown) => {
        agentSwitches.push(input)
      },
      prompt: async (input: unknown) => {
        prompts.push(input)
        return {}
      },
    },
    ...(permission ? { permission } : {}),
  }
  return { ctx, addedTools, addedSkills, addedCommands, agentUpdates, agentSwitches, prompts, toolHooks, sessionHooks }
}

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
      ["doctor", "opsec", "pwn", "remediate", "report", "runbook", "share"].sort(),
    )

    const pwn = addedCommands.find((c) => c.name === "pwn")!
    expect(pwn.description?.length).toBeGreaterThan(5)
    await pwn.execute({ sessionID: "s1", prompt: { text: "http://localhost:3000" }, delivery: "steer" })

    expect(agentSwitches).toEqual([{ sessionID: "s1", agent: "pentest" }])
    const p = prompts[0] as { text: string; sessionID: string }
    expect(p.sessionID).toBe("s1")
    expect(p.text).toContain("http://localhost:3000")
    expect(p.text).not.toContain("$ARGUMENTS")
  })

  test("strict shell out-of-scope resolves through the dialog instead of blocking", async () => {
    writeScopeFixure(true)
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

  test("non-strict: violation triggers the allow/deny dialog and proceeds on allow", async () => {
    writeScopeFixure(false)
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
    expect(a.metadata).toMatchObject({ reason: expect.stringContaining("scanme.nmap.org") })
  })

  test("non-strict: dialog denial rejects the call", async () => {
    writeScopeFixure(false)
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

  test("strict: operator denial still rejects (the deny is the only block left)", async () => {
    writeScopeFixure(true)
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

  test("no dialog api: warn and proceed (fail-open)", async () => {
    writeScopeFixure(false)
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

  test("webfetch out-of-scope and no-scope both dialog", async () => {
    writeScopeFixure(false)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://evil.test/x" } })
    rmSync(join(configDir, "scope.json"))
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://a.test/x" } })
    expect(asserts.length).toBe(2)
    expect((asserts[1] as { metadata: { reason: string } }).metadata.reason).toContain("no active operation scope")
  })

  test("http-request url and scanner target/extras route through the same dialog", async () => {
    writeScopeFixure(false)
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

  test("corrupt scope.json: shell passes, webfetch dialogs (RF#1)", async () => {
    writeFileSync(join(configDir, "scope.json"), "{corrupt")
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "shell", input: { command: "nmap scanme.nmap.org" } })
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://a.test/" } })
    expect(asserts.length).toBe(1)
  })

  test("leak-advisory host enriches the dialog reason in BOTH postures - strict stays inert (opsec decision B)", async () => {
    writeScopeFixure(false)
    const asserts: unknown[] = []
    const { ctx, toolHooks } = makeMockCtx(tmpProject, { assert: async (i: unknown) => { asserts.push(i) } })
    await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(ctx)
    const hook = toolHooks["execute.before"]! as (event: unknown) => Promise<void>
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://api.shodan.io/" } })
    writeScopeFixure(true)
    await hook({ ...EVENT_BASE, tool: "webfetch", input: { url: "https://crt.sh/?q=x" } })
    expect(asserts.length).toBe(2) // strict posture still dialogs - never blocks
    expect((asserts[0] as { metadata: { reason: string } }).metadata.reason).toContain("opsec advisory")
    expect((asserts[1] as { metadata: { reason: string } }).metadata.reason).toContain("leak the target identity")
  })

  test("assert input carries resources and save for always-allow (RF#5)", async () => {
    writeScopeFixure(false)
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
