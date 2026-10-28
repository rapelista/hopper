import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { request } from "../src/lib/tools"
import { saveScope, ScopeError } from "../src/lib/scope"

let configDir: string
let emptyDir: string

beforeAll(() => {
  configDir = join(tmpdir(), "hopper-t6-scoped")
  emptyDir = join(tmpdir(), "hopper-t6-empty")
  rmSync(configDir, { recursive: true, force: true })
  rmSync(emptyDir, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
  mkdirSync(emptyDir, { recursive: true })
  saveScope(configDir, { targets: ["*.example.test"], strict: true, created: "2026-10-28T00:00:00Z" })
})

afterAll(() => {
  rmSync(configDir, { recursive: true, force: true })
  rmSync(emptyDir, { recursive: true, force: true })
})

const ok = (body: string | null, init?: ResponseInit) => new Response(body, init)

describe("http-request dialog-always behavior", () => {
  test("in-scope 200 returns result with correct sha256", async () => {
    const res = await request(configDir, { url: "https://sub.example.test/x" }, { fetch: async () => ok("hello") })
    expect(res.status).toBe(200)
    expect(res.body).toBe("hello")
    expect(res.sha256).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // sha256("hello")
    )
    expect(res.hops).toEqual([])
  })

  test("out-of-scope initial url proceeds when no confirm is wired (hook owns the gate)", async () => {
    const res = await request(configDir, { url: "https://evil.test/" }, { fetch: async () => ok("x") })
    expect(res.body).toBe("x")
  })

  test("missing scope proceeds without confirm (RF#5 → dialog-always)", async () => {
    const res = await request(emptyDir, { url: "https://sub.example.test/" }, { fetch: async () => ok("x") })
    expect(res.status).toBe(200)
  })

  test("non-http scheme is left to fetch itself", async () => {
    await expect(
      request(configDir, { url: "file:///etc/passwd" }, { fetch: async () => { throw new Error("fetch refuses") } }),
    ).rejects.toThrow("fetch refuses")
  })

  test("in-scope redirect is followed and recorded", async () => {
    let calls = 0
    const res = await request(configDir, { url: "https://a.example.test/" }, {
      fetch: async () => {
        calls++
        if (calls === 1) return ok(null, { status: 302, headers: { location: "https://b.example.test/final" } })
        return ok("landed")
      },
    })
    expect(res.status).toBe(200)
    expect(res.body).toBe("landed")
    expect(res.hops).toEqual(["https://b.example.test/final"])
  })

  test("out-of-scope redirect hop confirms; allow follows, deny rejects", async () => {
    const calls: Array<[string[], string]> = []
    const hopTo = (loc: string) => {
      let n = 0
      return async () => {
        n++
        return n === 1 ? ok(null, { status: 302, headers: { location: loc } }) : ok("landed")
      }
    }
    const res = await request(configDir, { url: "https://a.example.test/" }, {
      fetch: hopTo("http://scanme.nmap.org/"),
      confirm: async (v, r) => {
        calls.push([v, r])
      },
      context: { sessionID: "s1", messageID: "m1", id: "c1" },
    })
    expect(calls).toEqual([[["scanme.nmap.org"], expect.stringContaining("redirect hop")]])
    expect(res.body).toBe("landed")
    await expect(
      request(configDir, { url: "https://a.example.test/" }, {
        fetch: hopTo("http://scanme.nmap.org/"),
        confirm: async () => {
          throw new Error("denied by operator")
        },
      }),
    ).rejects.toThrow("denied by operator")
  })

  test("redirect to an IP literal never confirms (RF#3)", async () => {
    let confirmed = 0
    let n = 0
    const res = await request(configDir, { url: "https://a.example.test/" }, {
      fetch: async () => {
        n++
        return n === 1 ? ok(null, { status: 302, headers: { location: "http://169.254.169.254/md" } }) : ok("metadata")
      },
      confirm: async () => {
        confirmed++
      },
    })
    expect(confirmed).toBe(0)
    expect(res.body).toBe("metadata")
  })

  test("sensitive response headers are redacted in the echo", async () => {    const res = await request(
      configDir,
      {
        url: "https://sub.example.test/auth",
        headers: { Authorization: "Bearer sekrit" },
      },
      {
        fetch: async () =>
          ok("fine", {
            headers: { "Set-Cookie": "session=abc", Authorization: "Bearer sekrit", "X-Custom": "keep" },
          }),
      },
    )
    expect(JSON.stringify(res.headers)).not.toContain("sekrit")
    expect(JSON.stringify(res.headers)).not.toContain("session=abc")
    expect(res.headers["x-custom"]).toBe("keep")
  })

  test("out-of-scope INITIAL url never confirms inside the tool (the hook owns hop 0)", async () => {
    let confirmed = 0
    const res = await request(configDir, { url: "https://scanme.nmap.org/" }, {
      fetch: async () => ok("direct"),
      confirm: async () => {
        confirmed++
      },
    })
    expect(confirmed).toBe(0)
    expect(res.body).toBe("direct")
  })
})

describe("corrupt scope.json (RF#1 - never hard-block)", () => {
  let corruptDir: string

  beforeAll(() => {
    corruptDir = join(tmpdir(), "hopper-t6-corrupt")
    rmSync(corruptDir, { recursive: true, force: true })
    mkdirSync(corruptDir, { recursive: true })
    writeFileSync(join(corruptDir, "scope.json"), "{corrupt")
  })
  afterAll(() => {
    rmSync(corruptDir, { recursive: true, force: true })
  })

  test("redirect hop dialogs with the no-scope reason and proceeds on allow - never ScopeError", async () => {
    const confirms: Array<[string[], string]> = []
    let n = 0
    const res = await request(corruptDir, { url: "https://a.example.test/" }, {
      fetch: async () => {
        n++
        return n === 1 ? ok(null, { status: 302, headers: { location: "https://b.test/x" } }) : ok("landed")
      },
      confirm: async (v, r) => {
        confirms.push([v, r])
      },
    })
    expect(confirms).toEqual([[["b.test"], expect.stringContaining("no active operation scope")]])
    expect(res.body).toBe("landed")
  })

  test("operator deny rejects with the denial - not a ScopeError", async () => {
    let n = 0
    const rejection = request(corruptDir, { url: "https://a.example.test/" }, {
      fetch: async () => {
        n++
        return n === 1 ? ok(null, { status: 302, headers: { location: "https://b.test/x" } }) : ok("never")
      },
      confirm: async () => {
        throw new Error("denied by operator")
      },
    })
    await expect(rejection).rejects.toThrow("denied by operator")
    await expect(rejection).rejects.not.toBeInstanceOf(ScopeError)
  })
})
