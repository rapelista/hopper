import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { request, type RequestResult } from "../.opencode/tools/http-request"
import { saveScope } from "../.opencode/lib/scope"
import { ScopeError } from "../.opencode/lib/scope"

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

const ok = (body: string, init?: ResponseInit) => new Response(body, init)

describe("http-request scope enforcement", () => {
  test("in-scope 200 returns result with correct sha256", async () => {
    const res = await request(configDir, { url: "https://sub.example.test/x" }, async () => ok("hello"))
    expect(res.status).toBe(200)
    expect(res.body).toBe("hello")
    expect(res.sha256).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // sha256("hello")
    )
    expect(res.hops).toEqual([])
  })

  test("out-of-scope url throws ScopeError", async () => {
    expect(request(configDir, { url: "https://evil.test/" }, async () => ok("x"))).rejects.toBeInstanceOf(ScopeError)
  })

  test("missing scope fails closed (RF#5)", async () => {
    expect(request(emptyDir, { url: "https://sub.example.test/" }, async () => ok("x"))).rejects.toBeInstanceOf(
      ScopeError,
    )
  })

  test("non-http protocol throws", async () => {
    expect(request(configDir, { url: "file:///etc/passwd" }, async () => ok("x"))).rejects.toBeInstanceOf(ScopeError)
  })

  test("in-scope redirect is followed and recorded", async () => {
    let calls = 0
    const res = await request(configDir, { url: "https://a.example.test/" }, async (input, init) => {
      calls++
      if (calls === 1) return ok(null, { status: 302, headers: { location: "https://b.example.test/final" } })
      return ok("landed")
    })
    expect(res.status).toBe(200)
    expect(res.body).toBe("landed")
    expect(res.hops).toEqual(["https://b.example.test/final"])
  })

  test("redirect to cloud metadata IP is blocked (RF#2)", async () => {
    let calls = 0
    const res = request(configDir, { url: "https://a.example.test/" }, async () => {
      calls++
      return ok(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data" } })
    })
    expect(res).rejects.toBeInstanceOf(ScopeError)
  })

  test("sensitive response headers are redacted in the echo", async () => {
    const res = await request(
      configDir,
      {
        url: "https://sub.example.test/auth",
        headers: { Authorization: "Bearer sekrit" },
      },
      async () =>
        ok("fine", {
          headers: { "Set-Cookie": "session=abc", Authorization: "Bearer sekrit", "X-Custom": "keep" },
        }),
    )
    expect(JSON.stringify(res.headers)).not.toContain("sekrit")
    expect(JSON.stringify(res.headers)).not.toContain("session=abc")
    expect(res.headers["x-custom"]).toBe("keep")
  })
})
