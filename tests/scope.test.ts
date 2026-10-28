import { describe, expect, test } from "bun:test"
import {
  ScopeError,
  parseScope,
  isInScope,
  assertInScope,
  checkUrl,
  loadScope,
  saveScope,
  type Scope,
} from "../.opencode/lib/scope"

const scope = (targets: string[]): Scope => ({ targets, strict: true, created: "2026-10-28T00:00:00Z" })

describe("parseScope", () => {
  test("parses valid json with targets", () => {
    const s = parseScope(JSON.stringify({ targets: ["a.test"], strict: true, created: "x" }))
    expect(s.targets).toEqual(["a.test"])
    expect(s.strict).toBe(true)
  })
  test("throws ScopeError on invalid json", () => {
    expect(() => parseScope("{nope")).toThrow(ScopeError)
  })
  test("throws ScopeError on empty targets", () => {
    expect(() => parseScope(JSON.stringify({ targets: [], strict: true, created: "x" }))).toThrow(ScopeError)
  })
})

describe("isInScope", () => {
  test("exact hostname match", () => {
    expect(isInScope(scope(["localhost"]), "localhost")).toBe(true)
  })
  test("exact hostname mismatch", () => {
    expect(isInScope(scope(["localhost"]), "evil.test")).toBe(false)
  })
  test("wildcard matches subdomain", () => {
    expect(isInScope(scope(["*.example.test"]), "sub.example.test")).toBe(true)
  })
  test("wildcard does NOT match lookalike suffix (RF#1)", () => {
    expect(isInScope(scope(["*.example.test"]), "evil-example.test")).toBe(false)
  })
  test("wildcard matches apex", () => {
    expect(isInScope(scope(["*.example.test"]), "example.test")).toBe(true)
  })
  test("cidr contains address", () => {
    expect(isInScope(scope(["10.0.0.0/8"]), "10.5.9.1")).toBe(true)
  })
  test("cidr does not contain outside address (RF#1)", () => {
    expect(isInScope(scope(["10.0.0.0/8"]), "11.0.0.1")).toBe(false)
  })
  test("exact ipv4", () => {
    expect(isInScope(scope(["192.168.1.10"]), "192.168.1.10")).toBe(true)
  })
})

describe("assertInScope (fail-closed)", () => {
  test("throws when scope is null (RF#5)", () => {
    expect(() => assertInScope(null, "example.test")).toThrow(ScopeError)
  })
  test("throws when host out of scope", () => {
    expect(() => assertInScope(scope(["a.test"]), "b.test")).toThrow(ScopeError)
  })
  test("passes when in scope", () => {
    expect(() => assertInScope(scope(["a.test"]), "a.test")).not.toThrow()
  })
})

describe("URL-form scope targets are normalized", () => {
  test("saveScope normalizes url targets to hostnames", () => {
    const dir = require("node:os").tmpdir() + "/hopper-fix1-" + Date.now()
    require("node:fs").mkdirSync(dir, { recursive: true })
    saveScope(dir, { targets: ["http://localhost:3000", "https://app.lab.test/x"], strict: true, created: "x" })
    const loaded = loadScope(dir)!
    expect(loaded.targets).toEqual(["localhost", "app.lab.test"])
    expect(isInScope(loaded, "localhost")).toBe(true)
    expect(() => checkUrl(loaded, "http://localhost:3000/api")).not.toThrow()
    require("node:fs").rmSync(dir, { recursive: true, force: true })
  })

  test("isInScope defensively normalizes url-shaped targets", () => {
    expect(isInScope({ targets: ["https://raw.example.test/path"], strict: true, created: "x" }, "raw.example.test")).toBe(true)
  })
})

describe("checkUrl", () => {
  test("accepts https url with in-scope host (port stripped)", () => {
    const u = checkUrl(scope(["*.example.test"]), "https://sub.example.test:8443/path")
    expect(u.hostname).toBe("sub.example.test")
  })
  test("rejects non-http protocol", () => {
    expect(() => checkUrl(scope(["*.example.test"]), "file:///etc/passwd")).toThrow(ScopeError)
  })
  test("rejects out-of-scope host", () => {
    expect(() => checkUrl(scope(["a.test"]), "https://b.test/")).toThrow(ScopeError)
  })
  test("rejects when scope null", () => {
    expect(() => checkUrl(null, "https://a.test/")).toThrow(ScopeError)
  })
})
