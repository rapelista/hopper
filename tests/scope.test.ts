import { describe, expect, test } from "bun:test"
import {
  ScopeError,
  parseScope,
  isInScope,
  loadScope,
  scopeViolations,
  type Scope,
} from "../src/lib/scope"

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

describe("loadScope (migration reader — the file writer is gone)", () => {
  test("reads the relic file verbatim when present, null when absent", () => {
    const dir = require("node:os").tmpdir() + "/hopper-fix1-" + Date.now()
    require("node:fs").mkdirSync(dir, { recursive: true })
    expect(loadScope(dir)).toBeNull() // no relic
    require("node:fs").writeFileSync(
      dir + "/scope.json",
      JSON.stringify({ targets: ["lab.test"], strict: false, created: "2025-01-01T00:00:00.000Z" }),
    )
    expect(loadScope(dir)).toEqual({ targets: ["lab.test"], strict: false, created: "2025-01-01T00:00:00.000Z" })
    require("node:fs").rmSync(dir, { recursive: true, force: true })
  })
})

describe("URL-form scope targets are normalized defensively", () => {
  test("isInScope defensively normalizes url-shaped targets", () => {
    expect(isInScope({ targets: ["https://raw.example.test/path"], strict: true, created: "x" }, "raw.example.test")).toBe(true)
  })
})

describe("scopeViolations (dialog-always)", () => {
  test("null scope: every fenceable host is a violation; IPs never", () => {
    expect(scopeViolations(null, ["a.test", "10.0.0.5", "localhost"])).toEqual(["a.test"])
  })
  test("in-scope hosts yield no violations", () => {
    expect(scopeViolations(scope(["*.example.test"]), ["sub.example.test", "example.test"])).toEqual([])
  })
  test("out-of-scope host is returned", () => {
    expect(scopeViolations(scope(["example.test"]), ["scanme.nmap.org"])).toEqual(["scanme.nmap.org"])
  })
  test("host:port and case are normalized (RF#4)", () => {
    expect(scopeViolations(scope(["example.test"]), ["EXAMPLE.test:8443"])).toEqual([])
    expect(scopeViolations(scope(["example.test"]), ["OTHER.test:80"])).toEqual(["other.test"])
  })
  test("dedupes repeated hosts", () => {
    expect(scopeViolations(scope(["example.test"]), ["b.test", "B.test"])).toEqual(["b.test"])
  })
})
