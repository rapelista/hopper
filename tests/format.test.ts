import { describe, expect, test } from "bun:test"
import { bannerText, compactCounts, groupFindings, severityToken, defaultOperationName, statusInitial } from "../src/tui/format"
import type { FindingsCounts, FindingSummary, OperationSummary } from "../src/rpc"

const counts = (over: Partial<FindingsCounts> = {}): FindingsCounts => ({
  candidate: 0,
  observed: 0,
  verified: 0,
  reportable: 0,
  rejected: 0,
  stale: 0,
  ...over,
})

const op = (over: Partial<OperationSummary> = {}): OperationSummary => ({
  id: "op_1",
  name: "juice",
  target: "localhost",
  createdAt: "2026-10-29T00:00:00Z",
  ...over,
})

const finding = (over: Partial<FindingSummary> = {}): FindingSummary => ({
  id: "f1",
  title: "XSS",
  severity: "high",
  status: "candidate",
  target: "localhost",
  createdAt: "2026-10-29T00:00:00Z",
  ...over,
})

describe("bannerText", () => {
  test("no operation → dim placeholder", () => {
    expect(bannerText({ operation: null, opsec: "normal", counts: counts() })).toBe("hop · no operation")
  })

  test("active operation → name → target · opsec", () => {
    expect(bannerText({ operation: op(), opsec: "strict", counts: counts() })).toBe("hop · juice → localhost · strict")
  })

  test("findings appended compactly when any exist", () => {
    expect(bannerText({ operation: op(), opsec: "normal", counts: counts({ candidate: 3, verified: 1 }) })).toBe(
      "hop · juice → localhost · normal · 3c/1v",
    )
  })

  test("all-zero counts add nothing", () => {
    expect(bannerText({ operation: op(), opsec: "normal", counts: counts() })).not.toContain("0c")
  })
})

describe("compactCounts", () => {
  test("empty → empty string", () => {
    expect(compactCounts(counts())).toBe("")
  })
  test("nonzero statuses only, lifecycle order", () => {
    expect(compactCounts(counts({ candidate: 3, verified: 1 }))).toBe("3c/1v")
    expect(compactCounts(counts({ reportable: 2, rejected: 1, stale: 4 }))).toBe("2r/1x/4s")
    expect(compactCounts(counts({ observed: 5 }))).toBe("5o")
  })
})

describe("groupFindings", () => {
  test("lifecycle order, empty groups omitted", () => {
    const groups = groupFindings([
      finding({ id: "a", status: "verified" }),
      finding({ id: "b", status: "candidate" }),
      finding({ id: "c", status: "candidate" }),
      finding({ id: "d", status: "rejected" }),
    ])
    expect(groups.map((g) => g.status)).toEqual(["candidate", "verified", "rejected"])
    expect(groups[0]!.items.map((f) => f.id)).toEqual(["b", "c"])
  })
  test("empty input → no groups", () => {
    expect(groupFindings([])).toEqual([])
  })
})

describe("statusInitial", () => {
  test("C O V R X S — rejected takes X so it never collides with reportable", () => {
    expect(statusInitial("candidate")).toBe("C")
    expect(statusInitial("observed")).toBe("O")
    expect(statusInitial("verified")).toBe("V")
    expect(statusInitial("reportable")).toBe("R")
    expect(statusInitial("rejected")).toBe("X")
    expect(statusInitial("stale")).toBe("S")
  })
  test("unknown status falls back to its first letter uppercased", () => {
    expect(statusInitial("weird")).toBe("W")
  })
})

describe("severityToken", () => {
  test("critical/high → error, medium → warning, low → base, info/unknown → muted", () => {
    expect(severityToken("critical")).toBe("error")
    expect(severityToken("high")).toBe("error")
    expect(severityToken("medium")).toBe("warning")
    expect(severityToken("low")).toBe("base")
    expect(severityToken("info")).toBe("muted")
    expect(severityToken("whatever")).toBe("muted")
  })
})

describe("defaultOperationName", () => {
  test("leftmost label of a hostname", () => {
    expect(defaultOperationName("api.acme.test")).toBe("api")
  })
  test("host:port and URL forms", () => {
    expect(defaultOperationName("localhost:3000")).toBe("localhost")
    expect(defaultOperationName("https://juice.example.test/x")).toBe("juice")
  })
  test("dotless target falls back to the whole target", () => {
    expect(defaultOperationName("localhost")).toBe("localhost")
  })
})
