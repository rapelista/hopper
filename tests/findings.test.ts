import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { TRANSITIONS, canTransition, assertTransition, FindingError, type FindingStatus } from "../.opencode/lib/findings"
import { HopperStore } from "../.opencode/lib/store"
import finding from "../.opencode/tools/finding"

let configDir: string
let store: HopperStore
let opId: string

beforeAll(() => {
  configDir = join(tmpdir(), "hopper-t11-" + Date.now())
  rmSync(configDir, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
  store = HopperStore.open(configDir)
  opId = store.createOperation("t11", "http://lab.test").id
})

afterAll(() => {
  store.close()
  rmSync(configDir, { recursive: true, force: true })
})

describe("findings state machine", () => {
  const statuses = Object.keys(TRANSITIONS) as FindingStatus[]

  test("covers exactly the six lifecycle states", () => {
    expect(statuses.sort()).toEqual(["candidate", "observed", "rejected", "reportable", "stale", "verified"])
  })

  test("canTransition matches TRANSITIONS for every pair", () => {
    for (const from of statuses) {
      for (const to of statuses) {
        expect(canTransition(from, to)).toBe(TRANSITIONS[from].includes(to))
      }
    }
  })

  test("candidate cannot jump to reportable (RF#3)", () => {
    expect(canTransition("candidate", "reportable")).toBe(false)
    expect(() => assertTransition("candidate", "reportable")).toThrow(FindingError)
  })

  test("legal promotions pass", () => {
    expect(() => assertTransition("candidate", "observed")).not.toThrow()
    expect(() => assertTransition("observed", "verified")).not.toThrow()
    expect(() => assertTransition("verified", "reportable")).not.toThrow()
  })
})

describe("store findings", () => {
  test("addFinding starts as candidate", () => {
    const f = store.addFinding(opId, { title: "IDOR on /api/orders", severity: "high", target: "lab.test" })
    expect(f.status).toBe("candidate")
    expect(f.severity).toBe("high")
  })

  test("legal status transition persists", () => {
    const f = store.addFinding(opId, { title: "SSTI in template", severity: "critical", target: "lab.test" })
    const updated = store.updateFindingStatus(f.id, "observed")
    expect(updated.status).toBe("observed")
    expect(store.getFinding(f.id)?.status).toBe("observed")
  })

  test("illegal transition throws FindingError", () => {
    const f = store.addFinding(opId, { title: "jump test", severity: "low", target: "lab.test" })
    expect(() => store.updateFindingStatus(f.id, "reportable")).toThrow(FindingError)
  })

  test("patch updates title/severity/notes", () => {
    const f = store.addFinding(opId, { title: "old title", severity: "info", target: "lab.test" })
    const updated = store.updateFinding(f.id, { title: "new title", notes: "triaged" })
    expect(updated.title).toBe("new title")
    expect(updated.notes).toBe("triaged")
  })

  test("listFindings filters by status and operation", () => {
    const observed = store.listFindings(opId, "observed")
    expect(observed.length).toBeGreaterThanOrEqual(1)
    expect(store.listFindings("nonexistent-op").length).toBe(0)
  })
})

describe("finding tool shape", () => {
  test("default export has description and execute", () => {
    const t = finding as unknown as { description: string; execute: (args: Record<string, unknown>) => Promise<string> }
    expect(t.description.length).toBeGreaterThan(10)
    expect(typeof t.execute).toBe("function")
  })
})
