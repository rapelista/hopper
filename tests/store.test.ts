import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { existsSync } from "node:fs"
import { Database } from "bun:sqlite"
import { HopperStore } from "../src/lib/store"
import { buildTools } from "../src/lib/tools"

let root: string

beforeAll(() => {
  root = join(tmpdir(), "hopper-t10-" + Date.now())
  rmSync(root, { recursive: true, force: true })
  mkdirSync(root, { recursive: true })
})

afterAll(() => {
  rmSync(root, { recursive: true, force: true })
})

/** Each test gets its own isolated config dir (its own store file). */
function openStore(): { store: HopperStore; dir: string } {
  const dir = join(root, "store-" + Math.random().toString(36).slice(2))
  return { store: HopperStore.open(dir), dir }
}

function openRaw(dir: string): Database {
  return new Database(join(dir, "data", "hopper.db"))
}

describe("HopperStore operations", () => {
  test("createOperation inserts an active operation and seeds its scopes row", () => {
    const { store } = openStore()
    const op = store.createOperation("juice-shop", "http://localhost:3000")
    expect(op.status).toBe("active")
    expect(op.name).toBe("juice-shop")
    const ops = store.listOperations()
    expect(ops).toHaveLength(1)
    expect(ops[0]!.status).toBe("active")
    expect(store.getScope(op.id)).toEqual({ targets: ["localhost"], strict: true })
    store.close()
  })

  test("createOperation is additive: two operations stay active, each with a scopes row", () => {
    const { store } = openStore()
    const first = store.createOperation("juice-shop", "http://localhost:3000")
    const second = store.createOperation("dvwa", "http://localhost:8080")
    const ops = store.listOperations()
    expect(ops).toHaveLength(2)
    expect(ops.find((o) => o.id === first.id)?.status).toBe("active")
    expect(ops.find((o) => o.id === second.id)?.status).toBe("active")
    expect(store.getScope(first.id)).toEqual({ targets: ["localhost"], strict: true })
    expect(store.getScope(second.id)).toEqual({ targets: ["localhost"], strict: true })
    store.close()
  })

  test("createOperation seeds the normalized target and does not write scope.json", () => {
    const { store, dir } = openStore()
    const op = store.createOperation("scoped-op", "http://Lab.Example.test:8080")
    expect(store.getScope(op.id)).toEqual({ targets: ["lab.example.test"], strict: true })
    store.close()
    expect(existsSync(join(dir, "scope.json"))).toBe(false)
  })

  test("data persists across close and reopen", () => {
    const { store, dir } = openStore()
    const before = store.listOperations().length
    store.close()
    const reopened = HopperStore.open(dir)
    expect(reopened.listOperations().length).toBe(before)
    reopened.close()
  })
})

describe("HopperStore bindings", () => {
  test("upsertBinding → getBinding roundtrip", () => {
    const { store } = openStore()
    const op = store.createOperation("op", "lab.test")
    store.upsertBinding("ses_1", op.id)
    expect(store.getBinding("ses_1")).toEqual({ operation_id: op.id, mode: "bound" })
    store.close()
  })

  test("getBinding on an unknown session returns null", () => {
    const { store } = openStore()
    expect(store.getBinding("ses_nobody")).toBeNull()
    store.close()
  })

  test("setFree overwrites a bound binding (operation_id NULL)", () => {
    const { store } = openStore()
    const op = store.createOperation("op", "lab.test")
    store.upsertBinding("ses_1", op.id)
    store.setFree("ses_1")
    expect(store.getBinding("ses_1")).toEqual({ operation_id: null, mode: "free" })
    store.close()
  })

  test("upsertBinding overwrites a free binding and rebinds to a new operation", () => {
    const { store } = openStore()
    const a = store.createOperation("a", "a.test")
    const b = store.createOperation("b", "b.test")
    store.upsertBinding("ses_1", a.id)
    store.setFree("ses_1")
    store.upsertBinding("ses_1", b.id)
    expect(store.getBinding("ses_1")).toEqual({ operation_id: b.id, mode: "bound" })
    store.close()
  })

  test("clearBinding removes the binding", () => {
    const { store } = openStore()
    const op = store.createOperation("op", "lab.test")
    store.upsertBinding("ses_1", op.id)
    store.clearBinding("ses_1")
    expect(store.getBinding("ses_1")).toBeNull()
    store.close()
  })

  test("purgeSession removes the binding and is a no-op for unknown sessions", () => {
    const { store } = openStore()
    const op = store.createOperation("op", "lab.test")
    store.upsertBinding("ses_1", op.id)
    store.purgeSession("ses_nobody") // must not throw
    store.purgeSession("ses_1")
    expect(store.getBinding("ses_1")).toBeNull()
    store.close()
  })
})

describe("HopperStore resolveSession", () => {
  test("bound mode joins the operation and its scope", () => {
    const { store } = openStore()
    const op = store.createOperation("op", "http://Lab.Test:8080")
    store.upsertBinding("ses_1", op.id)
    const res = store.resolveSession("ses_1")
    expect(res.mode).toBe("bound")
    if (res.mode !== "bound") return
    expect(res.operation).toMatchObject({ id: op.id, name: "op", target: "http://Lab.Test:8080", status: "active" })
    expect(res.scope).toEqual({ targets: ["lab.test"], strict: true })
    store.close()
  })

  test("free mode", () => {
    const { store } = openStore()
    store.setFree("ses_1")
    expect(store.resolveSession("ses_1")).toEqual({ mode: "free" })
    store.close()
  })

  test("unknown session → unbound", () => {
    const { store } = openStore()
    expect(store.resolveSession("ses_nobody")).toEqual({ mode: "unbound" })
    store.close()
  })

  test("a bound row whose operation vanished degrades to unbound, never throws", () => {
    const { store, dir } = openStore()
    store.close()
    const db = openRaw(dir)
    db.run("INSERT INTO bindings (session_id, operation_id, mode, updated_at) VALUES ('ses_ghost', 'no-such-op', 'bound', '2025-01-01T00:00:00.000Z')")
    db.close()
    const reopened = HopperStore.open(dir)
    expect(reopened.resolveSession("ses_ghost")).toEqual({ mode: "unbound" })
    reopened.close()
  })

  test("a corrupt bound row with a NULL operation degrades to unbound, never free (spec §2, F3)", () => {
    const { store, dir } = openStore()
    const op = store.createOperation("op", "lab.test")
    store.upsertBinding("ses_bound_ok", op.id)
    store.close()
    const db = openRaw(dir)
    // raw-seeded corruption the CHECK cannot prevent: mode 'bound' with a NULL
    // operation_id, and mode 'free' pointing at an operation
    db.run("INSERT INTO bindings (session_id, operation_id, mode, updated_at) VALUES ('ses_corrupt_null', NULL, 'bound', '2025-01-01T00:00:00.000Z')")
    db.run("INSERT INTO bindings (session_id, operation_id, mode, updated_at) VALUES ('ses_corrupt_free', 'some-op', 'free', '2025-01-01T00:00:00.000Z')")
    db.close()
    const reopened = HopperStore.open(dir)
    expect(reopened.resolveSession("ses_corrupt_null")).toEqual({ mode: "unbound" })
    expect(reopened.resolveSession("ses_corrupt_free")).toEqual({ mode: "unbound" })
    // well-formed rows still resolve both ways
    expect(reopened.resolveSession("ses_bound_ok").mode).toBe("bound")
    reopened.setFree("ses_free_ok")
    expect(reopened.resolveSession("ses_free_ok")).toEqual({ mode: "free" })
    reopened.close()
  })
})

describe("HopperStore lifecycle", () => {
  test("setOperationStatus flips status and unbinds every session of that op", () => {
    const { store } = openStore()
    const op = store.createOperation("op", "lab.test")
    store.upsertBinding("ses_1", op.id)
    store.upsertBinding("ses_2", op.id)
    const updated = store.setOperationStatus(op.id, "completed")
    expect(updated).toMatchObject({ id: op.id, status: "completed" })
    expect(store.listOperations().find((o) => o.id === op.id)?.status).toBe("completed")
    expect(store.getBinding("ses_1")).toBeNull()
    expect(store.getBinding("ses_2")).toBeNull()
    store.close()
  })

  test("setOperationStatus on an unknown operation returns null", () => {
    const { store } = openStore()
    expect(store.setOperationStatus("no-such-op", "archived")).toBeNull()
    store.close()
  })

  test("setOperationStatus unarchives: terminal → active persists, touches no bindings", () => {
    const { store } = openStore()
    const op = store.createOperation("revive", "revive.test")
    const otherOp = store.createOperation("other", "other.test")
    store.setOperationStatus(op.id, "archived")
    const revived = store.setOperationStatus(op.id, "active")
    expect(revived).toMatchObject({ id: op.id, status: "active" })
    expect(store.listOperations().find((o) => o.id === op.id)?.status).toBe("active") // persisted
    // a binding on a DIFFERENT op must survive an unarchive — the DELETE is scoped to the op, and no bindings can point at a terminal op anyway
    store.upsertBinding("ses_1", otherOp.id)
    store.setOperationStatus(op.id, "active")
    expect(store.getBinding("ses_1")).toEqual({ operation_id: otherOp.id, mode: "bound" })
    store.close()
  })

  test("deleteOperation removes scopes, bindings, findings, evidence, and orphaned evidence_findings links", () => {
    const { store, dir } = openStore()
    const op = store.createOperation("doomed", "doomed.test")
    const survivor = store.createOperation("survivor", "alive.test")
    const f = store.addFinding(op.id, { title: "SQLi", severity: "high", target: "doomed.test" })
    const ev = store.saveEvidence(op.id, { id: "ev-1", kind: "request", sha256: "a".repeat(64), size: 10, created_at: new Date().toISOString(), meta: {} }, "GET /")
    store.attachEvidence(f.id, ev.id)
    const sf = store.addFinding(survivor.id, { title: "XSS", severity: "low", target: "alive.test" })
    // cross-link: survivor evidence → doomed finding (an orphaned link after delete)
    const sev = store.saveEvidence(survivor.id, { id: "ev-2", kind: "note", sha256: "b".repeat(64), size: 5, created_at: new Date().toISOString(), meta: {} }, "note")
    store.attachEvidence(f.id, sev.id)
    // the survivor's own link must survive the delete
    store.attachEvidence(sf.id, sev.id)
    store.upsertBinding("ses_1", op.id)

    expect(store.deleteOperation(op.id)).toBe(true)
    expect(store.listOperations().map((o) => o.id)).toEqual([survivor.id])
    store.close()

    const db = openRaw(dir)
    const count = (table: string, where = "", params: string[] = []): number =>
      (db.query(`SELECT COUNT(*) AS n FROM ${table} ${where}`).get(...params) as { n: number }).n
    expect(count("operations")).toBe(1)
    expect(count("scopes")).toBe(1)
    expect(count("findings")).toBe(1)
    expect(count("evidence")).toBe(1)
    expect(count("bindings")).toBe(0)
    // every link row touching the deleted op's finding or evidence is gone;
    // the survivor's own link stays
    expect(count("evidence_findings", "WHERE finding_id = ?", [f.id])).toBe(0)
    expect(count("evidence_findings", "WHERE evidence_id IN ('ev-1')")).toBe(0)
    expect(count("evidence_findings")).toBe(1)
    db.close()
  })

  test("deleteOperation on an unknown operation returns false", () => {
    const { store } = openStore()
    expect(store.deleteOperation("no-such-op")).toBe(false)
    store.close()
  })
})

describe("HopperStore listOperationsWithCounts", () => {
  test("counts findings per operation across all six statuses", () => {
    const { store, dir } = openStore()
    const a = store.createOperation("a", "a.test")
    const b = store.createOperation("b", "b.test")
    const fa = store.addFinding(a.id, { title: "one", severity: "high", target: "a.test" })
    store.addFinding(a.id, { title: "two", severity: "low", target: "a.test" })
    store.updateFindingStatus(fa.id, "observed")
    const fb = store.addFinding(b.id, { title: "three", severity: "info", target: "b.test" })
    store.updateFindingStatus(fb.id, "rejected")
    // give the two ops distinct updated_at values so the updated_at DESC order is deterministic
    store.close()
    const db = openRaw(dir)
    db.run("UPDATE operations SET updated_at = '2025-01-01T00:00:01.000Z' WHERE id = ?", [a.id])
    db.run("UPDATE operations SET updated_at = '2025-01-01T00:00:02.000Z' WHERE id = ?", [b.id])
    db.close()
    const reopened = HopperStore.open(dir)
    const list = reopened.listOperationsWithCounts()
    expect(list.map((o) => o.id)).toEqual([b.id, a.id]) // updated_at DESC
    expect(list.find((o) => o.id === a.id)?.findings).toEqual({
      candidate: 1,
      observed: 1,
      verified: 0,
      reportable: 0,
      rejected: 0,
      stale: 0,
    })
    expect(list.find((o) => o.id === b.id)?.findings).toEqual({
      candidate: 0,
      observed: 0,
      verified: 0,
      reportable: 0,
      rejected: 1,
      stale: 0,
    })
    reopened.close()
  })

  test("an operation without findings reports all-zero counts", () => {
    const { store } = openStore()
    const op = store.createOperation("empty", "empty.test")
    const list = store.listOperationsWithCounts()
    expect(list.find((o) => o.id === op.id)?.findings).toEqual({
      candidate: 0,
      observed: 0,
      verified: 0,
      reportable: 0,
      rejected: 0,
      stale: 0,
    })
    store.close()
  })
})

describe("operation tool shape", () => {
  test("tool has description and executable content", () => {
    const t = buildTools("/tmp").find((x) => x.name === "operation")!
    expect(t.description.length).toBeGreaterThan(10)
    expect(typeof t.execute).toBe("function")
  })
})
