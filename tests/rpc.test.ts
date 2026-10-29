import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import hopperPlugin, { setUnboundGateFactory } from "../src/index"
import { Hopper } from "../src/rpc"
import { HopperStore } from "../src/lib/store"
import { createUnboundGate, type GuardAsk, type UnboundGate } from "../src/lib/unbound-gate"
import { makeMockCtx } from "./helpers"

let tmpProject: string
let configDir: string

beforeAll(() => {
  tmpProject = join(tmpdir(), "hopper-rpc-" + Date.now())
  configDir = join(tmpProject, ".opencode")
  rmSync(tmpProject, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
})

afterAll(() => {
  rmSync(tmpProject, { recursive: true, force: true })
})

const handlerCtx = () => ({
  error: (type: string, message: string, data: unknown) => ({ type, message, data }),
  signal: new AbortController().signal,
})

async function setup() {
  const m = makeMockCtx(tmpProject)
  await (hopperPlugin as { setup: (ctx: unknown) => Promise<unknown> }).setup(m.ctx)
  return m
}

describe("Hopper rpc contract", () => {
  test("defines the hopper id, ten methods, four events", () => {
    expect(Hopper.id).toBe("hopper")
    expect(Object.keys(Hopper.methods).sort()).toEqual([
      "bind",
      "createOperation",
      "deleteOperation",
      "findings",
      "guardAnswer",
      "operationStatus",
      "operationsList",
      "setOperationStatus",
      "setOpsec",
      "unbind",
    ])
    expect(Object.keys(Hopper.events).sort()).toEqual(["binding.changed", "finding.changed", "guard.ask", "operation.changed"])
  })

  test("setOpsec declares the no_operation error", () => {
    expect(Object.keys((Hopper.methods as Record<string, { errors?: Record<string, unknown> }>).setOpsec!.errors!)).toEqual(["no_operation"])
  })
})

describe("hopper rpc handlers", () => {
  test("server registers the Hopper contract with all ten handlers", async () => {
    const m = await setup()
    expect(m.rpcDefs).toContain(Hopper)
    expect(Object.keys(m.rpcHandlers).sort()).toEqual([
      "bind",
      "createOperation",
      "deleteOperation",
      "findings",
      "guardAnswer",
      "operationStatus",
      "operationsList",
      "setOperationStatus",
      "setOpsec",
      "unbind",
    ])
  })

  test("operationStatus on an empty store", async () => {
    const m = await setup()
    const res = await (m.rpcHandlers.operationStatus as (i: unknown, c: unknown) => Promise<any>)({}, handlerCtx())
    expect(res.operation).toBeNull()
    expect(res.opsec).toBe("normal")
    expect(res.findings).toEqual({ candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 })
  })

  test("createOperation normalizes the target, leaves scope.json to the store, emits operation.changed", async () => {
    const m = await setup()
    const res = await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)(
      { name: "juice", target: "localhost:3000" },
      handlerCtx(),
    )
    expect(res.operation.name).toBe("juice")
    expect(res.operation.target).toBe("localhost")
    // additive create: the handler no longer writes scope.json — the store seeds the scopes row
    expect(existsSync(join(configDir, "scope.json"))).toBe(false)
    expect(m.rpcEvents).toContainEqual({ name: "operation.changed", data: { operationId: res.operation.id } })
  })

  test("setOpsec: missing or unknown operationId → no_operation (controller ruling, Task 1 review)", async () => {
    rmSync(join(configDir, "scope.json"), { force: true })
    const m = await setup()
    await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)({ name: "a", target: "a.test" }, handlerCtx())
    // no implicit active-op pick: an opsec level is always written to a named operation
    const missing = await (m.rpcHandlers.setOpsec as (i: unknown, c: unknown) => Promise<any>)({ level: "strict" }, handlerCtx())
    expect(missing.type).toBe("no_operation")
    const unknown = await (m.rpcHandlers.setOpsec as (i: unknown, c: unknown) => Promise<any>)(
      { operationId: "op_does_not_exist", level: "strict" },
      handlerCtx(),
    )
    expect(unknown.type).toBe("no_operation")
  })

  test("corrupt scope.json relic is ignored: status reads the store rows, setOpsec adjusts them (RF#1)", async () => {
    writeFileSync(join(configDir, "scope.json"), "{corrupt")
    const m = await setup()
    const created = await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)(
      { name: "relic", target: "relic.test" },
      handlerCtx(),
    )
    await (m.rpcHandlers.bind as (i: unknown, c: unknown) => Promise<any>)(
      { sessionID: "ses_relic", operationId: created.operation.id },
      handlerCtx(),
    )
    const status = await (m.rpcHandlers.operationStatus as (i: unknown, c: unknown) => Promise<any>)(
      { sessionID: "ses_relic" },
      handlerCtx(),
    )
    expect(status.opsec).toBe("strict") // from the seeded scope row, not the corrupt file
    const res = await (m.rpcHandlers.setOpsec as (i: unknown, c: unknown) => Promise<any>)(
      { operationId: created.operation.id, level: "normal" },
      handlerCtx(),
    )
    expect(res).toEqual({ opsec: "normal" })
  })

  test("finding tool mutation notifies finding.changed through rpc", async () => {
    const m = await setup()
    const created = await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)(
      { name: "op", target: "b.test" },
      handlerCtx(),
    )
    // Task 7: the finding tool defaults to the session's BOUND op — bind first
    await (m.rpcHandlers.bind as (i: unknown, c: unknown) => Promise<any>)(
      { sessionID: "ses_finding_tool", operationId: created.operation.id },
      handlerCtx(),
    )
    const finding = m.addedTools.find((t) => t.name === "finding")!
    await (finding.execute as (i: unknown, c: unknown) => Promise<unknown>)(
      {
        action: "add",
        title: "XSS reflected",
        severity: "high",
        target: "b.test",
      },
      { sessionID: "ses_finding_tool" },
    )
    expect(m.rpcEvents).toContainEqual({
      name: "finding.changed",
      data: { operationId: created.operation.id, findingId: expect.any(String), status: "candidate" },
    })
    const list = await (m.rpcHandlers.findings as (i: unknown, c: unknown) => Promise<any>)(
      { operationId: created.operation.id },
      handlerCtx(),
    )
    expect(list.items[0]).toMatchObject({ title: "XSS reflected", severity: "high", status: "candidate", target: "b.test" })
  })

  test("findings without operationId returns an empty ledger even with findings around (R7)", async () => {
    const m = await setup()
    const created = await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)(
      { name: "r7", target: "r7.test" },
      handlerCtx(),
    )
    const store = HopperStore.open(configDir)
    try {
      store.addFinding(created.operation.id, { title: "r7 finding", severity: "low", target: "r7.test" })
    } finally {
      store.close()
    }
    // the singleton-era active-op fallback is gone: no operationId reads as empty
    const bare = await (m.rpcHandlers.findings as (i: unknown, c: unknown) => Promise<any>)({}, handlerCtx())
    expect(bare).toEqual({ items: [] })
    const named = await (m.rpcHandlers.findings as (i: unknown, c: unknown) => Promise<any>)(
      { operationId: created.operation.id },
      handlerCtx(),
    )
    expect(named.items).toHaveLength(1)
    expect(named.items[0]).toMatchObject({ title: "r7 finding" })
  })
})

describe("hopper rpc handlers: binding model (spec §6)", () => {
  const handler = (m: { rpcHandlers: Record<string, unknown> }, name: string) =>
    m.rpcHandlers[name] as (i: unknown, c: unknown) => Promise<any>
  const ZERO = { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 }

  test("operationStatus {sessionID}: bound session gets its operation, scope-row opsec, and counts", async () => {
    const m = await setup()
    const created = await handler(m, "createOperation")({ name: "st", target: "Status.Test:8443" }, handlerCtx())
    await handler(m, "bind")({ sessionID: "ses_st", operationId: created.operation.id }, handlerCtx())
    const store = HopperStore.open(configDir)
    try {
      store.addFinding(created.operation.id, { title: "f1", severity: "high", target: "status.test" })
      const f2 = store.addFinding(created.operation.id, { title: "f2", severity: "low", target: "status.test" })
      store.updateFindingStatus(f2.id, "observed")
    } finally {
      store.close()
    }
    const res = await handler(m, "operationStatus")({ sessionID: "ses_st" }, handlerCtx())
    expect(res.operation).toMatchObject({ id: created.operation.id, name: "st", target: "status.test" })
    expect(res.operation.createdAt).toEqual(expect.any(String))
    expect(res.opsec).toBe("strict") // scope rows seed strict
    expect(res.findings).toEqual({ ...ZERO, candidate: 1, observed: 1 })
  })

  test("operationStatus: free, unbound, and missing sessionID read as no-operation even with active ops around", async () => {
    const m = await setup()
    await handler(m, "createOperation")({ name: "idle", target: "idle.test" }, handlerCtx()) // active op exists — must not leak
    const store = HopperStore.open(configDir)
    try {
      store.setFree("ses_rpc_free")
    } finally {
      store.close()
    }
    for (const input of [{ sessionID: "ses_rpc_free" }, { sessionID: "ses_rpc_unbound" }, {}]) {
      const res = await handler(m, "operationStatus")(input, handlerCtx())
      expect(res.operation).toBeNull()
      expect(res.opsec).toBe("normal")
      expect(res.findings).toEqual(ZERO)
    }
  })

  test("operationsList: contract items with status and findings counts", async () => {
    const m = await setup()
    const a = await handler(m, "createOperation")({ name: "la", target: "la.test" }, handlerCtx())
    const b = await handler(m, "createOperation")({ name: "lb", target: "lb.test" }, handlerCtx())
    const store = HopperStore.open(configDir)
    try {
      store.addFinding(a.operation.id, { title: "f", severity: "info", target: "la.test" })
    } finally {
      store.close()
    }
    const res = await handler(m, "operationsList")({}, handlerCtx())
    const itemA = res.items.find((i: any) => i.id === a.operation.id)!
    const itemB = res.items.find((i: any) => i.id === b.operation.id)!
    expect(Object.keys(itemA).sort()).toEqual(["createdAt", "findings", "id", "name", "status", "target"])
    expect(itemA).toMatchObject({ name: "la", target: "la.test", status: "active" })
    expect(itemA.findings).toEqual({ ...ZERO, candidate: 1 })
    expect(itemB.findings).toEqual(ZERO)
  })

  test("bind: upserts the row and emits binding.changed; non-active → not_active; unknown → no_operation", async () => {
    const m = await setup()
    const created = await handler(m, "createOperation")({ name: "ba", target: "ba.test" }, handlerCtx())
    const res = await handler(m, "bind")({ sessionID: "ses_bind", operationId: created.operation.id }, handlerCtx())
    expect(res).toEqual({ operationId: created.operation.id })
    expect(m.rpcEvents).toContainEqual({ name: "binding.changed", data: { sessionID: "ses_bind" } })
    const store = HopperStore.open(configDir)
    let binding: unknown
    try {
      binding = store.getBinding("ses_bind")
    } finally {
      store.close()
    }
    expect(binding).toEqual({ operation_id: created.operation.id, mode: "bound" })
    await handler(m, "setOperationStatus")({ operationId: created.operation.id, status: "completed" }, handlerCtx())
    const na = await handler(m, "bind")({ sessionID: "ses_bind2", operationId: created.operation.id }, handlerCtx())
    expect(na.type).toBe("not_active")
    const no = await handler(m, "bind")({ sessionID: "ses_bind3", operationId: "op_nope" }, handlerCtx())
    expect(no.type).toBe("no_operation")
  })

  test("unbind: clears the row, returns null operationId, emits binding.changed", async () => {
    const m = await setup()
    const created = await handler(m, "createOperation")({ name: "ub", target: "ub.test" }, handlerCtx())
    await handler(m, "bind")({ sessionID: "ses_unbind", operationId: created.operation.id }, handlerCtx())
    const res = await handler(m, "unbind")({ sessionID: "ses_unbind" }, handlerCtx())
    expect(res).toEqual({ operationId: null })
    expect(m.rpcEvents).toContainEqual({ name: "binding.changed", data: { sessionID: "ses_unbind" } })
    const store = HopperStore.open(configDir)
    let binding: unknown
    try {
      binding = store.getBinding("ses_unbind")
    } finally {
      store.close()
    }
    expect(binding).toBeNull()
  })

  test("setOperationStatus: flips status, unbinds and notifies every affected session; unknown → no_operation", async () => {
    const m = await setup()
    const created = await handler(m, "createOperation")({ name: "sos", target: "sos.test" }, handlerCtx())
    await handler(m, "bind")({ sessionID: "ses_sos1", operationId: created.operation.id }, handlerCtx())
    await handler(m, "bind")({ sessionID: "ses_sos2", operationId: created.operation.id }, handlerCtx())
    const res = await handler(m, "setOperationStatus")({ operationId: created.operation.id, status: "completed" }, handlerCtx())
    expect(res).toEqual({ status: "completed" })
    const store = HopperStore.open(configDir)
    let b1: unknown
    let b2: unknown
    try {
      b1 = store.getBinding("ses_sos1")
      b2 = store.getBinding("ses_sos2")
    } finally {
      store.close()
    }
    expect(b1).toBeNull()
    expect(b2).toBeNull()
    expect(m.rpcEvents).toContainEqual({ name: "binding.changed", data: { sessionID: "ses_sos1" } })
    expect(m.rpcEvents).toContainEqual({ name: "binding.changed", data: { sessionID: "ses_sos2" } })
    const list = await handler(m, "operationsList")({}, handlerCtx())
    expect(list.items.find((i: any) => i.id === created.operation.id).status).toBe("completed")
    const no = await handler(m, "setOperationStatus")({ operationId: "op_nope", status: "archived" }, handlerCtx())
    expect(no.type).toBe("no_operation")
  })

  test("deleteOperation: removes the op, notifies affected sessions; unknown → no_operation", async () => {
    const m = await setup()
    const created = await handler(m, "createOperation")({ name: "del", target: "del.test" }, handlerCtx())
    await handler(m, "bind")({ sessionID: "ses_del", operationId: created.operation.id }, handlerCtx())
    const res = await handler(m, "deleteOperation")({ operationId: created.operation.id }, handlerCtx())
    expect(res).toEqual({ ok: true })
    const list = await handler(m, "operationsList")({}, handlerCtx())
    expect(list.items.find((i: any) => i.id === created.operation.id)).toBeUndefined()
    const store = HopperStore.open(configDir)
    let binding: unknown
    try {
      binding = store.getBinding("ses_del")
    } finally {
      store.close()
    }
    expect(binding).toBeNull()
    expect(m.rpcEvents).toContainEqual({ name: "binding.changed", data: { sessionID: "ses_del" } })
    // carry-along (Task 6 minor): the TUI ops list refreshes on operation.changed — a deletion reports the null id
    expect(m.rpcEvents).toContainEqual({ name: "operation.changed", data: { operationId: null } })
    const no = await handler(m, "deleteOperation")({ operationId: "op_nope" }, handlerCtx())
    expect(no.type).toBe("no_operation")
  })

  test("setOpsec: writes the op's scope-row strict flag and emits operation.changed with that id", async () => {
    const m = await setup()
    const created = await handler(m, "createOperation")({ name: "sec", target: "sec.test" }, handlerCtx())
    const res = await handler(m, "setOpsec")({ operationId: created.operation.id, level: "normal" }, handlerCtx())
    expect(res).toEqual({ opsec: "normal" })
    const store = HopperStore.open(configDir)
    let scope: { targets: string[]; strict: boolean } | null = null
    try {
      scope = store.getScope(created.operation.id)
    } finally {
      store.close()
    }
    expect(scope).toEqual({ targets: ["sec.test"], strict: false })
    expect(m.rpcEvents).toContainEqual({ name: "operation.changed", data: { operationId: created.operation.id } })
    const back = await handler(m, "setOpsec")({ operationId: created.operation.id, level: "strict" }, handlerCtx())
    expect(back).toEqual({ opsec: "strict" })
  })

  test("createOperation with sessionID binds it; without sessionID it binds nothing", async () => {
    const m = await setup()
    const res = await handler(m, "createOperation")({ name: "cb", target: "cb.test", sessionID: "ses_create_bind" }, handlerCtx())
    expect(res.operation.target).toBe("cb.test")
    expect(m.rpcEvents).toContainEqual({ name: "operation.changed", data: { operationId: res.operation.id } })
    expect(m.rpcEvents).toContainEqual({ name: "binding.changed", data: { sessionID: "ses_create_bind" } })
    await handler(m, "createOperation")({ name: "cb2", target: "cb2.test" }, handlerCtx())
    expect(m.rpcEvents.filter((e) => e.name === "binding.changed")).toEqual([
      { name: "binding.changed", data: { sessionID: "ses_create_bind" } },
    ])
    const store = HopperStore.open(configDir)
    let resolution: unknown
    try {
      resolution = store.resolveSession("ses_create_bind")
    } finally {
      store.close()
    }
    expect((resolution as { mode: string; operation?: { id: string } }).operation!.id).toBe(res.operation.id)
  })

  test("guardAnswer: malformed bind (no operationId) → accepted:false with the ask still pending; real answers resolve; stale asks are refused", async () => {
    const emitted: GuardAsk[] = []
    let gateRef: UnboundGate | undefined
    setUnboundGateFactory((forwardAsk) => {
      gateRef = createUnboundGate({
        timeoutMs: 60_000,
        emit: (ask) => {
          emitted.push(ask)
          forwardAsk(ask)
        },
      })
      return gateRef
    })
    try {
      const m = await setup()
      const hook = m.toolHooks["execute.before"]! as (event: unknown) => Promise<void>
      const pending = hook({
        sessionID: "ses_ga",
        agent: "pentest",
        messageID: "msg_ga",
        id: "call_ga",
        tool: "webfetch",
        input: { url: "https://evil.test/x" },
      })
      for (let i = 0; emitted.length === 0 && i < 100; i++) await new Promise((r) => setTimeout(r, 5))
      expect(emitted.length).toBe(1)
      const askId = emitted[0]!.askId
      // controller ruling: never write a NULL-op bound row — the type-safe refusal keeps the ask pending
      const bad = await handler(m, "guardAnswer")({ askId, choice: "bind" }, handlerCtx())
      expect(bad).toEqual({ accepted: false })
      expect(gateRef!.pending()).toEqual([askId])
      // carry-along (Task 6 minor): a bind naming a NONEXISTENT operation is refused the same way
      const ghost = await handler(m, "guardAnswer")({ askId, choice: "bind", operationId: "op_ghost" }, handlerCtx())
      expect(ghost).toEqual({ accepted: false })
      expect(gateRef!.pending()).toEqual([askId])
      const ok = await handler(m, "guardAnswer")({ askId, choice: "deny" }, handlerCtx())
      expect(ok).toEqual({ accepted: true })
      await expect(pending).rejects.toThrow("[hopper] operator denied:")
      const stale = await handler(m, "guardAnswer")({ askId, choice: "allow-once" }, handlerCtx())
      expect(stale).toEqual({ accepted: false })
      // a well-formed bind answer resolves through the gate and persists the binding
      const pending2 = hook({
        sessionID: "ses_ga2",
        agent: "pentest",
        messageID: "msg_ga2",
        id: "call_ga2",
        tool: "webfetch",
        input: { url: "https://evil.test/x" },
      })
      for (let i = 0; emitted.length === 1 && i < 100; i++) await new Promise((r) => setTimeout(r, 5))
      const created = await handler(m, "createOperation")({ name: "ga", target: "ga.test" }, handlerCtx())
      const bound = await handler(m, "guardAnswer")(
        { askId: emitted[1]!.askId, choice: "bind", operationId: created.operation.id },
        handlerCtx(),
      )
      expect(bound).toEqual({ accepted: true })
      await expect(pending2).resolves.toBeUndefined()
    } finally {
      setUnboundGateFactory(null)
    }
  })
})
