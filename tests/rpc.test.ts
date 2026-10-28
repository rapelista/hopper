import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import hopperPlugin from "../src/index"
import { Hopper } from "../src/rpc"
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
  test("defines the hopper id, four methods, two events", () => {
    expect(Hopper.id).toBe("hopper")
    expect(Object.keys(Hopper.methods).sort()).toEqual(["createOperation", "findings", "operationStatus", "setOpsec"])
    expect(Object.keys(Hopper.events).sort()).toEqual(["finding.changed", "operation.changed"])
  })

  test("setOpsec declares the no_scope error", () => {
    expect(Object.keys((Hopper.methods as Record<string, { errors?: Record<string, unknown> }>).setOpsec!.errors!)).toContain("no_scope")
  })
})

describe("hopper rpc handlers", () => {
  test("server registers the Hopper contract with all four handlers", async () => {
    const m = await setup()
    expect(m.rpcDefs).toContain(Hopper)
    expect(Object.keys(m.rpcHandlers).sort()).toEqual(["createOperation", "findings", "operationStatus", "setOpsec"])
  })

  test("operationStatus on an empty store", async () => {
    const m = await setup()
    const res = await (m.rpcHandlers.operationStatus as (i: unknown, c: unknown) => Promise<any>)({}, handlerCtx())
    expect(res.operation).toBeNull()
    expect(res.opsec).toBe("normal")
    expect(res.findings).toEqual({ candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 })
  })

  test("createOperation normalizes the target, writes scope, emits operation.changed", async () => {
    const m = await setup()
    const res = await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)(
      { name: "juice", target: "localhost:3000" },
      handlerCtx(),
    )
    expect(res.operation.name).toBe("juice")
    expect(res.operation.target).toBe("localhost")
    const scope = JSON.parse(readFileSync(join(configDir, "scope.json"), "utf8"))
    expect(scope.targets).toEqual(["localhost"])
    expect(m.rpcEvents).toContainEqual({ name: "operation.changed", data: { operationId: res.operation.id } })
  })

  test("setOpsec flips strict and emits; no scope file → no_scope error", async () => {
    rmSync(join(configDir, "scope.json"))
    const m = await setup()
    const no = await (m.rpcHandlers.setOpsec as (i: unknown, c: unknown) => Promise<any>)({ level: "strict" }, handlerCtx())
    expect(no.type).toBe("no_scope")
    await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)({ name: "a", target: "a.test" }, handlerCtx())
    const res = await (m.rpcHandlers.setOpsec as (i: unknown, c: unknown) => Promise<any>)({ level: "normal" }, handlerCtx())
    expect(res.opsec).toBe("normal")
    expect(JSON.parse(readFileSync(join(configDir, "scope.json"), "utf8")).strict).toBe(false)
    expect(m.rpcEvents.some((e) => e.name === "operation.changed")).toBe(true)
  })

  test("corrupt scope.json: operationStatus stays normal, setOpsec → no_scope (RF#1)", async () => {
    writeFileSync(join(configDir, "scope.json"), "{corrupt")
    const m = await setup()
    const status = await (m.rpcHandlers.operationStatus as (i: unknown, c: unknown) => Promise<any>)({}, handlerCtx())
    expect(status.opsec).toBe("normal")
    const err = await (m.rpcHandlers.setOpsec as (i: unknown, c: unknown) => Promise<any>)({ level: "strict" }, handlerCtx())
    expect(err.type).toBe("no_scope")
  })

  test("finding tool mutation notifies finding.changed through rpc", async () => {
    const m = await setup()
    const created = await (m.rpcHandlers.createOperation as (i: unknown, c: unknown) => Promise<any>)(
      { name: "op", target: "b.test" },
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
      handlerCtx(),
    )
    expect(m.rpcEvents).toContainEqual({
      name: "finding.changed",
      data: { operationId: created.operation.id, findingId: expect.any(String), status: "candidate" },
    })
    const list = await (m.rpcHandlers.findings as (i: unknown, c: unknown) => Promise<any>)({}, handlerCtx())
    expect(list.items[0]).toMatchObject({ title: "XSS reflected", severity: "high", status: "candidate", target: "b.test" })
  })
})
