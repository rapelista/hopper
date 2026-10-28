import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { HopperStore } from "../.opencode/lib/store"
import { existsSync, readFileSync } from "node:fs"
import operation from "../.opencode/tools/operation"

let configDir: string

beforeAll(() => {
  configDir = join(tmpdir(), "hopper-t10-" + Date.now())
  rmSync(configDir, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
})

afterAll(() => {
  rmSync(configDir, { recursive: true, force: true })
})

describe("HopperStore operations", () => {
  test("createOperation makes the operation active", () => {
    const store = HopperStore.open(configDir)
    const op = store.createOperation("juice-shop", "http://localhost:3000")
    expect(op.status).toBe("active")
    expect(op.name).toBe("juice-shop")
    const active = store.getActiveOperation()
    expect(active?.id).toBe(op.id)
    store.close()
  })

  test("creating a second operation archives the first", () => {
    const store = HopperStore.open(configDir)
    const first = store.getActiveOperation()!
    const second = store.createOperation("dvwa", "http://localhost:8080")
    const ops = store.listOperations()
    expect(ops.find((o) => o.id === first.id)?.status).toBe("archived")
    expect(ops.find((o) => o.id === second.id)?.status).toBe("active")
    expect(store.getActiveOperation()?.id).toBe(second.id)
    store.close()
  })

  test("data persists across close and reopen", () => {
    const store = HopperStore.open(configDir)
    const before = store.listOperations().length
    store.close()
    const reopened = HopperStore.open(configDir)
    expect(reopened.listOperations().length).toBe(before)
    expect(reopened.getActiveOperation()?.name).toBe("dvwa")
    reopened.close()
  })

  test("createOperation writes the scope file", () => {
    const store = HopperStore.open(configDir)
    store.createOperation("scoped-op", "lab.example.test")
    store.close()
    const scope = JSON.parse(readFileSync(join(configDir, "scope.json"), "utf8")) as { targets: string[] }
    expect(scope.targets).toEqual(["lab.example.test"])
    expect(existsSync(join(configDir, "data", "hopper.db"))).toBe(true)
  })
})

describe("operation tool shape", () => {
  test("default export has description and execute", () => {
    const t = operation as { description: string; execute: (args: Record<string, unknown>) => Promise<string> }
    expect(t.description.length).toBeGreaterThan(10)
    expect(typeof t.execute).toBe("function")
  })
})
