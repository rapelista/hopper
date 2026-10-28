import { describe, expect, test } from "bun:test"
import { Hopper } from "../src/rpc"

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
