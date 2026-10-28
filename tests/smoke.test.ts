import { describe, expect, test } from "bun:test"

describe("environment smoke", () => {
  test("runs inside the Hopper repo", () => {
    expect(import.meta.dir).toContain("Hopper")
  })
})
