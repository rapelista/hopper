import { describe, expect, test } from "bun:test"
import { fallbackStorage } from "../src/tui/panel"

describe("fallback storage (host-storage stand-in for tests)", () => {
  test("stores, mutates drafts, and memoizes per key", async () => {
    const storage = fallbackStorage()
    const [state, update] = storage.store<{ status: string }>("ledgerTab", { initial: { status: "candidate" } })
    expect(state.status).toBe("candidate")
    await update((draft) => {
      draft.status = "verified"
    })
    expect(state.status).toBe("verified") // object mutation visible through the same reference
    const [again] = storage.store<{ status: string }>("ledgerTab", { initial: { status: "candidate" } })
    expect(again).toBe(state) // memoized — one instance per key
  })
})
