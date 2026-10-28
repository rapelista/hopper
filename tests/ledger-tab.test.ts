import { describe, expect, test } from "bun:test"
import { ledgerTab } from "../src/tui/ledger-tab"
import { createRoot, createMemo } from "solid-js"

describe("shared ledger tab signal (cross-module, client solid build)", () => {
  test("memo recomputes on set — the server-build regression pin", () => {
    const seen: string[] = []
    createRoot((dispose) => {
      const view = createMemo(() => ledgerTab.get())
      seen.push(view())
      ledgerTab.set("verified")
      seen.push(view())
      ledgerTab.set("rejected")
      seen.push(view())
      dispose()
    })
    ledgerTab.reset()
    expect(seen).toEqual(["candidate", "verified", "rejected"])
  })

  test("update-function form works too (panel arrows use it)", () => {
    ledgerTab.reset()
    ledgerTab.set((t) => (t === "candidate" ? "observed" : t))
    expect(ledgerTab.get()).toBe("observed")
    ledgerTab.reset()
  })
})
