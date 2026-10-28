import { createSignal } from "./solid"

/**
 * The ledger's selected lifecycle tab, shared so the sidebar rows can aim the
 * panel at a status before opening it. Module-level signal — one tab state per
 * plugin instance (hot-reload resets it harmlessly).
 */
const [tab, setTab] = createSignal<string>("candidate")

export const ledgerTab = {
  get: tab,
  set: setTab,
  /** test isolation */
  reset(): void {
    setTab("candidate")
  },
}
