/**
 * The ledger's selected lifecycle tab, stored in the HOST's plugin storage
 * (key: plugin.hopper-tui.ledgerTab). Host storage is the one state mechanism
 * proven to update plugin UI in this TUI (the sidebar collapse uses it, as
 * does upstream's MCP view state) — and it syncs across TUI instances.
 * Both the sidebar (aim + open) and the panel read/write the same key.
 */
export const LEDGER_TAB_KEY = "ledgerTab"

export interface LedgerTabState {
  status: string
}

export interface StorageLike {
  store: <T>(key: string, opts: { initial: T }) => [T, (fn: (draft: T) => T | void) => Promise<void>]
}

export function ledgerTabStore(storage: StorageLike) {
  return storage.store<LedgerTabState>(LEDGER_TAB_KEY, { initial: { status: "candidate" } })
}
