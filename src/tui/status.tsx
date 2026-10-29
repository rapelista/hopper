import { createSignal, For, Show } from "solid-js"
import { Hopper, type OperationListItem, type OperationStatusResult } from "../rpc"
import { LIFECYCLE } from "./format"
import { currentSession } from "./current-session"
import { resolveToken, type HopperTheme } from "./theme"

/**
 * Surface 1 — the operation banner. The always-visible context strip the
 * persona prose called "the operation banner". The kernel is session-bound:
 * the sidebar block resolves through the sidebar slot input's sessionID, and
 * the home footer summarizes every operation cross-op.
 */

export interface HopperRpcClient {
  operationStatus: (input: unknown, options?: { location?: unknown }) => Promise<OperationStatusResult>
  operationsList: (input: unknown, options?: { location?: unknown }) => Promise<{ items: OperationListItem[] }>
  findings?: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: import("../rpc").FindingSummary[] }>
  events: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
}

export interface StatusCtx {
  ui: { slot: (spec: { append: string; render: (input?: { sessionID?: string }) => unknown }) => () => void }
  client: { rpc: (def: unknown) => HopperRpcClient }
  data: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
  storage?: { store: <T>(key: string, opts: { initial: T }) => [T, (fn: (draft: T) => T | void) => Promise<void>] }
  theme?: HopperTheme
  /** rpc calls must carry the plugin's location or the server consults its default registry */
  location?: unknown
  /** Task 9 wires the operation picker; banner row clicks call it — optional so clicks stay no-ops until then. */
  pickOperation?: () => void
}

export function registerStatus(ctx: StatusCtx): { cleanup: () => void; status: () => OperationStatusResult | null } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  // the session whose sidebar is on screen — the banner resolves through it
  const [renderedSession, setRenderedSession] = createSignal<string | undefined>(undefined)
  const [status, setStatus] = createSignal<OperationStatusResult | null>(null)
  const [operations, setOperations] = createSignal<{ items: OperationListItem[] } | null>(null)

  // Ledger section collapse — persisted through storage when available (survives
  // restarts, syncs across TUI instances), solid-signal fallback otherwise.
  const ledgerView = (() => {
    if (ctx.storage) {
      const [view, update] = ctx.storage.store<{ open: boolean }>("ledgerView", { initial: { open: true } })
      return {
        get: () => view,
        toggle: () => void update((draft) => { draft.open = !draft.open }).catch(() => {}),
      }
    }
    const [view, setView] = createSignal<{ open: boolean }>({ open: true })
    return { get: () => view(), toggle: () => setView((d) => ({ open: !d.open })) }
  })()

  const refreshStatus = async () => {
    const sessionID = renderedSession()
    if (sessionID === undefined) return // nothing on screen resolves without a session
    try {
      const result = await rpc.operationStatus({ sessionID }, opts())
      // a reply that crossed a session switch never lands — that would leak one session's op into another's banner
      if (sessionID === renderedSession()) setStatus(result)
    } catch (err) {
      // unreachable server / invalid call — keep the last known state, but leave a trace
      console.error("[hopper-tui] operationStatus failed:", err)
    }
  }

  const refreshOperations = async () => {
    try {
      setOperations(await rpc.operationsList({}, opts()))
    } catch (err) {
      console.error("[hopper-tui] operationsList failed:", err)
    }
  }
  void refreshOperations()

  /** Home footer — cross-op: `hop · <N> ops · <M> findings`; there is no single global active anymore. */
  const footerLine = () => {
    const ops = operations()
    if (ops === null) return "hop · …" // pre-fetch — visually distinct from "no operations"
    if (ops.items.length === 0) return "hop · no operations"
    const findings = ops.items.reduce(
      (n, op) => n + LIFECYCLE.reduce((m, key) => m + (op.findings[key] ?? 0), 0),
      0,
    )
    return `hop · ${ops.items.length} ops · ${findings} findings`
  }
  const footerFg = () => {
    const ops = operations()
    return ops !== null && ops.items.length > 0 ? resolveToken(ctx.theme, "base") : resolveToken(ctx.theme, "muted")
  }

  /** The sidebar block — bound: MCP-list idiom, bold section headers, label/count rows. */
  const renderSidebarBlock = () => {
    const theme = ctx.theme as HopperTheme | undefined
    const base = resolveToken(theme, "base")
    const muted = resolveToken(theme, "muted")
    const s = status()
    if (renderedSession() === undefined || s === null || s.operation === null) {
      // unbound, free, or sessionless — one muted line pointing at the binder
      return <text fg={muted}>hop · no operation — /op to bind</text>
    }
    const pick = () => ctx.pickOperation?.()
    const total = LIFECYCLE.reduce((n, key) => n + (s.findings[key as keyof typeof s.findings] ?? 0), 0)
    return (
      <box flexDirection="column">
        <box flexDirection="row" gap={1} onMouseDown={pick}>
          <text fg={base} flexGrow={1}>
            <b>Operation</b>
          </text>
          <text fg={s.opsec === "strict" ? resolveToken(theme, "error") : muted} wrapMode="none" flexShrink={0}>
            {s.opsec}
          </text>
        </box>
        <box flexDirection="column" onMouseDown={pick}>
          <text fg={base} wrapMode="none" truncate>
            {s.operation.name}
          </text>
          <text fg={muted} wrapMode="none" truncate>
            {s.operation.target}
          </text>
        </box>
        <text> </text>
        <box flexDirection="row" gap={1} onMouseDown={() => ledgerView.toggle()}>
          <text fg={base} flexShrink={0}>
            {ledgerView.get().open ? "▼" : "▶"}
          </text>
          <text fg={base} flexGrow={1} wrapMode="none" truncate>
            <b>Ledger</b>
            <Show when={!ledgerView.get().open}>
              <span style={{ fg: muted }}>{` (${total})`}</span>
            </Show>
          </text>
        </box>
        <Show when={ledgerView.get().open}>
          <For each={LIFECYCLE}>
            {(lifecycle) => (
              <box flexDirection="row" gap={1} onMouseDown={pick}>
                <text fg={base} flexGrow={1} wrapMode="none" truncate>
                  {lifecycle[0]!.toUpperCase() + lifecycle.slice(1)}
                </text>
                <text fg={muted} wrapMode="none" flexShrink={0}>
                  {String(s.findings[lifecycle as keyof typeof s.findings] ?? 0)}
                </text>
              </box>
            )}
          </For>
        </Show>
      </box>
    )
  }

  const stops = [
    rpc.events.on("operation.changed", () => {
      void refreshStatus()
      void refreshOperations()
    }),
    rpc.events.on("finding.changed", () => {
      void refreshStatus()
      void refreshOperations()
    }),
    rpc.events.on("binding.changed", (event) => {
      const data = event.data as { sessionID?: string } | undefined
      // only the rendered session's rebinding swaps the banner — other sessions rebind silently
      if (typeof data?.sessionID === "string" && data.sessionID === renderedSession()) void refreshStatus()
      void refreshOperations()
    }),
    // backstop: a finished agent turn may have mutated the store through tools
    ctx.data.on("session.execution.succeeded", () => void refreshStatus()),
    ctx.ui.slot({
      append: "sidebar.content",
      // SidebarContentInput carries the sidebar's sessionID — both the banner's
      // home and the most reliable "current session" source.
      render: (input?: { sessionID?: string }) => {
        if (input?.sessionID) currentSession.set(input.sessionID)
        const sessionID = input?.sessionID
        if (sessionID !== renderedSession()) {
          setRenderedSession(sessionID)
          // drop the previous session's banner immediately — stale display is a
          // cross-session leak too, and a failed fetch must not pin it permanently
          setStatus(null)
          if (sessionID !== undefined) void refreshStatus()
        }
        return renderSidebarBlock()
      },
    }),
    ctx.ui.slot({
      append: "home.footer.status",
      render: () => <text fg={footerFg()}>{footerLine()}</text>,
    }),
  ]

  return { status, cleanup: () => stops.forEach((stop) => stop()) }
}
