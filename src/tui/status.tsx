import { createSignal, For, Show } from "solid-js"
import { Hopper, type OperationStatusResult } from "../rpc"
import { bannerText, LIFECYCLE } from "./format"
import { currentSession } from "./current-session"
import { resolveToken, type HopperTheme } from "./theme"

/**
 * Surface 1 — the operation banner. The always-visible context strip Hopper's
 * persona prose called "the operation banner": operation → target · opsec +
 * compact findings counts, in the prompt footer and the home footer.
 */

export interface HopperRpcClient {
  operationStatus: (input: unknown, options?: { location?: unknown }) => Promise<OperationStatusResult>
  findings?: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: import("../rpc").FindingSummary[] }>
  events: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
}

export interface StatusCtx {
  ui: {
    slot: (spec: { append: string; render: (input?: { sessionID?: string }) => unknown }) => () => void
    panel?: { open: (name: string) => boolean }
  }
  client: { rpc: (def: unknown) => HopperRpcClient }
  data: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
  storage?: { store: <T>(key: string, opts: { initial: T }) => [T, (fn: (draft: T) => T | void) => Promise<void>] }
  theme?: HopperTheme
  /** rpc calls must carry the plugin's location or the server consults its default registry */
  location?: unknown
}

export function registerStatus(ctx: StatusCtx): { cleanup: () => void; status: () => OperationStatusResult | null } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  const [status, setStatus] = createSignal<OperationStatusResult | null>(null)

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

  const refresh = async () => {
    try {
      setStatus(await rpc.operationStatus({}, opts()))
    } catch (err) {
      // unreachable server / invalid call — keep the last known state, but leave a trace
      console.error("[hopper-tui] operationStatus failed:", err)
    }
  }
  void refresh()

  const line = () => {
    const s = status()
    if (s === null) return "hop"
    return bannerText({ operation: s.operation, opsec: s.opsec, counts: s.findings })
  }
  const fg = () => {
    const s = status()
    if (s === null || s.operation === null) return resolveToken(ctx.theme, "muted")
    return s.opsec === "strict" ? resolveToken(ctx.theme, "error") : resolveToken(ctx.theme, "base")
  }

  /** The sidebar block — MCP-list idiom: bold section headers, label/count rows. */
  const renderSidebarBlock = (s: OperationStatusResult | null) => {
    const theme = ctx.theme as HopperTheme | undefined
    const base = resolveToken(theme, "base")
    const muted = resolveToken(theme, "muted")
    if (s === null || s.operation === null) {
      return <text fg={muted}>hop · no operation</text>
    }
    const total = LIFECYCLE.reduce((n, key) => n + (s.findings[key as keyof typeof s.findings] ?? 0), 0)
    return (
      <box flexDirection="column">
        <box flexDirection="row" gap={1}>
          <text fg={base} flexGrow={1}>
            <b>Operation</b>
          </text>
          <text fg={s.opsec === "strict" ? resolveToken(theme, "error") : muted} wrapMode="none" flexShrink={0}>
            {s.opsec}
          </text>
        </box>
        <text fg={base} wrapMode="none" truncate>
          {s.operation.name}
        </text>
        <text fg={muted} wrapMode="none" truncate>
          {s.operation.target}
        </text>
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
              <box
                flexDirection="row"
                gap={1}
                onMouseDown={() => {
                  // aim the ledger panel at this lifecycle, then open it —
                  // same host-storage key the panel reads (plugin.hopper-tui.ledgerTab)
                  void ctx.storage
                    ?.store<{ status: string }>("ledgerTab", { initial: { status: "candidate" } })[1]((draft) => {
                      draft.status = lifecycle
                    })
                    .catch(() => {})
                  ctx.ui.panel?.open("hopper.ledger")
                }}
              >
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
    rpc.events.on("operation.changed", () => void refresh()),
    rpc.events.on("finding.changed", () => void refresh()),
    // backstop: a finished agent turn may have mutated the store through tools
    ctx.data.on("session.execution.succeeded", () => void refresh()),
    ctx.ui.slot({
      append: "sidebar.content",
      // SidebarContentInput carries the sidebar's sessionID — both the banner's
      // home and the most reliable "current session" source.
      render: (input?: { sessionID?: string }) => {
        if (input?.sessionID) currentSession.set(input.sessionID)
        return renderSidebarBlock(status())
      },
    }),
    ctx.ui.slot({
      append: "home.footer.status",
      render: () => <text fg={fg()}>{line()}</text>,
    }),
  ]

  return { status, cleanup: () => stops.forEach((stop) => stop()) }
}
