import { createSignal, For, Show } from "solid-js"
import { Hopper, type FindingSummary, type OperationStatusResult } from "../rpc"
import { LIFECYCLE, cycleStatus, severityToken, statusInitial, severityShort } from "./format"
import { resolveToken, resolveActiveBackground, type HopperTheme } from "./theme"
import type { HopperRpcClient } from "./status"

/**
 * Surface 2 — the findings ledger panel, tabbed per lifecycle status.
 * Guiding line: "The TUI is the ledger." Tab bar + list; left/right cycle,
 * 1–6 jump, click a tab to switch. The keymap layer is created inside the
 * component, so it lives and dies with the panel and only fires while the
 * panel owns input (diff-viewer idiom). The kernel is session-bound: the
 * panel resolves through the slot input's sessionID — the bound operation's
 * findings, or the "no active operation" fallback when unbound or free.
 */

export interface PanelModel {
  operation: OperationStatusResult["operation"]
  opsec: OperationStatusResult["opsec"]
  groups: Array<{ status: string; items: FindingSummary[] }>
  /** every lifecycle bucket, empty ones included — the panel's tab source */
  byStatus: Record<string, FindingSummary[]>
}

export function buildPanelModel(status: OperationStatusResult | null, findings: FindingSummary[]): PanelModel {
  const byStatus: Record<string, FindingSummary[]> = {}
  for (const lifecycle of LIFECYCLE) byStatus[lifecycle] = findings.filter((f) => f.status === lifecycle)
  return {
    operation: status?.operation ?? null,
    opsec: status?.opsec ?? "normal",
    groups: LIFECYCLE.map((g) => ({ status: g, items: byStatus[g]! })).filter((g) => g.items.length > 0),
    byStatus,
  }
}

export interface PanelCtx {
  ui: { slot: (spec: { append: string; render: (input: { name?: string; sessionID?: string; toggleFullscreen?: () => void }) => unknown }) => () => void }
  client: { rpc: (def: unknown) => HopperRpcClient & { findings: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: FindingSummary[] }> } }
  keymap?: { layer: (layer: unknown) => () => void }
  theme?: HopperTheme
  location?: unknown
}

export function registerPanel(ctx: PanelCtx): { cleanup: () => void; model: () => PanelModel } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  const [model, setModel] = createSignal<PanelModel>(buildPanelModel(null, []))
  // the session whose panel is on screen — the ledger resolves through it
  // (banner idiom: re-key clears, the reply that crossed the switch never lands)
  const [renderedSession, setRenderedSession] = createSignal<string | undefined>(undefined)

  const refresh = async () => {
    const sessionID = renderedSession()
    if (sessionID === undefined) return // nothing on screen resolves without a session
    try {
      const status = await rpc.operationStatus({ sessionID }, opts())
      if (sessionID !== renderedSession()) return // a reply that crossed a session switch never lands
      if (status.operation === null) {
        // unbound or free — the null-operation model keeps the fallback copy
        setModel(buildPanelModel(status, []))
        return
      }
      const findings = await rpc.findings({ operationId: status.operation.id }, opts())
      if (sessionID !== renderedSession()) return
      setModel(buildPanelModel(status, findings.items))
    } catch (err) {
      console.error("[hopper-tui] panel refresh failed:", err)
    }
  }

  const stops = [
    rpc.events.on("operation.changed", () => void refresh()),
    rpc.events.on("finding.changed", () => void refresh()),
    rpc.events.on("binding.changed", (event) => {
      const data = event.data as { sessionID?: string } | undefined
      // only the rendered session's rebinding swaps the ledger — other sessions rebind silently
      if (typeof data?.sessionID === "string" && data.sessionID === renderedSession()) void refresh()
    }),
    ctx.ui.slot({
      append: "session.panel",
      render: (panel: { name?: string; sessionID?: string; toggleFullscreen?: () => void }) => {
        if (panel.name !== "hopper.ledger") return null
        const sessionID = panel.sessionID
        if (sessionID !== renderedSession()) {
          setRenderedSession(sessionID)
          // drop the previous session's ledger immediately — stale display is a
          // cross-session leak too, and a failed fetch must not pin it permanently
          setModel(buildPanelModel(null, []))
          if (sessionID !== undefined) void refresh()
        }
        return <LedgerPanel ctx={ctx} model={model} toggleFullscreen={panel.toggleFullscreen} />
      },
    }),
  ]

  return { model, cleanup: () => stops.forEach((stop) => stop()) }
}

function LedgerPanel(props: { ctx: PanelCtx; model: () => PanelModel; toggleFullscreen?: () => void }) {
  const theme = props.ctx.theme
  const base = resolveToken(theme, "base")
  const muted = resolveToken(theme, "muted")
  const activeBg = resolveActiveBackground(theme)
  const [tab, setTab] = createSignal<string>("candidate")

  // Panel-scoped keymap: created in the component, disposed with it (diff-viewer idiom)
  props.ctx.keymap?.layer(() => ({
    commands: [
      { id: "hopper.ledger.tab.next", bind: "right", title: "Next lifecycle tab", run: () => setTab((t) => cycleStatus(t, 1)) },
      { id: "hopper.ledger.tab.prev", bind: "left", title: "Previous lifecycle tab", run: () => setTab((t) => cycleStatus(t, -1)) },
      { id: "hopper.ledger.fullscreen", bind: "f", title: "Toggle ledger fullscreen", run: () => props.toggleFullscreen?.() },
      ...LIFECYCLE.map((status, i) => ({
        id: `hopper.ledger.tab.${i + 1}`,
        bind: String(i + 1),
        title: `Jump to ${status}`,
        run: () => setTab(status),
      })),
    ],
  }))

  const items = () => props.model().byStatus[tab()] ?? []

  const tabBar = (
    <box flexDirection="row" gap={1} flexShrink={0} flexWrap="wrap" columnGap={1}>
      <For each={LIFECYCLE}>
        {(status) => (
          <box
            paddingLeft={1}
            paddingRight={1}
            flexShrink={0}
            backgroundColor={tab() === status ? activeBg : undefined}
            onMouseDown={() => setTab(status)}
          >
            <text fg={tab() === status ? base : muted} wrapMode="none">
              {`${statusInitial(status)}${props.model().byStatus[status]!.length}`}
            </text>
          </box>
        )}
      </For>
    </box>
  )

  return (
    <box flexDirection="column" width="100%" height="100%" paddingTop={1} paddingBottom={1} paddingLeft={2} paddingRight={2}>
      <box flexDirection="row" gap={1}>
        <text fg={base} flexGrow={1} wrapMode="none" truncate>
          <b>Ledger</b>
        </text>
        <text fg={muted} wrapMode="none" flexShrink={0}>
          {tab()[0]!.toUpperCase() + tab().slice(1)}
        </text>
      </box>
      <text> </text>
      {tabBar}
      <Show
        when={props.model().operation}
        fallback={<text fg={muted}>no active operation — start one with /pwn</text>}
      >
        <text> </text>
        <Show when={items().length > 0} fallback={<text fg={muted}>{`no ${tab()} findings`}</text>}>
          <For each={items()}>
            {(f) => (
              <box flexDirection="column">
                <box flexDirection="row" gap={1}>
                  <text fg={resolveToken(theme, severityToken(f.severity))} flexShrink={0} wrapMode="none">
                    {`[${severityShort(f.severity)}]`}
                  </text>
                  <text fg={base} wrapMode="none" truncate flexGrow={1} minWidth={0}>
                    {f.title || " "}
                  </text>
                </box>
                {/* URL aligned under the title: badge width (5) + gap (1) */}
                <box paddingLeft={6}>
                  <text fg={muted} wrapMode="none" truncate flexGrow={1} minWidth={0}>
                    {f.target}
                  </text>
                </box>
              </box>
            )}
          </For>
        </Show>
      </Show>
    </box>
  )
}
