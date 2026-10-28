import { createSignal, For, Show } from "solid-js"
import { Hopper, type FindingSummary, type OperationStatusResult } from "../rpc"
import { LIFECYCLE, cycleStatus, severityToken, statusInitial } from "./format"
import { resolveToken, resolveActiveBackground, type HopperTheme } from "./theme"
import type { HopperRpcClient } from "./status"

/**
 * Surface 2 — the findings ledger panel, tabbed per lifecycle status.
 * Hopper: "The TUI is the ledger." Tab bar + list; left/right cycle,
 * 1–6 jump, click a tab to switch. The keymap layer is created inside the
 * component, so it lives and dies with the panel and only fires while the
 * panel owns input (diff-viewer idiom).
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
  ui: { slot: (spec: { append: string; render: (input: { name?: string }) => unknown }) => () => void }
  client: { rpc: (def: unknown) => HopperRpcClient & { findings: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: FindingSummary[] }> } }
  keymap?: { layer: (layer: unknown) => () => void }
  theme?: HopperTheme
  location?: unknown
}

export function registerPanel(ctx: PanelCtx): { cleanup: () => void; model: () => PanelModel } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  const [model, setModel] = createSignal<PanelModel>(buildPanelModel(null, []))

  const refresh = async () => {
    try {
      const [status, findings] = await Promise.all([rpc.operationStatus({}, opts()), rpc.findings({}, opts())])
      setModel(buildPanelModel(status, findings.items))
    } catch (err) {
      console.error("[hopper-tui] panel refresh failed:", err)
    }
  }
  void refresh()

  const stops = [
    rpc.events.on("operation.changed", () => void refresh()),
    rpc.events.on("finding.changed", () => void refresh()),
    ctx.ui.slot({
      append: "session.panel",
      render: (panel: { name?: string }) =>
        panel.name === "hopper.ledger" ? <LedgerPanel ctx={ctx} model={model} /> : null,
    }),
  ]

  return { model, cleanup: () => stops.forEach((stop) => stop()) }
}

function LedgerPanel(props: { ctx: PanelCtx; model: () => PanelModel }) {
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
    <box flexDirection="row" gap={1} flexShrink={0}>
      <For each={LIFECYCLE}>
        {(status) => {
          const active = status === tab()
          return (
            <box
              paddingLeft={1}
              paddingRight={1}
              flexShrink={0}
              backgroundColor={active ? activeBg : undefined}
              onMouseDown={() => setTab(status)}
            >
              <text fg={active ? base : muted} wrapMode="none">
                {`${statusInitial(status)}${props.model().byStatus[status]!.length}`}
              </text>
            </box>
          )
        }}
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
              <box flexDirection="row" gap={1}>
                <text fg={resolveToken(theme, severityToken(f.severity))} flexShrink={0}>
                  [{f.severity}]
                </text>
                <text fg={base} wrapMode="none" truncate flexGrow={1}>
                  {f.title}
                </text>
                <text fg={muted} wrapMode="none" truncate flexShrink={0}>
                  {f.target}
                </text>
              </box>
            )}
          </For>
        </Show>
      </Show>
    </box>
  )
}
