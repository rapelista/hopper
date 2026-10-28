import { For, Show } from "solid-js"
import { Hopper, type FindingSummary, type OperationStatusResult } from "../rpc"
import { LIFECYCLE, cycleStatus, severityToken, statusInitial, severityShort } from "./format"
import { resolveToken, resolveActiveBackground, type HopperTheme } from "./theme"
import { ledgerTabStore, type StorageLike } from "./ledger-tab"
import type { HopperRpcClient } from "./status"

/**
 * Surface 2 — the findings ledger panel, tabbed per lifecycle status.
 * State lives in the HOST's plugin storage (the mechanism proven to drive
 * plugin UI updates here): ledgerTab for the selected tab, ledgerModel as
 * the refreshed cache. left/right cycle, 1–6 jump, click a tab to switch,
 * escape closes. The keymap layer is created inside the component, so it
 * lives and dies with the panel (diff-viewer idiom).
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
  ui: {
    slot: (spec: { append: string; render: (input: { name?: string; close?: () => void }) => unknown }) => () => void
    panel?: { open: (name: string) => boolean; close: () => void }
  }
  client: { rpc: (def: unknown) => HopperRpcClient & { findings: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: FindingSummary[] }> } }
  keymap?: { layer: (layer: unknown) => () => void }
  storage?: StorageLike
  theme?: HopperTheme
  location?: unknown
}

/** in-memory stand-in when host storage is unavailable (tests): plain object state */
export function fallbackStorage(): StorageLike {
  const states = new Map<string, unknown>()
  return {
    store: <T,>(key: string, opts: { initial: T }): [T, (fn: (draft: T) => T | void) => Promise<void>] => {
      if (!states.has(key)) states.set(key, opts.initial)
      const state = states.get(key) as T
      const update = async (fn: (draft: T) => T | void) => {
        const draft = states.get(key) as T
        const result = fn(draft)
        if (result !== undefined) states.set(key, result)
      }
      return [state, update]
    },
  }
}

export function registerPanel(ctx: PanelCtx): { cleanup: () => void; model: () => PanelModel } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  const storage = ctx.storage ?? fallbackStorage()
  const [modelStore, updateModel] = storage.store<{ value: PanelModel }>("ledgerModel", {
    initial: { value: buildPanelModel(null, []) },
  })
  const [tabState, updateTab] = ledgerTabStore(storage)
  const setTabStatus = (status: string) => void updateTab((draft) => { draft.status = status }).catch(() => {})

  const refresh = async () => {
    try {
      const [status, findings] = await Promise.all([rpc.operationStatus({}, opts()), rpc.findings({}, opts())])
      await updateModel((draft) => {
        draft.value = buildPanelModel(status, findings.items)
      })
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
      render: (panel: { name?: string; close?: () => void }) =>
        panel.name === "hopper.ledger" ? (
          <LedgerPanel
            ctx={ctx}
            model={() => modelStore.value}
            tab={() => tabState.status}
            setTab={setTabStatus}
            close={panel.close}
          />
        ) : null,
    }),
  ]

  return { model: () => modelStore.value, cleanup: () => stops.forEach((stop) => stop()) }
}

function LedgerPanel(props: {
  ctx: PanelCtx
  model: () => PanelModel
  tab: () => string
  setTab: (status: string) => void
  close?: () => void
}) {
  const theme = props.ctx.theme
  const base = resolveToken(theme, "base")
  const muted = resolveToken(theme, "muted")
  const activeBg = resolveActiveBackground(theme)
  const tab = props.tab
  const setTab = props.setTab
  const close = () => (props.close ? props.close() : props.ctx.ui.panel?.close())

  // Panel-scoped keymap: created in the component, disposed with it (diff-viewer idiom)
  props.ctx.keymap?.layer(() => ({
    commands: [
      { id: "hopper.ledger.close", bind: "escape", title: "Close the ledger", run: close },
      { id: "hopper.ledger.tab.next", bind: "right", title: "Next lifecycle tab", run: () => setTab(cycleStatus(tab(), 1)) },
      { id: "hopper.ledger.tab.prev", bind: "left", title: "Previous lifecycle tab", run: () => setTab(cycleStatus(tab(), -1)) },
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
            onMouseUp={() => setTab(status)}
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
