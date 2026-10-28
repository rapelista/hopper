import { createSignal, For, Show, onMount, onCleanup } from "solid-js"
import { Hopper, type FindingSummary, type OperationStatusResult } from "../rpc"
import { LIFECYCLE, cycleStatus, severityToken, statusInitial, severityShort } from "./format"
import { resolveToken, resolveActiveBackground, type HopperTheme } from "./theme"
import type { HopperRpcClient } from "./status"

/**
 * Surface 2 — the findings ledger as a modal dialog. Hopper: "The TUI is the
 * ledger." Wider canvas than the side panel (tabs never squeeze), escape closes
 * natively, and the tab state is a local component signal — the pattern proven
 * to update plugin UI here. left/right cycle, 1–6 jump, click a tab to switch.
 */

export interface PanelModel {
  operation: OperationStatusResult["operation"]
  opsec: OperationStatusResult["opsec"]
  groups: Array<{ status: string; items: FindingSummary[] }>
  /** every lifecycle bucket, empty ones included — the dialog's tab source */
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

export interface LedgerCtx {
  ui: {
    dialog: {
      set: (options: { size?: "large" | "xlarge"; centered?: boolean }) => void
      show: (render: () => unknown, onClose?: () => void) => void
    }
  }
  client: { rpc: (def: unknown) => HopperRpcClient & { findings: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: FindingSummary[] }> } }
  keymap?: { layer: (layer: unknown) => () => void }
  theme?: HopperTheme
  location?: unknown
}

export function registerLedger(ctx: LedgerCtx): { cleanup: () => void; open: () => void; model: () => PanelModel | null } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  const [model, setModel] = createSignal<PanelModel | null>(null)

  const refresh = async () => {
    try {
      const [status, findings] = await Promise.all([rpc.operationStatus({}, opts()), rpc.findings({}, opts())])
      setModel(buildPanelModel(status, findings.items))
    } catch (err) {
      console.error("[hopper-tui] ledger refresh failed:", err)
    }
  }
  void refresh()

  const stops = [
    rpc.events.on("operation.changed", () => void refresh()),
    rpc.events.on("finding.changed", () => void refresh()),
  ]

  const open = () => {
    try {
      // upstream order (btw.tsx): show first, then set — set() applies to the ACTIVE dialog
      ctx.ui.dialog.show(() => <LedgerDialog ctx={ctx} model={model} />)
      ctx.ui.dialog.set({ size: "xlarge", centered: true })
    } catch (err) {
      console.error("[hopper-tui] ledger dialog failed to open:", err)
    }
  }

  return { open, model, cleanup: () => stops.forEach((stop) => stop()) }
}

function LedgerDialog(props: { ctx: LedgerCtx; model: () => PanelModel | null }) {
  const theme = props.ctx.theme
  const base = resolveToken(theme, "base")
  const muted = resolveToken(theme, "muted")
  const activeBg = resolveActiveBackground(theme)
  const [tab, setTab] = createSignal<string>("candidate")

  // Dialog-scoped keymap: created after mount (never during render — no
  // upstream dialog creates layers inline), disposed with the dialog
  onMount(() => {
    const stop = props.ctx.keymap?.layer(() => ({
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
    if (stop) onCleanup(stop)
  })

  const m = () => props.model() ?? buildPanelModel(null, [])
  const items = () => m().byStatus[tab()] ?? []

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
              {`${statusInitial(status)}${m().byStatus[status]!.length}`}
            </text>
          </box>
        )}
      </For>
    </box>
  )

  return (
    <box flexDirection="column" paddingTop={1} paddingBottom={1} paddingLeft={2} paddingRight={2}>
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
      <Show when={m().operation} fallback={<text fg={muted}>no active operation — start one with /pwn</text>}>
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
