import { createSignal } from "solid-js"
import { Hopper, type FindingSummary, type OperationStatusResult } from "../rpc"
import { groupFindings, severityToken } from "./format"
import { resolveToken, type HopperTheme } from "./theme"
import type { HopperRpcClient } from "./status"

/**
 * Surface 2 — the findings ledger panel. Hopper: "The TUI is the ledger."
 * One session.panel contribution (`hopper.ledger`) grouping findings along
 * the lifecycle, severity-colored through theme tokens.
 */

export interface PanelModel {
  operation: OperationStatusResult["operation"]
  opsec: OperationStatusResult["opsec"]
  groups: Array<{ status: string; items: FindingSummary[] }>
}

export function buildPanelModel(status: OperationStatusResult | null, findings: FindingSummary[]): PanelModel {
  return {
    operation: status?.operation ?? null,
    opsec: status?.opsec ?? "normal",
    groups: groupFindings(findings),
  }
}

export interface PanelCtx {
  ui: { slot: (spec: { append: string; render: (input: { name?: string }) => unknown }) => () => void }
  client: { rpc: (def: unknown) => HopperRpcClient & { findings: (input: { operationId?: string }, options?: { location?: unknown }) => Promise<{ items: FindingSummary[] }> } }
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

  const token = (severity: string) => resolveToken(ctx.theme as HopperTheme | undefined, severityToken(severity))
  const groupToken = (status: string) => {
    if (status === "reportable" || status === "verified") return resolveToken(ctx.theme as HopperTheme | undefined, "base")
    if (status === "rejected" || status === "stale") return resolveToken(ctx.theme as HopperTheme | undefined, "muted")
    return resolveToken(ctx.theme as HopperTheme | undefined, "warning")
  }

  const stops = [
    rpc.events.on("operation.changed", () => void refresh()),
    rpc.events.on("finding.changed", () => void refresh()),
    ctx.ui.slot({
      append: "session.panel",
      render: (panel: { name?: string; toggleFullscreen?: () => void }) =>
        panel.name === "hopper.ledger" ? renderPanel(model(), token, groupToken) : null,
    }),
  ]

  return { model, cleanup: () => stops.forEach((stop) => stop()) }
}

function renderPanel(
  m: PanelModel,
  token: (severity: string) => string,
  groupToken: (status: string) => string,
) {
  if (m.operation === null) {
    return (
      <text fg="">
        no active operation — start one with /pwn
      </text>
    )
  }
  if (m.groups.length === 0) {
    return (
      <text fg="">
        {`${m.operation.name} → ${m.operation.target} · ${m.opsec} · no findings yet`}
      </text>
    )
  }
  return (
    <box flexDirection="column" gap={0}>
      <text fg="">{`${m.operation.name} → ${m.operation.target} · ${m.opsec}`}</text>
      {m.groups.map((group) => (
        <box flexDirection="column">
          <text fg={groupToken(group.status)}>{`${group.status} (${group.items.length})`}</text>
          {group.items.map((f) => (
            <text fg={token(f.severity)}>{`  [${f.severity}] ${f.title} — ${f.target}`}</text>
          ))}
        </box>
      ))}
    </box>
  )
}
