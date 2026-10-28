import { createSignal } from "solid-js"
import { Hopper, type OperationStatusResult } from "../rpc"
import { bannerText } from "./format"

/**
 * Surface 1 — the operation banner. The always-visible context strip Hopper's
 * persona prose called "the operation banner": operation → target · opsec +
 * compact findings counts, in the prompt footer and the home footer.
 */

export interface HopperRpcClient {
  operationStatus: (input: unknown) => Promise<OperationStatusResult>
  findings?: (input: { operationId?: string }) => Promise<{ items: import("../rpc").FindingSummary[] }>
  events: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
}

export interface StatusCtx {
  ui: { slot: (spec: { append: string; render: () => unknown }) => () => void }
  client: { rpc: (def: unknown) => HopperRpcClient }
  data: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
  theme?: { text: Record<string, string> }
}

export function registerStatus(ctx: StatusCtx): { cleanup: () => void; status: () => OperationStatusResult | null } {
  const rpc = ctx.client.rpc(Hopper)
  const [status, setStatus] = createSignal<OperationStatusResult | null>(null)

  const refresh = async () => {
    try {
      setStatus(await rpc.operationStatus({}))
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
    if (s === null || s.operation === null) return ctx.theme?.text.muted ?? ""
    return s.opsec === "strict" ? ctx.theme?.text.error ?? "" : ctx.theme?.text.base ?? ""
  }

  const stops = [
    rpc.events.on("operation.changed", () => void refresh()),
    rpc.events.on("finding.changed", () => void refresh()),
    // backstop: a finished agent turn may have mutated the store through tools
    ctx.data.on("session.execution.succeeded", () => void refresh()),
    ctx.ui.slot({
      append: "prompt.footer.status",
      render: () => <text fg={fg()}>{line()}</text>,
    }),
    ctx.ui.slot({
      append: "home.footer.status",
      render: () => <text fg={fg()}>{line()}</text>,
    }),
  ]

  return { status, cleanup: () => stops.forEach((stop) => stop()) }
}
