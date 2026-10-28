import { Hopper, type OperationSummary } from "../rpc"
import { defaultOperationName } from "./format"
import { currentSession } from "./current-session"
import type { HopperRpcClient } from "./status"

/**
 * Surface 3 — interactive flows: `/pwn` (create an operation, confirm-on-replace,
 * kickoff prompt with NO auto-OSINT) and `/opsec` (posture select), plus
 * `/ledger` to open the findings ledger dialog.
 */

export function parsePwnArgument(arg: string): { target?: string } {
  const t = arg.trim()
  return t === "" ? {} : { target: t }
}

export function buildKickoffPrompt(name: string, target: string): string {
  return [
    `Bootstrapping the Hopper operation "${name}" against target ${target}.`,
    "",
    "1. Run the doctor tool and summarize readiness in one line.",
    "2. Draft the engagement plan using PTES phases (scope, recon, enumeration, exploitation, post-exploit, reporting) as a terse checklist.",
    "",
    "Do NOT start passive OSINT or any third-party lookup — the operator will ask explicitly.",
  ].join("\n")
}

export interface CommandsCtx {
  keymap: { layer: (layer: unknown) => () => void }
  ui: {
    dialog: {
      prompt: (i: { title: string; placeholder?: string }) => Promise<string | undefined>
      confirm: (i: { title: string; message: string }) => Promise<boolean>
      select: (i: unknown) => Promise<unknown>
    }
    toast: { show: (t: { title?: string; message: string; variant?: "success" | "error" | "warning" }) => void }
    ledger: { open: () => void }
  }
  client: {
    rpc: (def: unknown) => HopperRpcClient & {
      createOperation: (i: { name: string; target: string }, options?: { location?: unknown }) => Promise<{ operation: OperationSummary }>
      setOpsec: (i: { level: "normal" | "strict" }, options?: { location?: unknown }) => Promise<{ opsec: "normal" | "strict" } | { type: string; message: string }>
    }
  }
  data: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
  session: { prompt: (input: { sessionID: string; text: string }) => Promise<unknown> }
  location?: unknown
}

export function registerCommands(ctx: CommandsCtx): { cleanup: () => void } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  // secondary source: the prompt footer's slot input (see current-session.ts) is primary
  const stopTrack = ctx.data.on("tui.session.select", (event) => {
    const data = event.data as { sessionID?: string } | undefined
    if (data?.sessionID) currentSession.set(data.sessionID)
  })

  const runPwn = async (input?: string) => {
    const { target } = parsePwnArgument(input ?? "")
    let t = target
    if (t === undefined) {
      t = (await ctx.ui.dialog.prompt({ title: "Operation target", placeholder: "localhost:3000 or example.test" }))?.trim()
      if (!t) return // cancelled
    }
    const name = defaultOperationName(t)
    const status = await rpc.operationStatus({}, opts()).catch(() => null)
    if (status?.operation) {
      const replace = await ctx.ui.dialog.confirm({
        title: "Replace active operation?",
        message: `Archiving "${status.operation.name}" (${status.operation.target}) — start "${name}" → ${t}?`,
      })
      if (!replace) return
    }
    let created: { operation: OperationSummary }
    try {
      created = await rpc.createOperation({ name, target: t }, opts())
    } catch (err) {
      console.error("[hopper-tui] createOperation failed:", err)
      ctx.ui.toast.show({
        title: "Hopper",
        message: `createOperation failed: ${JSON.stringify(err)}`,
        variant: "error",
      })
      return
    }
    ctx.ui.toast.show({
      title: "Hopper",
      message: `Operation ${created.operation.name} active — target ${created.operation.target}`,
      variant: "success",
    })
    const sessionID = currentSession.get()
    if (sessionID === undefined) {
      ctx.ui.toast.show({
        title: "Hopper",
        message: "Operation active — open a session and ask for the kickoff plan",
        variant: "warning",
      })
      return
    }
    await ctx.session.prompt({ sessionID, text: buildKickoffPrompt(created.operation.name, created.operation.target) })
  }

  const runOpsec = async () => {
    const status = await rpc.operationStatus({}, opts()).catch(() => null)
    const picked = await ctx.ui.dialog.select({
      title: "Opsec posture",
      current: status?.opsec ?? "normal",
      options: [
        { title: "Normal", value: "normal", description: "Advisory leak warnings in scope dialogs" },
        { title: "Strict", value: "strict", description: "Personas avoid leaky third-party lookups; banner flags strict" },
      ],
    })
    if (picked !== "normal" && picked !== "strict") return
    try {
      const res = await rpc.setOpsec({ level: picked }, opts())
      if (typeof res === "object" && res !== null && "type" in res && (res as { type: string }).type === "no_scope") {
        ctx.ui.toast.show({ title: "Hopper", message: (res as { message?: string }).message ?? "no active scope", variant: "error" })
        return
      }
      ctx.ui.toast.show({ title: "Hopper", message: `opsec: ${picked}`, variant: "success" })
    } catch (err) {
      console.error("[hopper-tui] setOpsec failed:", err)
      ctx.ui.toast.show({ title: "Hopper", message: `setOpsec failed: ${JSON.stringify(err)}`, variant: "error" })
    }
  }

  // keymap layers dispose with the plugin (disable/reload/component dispose) —
  // layer() returns no disposer; only the session tracker needs manual cleanup.
  ctx.keymap.layer(() => ({
    mode: "global",
    commands: [
      {
        id: "hopper.pwn",
        title: "Start a Hopper operation",
        slash: { name: "pwn", arguments: true },
        palette: true,
        run: runPwn,
      },
      {
        id: "hopper.opsec",
        title: "Set the opsec posture",
        slash: { name: "opsec" },
        palette: true,
        run: runOpsec,
      },
      {
        id: "hopper.ledger",
        title: "Open the findings ledger",
        slash: { name: "ledger" },
        palette: true,
        run: () => {
          ctx.ui.ledger.open()
        },
      },
    ],
  }))

  return { cleanup: () => { stopTrack() } }
}
