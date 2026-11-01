import { Hopper, type FindingsCounts, type OperationListItem, type OperationSummary } from "../rpc"
import { defaultOperationName, errText, LIFECYCLE } from "./format"
import { currentSession } from "./current-session"
import type { HopperRpcClient } from "./status"

/**
 * Surface 3 — interactive flows: `/pwn` (create an operation — rebind-confirm
 * when the session is already bound — kickoff prompt with NO auto-OSINT),
 * `/op` (the operation picker: bind the session, or complete/archive/delete
 * from the footer), two-stage `/opsec` (the bound operation directly, or pick
 * one first), plus `/ledger` to open the findings panel.
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

/** The commands' rpc surface: the status client plus every mutation the flows drive. */
export interface CommandsRpc extends HopperRpcClient {
  createOperation: (i: { name: string; target: string; sessionID?: string }, options?: { location?: unknown }) => Promise<{ operation: OperationSummary }>
  setOpsec: (i: { operationId: string; level: "normal" | "strict" }, options?: { location?: unknown }) => Promise<{ opsec: "normal" | "strict" }>
  bind: (i: { sessionID: string; operationId: string }, options?: { location?: unknown }) => Promise<{ operationId: string }>
  unbind: (i: { sessionID: string }, options?: { location?: unknown }) => Promise<{ operationId: string | null }>
  setOperationStatus: (i: { operationId: string; status: "completed" | "archived" | "active" }, options?: { location?: unknown }) => Promise<{ status: string }>
  deleteOperation: (i: { operationId: string }, options?: { location?: unknown }) => Promise<{ ok: boolean }>
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
    panel: {
      open: (name: string) => boolean
      close: () => void
      current: () => { name: string; sessionID: string } | undefined
    }
  }
  client: { rpc: (def: unknown) => CommandsRpc }
  data: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
  session: { prompt: (input: { sessionID: string; text: string }) => Promise<unknown> }
  location?: unknown
}

/**
 * Typed-error detector. Every success shape in the contract lacks a string
 * `type`; every typed error carries one. Covers both transports — errors the
 * client rejects with and lenient ones that resolve.
 */
const errorType = (value: unknown): string | undefined =>
  typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string"
    ? (value as { type: string }).type
    : undefined

/** "3 findings" / "no findings" — the picker's one-line ledger summary. */
const findingsSummary = (counts: FindingsCounts): string => {
  const total = LIFECYCLE.reduce((n, key) => n + (counts[key] ?? 0), 0)
  return total === 0 ? "no findings" : `${total} findings`
}

/**
 * dialog.select over ACTIVE operations only (completed/archived are read-only
 * history). Resolves the picked item, or undefined when the operator cancelled
 * or nothing is active (a toast already said why). `actions` carries the /op
 * footer; /opsec's stage one passes none.
 */
async function chooseActiveOperation(
  ctx: CommandsCtx,
  rpc: CommandsRpc,
  opts: () => { location?: unknown },
  spec: {
    title: string
    actions?: Array<{ bind: string; title: string; side?: "left" | "right"; onTrigger: (operationId: string) => void }>
  },
): Promise<OperationListItem | undefined> {
  let items: OperationListItem[]
  try {
    items = (await rpc.operationsList({}, opts())).items
  } catch (err) {
    console.error("[hopper-tui] operationsList failed:", err)
    ctx.ui.toast.show({ title: "Hopper", message: `operationsList failed: ${errText(err)}`, variant: "error" })
    return undefined
  }
  const active = items.filter((op) => op.status === "active")
  if (active.length === 0) {
    ctx.ui.toast.show({ title: "Hopper", message: "no active operations — /pwn starts one", variant: "warning" })
    return undefined
  }
  // a torn-down or superseded select must never surface as an unhandled
  // rejection (Bun's default would kill the TUI) — same defense as the guard dialog
  let picked: unknown
  try {
    picked = await ctx.ui.dialog.select({
      title: spec.title,
      options: active.map((op) => ({
        value: op.id,
        title: `${op.name} · ${op.target}`,
        description: findingsSummary(op.findings),
      })),
      ...(spec.actions !== undefined ? { actions: spec.actions } : {}),
    })
  } catch (err) {
    console.error("[hopper-tui] operation select failed:", err)
    return undefined
  }
  if (picked === undefined) return undefined // cancelled
  return active.find((op) => op.id === picked)
}

/**
 * The `/op` picker — bind the current session to an active operation, or run
 * a lifecycle action on the highlighted one from the footer. Complete/archive
 * and a confirmed delete re-open the picker with the fresh list; unbind keeps
 * it open so the operator can bind a different operation next; a declined
 * delete is a plain cancel. Typed errors (`not_active`, `no_operation`)
 * surface as error toasts — never as crashes or hard blocks.
 */
export function buildOperationPicker(ctx: CommandsCtx): () => Promise<void> {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  // bumped whenever an action supersedes the open dialog — a late resolution
  // of the superseded select must never fall through to bind
  let generation = 0

  const runAndToast = async (
    run: () => Promise<unknown>,
    messages: { success: () => string; failure: (err: unknown) => string },
  ): Promise<void> => {
    try {
      const res = await run()
      if (errorType(res) !== undefined) {
        ctx.ui.toast.show({ title: "Hopper", message: errText(res), variant: "error" })
        return
      }
      ctx.ui.toast.show({ title: "Hopper", message: messages.success(), variant: "success" })
    } catch (err) {
      console.error("[hopper-tui] picker action failed:", err)
      ctx.ui.toast.show({ title: "Hopper", message: messages.failure(err), variant: "error" })
    }
  }

  const setStatus = async (operationId: string, status: "completed" | "archived"): Promise<void> => {
    generation++ // the picker that fired this action is superseded
    await runAndToast(
      () => rpc.setOperationStatus({ operationId, status }, opts()),
      { success: () => `operation ${status}`, failure: (err) => `setOperationStatus failed: ${errText(err)}` },
    )
    void open() // re-open: the list changed (or shows why it did not)
  }

  const remove = async (operationId: string): Promise<void> => {
    const sure = await ctx.ui.dialog.confirm({
      title: "Delete operation?",
      message: "Deleting this operation removes its findings ledger — there is no undo.",
    })
    if (!sure) return // a user cancel; the picker underneath stays open and live
    generation++
    await runAndToast(
      () => rpc.deleteOperation({ operationId }, opts()),
      { success: () => "operation deleted", failure: (err) => `deleteOperation failed: ${errText(err)}` },
    )
    void open()
  }

  const unbind = async (sessionID: string): Promise<void> => {
    await runAndToast(
      () => rpc.unbind({ sessionID }, opts()),
      { success: () => "session unbound", failure: (err) => `unbind failed: ${errText(err)}` },
    )
    // no re-open: the picker stays live — bind the next operation or cancel
  }

  const unarchive = async (operationId: string): Promise<void> => {
    generation++ // the archive list that fired this action is superseded
    await runAndToast(
      () => rpc.setOperationStatus({ operationId, status: "active" }, opts()),
      { success: () => "operation active", failure: (err) => `setOperationStatus failed: ${errText(err)}` },
    )
    // re-open the archive list; when the unarchive emptied it, its empty-check
    // chains back to the main picker — never a dead end
    void openArchived()
  }

  /** The `g` (Graveyard) view: archived operations only (completed stays read-only history). */
  const openArchived = async (): Promise<void> => {
    let items: OperationListItem[]
    try {
      items = (await rpc.operationsList({}, opts())).items
    } catch (err) {
      console.error("[hopper-tui] operationsList failed:", err)
      ctx.ui.toast.show({ title: "Hopper", message: `operationsList failed: ${errText(err)}`, variant: "error" })
      return
    }
    const archived = items.filter((op) => op.status === "archived")
    if (archived.length === 0) {
      ctx.ui.toast.show({ title: "Hopper", message: "no archived operations", variant: "warning" })
      void open() // the main picker re-opens — the archive view never dead-ends
      return
    }
    const gen = ++generation
    // a torn-down or superseded select must never surface as an unhandled
    // rejection (Bun's default would kill the TUI) — same defense as the guard dialog
    let picked: unknown
    try {
      picked = await ctx.ui.dialog.select({
        title: "Archived operations",
        options: archived.map((op) => ({
          value: op.id,
          title: `${op.name} · ${op.target}`,
          description: findingsSummary(op.findings),
        })),
        actions: [{ bind: "u", title: "Unarchive", onTrigger: (id: string) => void unarchive(id) }],
      })
    } catch (err) {
      console.error("[hopper-tui] archive select failed:", err)
      return
    }
    if (gen !== generation) return // superseded by an action or another dialog
    if (typeof picked !== "string") return // cancelled (esc) — nothing re-opens
    void unarchive(picked) // Enter on an item unarchives it too
  }

  const open = async (): Promise<void> => {
    const sessionID = currentSession.get()
    if (sessionID === undefined) {
      ctx.ui.toast.show({ title: "Hopper", message: "no current session — select a session first", variant: "warning" })
      return
    }
    const gen = ++generation
    const picked = await chooseActiveOperation(ctx, rpc, opts, {
      title: "Bind an operation",
      actions: [
        { bind: "u", title: "Unbind session", onTrigger: () => void unbind(sessionID) },
        { bind: "c", title: "Complete", onTrigger: (id) => void setStatus(id, "completed") },
        { bind: "a", title: "Archive", onTrigger: (id) => void setStatus(id, "archived") },
        { bind: "g", title: "Graveyard", onTrigger: () => { generation++; void openArchived() } },
        { bind: "d", title: "Delete", side: "right", onTrigger: (id) => void remove(id) },
      ],
    })
    if (gen !== generation) return // an action superseded this dialog — its flow owns the next step
    if (picked === undefined) return // cancelled or nothing to offer
    await runAndToast(
      () => rpc.bind({ sessionID, operationId: picked.id }, opts()),
      {
        success: () => `session bound to ${picked.name} (${picked.target})`,
        failure: (err) => `bind failed: ${errText(err)}`,
      },
    )
  }

  return open
}

export function registerCommands(ctx: CommandsCtx): { cleanup: () => void } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })
  const picker = buildOperationPicker(ctx)
  // secondary source: the prompt footer's slot input (see current-session.ts) is primary
  const stopTrack = ctx.data.on("tui.session.select", (event) => {
    const data = event.data as { sessionID?: string } | undefined
    if (data?.sessionID) currentSession.set(data.sessionID)
  })
  // a deleted session must never receive the kickoff prompt
  const stopDelete = ctx.data.on("session.deleted", (event) => {
    const data = event.data as { sessionID?: string } | undefined
    if (data?.sessionID) currentSession.clear(data.sessionID)
  })

  const runPwn = async (input?: string) => {
    const { target } = parsePwnArgument(input ?? "")
    let t = target
    if (t === undefined) {
      t = (await ctx.ui.dialog.prompt({ title: "Operation target", placeholder: "localhost:3000 or example.test" }))?.trim()
      if (!t) return // cancelled
    }
    const name = defaultOperationName(t)
    // a BOUND session rebinds only with the operator's blessing — declining
    // leaves the old operation bound (and active everywhere else)
    const sessionID = currentSession.get()
    if (sessionID !== undefined) {
      const status = await rpc.operationStatus({ sessionID }, opts()).catch(() => null)
      if (status?.operation) {
        const rebind = await ctx.ui.dialog.confirm({
          title: "Start a new operation and rebind this session?",
          message: `"${status.operation.name}" (${status.operation.target}) stays active — "${name}" → ${t} takes over this session.`,
        })
        if (!rebind) return
      }
    }
    let created: { operation: OperationSummary }
    try {
      const res = await rpc.createOperation(
        sessionID === undefined ? { name, target: t } : { name, target: t, sessionID },
        opts(),
      )
      if (errorType(res) !== undefined) {
        // a typed error that RESOLVES (lenient transport) is not a success —
        // same guard as runAndToast/runOpsec: no "active" toast, no kickoff
        // for an operation that was never created
        ctx.ui.toast.show({ title: "Hopper", message: errText(res), variant: "error" })
        return
      }
      created = res
    } catch (err) {
      console.error("[hopper-tui] createOperation failed:", err)
      ctx.ui.toast.show({
        title: "Hopper",
        message: `createOperation failed: ${errText(err)}`,
        variant: "error",
      })
      return
    }
    ctx.ui.toast.show({
      title: "Hopper",
      message: `Operation ${created.operation.name} active — target ${created.operation.target}`,
      variant: "success",
    })
    const kickoffTo = currentSession.get()
    if (kickoffTo === undefined) {
      ctx.ui.toast.show({
        title: "Hopper",
        message: "Operation active — open a session and ask for the kickoff plan",
        variant: "warning",
      })
      return
    }
    try {
      await ctx.session.prompt({ sessionID: kickoffTo, text: buildKickoffPrompt(created.operation.name, created.operation.target) })
    } catch (err) {
      // the operation IS active — only the automatic kickoff failed; say so, never crash
      console.error("[hopper-tui] kickoff prompt failed:", err)
      ctx.ui.toast.show({
        title: "Hopper",
        message: `Operation active, but the kickoff prompt failed: ${errText(err)} — ask for the plan manually`,
        variant: "warning",
      })
    }
  }

  const runOpsec = async () => {
    // stage 0 — the bound operation goes straight to the level; unbound or
    // sessionless picks one first (no lifecycle actions in that stage)
    const sessionID = currentSession.get()
    let operation: { id: string; name: string } | undefined
    let currentLevel: "normal" | "strict" | undefined
    if (sessionID !== undefined) {
      const status = await rpc.operationStatus({ sessionID }, opts()).catch(() => null)
      if (status?.operation) {
        operation = { id: status.operation.id, name: status.operation.name }
        currentLevel = status.opsec
      }
    }
    if (operation === undefined) {
      operation = await chooseActiveOperation(ctx, rpc, opts, { title: "Set opsec on" })
      if (operation === undefined) return // cancelled or nothing to offer
    }
    const level = await ctx.ui.dialog.select({
      title: `Opsec — ${operation.name}`,
      ...(currentLevel !== undefined ? { current: currentLevel } : {}),
      options: [
        { title: "Normal", value: "normal", description: "Advisory leak warnings in scope dialogs" },
        { title: "Strict", value: "strict", description: "Personas avoid leaky third-party lookups; banner flags strict" },
      ],
    })
    if (level !== "normal" && level !== "strict") return
    try {
      const res = await rpc.setOpsec({ operationId: operation.id, level }, opts())
      if (errorType(res) !== undefined) {
        ctx.ui.toast.show({ title: "Hopper", message: errText(res), variant: "error" })
        return
      }
      ctx.ui.toast.show({ title: "Hopper", message: `opsec: ${level} — ${operation.name}`, variant: "success" })
    } catch (err) {
      console.error("[hopper-tui] setOpsec failed:", err)
      ctx.ui.toast.show({ title: "Hopper", message: `setOpsec failed: ${errText(err)}`, variant: "error" })
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
        id: "hopper.op",
        title: "Pick the session's operation",
        slash: { name: "op" },
        palette: true,
        run: () => picker(),
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
        title: "Toggle the findings ledger",
        slash: { name: "ledger" },
        palette: true,
        run: () => {
          // toggle: close only OUR panel; another plugin's panel is never touched
          if (ctx.ui.panel.current()?.name === "hopper.ledger") ctx.ui.panel.close()
          else ctx.ui.panel.open("hopper.ledger")
        },
      },
    ],
  }))

  return { cleanup: () => { stopTrack(); stopDelete() } }
}
