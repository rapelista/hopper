import { Plugin } from "@opencode/plugin/tui"
import { Hopper, type GuardAnswerChoice, type GuardAskData, type OperationListItem } from "./rpc"
import { registerStatus, type StatusCtx } from "./tui/status"
import { registerPanel, type PanelCtx } from "./tui/panel"
import { registerCommands, buildOperationPicker, type CommandsCtx } from "./tui/commands"
import { registerNotifications, type NotificationsCtx } from "./tui/notifications"
import { currentSession } from "./tui/current-session"

/**
 * Surface 4 — the `guard.ask` operator dialog. When an unbound session reaches
 * for a scoped weapon, the kernel asks; the TUI answers. One global listener:
 * asks for other sessions are ignored — their tool calls ride the server
 * timeout, never another session's operator dialog.
 */
export interface GuardDialogCtx {
  ui: { dialog: { select: (i: unknown) => Promise<unknown> } }
  client: { rpc: (def: unknown) => GuardDialogRpc }
  location?: unknown
}

interface GuardDialogRpc {
  operationsList: (input: unknown, options?: { location?: unknown }) => Promise<{ items: OperationListItem[] }>
  guardAnswer: (
    input: { askId: string; choice: GuardAnswerChoice; operationId?: string },
    options?: { location?: unknown },
  ) => Promise<unknown>
  events: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
}

/** dialog titles are one line — long ask reasons get clipped to a sane width. */
const GUARD_TITLE_MAX = 80
const askTitle = (reason: string): string => {
  const t = reason.trim()
  return t.length > GUARD_TITLE_MAX ? `${t.slice(0, GUARD_TITLE_MAX - 1)}…` : t
}

export function registerGuardDialog(ctx: GuardDialogCtx): { cleanup: () => void } {
  const rpc = ctx.client.rpc(Hopper)
  const opts = () => (ctx.location === undefined ? {} : { location: ctx.location })

  const onAsk = async (ask: GuardAskData) => {
    // the bind option names the first ACTIVE operation — fetched lazily here,
    // never at setup: no ask, no fetch
    let bind: { id: string; label: string } | undefined
    try {
      const list = await rpc.operationsList({}, opts())
      const first = list.items.find((op) => op.status === "active")
      if (first) bind = { id: first.id, label: `Bind: ${first.name} · ${first.target}` }
    } catch (err) {
      console.error("[hopper-tui] operationsList failed:", err)
    }
    const options = [
      ...(bind !== undefined ? [{ value: "bind", title: bind.label }] : []),
      { value: "free", title: "Free this session until closed" },
      { value: "allow-once", title: "Allow once" },
      { value: "deny", title: "Deny" },
    ]
    let picked: unknown
    try {
      picked = await ctx.ui.dialog.select({ title: askTitle(ask.reason), options })
    } catch (err) {
      // a torn-down or superseded select must never surface as an unhandled
      // rejection (Bun's default would kill the TUI) — dismissal semantics,
      // same as esc: answer deny
      console.error("[hopper-tui] guard dialog failed:", err)
      picked = undefined
    }
    // Dismissal IS a decision: an esc'd dialog must not leave the tool hanging
    // on the server timeout — an explicit dismiss is answered as an explicit deny.
    const choice: GuardAnswerChoice =
      picked === "bind" || picked === "free" || picked === "allow-once" ? picked : "deny"
    // operationId rides along for bind only (the schema allows it, the choice does not)
    const input =
      choice === "bind" && bind !== undefined
        ? { askId: ask.askId, choice, operationId: bind.id }
        : { askId: ask.askId, choice }
    try {
      await rpc.guardAnswer(input, opts())
    } catch (err) {
      console.error("[hopper-tui] guardAnswer failed:", err)
    }
  }

  const stop = rpc.events.on("guard.ask", (event) => {
    const data = event.data as GuardAskData | undefined
    // only the operator's own session asks here — everything else is not ours to answer
    if (typeof data?.askId === "string" && data.sessionID === currentSession.get()) void onAsk(data)
  })

  return { cleanup: stop }
}

/**
 * Hopper TUI part — the operator surface, built the way opencode v2 builds its
 * own features: one focused module per surface, composed here, every
 * subscription and layer cleaned up on unload (hot-reload safe).
 */
export default Plugin.define({
  id: "hopper-tui",
  setup(context) {
    const cleanups: Array<() => void> = []
    // rpc calls must carry the location or the server consults its default registry
    const location = context.location ?? context.data.location.default()

    // one commands ctx feeds registerCommands and the /op picker; one picker
    // instance keeps any stale open dialog superseded when the banner reopens it
    const commandsCtx = {
      keymap: context.keymap,
      ui: context.ui,
      client: context.client,
      data: context.data,
      session: { prompt: (input: { sessionID: string; text: string }) => context.client.session.prompt(input) },
      location,
    } as unknown as CommandsCtx
    const openOperationPicker = buildOperationPicker(commandsCtx)

    cleanups.push(
      registerStatus({
        ui: context.ui,
        client: context.client,
        data: context.data,
        storage: context.storage,
        theme: context.theme,
        location,
        pickOperation: () => void openOperationPicker(),
      } as unknown as StatusCtx).cleanup,
    )

    cleanups.push(
      registerPanel({
        ui: context.ui,
        client: context.client,
        keymap: context.keymap,
        theme: context.theme,
        location,
      } as unknown as PanelCtx).cleanup,
    )

    cleanups.push(registerCommands(commandsCtx).cleanup)

    cleanups.push(registerNotifications({ data: context.data, attention: context.attention } as unknown as NotificationsCtx).cleanup)

    cleanups.push(
      registerGuardDialog({
        ui: context.ui,
        client: context.client,
        location,
      } as unknown as GuardDialogCtx).cleanup,
    )

    return () => {
      for (const cleanup of cleanups) cleanup()
    }
  },
})
