import { Plugin } from "@opencode/plugin/tui"
import { Hopper, type GuardAnswerChoice, type GuardAskData, type OperationListItem } from "./rpc"
import { registerStatus, type StatusCtx } from "./tui/status"
import { registerPanel, type PanelCtx } from "./tui/panel"
import { registerCommands, buildOperationPicker, errorType, findingsSummary, type CommandsCtx } from "./tui/commands"
import { registerNotifications, type NotificationsCtx } from "./tui/notifications"
import { currentSession } from "./tui/current-session"
import { defaultOperationName, errText } from "./tui/format"

/**
 * Surface 4 — the `guard.ask` operator dialog. When an unbound session reaches
 * for a scoped weapon, the kernel asks; the TUI answers. One global listener:
 * asks for other sessions are ignored — their tool calls ride the server
 * timeout, never another session's operator dialog.
 */
export interface GuardDialogCtx {
  ui: {
    dialog: {
      select: (i: unknown) => Promise<unknown>
      prompt: (i: { title: string; placeholder?: string }) => Promise<string | undefined>
    }
    toast: { show: (t: { title?: string; message: string; variant?: "success" | "error" | "warning" }) => void }
  }
  client: { rpc: (def: unknown) => GuardDialogRpc }
  location?: unknown
}

interface GuardDialogRpc {
  operationsList: (input: unknown, options?: { location?: unknown }) => Promise<{ items: OperationListItem[] }>
  createOperation: (
    i: { name: string; target: string; sessionID?: string },
    options?: { location?: unknown },
  ) => Promise<{ operation: { id: string } } | { type: string; message: string }>
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

  const answer = async (input: { askId: string; choice: GuardAnswerChoice; operationId?: string }): Promise<void> => {
    try {
      await rpc.guardAnswer(input, opts())
    } catch (err) {
      console.error("[hopper-tui] guardAnswer failed:", err)
    }
  }

  const onAsk = async (ask: GuardAskData) => {
    // actives are fetched lazily here, never at setup: no ask, no fetch
    let actives: OperationListItem[] = []
    try {
      const list = await rpc.operationsList({}, opts())
      actives = list.items.filter((op) => op.status === "active")
    } catch (err) {
      console.error("[hopper-tui] operationsList failed:", err)
    }
    // one active → quick-bind shortcut; several → chooser; none → only creation
    const options = [
      ...(actives.length === 1
        ? [{ value: "bind", title: `Bind: ${actives[0]!.name} · ${actives[0]!.target}` }]
        : actives.length >= 2
          ? [{ value: "choose", title: "Choose operation…" }]
          : []),
      { value: "new", title: "New operation…" },
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

    if (picked === "choose" && actives.length >= 2) {
      let opId: unknown
      try {
        opId = await ctx.ui.dialog.select({
          title: "Bind an operation",
          options: actives.map((op) => ({
            value: op.id,
            title: `${op.name} · ${op.target}`,
            description: findingsSummary(op.findings),
          })),
        })
      } catch (err) {
        console.error("[hopper-tui] operation chooser failed:", err)
        opId = undefined
      }
      // esc/rejection at ANY depth is a decision — answer deny, never hang
      if (typeof opId !== "string") return void answer({ askId: ask.askId, choice: "deny" })
      return void answer({ askId: ask.askId, choice: "bind", operationId: opId })
    }

    if (picked === "new") {
      // the target is the weapon target that TRIGGERED this ask — the operator
      // only names the engagement; the kernel normalizes the target for the fence.
      // `?.` — a missing array is the defensive clause's other half: route to
      // toast + deny, never a TypeError through `void onAsk`
      const target = ask.targets?.[0]
      if (typeof target !== "string" || target === "") {
        ctx.ui.toast.show({
          title: "Hopper",
          message: "Operation create failed: the ask carries no target",
          variant: "error",
        })
        return void answer({ askId: ask.askId, choice: "deny" })
      }
      let name: string | undefined
      try {
        name = await ctx.ui.dialog.prompt({
          title: `Operation name — target ${target}`,
          placeholder: defaultOperationName(target),
        })
      } catch (err) {
        console.error("[hopper-tui] name prompt failed:", err)
        name = undefined
      }
      // a blank submit is a cancel — never create an unnamed operation
      if (name === undefined || name.trim() === "") return void answer({ askId: ask.askId, choice: "deny" })
      try {
        const res = await rpc.createOperation(
          { name: name.trim(), target, sessionID: ask.sessionID },
          opts(),
        )
        // typed errors may RESOLVE on the lenient transport — never treat one as success
        if (errorType(res) !== undefined) {
          ctx.ui.toast.show({
            title: "Hopper",
            message: `Operation create failed: ${(res as { message?: string }).message}`,
            variant: "error",
          })
          return void answer({ askId: ask.askId, choice: "deny" })
        }
        const created = res as { operation: { id: string } }
        return void answer({ askId: ask.askId, choice: "bind", operationId: created.operation.id })
      } catch (err) {
        ctx.ui.toast.show({ title: "Hopper", message: `Operation create failed: ${errText(err)}`, variant: "error" })
        return void answer({ askId: ask.askId, choice: "deny" })
      }
    }

    const choice: GuardAnswerChoice =
      picked === "bind" || picked === "free" || picked === "allow-once" ? picked : "deny"
    // operationId rides along for bind only (the schema allows it, the choice does not)
    const input =
      choice === "bind" && actives.length === 1
        ? { askId: ask.askId, choice, operationId: actives[0]!.id }
        : { askId: ask.askId, choice }
    void answer(input)
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

    // one commands ctx feeds registerCommands and the /hop:operations picker; one picker
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
