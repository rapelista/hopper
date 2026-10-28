/**
 * Surface 5 — operator attention. When an engagement step (agent execution)
 * runs a minute or longer, notify the operator if the terminal is unfocused.
 * Silent by default: sound is the operator's opencode setting, not ours.
 */

export interface NotificationsCtx {
  data: { on: (name: string, cb: (event: { data: unknown }) => void) => () => void }
  attention: { notify: (i: unknown) => Promise<unknown> }
}

export function registerNotifications(
  ctx: NotificationsCtx,
  deps?: { now?: () => number; thresholdMs?: number },
): { cleanup: () => void } {
  const now = deps?.now ?? (() => Date.now())
  const threshold = deps?.thresholdMs ?? 60_000
  const startedAt = new Map<string, number>()

  const sessionID = (event: { data: unknown }): string | undefined =>
    (event.data as { sessionID?: string } | undefined)?.sessionID

  const stops = [
    ctx.data.on("session.execution.started", (event) => {
      const id = sessionID(event)
      if (id) startedAt.set(id, now())
    }),
    ctx.data.on("session.execution.succeeded", (event) => {
      const id = sessionID(event)
      if (!id) return
      const t0 = startedAt.get(id)
      startedAt.delete(id)
      if (t0 === undefined) return // orphan succeeded — nothing measured, never throw
      if (now() - t0 < threshold) return
      void ctx.attention
        .notify({
          title: "Hopper",
          message: "engagement step",
          notification: { when: "blurred" },
          sound: { name: "done", when: "never" },
        })
        .catch(() => {})
    }),
    ctx.data.on("session.deleted", (event) => {
      const id = sessionID(event)
      if (id) startedAt.delete(id)
    }),
  ]

  return { cleanup: () => stops.forEach((stop) => stop()) }
}
