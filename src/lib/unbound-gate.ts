import type { GuardAnswerChoice } from "../rpc"

/**
 * Coordination for unbound sessions: when a session with no operation
 * binding reaches for a scoped tool, the kernel hands an ask to the
 * operator (TUI) via a `guard.ask` event and waits for the `guardAnswer`
 * RPC to come back. This module owns that round-trip — the pending-ask
 * registry keyed by askId, with a fail-open timeout so a headless or
 * distracted operator never deadlocks the session.
 */

export interface GuardAsk {
  askId: string
  sessionID: string
  messageID: string
  tool: string
  targets: string[]
  reason: string
}

export type GuardAnswer = { choice: GuardAnswerChoice; operationId?: string }

interface PendingAsk {
  resolve: (answer: GuardAnswer) => void
  timer: ReturnType<typeof setTimeout>
}

export interface UnboundGate {
  /** Resolve an open ask by id; false when unknown or already resolved. */
  answer(askId: string, choice: GuardAnswerChoice, operationId?: string): boolean
  /** Emit the ask and await the operator; fails open to allow-once on timeout. */
  decide(ask: GuardAsk): Promise<GuardAnswer>
  /** AskIds still awaiting an answer. */
  pending(): string[]
}

export function createUnboundGate(opts: {
  timeoutMs?: number
  emit: (ask: GuardAsk) => void
  log?: (msg: string, ...rest: unknown[]) => void
}): UnboundGate {
  const timeoutMs = opts.timeoutMs ?? 120_000
  const log = opts.log ?? (() => {})
  const pending = new Map<string, PendingAsk>()

  return {
    decide(ask) {
      // The gate is the authority for ask ids: callers may leave askId
      // empty and get a freshly minted one on the emitted event.
      const askId = ask.askId === "" ? crypto.randomUUID() : ask.askId
      return new Promise<GuardAnswer>((resolve) => {
        const timer = setTimeout(() => {
          // The answer path removes the entry before resolving; if it
          // won the race there is nothing left to time out.
          if (!pending.delete(askId)) return
          log("[hopper] guard.ask timed out, proceeding:", askId)
          resolve({ choice: "allow-once" })
        }, timeoutMs)
        pending.set(askId, { resolve, timer })
        opts.emit({ ...ask, askId })
      })
    },

    answer(askId, choice, operationId) {
      const entry = pending.get(askId)
      if (!entry) return false
      pending.delete(askId)
      clearTimeout(entry.timer)
      entry.resolve(operationId !== undefined ? { choice, operationId } : { choice })
      return true
    },

    pending() {
      return [...pending.keys()]
    },
  }
}
