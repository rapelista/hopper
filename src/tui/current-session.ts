/**
 * The TUI plugin API has no global "current session" getter. Two passive
 * sources keep this holder fresh: the prompt footer slot (rendered inside a
 * session, carries its sessionID) and the tui.session.select event. The /pwn
 * kickoff submits to whatever session is current when it runs.
 */
let current: string | undefined

export const currentSession = {
  set(id: string): void {
    current = id
  },
  get(): string | undefined {
    return current
  },
  /** test isolation — module-level state otherwise leaks between bun tests */
  reset(): void {
    current = undefined
  },
}
