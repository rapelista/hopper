import { describe, expect, test } from "bun:test"
import { registerStatus } from "../src/tui/status"
import { buildPanelModel } from "../src/tui/panel"
import { parsePwnArgument, buildKickoffPrompt, registerCommands } from "../src/tui/commands"
import { registerNotifications } from "../src/tui/notifications"
import type { FindingSummary, OperationStatusResult } from "../src/rpc"

const status: OperationStatusResult = {
  operation: { id: "op1", name: "juice", target: "localhost", createdAt: "2026-10-29T00:00:00Z" },
  opsec: "strict",
  findings: { candidate: 2, observed: 0, verified: 1, reportable: 0, rejected: 0, stale: 0 },
}

const settle = () => new Promise((r) => setTimeout(r, 5))

// ---------------------------------------------------------------- status ----

function statusCtx() {
  let fetches = 0
  const eventSubs: Record<string, Array<(e: { data: unknown }) => void>> = {}
  const slots: Array<{ append: string; render: () => unknown }> = []
  const ctx = {
    ui: {
      slot: (spec: { append: string; render: () => unknown }) => {
        slots.push(spec)
        return () => {}
      },
    },
    client: {
      rpc: () => ({
        operationStatus: async () => {
          fetches++
          return status
        },
        events: {
          on: (name: string, cb: (e: { data: unknown }) => void) => {
            ;(eventSubs[name] ??= []).push(cb)
            return () => {
              eventSubs[name] = (eventSubs[name] ?? []).filter((x) => x !== cb)
            }
          },
        },
      }),
    },
    data: {
      on: (name: string, cb: (e: { data: unknown }) => void) => {
        ;(eventSubs[name] ??= []).push(cb)
        return () => {
          eventSubs[name] = (eventSubs[name] ?? []).filter((x) => x !== cb)
        }
      },
    },
  }
  return { ctx, get fetches() { return fetches }, eventSubs, slots }
}

describe("status module", () => {
  test("fetches once on register, exposes status, registers both footer slots", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    await settle()
    expect(s.fetches).toBe(1)
    expect(reg.status()?.operation?.name).toBe("juice")
    expect(s.slots.map((x) => x.append).sort()).toEqual(["home.footer.status", "prompt.footer.status"])
    reg.cleanup()
  })

  test("operation/finding events refetch; cleanup stops the wiring", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    await settle()
    expect(s.fetches).toBe(1)
    s.eventSubs["operation.changed"]![0]!({ data: { operationId: "op1" } })
    await settle()
    expect(s.fetches).toBe(2)
    s.eventSubs["finding.changed"]![0]!({ data: {} })
    await settle()
    expect(s.fetches).toBe(3)
    reg.cleanup()
    // every listener unregistered — the event bus can no longer reach us
    expect(s.eventSubs["operation.changed"]?.length ?? 0).toBe(0)
    expect(s.eventSubs["finding.changed"]?.length ?? 0).toBe(0)
    expect(s.eventSubs["session.execution.succeeded"]?.length ?? 0).toBe(0)
    const before = s.fetches
    await settle()
    expect(s.fetches).toBe(before)
  })
})

// ----------------------------------------------------------------- panel ----

describe("panel model", () => {
  const f = (id: string, st: string, sev = "high"): FindingSummary =>
    ({ id, title: `t-${id}`, severity: sev, status: st, target: "localhost", createdAt: "x" })

  test("groups in lifecycle order and carries operation context", () => {
    const model = buildPanelModel(status, [f("a", "verified"), f("b", "candidate"), f("c", "candidate")])
    expect(model.operation?.name).toBe("juice")
    expect(model.opsec).toBe("strict")
    expect(model.groups.map((g) => g.status)).toEqual(["candidate", "verified"])
    expect(model.groups[0]!.items.map((i) => i.id)).toEqual(["b", "c"])
  })

  test("no operation → empty model", () => {
    const model = buildPanelModel(
      { operation: null, opsec: "normal", findings: { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 } },
      [],
    )
    expect(model.operation).toBeNull()
    expect(model.groups).toEqual([])
  })
})

// -------------------------------------------------------------- commands ----

describe("commands module (pure)", () => {
  test("parsePwnArgument", () => {
    expect(parsePwnArgument("localhost:3000")).toEqual({ target: "localhost:3000" })
    expect(parsePwnArgument("  ")).toEqual({})
    expect(parsePwnArgument("")).toEqual({})
  })
  test("kickoff prompt pins the no-auto-osint contract", () => {
    const text = buildKickoffPrompt("juice", "localhost")
    expect(text).toContain("doctor")
    expect(text).toContain("PTES")
    expect(text).toContain("Do NOT start passive OSINT")
    expect(text).toContain("juice")
    expect(text).toContain("localhost")
  })
})

describe("commands module (registration)", () => {
  function commandsCtx() {
    const layers: Array<Record<string, unknown>> = []
    const toasts: unknown[] = []
    const dialogs: string[] = []
    const calls: Array<{ method: string; input: unknown }> = []
    const subs: Record<string, Array<(e: { data: unknown }) => void>> = {}
    const ctx = {
      keymap: { layer: (factory: () => Record<string, unknown>) => { layers.push(factory()); return () => {} } },
      ui: {
        dialog: {
          prompt: async (i: { title: string }) => { dialogs.push(`prompt:${i.title}`); return "example.test" },
          confirm: async (i: { title: string }) => { dialogs.push(`confirm:${i.title}`); return true },
          select: async (i: unknown) => { dialogs.push("select"); return "strict" },
        },
        toast: { show: (t: unknown) => { toasts.push(t) } },
        panel: { open: (name: string) => { calls.push({ method: "panel.open", input: name }); return true } },
      },
      client: {
        rpc: () => ({
          operationStatus: async () => status,
          createOperation: async (i: unknown) => {
            calls.push({ method: "createOperation", input: i })
            return { operation: { id: "op2", name: "example", target: "example.test", createdAt: "x" } }
          },
          setOpsec: async (i: unknown) => { calls.push({ method: "setOpsec", input: i }); return { opsec: "strict" } },
          events: { on: () => () => {} },
        }),
      },
      data: { on: (name: string, cb: (e: { data: unknown }) => void) => { (subs[name] ??= []).push(cb); return () => {} } },
      session: { prompt: async (i: unknown) => { calls.push({ method: "session.prompt", input: i }); return {} } },
    }
    return { ctx, layers, toasts, dialogs, calls, subs }
  }

  const commandsOf = (c: ReturnType<typeof commandsCtx>) =>
    c.layers[0]!.commands as Array<{ id: string; run: (input?: string) => unknown }>

  test("registers pwn/opsec/ledger slash commands", () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    const cmds = commandsOf(c).map((cmd) => cmd.id)
    expect(cmds).toContain("hopper.pwn")
    expect(cmds).toContain("hopper.opsec")
    expect(cmds).toContain("hopper.ledger")
  })

  test("ledger opens the panel", () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    commandsOf(c).find((cmd) => cmd.id === "hopper.ledger")!.run()
    expect(c.calls).toContainEqual({ method: "panel.open", input: "hopper.ledger" })
  })

  test("pwn: prompts target, confirms replacement, creates, toasts, submits kickoff", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } }) // a session is current
    const pwn = commandsOf(c).find((cmd) => cmd.id === "hopper.pwn")!
    await pwn.run("")
    expect(c.dialogs).toContainEqual("prompt:Operation target")
    expect(c.dialogs).toContainEqual("confirm:Replace active operation?")
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("active"))).toBe(true)
    expect(c.calls.some((call) => call.method === "session.prompt" && JSON.stringify(call.input).includes("PTES"))).toBe(true)
  })

  test("pwn without a current session: still creates, hints instead of submitting", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    const pwn = commandsOf(c).find((cmd) => cmd.id === "hopper.pwn")!
    await pwn.run("example.test") // target given — no prompt dialog
    expect(c.dialogs).not.toContain("prompt:Operation target")
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test" } })
    expect(c.calls.some((call) => call.method === "session.prompt")).toBe(false)
    expect(c.toasts.some((t) => JSON.stringify(t).includes("open a session"))).toBe(true)
  })

  test("opsec runs the select dialog and sets the level", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    await commandsOf(c).find((cmd) => cmd.id === "hopper.opsec")!.run()
    expect(c.dialogs).toContainEqual("select")
    expect(c.calls).toContainEqual({ method: "setOpsec", input: { level: "strict" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("strict"))).toBe(true)
  })
})

// --------------------------------------------------------- notifications ----

describe("notifications module", () => {
  function notificationsCtx() {
    const subs: Record<string, Array<(e: { data: unknown }) => void>> = {}
    const notified: unknown[] = []
    const ctx = {
      data: {
        on: (name: string, cb: (e: { data: unknown }) => void) => {
          ;(subs[name] ??= []).push(cb)
          return () => {}
        },
      },
      attention: { notify: async (i: unknown) => { notified.push(i); return { ok: true } } },
    }
    return { ctx, subs, notified }
  }
  const fire = (n: { subs: Record<string, Array<(e: { data: unknown }) => void>> }, name: string, sessionID: string) =>
    n.subs[name]![0]!({ data: { sessionID } })

  test("execution ≥60s notifies blurred; shorter does not", async () => {
    const n = notificationsCtx()
    let t = 1_000_000
    const reg = registerNotifications(n.ctx as never, { now: () => t })
    fire(n, "session.execution.started", "s1")
    t += 61_000
    fire(n, "session.execution.succeeded", "s1")
    await settle()
    expect(n.notified.length).toBe(1)
    expect((n.notified[0] as { notification: { when: string } }).notification.when).toBe("blurred")
    fire(n, "session.execution.started", "s2")
    t += 30_000
    fire(n, "session.execution.succeeded", "s2")
    await settle()
    expect(n.notified.length).toBe(1)
    reg.cleanup()
  })

  test("orphan succeeded (no started) never throws, never notifies (RF#3)", async () => {
    const n = notificationsCtx()
    const reg = registerNotifications(n.ctx as never, { now: () => 0 })
    expect(() => fire(n, "session.execution.succeeded", "ghost")).not.toThrow()
    await settle()
    expect(n.notified.length).toBe(0)
    reg.cleanup()
  })
})
