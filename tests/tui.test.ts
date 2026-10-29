import { describe, expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { registerStatus } from "../src/tui/status"
import { buildPanelModel } from "../src/tui/panel"
import { parsePwnArgument, buildKickoffPrompt, registerCommands } from "../src/tui/commands"
import { registerNotifications } from "../src/tui/notifications"
import { currentSession } from "../src/tui/current-session"
import { LIFECYCLE, cycleStatus } from "../src/tui/format"
import type { FindingSummary, OperationListItem, OperationStatusResult } from "../src/rpc"

const status: OperationStatusResult = {
  operation: { id: "op1", name: "juice", target: "localhost", createdAt: "2026-10-29T00:00:00Z" },
  opsec: "strict",
  findings: { candidate: 2, observed: 0, verified: 1, reportable: 0, rejected: 0, stale: 0 },
}

const unbound: OperationStatusResult = {
  operation: null,
  opsec: "normal",
  findings: { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 },
}

const opItem = (id: string, name: string, target: string, findings: OperationListItem["findings"]): OperationListItem => ({
  id,
  name,
  target,
  createdAt: "x",
  status: "active",
  findings,
})

// 2 ops · 5 findings across them — the home footer's cross-op summary source
const opsList: OperationListItem[] = [
  opItem("op1", "juice", "localhost", status.findings),
  opItem("op2", "shop", "example.test", { candidate: 0, observed: 2, verified: 0, reportable: 0, rejected: 0, stale: 0 }),
]

const settle = () => new Promise((r) => setTimeout(r, 5))

// ---------------------------------------------------------------- status ----

function statusCtx(listItems: OperationListItem[] = opsList) {
  let statusFetches = 0
  let listFetches = 0
  let picks = 0
  const statusInputs: Array<{ sessionID?: string }> = []
  const eventSubs: Record<string, Array<(e: { data: unknown }) => void>> = {}
  const slots: Array<{ append: string; render: (input?: { sessionID?: string }) => unknown }> = []
  const storeKeys: string[] = []
  const ctx = {
    // minimal real-shape theme so rendered frames resolve actual colors
    theme: {
      text: { base: "#e6e6e6", muted: "#888888", feedback: { error: { base: "#ff0000" } } },
    },
    // Task 9 wires the real picker; until then clicks are recorded no-ops
    pickOperation: () => {
      picks++
    },
    ui: {
      slot: (spec: { append: string; render: (input?: { sessionID?: string }) => unknown }) => {
        slots.push(spec)
        return () => {}
      },
    },
    client: {
      rpc: () => ({
        // session-keyed: s1 is bound to juice, s2 is unbound
        operationStatus: async (input: { sessionID?: string } = {}) => {
          statusFetches++
          statusInputs.push(input)
          return input.sessionID === "s2" ? unbound : status
        },
        operationsList: async () => {
          listFetches++
          return { items: listItems }
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
    // host-storage branch: records the key and mutates the draft in place,
    // the same observable semantics the host's store tuple has
    storage: {
      store: <T,>(key: string, opts: { initial: T }): [T, (fn: (draft: T) => T | void) => Promise<void>] => {
        storeKeys.push(key)
        return [
          opts.initial,
          async (fn) => {
            fn(opts.initial)
          },
        ]
      },
    },
  }
  return {
    ctx,
    get statusFetches() { return statusFetches },
    get listFetches() { return listFetches },
    get picks() { return picks },
    statusInputs,
    eventSubs,
    slots,
    storeKeys,
  }
}

/**
 * Slot renders must happen inside a renderer (intrinsic elements throw without
 * one) — testRender gives us the headless opentui renderer, a text frame, and
 * the built element tree (for mouse-handler assertions).
 */
const renderSlot = async (
  slot: { render: (input?: { sessionID?: string }) => unknown },
  input?: { sessionID?: string },
  visit?: (tree: unknown) => void,
) => {
  let tree: unknown
  const setup = await testRender(() => {
    tree = slot.render(input)
    return tree as never
  })
  await setup.flush()
  const frame = setup.captureCharFrame()
  visit?.(tree)
  await setup.dispose()
  return frame
}

const sidebarOf = (s: ReturnType<typeof statusCtx>) => s.slots.find((x) => x.append === "sidebar.content")!

describe("status module", () => {
  test("registers both slots; the footer fetches operationsList on register, the sidebar waits for a session", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    await settle()
    expect(s.slots.map((x) => x.append).sort()).toEqual(["home.footer.status", "sidebar.content"])
    expect(s.listFetches).toBe(1)
    // per-session resolution: no global operationStatus fetch before a session renders
    expect(s.statusFetches).toBe(0)
    // host-storage branch runs: the collapse state asks for its persisted key
    expect(s.storeKeys).toContain("ledgerView")
    reg.cleanup()
  })

  test("sidebar resolves through the slot-input sessionID: bound session renders the operation block", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    const sidebar = sidebarOf(s)
    await renderSlot(sidebar, { sessionID: "s1" }) // first render fires the keyed fetch
    await settle()
    expect(s.statusInputs).toEqual([{ sessionID: "s1" }])
    const frame = await renderSlot(sidebar, { sessionID: "s1" }) // same session — no extra fetch
    expect(s.statusFetches).toBe(1)
    expect(frame).toContain("juice")
    expect(frame).toContain("localhost")
    expect(frame).toContain("strict")
    reg.cleanup()
  })

  test("unbound or sessionless renders the muted /op hint, never another session's operation", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    const sidebar = sidebarOf(s)
    await renderSlot(sidebar, { sessionID: "s2" }) // s2 is unbound
    await settle()
    expect(s.statusInputs).toEqual([{ sessionID: "s2" }])
    const unboundFrame = await renderSlot(sidebar, { sessionID: "s2" })
    expect(unboundFrame).toContain("hop · no operation — /op to bind")
    expect(unboundFrame).not.toContain("juice") // no cross-session leak
    // no sessionID at all (home): the same hint, and still no fetch
    const sessionless = await renderSlot(sidebar)
    expect(sessionless).toContain("hop · no operation — /op to bind")
    expect(s.statusFetches).toBe(1)
    reg.cleanup()
  })

  test("home footer summarizes every operation; none ⇒ the empty marker", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    await settle()
    const footer = s.slots.find((x) => x.append === "home.footer.status")!
    const frame = await renderSlot(footer)
    expect(frame).toContain("hop · 2 ops · 5 findings")
    reg.cleanup()

    const empty = statusCtx([])
    const reg2 = registerStatus(empty.ctx as never)
    await settle()
    const frame2 = await renderSlot(empty.slots.find((x) => x.append === "home.footer.status")!)
    expect(frame2).toContain("hop · no operations")
    reg2.cleanup()
  })

  test("binding.changed refetches the rendered session only; a session change refetches keyed", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    const sidebar = sidebarOf(s)
    await renderSlot(sidebar, { sessionID: "s1" })
    await settle()
    expect(s.statusFetches).toBe(1)
    // another session's rebinding is not ours to show
    s.eventSubs["binding.changed"]![0]!({ data: { sessionID: "s9" } })
    await settle()
    expect(s.statusFetches).toBe(1)
    // our session rebinding (bind or unbind) refetches it
    s.eventSubs["binding.changed"]![0]!({ data: { sessionID: "s1" } })
    await settle()
    expect(s.statusFetches).toBe(2)
    expect(s.statusInputs[1]).toEqual({ sessionID: "s1" })
    // the sidebar following the operator to another session refetches keyed
    await renderSlot(sidebar, { sessionID: "s2" })
    expect(s.statusFetches).toBe(3)
    expect(s.statusInputs[2]).toEqual({ sessionID: "s2" })
    reg.cleanup()
  })

  test("operation/finding events refetch both surfaces; execution backstops the sidebar; cleanup unwires all", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    const sidebar = sidebarOf(s)
    await renderSlot(sidebar, { sessionID: "s1" })
    await settle()
    expect(s.statusFetches).toBe(1)
    expect(s.listFetches).toBe(1)
    s.eventSubs["operation.changed"]![0]!({ data: { operationId: "op1" } })
    await settle()
    expect(s.statusFetches).toBe(2)
    expect(s.listFetches).toBe(2)
    s.eventSubs["finding.changed"]![0]!({ data: {} })
    await settle()
    expect(s.statusFetches).toBe(3)
    expect(s.listFetches).toBe(3)
    // backstop: a finished agent turn may have mutated the store through tools
    s.eventSubs["session.execution.succeeded"]![0]!({ data: { sessionID: "s1" } })
    await settle()
    expect(s.statusFetches).toBe(4)
    expect(s.listFetches).toBe(3) // the footer rides the kernel events, not the backstop
    reg.cleanup()
    // every listener unregistered — the event bus can no longer reach us
    for (const name of ["operation.changed", "finding.changed", "binding.changed", "session.execution.succeeded"]) {
      expect(s.eventSubs[name]?.length ?? 0).toBe(0)
    }
    const before = s.statusFetches
    await settle()
    expect(s.statusFetches).toBe(before)
  })

  test("operation rows click through to pickOperation (onMouseDown idiom)", async () => {
    const s = statusCtx()
    const reg = registerStatus(s.ctx as never)
    const sidebar = sidebarOf(s)
    await renderSlot(sidebar, { sessionID: "s1" })
    await settle()
    const handlers: Array<() => void> = []
    await renderSlot(sidebar, { sessionID: "s1" }, (tree) => {
      ;(function walk(node: unknown) {
        const n = node as { _mouseListeners?: Record<string, unknown>; getChildren?: () => unknown[] } | undefined
        const down = n?._mouseListeners?.down
        if (typeof down === "function") handlers.push(down as () => void)
        for (const child of n?.getChildren?.() ?? []) walk(child)
      })(tree)
    })
    // header/name/target rows + ledger rows carry pick; the ledger header keeps its collapse toggle
    expect(handlers.length).toBeGreaterThan(1)
    for (const handler of handlers) handler()
    expect(s.picks).toBeGreaterThan(0)
    reg.cleanup()
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

  test("byStatus carries every lifecycle bucket, empty ones included (tab source)", () => {
    const model = buildPanelModel(status, [f("a", "verified"), f("b", "candidate"), f("c", "candidate")])
    expect(Object.keys(model.byStatus)).toEqual([...LIFECYCLE])
    expect(model.byStatus.candidate!.map((i) => i.id)).toEqual(["b", "c"])
    expect(model.byStatus.observed).toEqual([])
    expect(model.byStatus.stale).toEqual([])
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

describe("cycleStatus (panel tab cycling)", () => {
  test("steps forward and wraps", () => {
    expect(cycleStatus("candidate", 1)).toBe("observed")
    expect(cycleStatus("stale", 1)).toBe("candidate")
  })
  test("steps backward and wraps", () => {
    expect(cycleStatus("candidate", -1)).toBe("stale")
    expect(cycleStatus("verified", -1)).toBe("observed")
  })
  test("unknown status falls back to a sane neighbor", () => {
    const all: string[] = [...LIFECYCLE]
    expect(all).toContain(cycleStatus("nonsense", 1))
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
    let openPanel: { name: string; sessionID: string } | undefined
    const ctx = {
      keymap: { layer: (factory: () => Record<string, unknown>) => { layers.push(factory()); return () => {} } },
      ui: {
        dialog: {
          prompt: async (i: { title: string }) => { dialogs.push(`prompt:${i.title}`); return "example.test" },
          confirm: async (i: { title: string }) => { dialogs.push(`confirm:${i.title}`); return true },
          select: async (i: unknown) => { dialogs.push("select"); return "strict" },
        },
        toast: { show: (t: unknown) => { toasts.push(t) } },
        panel: {
          open: (name: string) => { calls.push({ method: "panel.open", input: name }); openPanel = { name, sessionID: "s1" }; return true },
          close: () => { calls.push({ method: "panel.close", input: undefined }); openPanel = undefined },
          current: () => openPanel,
        },
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

  test("registers pwn/opsec/ledger slash commands with slash names", () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    const cmds = commandsOf(c) as Array<{ id: string; slash?: { name: string } }>
    expect(cmds.map((cmd) => cmd.id)).toContain("hopper.pwn")
    expect(cmds.map((cmd) => cmd.id)).toContain("hopper.opsec")
    expect(cmds.map((cmd) => cmd.id)).toContain("hopper.ledger")
    expect(cmds.map((cmd) => cmd.slash?.name)).toEqual(["pwn", "opsec", "ledger"])
  })

  test("ledger toggles: opens when closed, closes when already open", () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    const ledger = commandsOf(c).find((cmd) => cmd.id === "hopper.ledger")!
    ledger.run()
    expect(c.calls).toContainEqual({ method: "panel.open", input: "hopper.ledger" })
    ledger.run() // panel now open → this run closes it
    expect(c.calls).toContainEqual({ method: "panel.close", input: undefined })
    expect(c.calls.filter((call) => call.method === "panel.open")).toHaveLength(1)
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
    currentSession.reset()
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    const pwn = commandsOf(c).find((cmd) => cmd.id === "hopper.pwn")!
    await pwn.run("example.test") // target given — no prompt dialog
    expect(c.dialogs).not.toContain("prompt:Operation target")
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test" } })
    expect(c.calls.some((call) => call.method === "session.prompt")).toBe(false)
    expect(c.toasts.some((t) => JSON.stringify(t).includes("open a session"))).toBe(true)
  })

  test("kickoff failure: operation stays created, warning toast lands, never crashes", async () => {
    currentSession.reset()
    const c = commandsCtx()
    c.ctx.session.prompt = async () => {
      throw new Error("session gone")
    }
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    const pwn = commandsOf(c).find((cmd) => cmd.id === "hopper.pwn")!
    await pwn.run("example.test")
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("kickoff prompt failed"))).toBe(true)
  })

  test("session.deleted clears the current-session holder", () => {
    currentSession.reset()
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    expect(currentSession.get()).toBe("s1")
    c.subs["session.deleted"]![0]!({ data: { sessionID: "s1" } })
    expect(currentSession.get()).toBeUndefined()
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
  function notificationsCtx(session?: { get: (sessionID: string) => { title?: string } | undefined }) {
    const subs: Record<string, Array<(e: { data: unknown }) => void>> = {}
    const notified: unknown[] = []
    const ctx = {
      data: {
        on: (name: string, cb: (e: { data: unknown }) => void) => {
          ;(subs[name] ??= []).push(cb)
          return () => {}
        },
        ...(session ? { session } : {}),
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

  test("notification names the session when its title is known", async () => {
    const n = notificationsCtx({ get: (id) => (id === "s1" ? { title: "Recon sweep" } : undefined) })
    let t = 1_000_000
    const reg = registerNotifications(n.ctx as never, { now: () => t })
    fire(n, "session.execution.started", "s1")
    t += 61_000
    fire(n, "session.execution.succeeded", "s1")
    await settle()
    expect((n.notified[0] as { message: string }).message).toBe("Recon sweep")
    reg.cleanup()
  })

  test("notification falls back to the generic message without session info", async () => {
    const n = notificationsCtx() // no data.session in ctx
    let t = 1_000_000
    const reg = registerNotifications(n.ctx as never, { now: () => t })
    fire(n, "session.execution.started", "s9")
    t += 61_000
    fire(n, "session.execution.succeeded", "s9")
    await settle()
    expect((n.notified[0] as { message: string }).message).toBe("engagement step")
    reg.cleanup()
  })
})
