import { describe, expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { registerStatus } from "../src/tui/status"
import { buildPanelModel, registerPanel } from "../src/tui/panel"
import { parsePwnArgument, buildKickoffPrompt, registerCommands } from "../src/tui/commands"
import { registerNotifications } from "../src/tui/notifications"
import { currentSession } from "../src/tui/current-session"
import { defaultOperationName } from "../src/tui/format"
import { registerGuardDialog } from "../src/tui"
import { LIFECYCLE, cycleStatus } from "../src/tui/format"
import type { FindingSummary, GuardAskData, OperationListItem, OperationStatusResult } from "../src/rpc"

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

// the /op picker's source: the two actives above plus a completed relic that
// must never be offered (terminal operations are read-only history)
const opsAll: OperationListItem[] = [
  ...opsList,
  { ...opItem("op3", "ghost", "retired.test", { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 }), status: "completed" },
]

const settle = () => new Promise((r) => setTimeout(r, 5))

// ---------------------------------------------------------------- status ----

function statusCtx(listItems: OperationListItem[] = opsList, failStatusFor: string[] = []) {
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
        // session-keyed: s1 is bound to juice, s2 is unbound; failStatusFor sessions reject
        operationStatus: async (input: { sessionID?: string } = {}) => {
          statusFetches++
          statusInputs.push(input)
          if (input.sessionID !== undefined && failStatusFor.includes(input.sessionID)) throw new Error("rpc down")
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
const renderSlot = async <I,>(
  slot: { render: (input?: I) => unknown },
  input?: I,
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
    await renderSlot(sidebar, { sessionID: "s1" })
    await settle()
    const boundFrame = await renderSlot(sidebar, { sessionID: "s1" })
    expect(boundFrame).toContain("juice")
    // switch to s2 — its fetch is in flight, but s1's banner must already be gone
    const pendingFrame = await renderSlot(sidebar, { sessionID: "s2" })
    expect(pendingFrame).not.toContain("juice") // stale display is a cross-session leak too
    expect(pendingFrame).toContain("hop · no operation — /op to bind")
    await settle()
    expect(s.statusInputs).toEqual([{ sessionID: "s1" }, { sessionID: "s2" }])
    const unboundFrame = await renderSlot(sidebar, { sessionID: "s2" })
    expect(unboundFrame).toContain("hop · no operation — /op to bind")
    expect(unboundFrame).not.toContain("juice") // no cross-session leak
    // no sessionID at all (home): the same hint, and still no fetch
    const sessionless = await renderSlot(sidebar)
    expect(sessionless).toContain("hop · no operation — /op to bind")
    expect(s.statusFetches).toBe(2)
    reg.cleanup()
  })

  test("a failed fetch after a session switch leaves the hint — the previous session's block never returns", async () => {
    const s = statusCtx(opsList, ["s2"]) // s2's operationStatus rejects
    const reg = registerStatus(s.ctx as never)
    const sidebar = sidebarOf(s)
    await renderSlot(sidebar, { sessionID: "s1" })
    await settle()
    const boundFrame = await renderSlot(sidebar, { sessionID: "s1" })
    expect(boundFrame).toContain("juice")
    await renderSlot(sidebar, { sessionID: "s2" }) // re-key, then its fetch rejects
    await settle()
    const failedFrame = await renderSlot(sidebar, { sessionID: "s2" })
    expect(failedFrame).not.toContain("juice") // the catch kept the cleared state, not s1's
    expect(failedFrame).toContain("hop · no operation — /op to bind")
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

describe("panel (per session)", () => {
  interface PanelSlotInput {
    name?: string
    sessionID?: string
    toggleFullscreen?: () => void
  }

  // rpc mock keyed by sessionID (statusCtx idiom): s1 bound to op1 (juice),
  // s2 unbound; findings keyed by operationId
  function panelCtx() {
    const finding = (id: string, st: string, target: string): FindingSummary =>
      ({ id, title: `t-${id}`, severity: "high", status: st, target, createdAt: "x" })
    const findingsByOp: Record<string, FindingSummary[]> = {
      op1: [finding("fa", "candidate", "localhost"), finding("fb", "verified", "localhost")],
      op2: [finding("fc", "observed", "example.test")],
    }
    let statusFetches = 0
    let findingsFetches = 0
    const statusInputs: Array<{ sessionID?: string }> = []
    const findingsInputs: Array<{ operationId?: string }> = []
    const eventSubs: Record<string, Array<(e: { data: unknown }) => void>> = {}
    const slots: Array<{ append: string; render: (input?: PanelSlotInput) => unknown }> = []
    const ctx = {
      theme: {
        text: { base: "#e6e6e6", muted: "#888888", feedback: { error: { base: "#ff0000" } } },
      },
      ui: {
        slot: (spec: { append: string; render: (input?: PanelSlotInput) => unknown }) => {
          slots.push(spec)
          return () => {}
        },
      },
      client: {
        rpc: () => ({
          operationStatus: async (input: { sessionID?: string } = {}) => {
            statusFetches++
            statusInputs.push(input)
            return input.sessionID === "s2" ? unbound : status
          },
          findings: async (input: { operationId?: string } = {}) => {
            findingsFetches++
            findingsInputs.push(input)
            return { items: input.operationId === undefined ? [] : (findingsByOp[input.operationId] ?? []) }
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
      keymap: { layer: (cb: () => unknown) => { cb(); return () => {} } },
    }
    return {
      ctx,
      slots,
      eventSubs,
      statusInputs,
      findingsInputs,
      get statusFetches() { return statusFetches },
      get findingsFetches() { return findingsFetches },
    }
  }

  test("renders the session's bound operation findings — findings fetched by operationId", async () => {
    const p = panelCtx()
    const reg = registerPanel(p.ctx as never)
    const slot = p.slots[0]!
    await renderSlot(slot, { name: "hopper.ledger", sessionID: "s1" })
    await settle()
    expect(p.statusInputs).toEqual([{ sessionID: "s1" }])
    expect(p.findingsInputs).toEqual([{ operationId: "op1" }])
    const frame = await renderSlot(slot, { name: "hopper.ledger", sessionID: "s1" })
    expect(frame).toContain("t-fa") // the bound op's finding, on the default candidate tab
    expect(frame).not.toContain("t-fc") // op2's finding never bleeds in
    reg.cleanup()
  })

  test("unbound session: the fallback copy, and no findings fetch", async () => {
    const p = panelCtx()
    const reg = registerPanel(p.ctx as never)
    const slot = p.slots[0]!
    await renderSlot(slot, { name: "hopper.ledger", sessionID: "s2" })
    await settle()
    expect(p.statusInputs).toEqual([{ sessionID: "s2" }])
    expect(p.findingsFetches).toBe(0)
    const frame = await renderSlot(slot, { name: "hopper.ledger", sessionID: "s2" })
    expect(frame).toContain("no active operation — start one with /pwn")
    reg.cleanup()
  })

  test("no session rendered: fallback copy, no fetch; another panel's slot render is a no-op", async () => {
    const p = panelCtx()
    const reg = registerPanel(p.ctx as never)
    await settle()
    expect(p.statusFetches).toBe(0) // nothing resolves without a session
    const frame = await renderSlot(p.slots[0]!, { name: "hopper.ledger" })
    expect(frame).toContain("no active operation — start one with /pwn")
    expect(p.statusFetches).toBe(0)
    const foreign = await renderSlot(p.slots[0]!, { name: "other.panel", sessionID: "s1" })
    expect(foreign).not.toContain("Ledger") // a foreign panel render is a null no-op
    expect(foreign).not.toContain("no active operation")
    expect(p.statusFetches).toBe(0) // a foreign panel never keys our fetches
    reg.cleanup()
  })

  test("re-keying to another session clears the previous session's ledger immediately", async () => {
    const p = panelCtx()
    const reg = registerPanel(p.ctx as never)
    const slot = p.slots[0]!
    await renderSlot(slot, { name: "hopper.ledger", sessionID: "s1" })
    await settle()
    const bound = await renderSlot(slot, { name: "hopper.ledger", sessionID: "s1" })
    expect(bound).toContain("t-fa")
    // switch to s2 — its fetch is in flight, but s1's findings must already be gone
    const pending = await renderSlot(slot, { name: "hopper.ledger", sessionID: "s2" })
    expect(pending).not.toContain("t-fa") // stale display is a cross-session leak too
    expect(pending).toContain("no active operation — start one with /pwn")
    await settle()
    expect(p.statusInputs).toEqual([{ sessionID: "s1" }, { sessionID: "s2" }])
    reg.cleanup()
  })

  test("binding.changed refetches only the panel's session; operation/finding events refetch; cleanup unwires", async () => {
    const p = panelCtx()
    const reg = registerPanel(p.ctx as never)
    const slot = p.slots[0]!
    await renderSlot(slot, { name: "hopper.ledger", sessionID: "s1" })
    await settle()
    expect(p.statusFetches).toBe(1)
    // another session's rebinding is not ours to show
    p.eventSubs["binding.changed"]![0]!({ data: { sessionID: "s9" } })
    await settle()
    expect(p.statusFetches).toBe(1)
    // our session rebinding (bind or unbind) refetches it
    p.eventSubs["binding.changed"]![0]!({ data: { sessionID: "s1" } })
    await settle()
    expect(p.statusFetches).toBe(2)
    expect(p.statusInputs[1]).toEqual({ sessionID: "s1" })
    p.eventSubs["operation.changed"]![0]!({ data: { operationId: "op1" } })
    await settle()
    expect(p.statusFetches).toBe(3)
    p.eventSubs["finding.changed"]![0]!({ data: { operationId: "op1", findingId: "fa", status: "observed" } })
    await settle()
    expect(p.statusFetches).toBe(4)
    reg.cleanup()
    for (const name of ["operation.changed", "finding.changed", "binding.changed"]) {
      expect(p.eventSubs[name]?.length ?? 0).toBe(0)
    }
    const before = p.statusFetches
    await settle()
    expect(p.statusFetches).toBe(before)
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
  interface SelectSpec {
    title: string
    current?: unknown
    options: Array<{ value: string; title: string; description?: string }>
    actions?: Array<{ bind: string; title: string; onTrigger: (value: string) => void }>
  }

  function commandsCtx() {
    const layers: Array<Record<string, unknown>> = []
    const toasts: unknown[] = []
    const dialogs: string[] = []
    const calls: Array<{ method: string; input: unknown }> = []
    const subs: Record<string, Array<(e: { data: unknown }) => void>> = {}
    const selects: Array<{ spec: SelectSpec; resolve: (value: unknown) => void }> = []
    let confirmAnswer = true
    let openPanel: { name: string; sessionID: string } | undefined
    // mutable on purpose — failure-path tests swap methods per test
    const client: {
      operationStatus: (input?: { sessionID?: string }) => Promise<OperationStatusResult>
      operationsList: (input?: unknown) => Promise<{ items: OperationListItem[] }>
      bind: (i: unknown) => Promise<unknown>
      unbind: (i: unknown) => Promise<unknown>
      setOperationStatus: (i: unknown) => Promise<unknown>
      deleteOperation: (i: unknown) => Promise<unknown>
      createOperation: (i: unknown) => Promise<unknown>
      setOpsec: (i: unknown) => Promise<unknown>
      events: { on: () => () => void }
    } = {
      // session-keyed: s1 is bound to juice (op1); s2 reads unbound
      operationStatus: async (input: { sessionID?: string } = {}) => {
        calls.push({ method: "operationStatus", input })
        return input.sessionID === "s2" ? unbound : status
      },
      operationsList: async () => {
        calls.push({ method: "operationsList", input: {} })
        return { items: opsAll }
      },
      bind: async (input: unknown) => {
        const i = input as { sessionID: string; operationId: string }
        calls.push({ method: "bind", input: i })
        return { operationId: i.operationId }
      },
      unbind: async (input: unknown) => {
        const i = input as { sessionID: string }
        calls.push({ method: "unbind", input: i })
        return { operationId: null }
      },
      setOperationStatus: async (input: unknown) => {
        const i = input as { operationId: string; status: string }
        calls.push({ method: "setOperationStatus", input: i })
        return { status: i.status }
      },
      deleteOperation: async (input: unknown) => {
        const i = input as { operationId: string }
        calls.push({ method: "deleteOperation", input: i })
        return { ok: true }
      },
      createOperation: async (i: unknown) => {
        calls.push({ method: "createOperation", input: i })
        return { operation: { id: "op9", name: "example", target: "example.test", createdAt: "x" } }
      },
      setOpsec: async (i: unknown) => {
        calls.push({ method: "setOpsec", input: i })
        return { opsec: "strict" }
      },
      events: { on: () => () => {} },
    }
    const ctx = {
      keymap: { layer: (factory: () => Record<string, unknown>) => { layers.push(factory()); return () => {} } },
      ui: {
        dialog: {
          prompt: async (i: { title: string }) => { dialogs.push(`prompt:${i.title}`); return "example.test" },
          confirm: async (i: { title: string }) => { dialogs.push(`confirm:${i.title}`); return confirmAnswer },
          // deferred like the real one: the dialog stays open until the test
          // resolves it — footer actions do not close it either
          select: (i: SelectSpec) => {
            dialogs.push("select")
            return new Promise<unknown>((resolve) => selects.push({ spec: i, resolve }))
          },
        },
        toast: { show: (t: unknown) => { toasts.push(t) } },
        panel: {
          open: (name: string) => { calls.push({ method: "panel.open", input: name }); openPanel = { name, sessionID: "s1" }; return true },
          close: () => { calls.push({ method: "panel.close", input: undefined }); openPanel = undefined },
          current: () => openPanel,
        },
      },
      client: { rpc: () => client },
      data: { on: (name: string, cb: (e: { data: unknown }) => void) => { (subs[name] ??= []).push(cb); return () => {} } },
      session: { prompt: async (i: unknown) => { calls.push({ method: "session.prompt", input: i }); return {} } },
    }
    return { ctx, client, layers, toasts, dialogs, calls, subs, selects, decline: () => { confirmAnswer = false } }
  }

  const commandsOf = (c: ReturnType<typeof commandsCtx>) =>
    c.layers[0]!.commands as Array<{ id: string; run: (input?: string) => unknown }>

  // fire-and-settle: picker flows hold their select open, so run() may legitimately never resolve
  const runCommand = async (c: ReturnType<typeof commandsCtx>, id: string, input?: string) => {
    void commandsOf(c).find((cmd) => cmd.id === id)!.run(input)
    await settle()
  }

  test("registers pwn/op/opsec/ledger slash commands with slash names", () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    const cmds = commandsOf(c) as Array<{ id: string; slash?: { name: string } }>
    expect(cmds.map((cmd) => cmd.id)).toEqual(["hopper.pwn", "hopper.op", "hopper.opsec", "hopper.ledger"])
    expect(cmds.map((cmd) => cmd.slash?.name)).toEqual(["pwn", "op", "opsec", "ledger"])
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

  test("pwn on a bound session: rebind confirm first, create carries the session, kickoff submits", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } }) // s1 is bound to juice
    await runCommand(c, "hopper.pwn", "")
    expect(c.dialogs).toContainEqual("prompt:Operation target")
    expect(c.calls).toContainEqual({ method: "operationStatus", input: { sessionID: "s1" } })
    expect(c.dialogs).toContainEqual("confirm:Start a new operation and rebind this session?")
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test", sessionID: "s1" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("active"))).toBe(true)
    expect(c.calls.some((call) => call.method === "session.prompt" && JSON.stringify(call.input).includes("PTES"))).toBe(true)
  })

  test("pwn decline is a cancel: nothing is created, the old operation keeps the session", async () => {
    const c = commandsCtx()
    c.decline()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.pwn", "example.test")
    expect(c.dialogs).toContainEqual("confirm:Start a new operation and rebind this session?")
    expect(c.calls.some((call) => call.method === "createOperation")).toBe(false)
    expect(c.calls.some((call) => call.method === "session.prompt")).toBe(false)
  })

  test("pwn on an unbound session: no confirm, create still carries the session", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s2" } }) // s2 reads unbound
    await runCommand(c, "hopper.pwn", "example.test")
    expect(c.calls).toContainEqual({ method: "operationStatus", input: { sessionID: "s2" } })
    expect(c.dialogs.some((d) => d.startsWith("confirm:"))).toBe(false)
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test", sessionID: "s2" } })
    expect(c.calls.some((call) => call.method === "session.prompt")).toBe(true)
  })

  test("pwn without a current session: creates unbound, hints instead of submitting", async () => {
    currentSession.reset()
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    await runCommand(c, "hopper.pwn", "example.test") // target given — no prompt dialog
    expect(c.dialogs).not.toContain("prompt:Operation target")
    expect(c.calls.some((call) => call.method === "operationStatus")).toBe(false)
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
    await runCommand(c, "hopper.pwn", "example.test")
    expect(c.calls).toContainEqual({ method: "createOperation", input: { name: "example", target: "example.test", sessionID: "s1" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("kickoff prompt failed"))).toBe(true)
  })

  test("pwn createOperation RESOLVING a typed error: error toast only — no success toast, no kickoff (F4)", async () => {
    const c = commandsCtx()
    // lenient transport shape: the typed error resolves instead of rejecting —
    // without the errorType guard this toasts "Operation … active" and kicks
    // off a session for an operation that was never created
    c.client.createOperation = async () => ({ type: "no_operation", message: "store unwritable" })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.pwn", "example.test")
    expect(c.toasts.some((t) => (t as { variant?: string }).variant === "error" && JSON.stringify(t).includes("store unwritable"))).toBe(true)
    expect(c.toasts.some((t) => (t as { variant?: string }).variant === "success")).toBe(false)
    expect(c.calls.some((call) => call.method === "session.prompt")).toBe(false)
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

  test("opsec on a bound session: one level select naming the operation, setOpsec carries its id", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.opsec")
    expect(c.selects).toHaveLength(1) // direct — no picker stage
    expect(c.selects[0]!.spec.title).toBe("Opsec — juice")
    expect(c.selects[0]!.spec.current).toBe("strict")
    c.selects[0]!.resolve("strict")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOpsec", input: { operationId: "op1", level: "strict" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("strict"))).toBe(true)
  })

  test("opsec sessionless: two stages — pick the operation, then the level", async () => {
    currentSession.reset()
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    await runCommand(c, "hopper.opsec")
    const picker = c.selects[0]!.spec
    expect(picker.title).toBe("Set opsec on")
    expect(picker.options.map((o) => o.title)).toEqual(["juice · localhost", "shop · example.test"])
    expect(picker.actions).toBeUndefined() // the opsec stage carries no lifecycle actions
    c.selects[0]!.resolve("op2")
    await settle()
    expect(c.selects[1]!.spec.title).toBe("Opsec — shop")
    c.selects[1]!.resolve("strict")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOpsec", input: { operationId: "op2", level: "strict" } })
  })

  test("opsec setOpsec failure surfaces as an error toast", async () => {
    const c = commandsCtx()
    c.client.setOpsec = async () => {
      throw { type: "no_operation", message: "unknown operation op1" }
    }
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.opsec")
    c.selects[0]!.resolve("strict")
    await settle()
    expect(c.toasts.some((t) => (t as { variant?: string }).variant === "error" && JSON.stringify(t).includes("unknown operation"))).toBe(true)
  })

  test("op picker: actives only with findings summaries; selecting binds the current session", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    const spec = c.selects[0]!.spec
    expect(spec.title).toBe("Bind an operation")
    expect(spec.options.map((o) => o.title)).toEqual(["juice · localhost", "shop · example.test"]) // ghost (completed) is absent
    expect(spec.options.map((o) => o.description)).toEqual(["3 findings", "2 findings"])
    expect(spec.actions!.map((a) => a.bind)).toEqual(["u", "c", "a", "g", "d"])
    c.selects[0]!.resolve("op2")
    await settle()
    expect(c.calls).toContainEqual({ method: "bind", input: { sessionID: "s1", operationId: "op2" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("shop"))).toBe(true)
  })

  test("op picker without a current session: warning toast, no dialog, no bind", async () => {
    currentSession.reset()
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    await runCommand(c, "hopper.op")
    expect(c.toasts.some((t) => JSON.stringify(t).includes("no current session"))).toBe(true)
    expect(c.selects).toHaveLength(0)
    expect(c.calls.some((call) => call.method === "bind")).toBe(false)
  })

  test("op picker with no active operations: warning toast instead of a dialog", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: [opsAll[2]!] }) // only the completed ghost
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    expect(c.toasts.some((t) => JSON.stringify(t).includes("no active operations"))).toBe(true)
    expect(c.selects).toHaveLength(0)
  })

  test("lifecycle actions: complete/archive hit setOperationStatus on the highlighted op and re-open; a superseded select never binds", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "c")!.onTrigger("op2")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOperationStatus", input: { operationId: "op2", status: "completed" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("completed"))).toBe(true)
    expect(c.selects).toHaveLength(2) // re-opened with the fresh list
    c.selects[1]!.spec.actions!.find((a) => a.bind === "a")!.onTrigger("op1")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOperationStatus", input: { operationId: "op1", status: "archived" } })
    expect(c.selects).toHaveLength(3)
    // the first (superseded) select resolving late must NOT fall through to bind
    c.selects[0]!.resolve("op2")
    await settle()
    expect(c.calls.some((call) => call.method === "bind")).toBe(false)
  })

  // fixtures for the archive view: one active, two archived, one completed
  const archiveOps = (): OperationListItem[] => [
    opItem("op1", "juice", "localhost", status.findings),
    { ...opItem("op4", "old-shop", "old.test", { candidate: 0, observed: 1, verified: 0, reportable: 0, rejected: 0, stale: 0 }), status: "archived" },
    { ...opItem("op5", "older", "ancient.test", { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 }), status: "archived" },
    { ...opItem("op3", "ghost", "retired.test", { candidate: 0, observed: 0, verified: 0, reportable: 0, rejected: 0, stale: 0 }), status: "completed" },
  ]

  test("g opens the archive list: archived only, completed absent, footer u", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: archiveOps() })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    expect(c.selects).toHaveLength(2)
    const spec = c.selects[1]!.spec
    expect(spec.title).toBe("Archived operations")
    expect(spec.options.map((o) => o.title)).toEqual(["old-shop · old.test", "older · ancient.test"]) // completed ghost absent
    expect(spec.actions!.map((a) => a.bind)).toEqual(["u"])
  })

  test("u unarchives the highlighted op and re-opens the archive list", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: archiveOps() })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    c.selects[1]!.spec.actions!.find((a) => a.bind === "u")!.onTrigger("op4")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOperationStatus", input: { operationId: "op4", status: "active" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("operation active"))).toBe(true)
    expect(c.selects).toHaveLength(3) // archive list re-opened
    // the mock still returns op4 archived, so the re-opened list is unchanged — the RPC call is the proof
  })

  test("Enter on an archived op unarchives it", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: archiveOps() })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    c.selects[1]!.resolve("op5")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOperationStatus", input: { operationId: "op5", status: "active" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("operation active"))).toBe(true)
  })

  test("last archived op unarchived → archive falls back to the main picker", async () => {
    const c = commandsCtx()
    // one active (so the main picker opens) + a single archived op
    let items = [archiveOps()[0]!, archiveOps()[1]!]
    c.client.operationsList = async () => ({ items })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    // the mock reflects the mutation: the revived op comes back active
    c.client.setOperationStatus = async (input: unknown) => {
      const i = input as { operationId: string; status: string }
      c.calls.push({ method: "setOperationStatus", input: i })
      items = [items[0]!, { ...items[1]!, status: "active" as const }]
      return { status: i.status }
    }
    c.selects[1]!.spec.actions!.find((a) => a.bind === "u")!.onTrigger("op4")
    await settle()
    expect(c.calls).toContainEqual({ method: "setOperationStatus", input: { operationId: "op4", status: "active" } })
    expect(c.selects).toHaveLength(3)
    expect(c.selects[2]!.spec.title).toBe("Bind an operation") // fell back to the main picker
    expect(c.selects[2]!.spec.options.map((o) => o.title)).toEqual(["juice · localhost", "old-shop · old.test"]) // revived, now active
  })

  test("stale archive list: typed no_operation → error toast, re-open still happens", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: archiveOps() })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    // lenient transport shape: the typed error resolves instead of rejecting
    c.client.setOperationStatus = async () => ({ type: "no_operation", message: "unknown operation op4" })
    c.selects[1]!.spec.actions!.find((a) => a.bind === "u")!.onTrigger("op4")
    await settle()
    expect(c.toasts.some((t) => (t as { variant?: string }).variant === "error" && JSON.stringify(t).includes("unknown operation op4"))).toBe(true)
    expect(c.toasts.some((t) => (t as { variant?: string }).variant === "success")).toBe(false) // no false success
    expect(c.selects).toHaveLength(3) // archive list re-opened anyway
  })

  test("empty archive list → warning toast, main picker re-opens", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: opsAll }) // actives + completed, nothing archived
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    expect(c.toasts.some((t) => JSON.stringify(t).includes("no archived operations"))).toBe(true)
    expect(c.selects).toHaveLength(2)
    expect(c.selects[1]!.spec.title).toBe("Bind an operation") // main picker re-opened, not a dead end
  })

  test("superseded main-picker select after g never binds", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: archiveOps() })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
    await settle()
    c.selects[0]!.resolve("op1") // the superseded main picker resolving late
    await settle()
    expect(c.calls.some((call) => call.method === "bind")).toBe(false)
  })

  test("a torn-down archive select never surfaces as an unhandled rejection", async () => {
    const c = commandsCtx()
    c.client.operationsList = async () => ({ items: archiveOps() })
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    const original = console.error
    console.error = () => {}
    try {
      // the host tears the dialog down (or a superseded select rejects) mid-archive-view
      ;(c.ctx.ui.dialog as { select: unknown }).select = () => Promise.reject(new Error("dialog torn down"))
      c.selects[0]!.spec.actions!.find((a) => a.bind === "g")!.onTrigger("op4")
      await settle()
      await settle()
    } finally {
      console.error = original
    }
    expect(c.selects).toHaveLength(1) // the archive flow bailed — no dialog registered, no unhandled rejection
    expect(c.calls.some((call) => call.method === "bind")).toBe(false)
  })

  test("a torn-down main-picker select never surfaces as an unhandled rejection", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    const original = console.error
    console.error = () => {}
    try {
      ;(c.ctx.ui.dialog as { select: unknown }).select = () => Promise.reject(new Error("dialog torn down"))
      await runCommand(c, "hopper.op")
    } finally {
      console.error = original
    }
    expect(c.selects).toHaveLength(0)
    expect(c.calls.some((call) => call.method === "bind")).toBe(false)
  })

  test("delete action: confirms first; a decline is a cancel — no delete, no re-open, the picker stays live", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.decline()
    c.selects[0]!.spec.actions!.find((a) => a.bind === "d")!.onTrigger("op2")
    await settle()
    expect(c.dialogs).toContainEqual("confirm:Delete operation?")
    expect(c.calls.some((call) => call.method === "deleteOperation")).toBe(false)
    expect(c.selects).toHaveLength(1) // no re-open after a cancel
    c.selects[0]!.resolve("op1") // the picker survived the decline
    await settle()
    expect(c.calls).toContainEqual({ method: "bind", input: { sessionID: "s1", operationId: "op1" } })
  })

  test("delete action confirmed: deleteOperation runs and the picker re-opens", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "d")!.onTrigger("op2")
    await settle()
    expect(c.calls).toContainEqual({ method: "deleteOperation", input: { operationId: "op2" } })
    expect(c.toasts.some((t) => JSON.stringify(t).includes("deleted"))).toBe(true)
    expect(c.selects).toHaveLength(2)
  })

  test("unbind action: unbinds the current session, keeps the picker live (no re-open)", async () => {
    const c = commandsCtx()
    registerCommands(c.ctx as never)
    c.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(c, "hopper.op")
    c.selects[0]!.spec.actions!.find((a) => a.bind === "u")!.onTrigger("op1")
    await settle()
    expect(c.calls).toContainEqual({ method: "unbind", input: { sessionID: "s1" } })
    expect(c.selects).toHaveLength(1)
    c.selects[0]!.resolve("op2") // still open — a follow-up selection binds
    await settle()
    expect(c.calls).toContainEqual({ method: "bind", input: { sessionID: "s1", operationId: "op2" } })
  })

  test("bind typed errors surface as error toasts — thrown and resolved shapes", async () => {
    const thrown = commandsCtx()
    thrown.client.bind = async () => {
      throw { type: "not_active", message: "operation op2 is completed, not active" }
    }
    registerCommands(thrown.ctx as never)
    thrown.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(thrown, "hopper.op")
    thrown.selects[0]!.resolve("op2")
    await settle()
    expect(thrown.toasts.some((t) => (t as { variant?: string }).variant === "error" && JSON.stringify(t).includes("not active"))).toBe(true)

    const resolved = commandsCtx()
    resolved.client.bind = async () => ({ type: "not_active", message: "operation op2 is completed, not active" })
    registerCommands(resolved.ctx as never)
    resolved.subs["tui.session.select"]![0]!({ data: { sessionID: "s1" } })
    await runCommand(resolved, "hopper.op")
    resolved.selects[0]!.resolve("op2")
    await settle()
    expect(resolved.toasts.some((t) => (t as { variant?: string }).variant === "error" && JSON.stringify(t).includes("not active"))).toBe(true)
  })
})

// ----------------------------------------------------------- guard.ask ----

describe("guard.ask dialog", () => {
  interface GuardSelectSpec {
    title: string
    options: Array<{ value: string; title: string }>
  }
  type GuardAnswer = { askId: string; choice: string; operationId?: string }

  function guardCtx(listItems: OperationListItem[] = opsAll, opts: { rejectSelect?: boolean } = {}) {
    let listFetches = 0
    const selects: Array<{ spec: GuardSelectSpec; resolve: (value: unknown) => void }> = []
    const prompts: Array<{ spec: { title: string; placeholder?: string }; resolve: (value: unknown) => void }> = []
    const answers: GuardAnswer[] = []
    const creates: Array<{ name: string; target: string; sessionID?: string }> = []
    const toasts: unknown[] = []
    const subs: Record<string, Array<(e: { data: unknown }) => void>> = {}
    // mutable on purpose — failure-path tests swap createOperation per test
    const client = {
      operationsList: async () => {
        listFetches++
        return { items: listItems }
      },
      createOperation: async (i: { name: string; target: string; sessionID?: string }): Promise<
        { operation: { id: string; name: string; target: string; createdAt: string } } | { type: string; message: string }
      > => {
        creates.push(i)
        return { operation: { id: "op9", name: "fresh", target: "fresh.test", createdAt: "x" } }
      },
      guardAnswer: async (input: GuardAnswer) => {
        answers.push(input)
        return { accepted: true }
      },
      events: {
        on: (name: string, cb: (e: { data: unknown }) => void) => {
          ;(subs[name] ??= []).push(cb)
          return () => {
            subs[name] = (subs[name] ?? []).filter((x) => x !== cb)
          }
        },
      },
    }
    const ctx = {
      ui: {
        dialog: {
          // deferred like the real one: the dialog stays open until the test resolves it
          select: (i: GuardSelectSpec) => {
            if (opts.rejectSelect) return Promise.reject(new Error("dialog torn down"))
            return new Promise<unknown>((resolve) => selects.push({ spec: i, resolve }))
          },
          prompt: (i: { title: string; placeholder?: string }) =>
            new Promise<unknown>((resolve) => prompts.push({ spec: i, resolve })),
        },
        toast: { show: (t: unknown) => { toasts.push(t) } },
      },
      client: { rpc: () => client },
    }
    return { ctx, client, selects, prompts, answers, creates, toasts, subs, get listFetches() { return listFetches } }
  }

  const ask = (sessionID = "s1"): GuardAskData => ({
    askId: "ask1",
    sessionID,
    messageID: "m1",
    tool: "websearch",
    targets: ["example.test"],
    reason: "websearch is a scoped weapon and this session has no bound operation",
  })
  const fire = (g: ReturnType<typeof guardCtx>, data: GuardAskData) =>
    g.subs["guard.ask"]![0]!({ data })

  const OPTION_TITLES = ["Free this session until closed", "Allow once", "Deny"]

  test("single active: quick-bind names it; bind answers with operationId", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx([opsList[0]!]) // exactly one active op
    const reg = registerGuardDialog(g.ctx as never)
    expect(g.listFetches).toBe(0) // lazy — operationsList is not fetched at setup
    fire(g, ask())
    await settle()
    expect(g.listFetches).toBe(1) // fetched when the ask arrived
    expect(g.selects).toHaveLength(1)
    expect(g.selects[0]!.spec.title).toBe("websearch is a scoped weapon and this session has no bound operation")
    expect(g.selects[0]!.spec.options.map((o) => o.title)).toEqual(["Bind: juice · localhost", "New operation…", ...OPTION_TITLES])
    g.selects[0]!.resolve("bind")
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "bind", operationId: "op1" }])
    reg.cleanup()
  })

  test("two actives: chooser sub-picker; the chosen op (not the first) answers", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx() // opsAll: juice + shop active, ghost completed
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    expect(g.selects[0]!.spec.options.map((o) => o.title)).toEqual(["Choose operation…", "New operation…", ...OPTION_TITLES])
    g.selects[0]!.resolve("choose")
    await settle()
    expect(g.selects).toHaveLength(2)
    expect(g.selects[1]!.spec.title).toBe("Bind an operation")
    expect(g.selects[1]!.spec.options.map((o) => o.title)).toEqual(["juice · localhost", "shop · example.test"])
    expect(g.selects[1]!.spec.options.map((o) => (o as { description?: string }).description)).toEqual(["3 findings", "2 findings"])
    g.selects[1]!.resolve("op2")
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "bind", operationId: "op2" }])
    reg.cleanup()
  })

  test("new operation: prompt target, create binds the ask's session, answer bind with the new id", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx([opsList[0]!])
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve("new")
    await settle()
    expect(g.prompts).toHaveLength(1)
    expect(g.prompts[0]!.spec.title).toBe("Operation target")
    g.prompts[0]!.resolve("fresh.test")
    await settle()
    expect(g.creates).toEqual([{ name: defaultOperationName("fresh.test"), target: "fresh.test", sessionID: "s1" }])
    expect(g.answers).toEqual([{ askId: "ask1", choice: "bind", operationId: "op9" }])
    reg.cleanup()
  })

  test("esc in the sub-picker answers deny — no create, nothing left hanging", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve("choose")
    await settle()
    g.selects[1]!.resolve(undefined)
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    expect(g.creates).toHaveLength(0)
    reg.cleanup()
  })

  test("esc in the target prompt answers deny — nothing is created", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx([opsList[0]!])
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve("new")
    await settle()
    g.prompts[0]!.resolve(undefined)
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    expect(g.creates).toHaveLength(0)
    reg.cleanup()
  })

  test("create typed error → error toast + deny, never a bind answer with a bogus id", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx([opsList[0]!])
    // lenient transport shape: the typed error resolves instead of rejecting
    g.client.createOperation = async () => ({ type: "no_operation", message: "store unwritable" })
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve("new")
    await settle()
    g.prompts[0]!.resolve("fresh.test")
    await settle()
    expect(g.toasts.some((t) => (t as { variant?: string }).variant === "error" && JSON.stringify(t).includes("store unwritable"))).toBe(true)
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    reg.cleanup()
  })

  test("blank target prompt answers deny — no garbage operation, no bind", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx([opsList[0]!])
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve("new")
    await settle()
    g.prompts[0]!.resolve("   ") // blank submit is a cancel, not an operation
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    expect(g.creates).toHaveLength(0)
    reg.cleanup()
  })

  test("torn-down sub-picker answers deny — logged, never an unhandled rejection", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    const original = console.error
    console.error = () => {}
    try {
      ;(g.ctx.ui.dialog as { select: unknown }).select = () => Promise.reject(new Error("dialog torn down"))
      g.selects[0]!.resolve("choose")
      await settle()
      await settle()
    } finally {
      console.error = original
    }
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    reg.cleanup()
  })

  test("ask for another session: no dialog, no answer, no fetch — the server timeout covers it", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask("s9"))
    await settle()
    expect(g.selects).toHaveLength(0)
    expect(g.answers).toHaveLength(0)
    expect(g.listFetches).toBe(0)
    reg.cleanup()
  })

  test("no active operations: New operation… is the only bind path; free answers without operationId", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx([opsAll[2]!]) // only the completed ghost
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    expect(g.selects[0]!.spec.options.map((o) => o.title)).toEqual(["New operation…", ...OPTION_TITLES])
    g.selects[0]!.resolve("free")
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "free" }])
    reg.cleanup()
  })

  test("allow-once maps to its choice", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve("allow-once")
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "allow-once" }])
    reg.cleanup()
  })

  test("a dismissed select (esc) answers deny — dismissal is a decision, not a hang until timeout", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    g.selects[0]!.resolve(undefined)
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    reg.cleanup()
  })

  test("a REJECTED select (teardown/supersession) answers deny — logged, never an unhandled rejection (F6)", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx(opsAll, { rejectSelect: true })
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    // two settles: if onAsk left the rejection unhandled, bun's default
    // unhandled-rejection handling fails this run right here
    await settle()
    await settle()
    expect(g.answers).toEqual([{ askId: "ask1", choice: "deny" }])
    reg.cleanup()
  })

  test("a long reason truncates to a sane title", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    const long = { ...ask(), reason: "r".repeat(200) }
    fire(g, long)
    await settle()
    const title = g.selects[0]!.spec.title
    expect(title.length).toBeLessThanOrEqual(80)
    expect(title.endsWith("…")).toBe(true)
    reg.cleanup()
  })

  test("cleanup unwires the listener", async () => {
    currentSession.reset()
    currentSession.set("s1")
    const g = guardCtx()
    const reg = registerGuardDialog(g.ctx as never)
    fire(g, ask())
    await settle()
    expect(g.selects).toHaveLength(1) // it was live
    reg.cleanup()
    // the event bus can no longer reach us — nothing left to deliver to
    expect(g.subs["guard.ask"]?.length ?? 0).toBe(0)
    await settle()
    expect(g.answers).toHaveLength(0)
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
