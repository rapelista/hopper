import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { sha256Hex, captureEvidence, verifyEvidence } from "../src/lib/evidence"
import { HopperStore } from "../src/lib/store"
import { buildTools } from "../src/lib/tools"

let configDir: string
let store: HopperStore
let opId: string
let findingId: string

beforeAll(() => {
  configDir = join(tmpdir(), "hopper-t12-" + Date.now())
  rmSync(configDir, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
  store = HopperStore.open(configDir)
  opId = store.createOperation("t12", "http://lab.test").id
  findingId = store.addFinding(opId, { title: "XSS in search", severity: "high", target: "lab.test" }).id
})

afterAll(() => {
  store.close()
  rmSync(configDir, { recursive: true, force: true })
})

describe("hashing", () => {
  test("sha256 known vector", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  })

  test("tampered content fails verification (RF#4)", () => {
    const hash = sha256Hex("original evidence")
    expect(verifyEvidence("original evidence", hash)).toBe(true)
    expect(verifyEvidence("original evidence-x", hash)).toBe(false)
  })
})

describe("captureEvidence", () => {
  test("produces id, kind, sha256, size, meta", () => {
    const cap = captureEvidence("response", "HTTP/1.1 200 OK\n\nsecret-token", { url: "https://lab.test/x" })
    expect(cap.id).toMatch(/^[0-9a-f-]{36}$/)
    expect(cap.kind).toBe("response")
    expect(cap.sha256).toBe(sha256Hex("HTTP/1.1 200 OK\n\nsecret-token"))
    expect(cap.size).toBe(29)
    expect(cap.meta.url).toBe("https://lab.test/x")
    expect(cap.created_at).toBeTruthy()
  })
})

describe("store evidence", () => {
  test("save + list roundtrip", () => {
    const cap = captureEvidence("command", "nmap -sV lab.test\n…open ports…")
    const saved = store.saveEvidence(opId, cap, "nmap -sV lab.test\n…open ports…")
    expect(saved.operation_id).toBe(opId)
    const listed = store.listEvidence(opId)
    expect(listed.some((e) => e.id === cap.id)).toBe(true)
  })

  test("attach to finding and list by finding", () => {
    const cap = captureEvidence("request", "GET /search?q=<script> HTTP/1.1")
    store.saveEvidence(opId, cap, "GET /search?q=<script> HTTP/1.1")
    store.attachEvidence(findingId, cap.id)
    const forFinding = store.listEvidence(opId, findingId)
    expect(forFinding.some((e) => e.id === cap.id)).toBe(true)
  })
})

describe("evidence tool shape", () => {
  test("tool has description and executable content", () => {
    const t = buildTools("/tmp").find((x) => x.name === "evidence")!
    expect(t.description.length).toBeGreaterThan(10)
    expect(typeof t.execute).toBe("function")
  })
})
