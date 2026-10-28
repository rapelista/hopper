import { describe, expect, test, beforeAll, afterAll } from "bun:test"
import { mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { HopperStore } from "../.opencode/lib/store"
import { redactSecrets, buildShareBundle } from "../.opencode/lib/share"
import { captureEvidence } from "../.opencode/lib/evidence"
import { buildTools } from "../.opencode/lib/tools"

let configDir: string
let store: HopperStore
let opId: string

beforeAll(() => {
  configDir = join(tmpdir(), "hopper-t16-" + Date.now())
  rmSync(configDir, { recursive: true, force: true })
  mkdirSync(configDir, { recursive: true })
  store = HopperStore.open(configDir)
  opId = store.createOperation("share-op", "http://lab.test").id
})

afterAll(() => {
  store.close()
  rmSync(configDir, { recursive: true, force: true })
})

describe("redactSecrets", () => {
  test("strips authorization headers", () => {
    expect(redactSecrets("Authorization: Bearer abc123secret")).toBe("Authorization:<REDACTED>")
    expect(redactSecrets("authorization: Basic dXNlcjpwYXNz")).toBe("authorization:<REDACTED>")
  })

  test("strips cookies and api keys", () => {
    expect(redactSecrets("Cookie: session=abc")).toBe("Cookie:<REDACTED>")
    expect(redactSecrets("X-API-Key: deadbeef")).toBe("X-API-Key:<REDACTED>")
    expect(redactSecrets("token: zzz")).toBe("token:<REDACTED>")
  })

  test("strips quoted-JSON secret shapes", () => {
    expect(redactSecrets('{"token": "eyJhbGci.secret.payload"}')).not.toContain("eyJhbGci")
    expect(redactSecrets('{"access_token":"sk-91"}')).not.toContain("sk-91")
  })

  test("strips password and key material", () => {
    expect(redactSecrets("password=hunter2")).not.toContain("hunter2")
    expect(redactSecrets("client_secret: zzz")).not.toContain("zzz")
    expect(redactSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----")).not.toContain("MIIEow")
  })

  test("leaves ordinary content alone", () => {
    expect(redactSecrets("GET / HTTP/1.1")).toBe("GET / HTTP/1.1")
  })
})

describe("buildShareBundle secret hygiene", () => {
  test("finding notes are redacted in the bundle", () => {
    const f = store.addFinding(opId, { title: "notes-leak", severity: "low", target: "lab.test", notes: "Authorization: Bearer notetoken123" })
    void f
    const { bundle } = buildShareBundle(store, opId)
    expect(JSON.stringify(bundle.findings)).not.toContain("notetoken123")
  })
})

describe("buildShareBundle", () => {
  test("redacts evidence content in the bundle", () => {
    const f = store.addFinding(opId, { title: "leaky", severity: "high", target: "lab.test" })
    const cap = captureEvidence("request", "GET /x\r\nAuthorization: Bearer supersecret")
    store.saveEvidence(opId, cap, "GET /x\r\nAuthorization: Bearer supersecret")
    store.attachEvidence(f.id, cap.id)
    const { bundle } = buildShareBundle(store, opId)
    const ev = bundle.evidence.find((e) => e.id === cap.id)!
    expect(ev.content).not.toContain("supersecret")
    expect(ev.content).toContain("<REDACTED>")
  })

  test("manifest changes when a finding is edited (tamper-evidence)", () => {
    const f = store.addFinding(opId, { title: "before-edit", severity: "medium", target: "lab.test" })
    const first = buildShareBundle(store, opId).manifestSha256
    store.updateFinding(f.id, { title: "after-edit" })
    const second = buildShareBundle(store, opId).manifestSha256
    expect(first).not.toBe(second)
  })

  test("bundle serializes to JSON roundtrip", () => {
    const { bundle, manifestSha256 } = buildShareBundle(store, opId)
    const parsed = JSON.parse(JSON.stringify(bundle))
    expect(parsed.operation.id).toBe(bundle.operation.id)
    expect(manifestSha256).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe("share tool + remediate command", () => {
  test("share tool has description and execute", () => {
    const share = buildTools("/tmp").find((x) => x.name === "share")!
    expect(share.description.length).toBeGreaterThan(10)
    expect(typeof share.execute).toBe("function")
  })

  test("/remediate command targets a finding via $ARGUMENTS", async () => {
    const { readFileSync } = await import("node:fs")
    const raw = readFileSync(join(import.meta.dir, "..", ".opencode", "commands", "remediate.md"), "utf8")
    expect(raw).toContain("$ARGUMENTS")
    expect(raw).toMatch(/^description:\s*.+/m)
  })
})
