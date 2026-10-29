import { describe, expect, test, afterAll } from "bun:test"
import { mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { Database } from "bun:sqlite"
import { HopperStore } from "../src/lib/store"

const dirs: string[] = []

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
})

function tempDir(label: string): string {
  const dir = join(tmpdir(), `hopper-mig-${label}-` + Date.now() + "-" + Math.random().toString(36).slice(2))
  rmSync(dir, { recursive: true, force: true })
  mkdirSync(dir, { recursive: true })
  dirs.push(dir)
  return dir
}

/** Pre-migration DB: old status CHECK, one active + one archived op, one finding. */
function seedLegacyDb(configDir: string): void {
  mkdirSync(join(configDir, "data"), { recursive: true })
  const db = new Database(join(configDir, "data", "hopper.db"))
  db.run(`
    CREATE TABLE operations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      target TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('active','archived')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `)
  db.run(`
    CREATE TABLE findings (
      id TEXT PRIMARY KEY,
      operation_id TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
      status TEXT NOT NULL CHECK (status IN ('candidate','observed','verified','reportable','rejected','stale')),
      target TEXT NOT NULL,
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `)
  db.run(
    "INSERT INTO operations (id, name, target, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    ["op-active", "legacy-active", "http://legacy.example.test", "active", "2025-01-01T00:00:00.000Z", "2025-01-01T00:00:00.000Z"],
  )
  db.run(
    "INSERT INTO operations (id, name, target, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    ["op-archived", "legacy-archived", "http://old.example.test", "archived", "2025-01-01T00:00:00.000Z", "2025-01-01T01:00:00.000Z"],
  )
  db.run(
    "INSERT INTO findings (id, operation_id, title, severity, status, target, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ["f-1", "op-active", "SQLi in login", "high", "candidate", "legacy.example.test", "", "2025-01-02T00:00:00.000Z", "2025-01-02T00:00:00.000Z"],
  )
  db.close()
  writeFileSync(
    join(configDir, "scope.json"),
    JSON.stringify({ targets: ["legacy.example.test"], strict: false, created: "2025-01-01T00:00:00.000Z" }, null, 2) + "\n",
  )
}

function openRaw(configDir: string): Database {
  return new Database(join(configDir, "data", "hopper.db"))
}

function userVersion(db: Database): number {
  return (db.query("PRAGMA user_version").get() as { user_version: number }).user_version
}

function tableSql(db: Database, name: string): string {
  return (db.query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) as { sql: string }).sql
}

function count(db: Database, table: string): number {
  return (db.query(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n
}

describe("HopperStore schema migration", () => {
  test("legacy DB upgrades: status CHECK widened, scope.json imported, findings untouched", () => {
    const dir = tempDir("legacy")
    seedLegacyDb(dir)
    const store = HopperStore.open(dir)
    const finding = store.listFindings().find((f) => f.id === "f-1")
    expect(finding?.title).toBe("SQLi in login")
    expect(finding?.operation_id).toBe("op-active")
    const ops = store.listOperations()
    expect(ops.find((o) => o.id === "op-active")?.status).toBe("active")
    expect(ops.find((o) => o.id === "op-archived")?.status).toBe("archived")
    store.close()

    const db = openRaw(dir)
    expect(userVersion(db)).toBe(2)
    expect(tableSql(db, "operations")).toContain("'active','completed','archived'")
    // the widened CHECK is real: 'completed' is now accepted, garbage still rejected
    db.run(
      "INSERT INTO operations (id, name, target, status, created_at, updated_at) VALUES ('op-completed', 'done', 'http://done.example.test', 'completed', '2025-01-03T00:00:00.000Z', '2025-01-03T00:00:00.000Z')",
    )
    expect(() =>
      db.run(
        "INSERT INTO operations (id, name, target, status, created_at, updated_at) VALUES ('op-bogus', 'bogus', 'http://bogus.example.test', 'zombie', '2025-01-03T00:00:00.000Z', '2025-01-03T00:00:00.000Z')",
      ),
    ).toThrow()
    // scope.json imported into the active operation's scopes row (targets/strict from the file)
    const scope = db.query("SELECT targets, strict FROM scopes WHERE operation_id = 'op-active'").get() as {
      targets: string
      strict: number
    }
    expect(JSON.parse(scope.targets)).toEqual(["legacy.example.test"])
    expect(scope.strict).toBe(0)
    // bindings table exists, starts empty
    expect(tableSql(db, "bindings")).toContain("mode")
    expect(count(db, "bindings")).toBe(0)
    db.close()
    // the file is left on disk untouched
    expect(JSON.parse(readFileSync(join(dir, "scope.json"), "utf8"))).toEqual({
      targets: ["legacy.example.test"],
      strict: false,
      created: "2025-01-01T00:00:00.000Z",
    })
  })

  test("fresh DB gets the v2 schema directly with no scopes row", () => {
    const dir = tempDir("fresh")
    const store = HopperStore.open(dir)
    store.close()
    const db = openRaw(dir)
    expect(userVersion(db)).toBe(2)
    expect(tableSql(db, "operations")).toContain("'active','completed','archived'")
    expect(count(db, "scopes")).toBe(0)
    expect(count(db, "bindings")).toBe(0)
    db.close()
  })

  test("double-open is idempotent: no duplicate migration or scope import", () => {
    const dir = tempDir("idempotent")
    seedLegacyDb(dir)
    HopperStore.open(dir).close()
    HopperStore.open(dir).close()
    const db = openRaw(dir)
    expect(userVersion(db)).toBe(2)
    expect(count(db, "operations")).toBe(2)
    expect(count(db, "scopes")).toBe(1)
    expect(count(db, "findings")).toBe(1)
    db.close()
  })

  test("unreadable scope.json relic does not block startup", () => {
    const dir = tempDir("corrupt")
    seedLegacyDb(dir)
    writeFileSync(join(dir, "scope.json"), "{not json at all")
    const store = HopperStore.open(dir)
    expect(store.listOperations().length).toBe(2)
    store.close()
    const db = openRaw(dir)
    expect(userVersion(db)).toBe(2)
    expect(count(db, "scopes")).toBe(0)
    db.close()
  })
})
