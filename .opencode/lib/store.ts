import { Database } from "bun:sqlite"
import { mkdirSync } from "node:fs"
import { join } from "node:path"
import { saveScope } from "./scope"

export interface Operation {
  id: string
  name: string
  target: string
  status: "active" | "archived"
  created_at: string
  updated_at: string
}

function rowToOperation(row: Record<string, unknown>): Operation {
  return {
    id: row.id as string,
    name: row.name as string,
    target: row.target as string,
    status: row.status as Operation["status"],
    created_at: row.created_at as string,
    updated_at: row.updated_at as string,
  }
}

export class HopperStore {
  private db: Database
  private configDir: string | null

  constructor(dbPath: string, configDir: string | null = null) {
    this.configDir = configDir
    mkdirSync(dbPath.slice(0, dbPath.lastIndexOf("/")), { recursive: true })
    this.db = new Database(dbPath)
    this.db.run("PRAGMA journal_mode = WAL")
    this.db.run(`
      CREATE TABLE IF NOT EXISTS operations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active','archived')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `)
  }

  static open(configDir: string): HopperStore {
    return new HopperStore(join(configDir, "data", "hopper.db"), configDir)
  }

  close(): void {
    this.db.close()
  }

  createOperation(name: string, target: string): Operation {
    const now = new Date().toISOString()
    this.db.run("UPDATE operations SET status = 'archived', updated_at = ? WHERE status = 'active'", [now])
    const op: Operation = {
      id: crypto.randomUUID(),
      name,
      target,
      status: "active",
      created_at: now,
      updated_at: now,
    }
    this.db.run(
      "INSERT INTO operations (id, name, target, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      [op.id, op.name, op.target, op.status, op.created_at, op.updated_at],
    )
    if (this.configDir) {
      // scope bootstrap is owned by the store so every creation path stays fail-closed
      saveScope(this.configDir, { targets: [target], strict: true, created: now })
    }
    return op
  }

  getActiveOperation(): Operation | null {
    const row = this.db.query("SELECT * FROM operations WHERE status = 'active' ORDER BY updated_at DESC LIMIT 1").get() as
      | Record<string, unknown>
      | null
    return row ? rowToOperation(row) : null
  }

  listOperations(): Operation[] {
    const rows = this.db
      .query("SELECT * FROM operations ORDER BY updated_at DESC")
      .all() as Array<Record<string, unknown>>
    return rows.map(rowToOperation)
  }

  archiveOperation(id: string): void {
    this.db.run("UPDATE operations SET status = 'archived', updated_at = ? WHERE id = ?", [
      new Date().toISOString(),
      id,
    ])
  }
}
