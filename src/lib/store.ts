import { Database } from "bun:sqlite"
import { mkdirSync } from "node:fs"
import { join } from "node:path"
import { loadScope, saveScope } from "./scope"
import { assertTransition, FindingError, type FindingStatus, type Severity } from "./findings"
import type { CapturedEvidence, EvidenceKind } from "./evidence"

export type { FindingStatus, Severity }

export interface Evidence extends CapturedEvidence {
  operation_id: string
  content: string
}

export interface Operation {
  id: string
  name: string
  target: string
  status: "active" | "archived"
  created_at: string
  updated_at: string
}

export interface Finding {
  id: string
  operation_id: string
  title: string
  severity: Severity
  status: FindingStatus
  target: string
  notes: string
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
    this.migrate()
  }

  /**
   * Schema migration keyed on PRAGMA user_version (current schema = 2).
   * Legacy DBs (version 0, status CHECK ('active','archived')) get a one-time
   * upgrade: SQLite cannot ALTER a CHECK, so `operations` is recreated with
   * the widened CHECK and its rows copied (all statuses in the wild are
   * 'active'|'archived' — valid under the new CHECK); the file-based
   * scope.json is imported into the active operation's scopes row. The
   * declared REFERENCES ... ON DELETE CASCADE on the new tables is
   * informational only — nothing may depend on FK enforcement
   * (foreign_keys stays OFF; no pragma enables it).
   */
  private migrate(): void {
    const { user_version: version } = this.db.query("PRAGMA user_version").get() as { user_version: number }
    if (version >= 2) return
    const legacy = this.db.query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'operations'").get() !== null
    if (legacy) {
      this.db.run("BEGIN")
      try {
        this.db.run(`
          CREATE TABLE operations_v2 (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active','completed','archived')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
          )
        `)
        this.db.run(
          "INSERT INTO operations_v2 (id, name, target, status, created_at, updated_at) SELECT id, name, target, status, created_at, updated_at FROM operations",
        )
        this.db.run("DROP TABLE operations")
        this.db.run("ALTER TABLE operations_v2 RENAME TO operations")
        this.db.run("COMMIT")
      } catch (error) {
        this.db.run("ROLLBACK")
        throw error
      }
    }
    this.createTables()
    if (legacy) this.importLegacyScope()
    this.db.run("PRAGMA user_version = 2")
  }

  private createTables(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS operations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active','completed','archived')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS findings (
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
    this.db.run(`
      CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('request','response','command','file','note')),
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        meta TEXT NOT NULL DEFAULT '{}',
        content TEXT NOT NULL
      )
    `)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS evidence_findings (
        evidence_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        PRIMARY KEY (evidence_id, finding_id)
      )
    `)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS scopes (
        operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
        targets TEXT NOT NULL,
        strict INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS bindings (
        session_id TEXT PRIMARY KEY,
        operation_id TEXT REFERENCES operations(id) ON DELETE CASCADE,
        mode TEXT NOT NULL CHECK (mode IN ('bound','free')),
        updated_at TEXT NOT NULL
      )
    `)
  }

  /**
   * One-time legacy import: the old file-based scope becomes the active
   * operation's scopes row. Best-effort — an unreadable scope.json relic
   * never blocks startup. The file is left on disk untouched (a
   * human-readable relic of the old contract, not ours to delete).
   */
  private importLegacyScope(): void {
    if (!this.configDir) return
    try {
      const scope = loadScope(this.configDir)
      if (!scope) return
      const active = this.db
        .query("SELECT id FROM operations WHERE status = 'active' ORDER BY updated_at DESC LIMIT 1")
        .get() as { id: string } | null
      if (!active) return
      const now = new Date().toISOString()
      this.db.run(
        "INSERT OR IGNORE INTO scopes (operation_id, targets, strict, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        [active.id, JSON.stringify(scope.targets), scope.strict ? 1 : 0, scope.created, now],
      )
    } catch {
      // a malformed relic is not a startup blocker
    }
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
      // scope bootstrap is owned by the store so every creation path activates
      // the fence the dialog consults (dialog-always: the fence asks, never blocks)
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

  addFinding(
    opId: string,
    input: { title: string; severity: Severity; target: string; notes?: string },
  ): Finding {
    const now = new Date().toISOString()
    const f: Finding = {
      id: crypto.randomUUID(),
      operation_id: opId,
      title: input.title,
      severity: input.severity,
      status: "candidate",
      target: input.target,
      notes: input.notes ?? "",
      created_at: now,
      updated_at: now,
    }
    this.db.run(
      "INSERT INTO findings (id, operation_id, title, severity, status, target, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [f.id, f.operation_id, f.title, f.severity, f.status, f.target, f.notes, f.created_at, f.updated_at],
    )
    return f
  }

  listFindings(opId?: string, status?: FindingStatus): Finding[] {
    const rows = (opId
      ? this.db.query("SELECT * FROM findings WHERE operation_id = ? ORDER BY created_at DESC").all(opId)
      : this.db.query("SELECT * FROM findings ORDER BY created_at DESC").all()
    ) as Array<Record<string, unknown>>
    const all = rows.map(rowToFinding)
    return status ? all.filter((f) => f.status === status) : all
  }

  getFinding(id: string): Finding | null {
    const row = this.db.query("SELECT * FROM findings WHERE id = ?").get(id) as Record<string, unknown> | null
    return row ? rowToFinding(row) : null
  }

  updateFindingStatus(id: string, to: FindingStatus): Finding {
    const current = this.getFinding(id)
    if (!current) throw new FindingError(`finding ${id} not found`)
    assertTransition(current.status, to)
    const now = new Date().toISOString()
    this.db.run("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?", [to, now, id])
    return { ...current, status: to, updated_at: now }
  }

  updateFinding(id: string, patch: { title?: string; severity?: Severity; notes?: string }): Finding {
    const current = this.getFinding(id)
    if (!current) throw new FindingError(`finding ${id} not found`)
    const next = {
      title: patch.title ?? current.title,
      severity: patch.severity ?? current.severity,
      notes: patch.notes ?? current.notes,
    }
    const now = new Date().toISOString()
    this.db.run("UPDATE findings SET title = ?, severity = ?, notes = ?, updated_at = ? WHERE id = ?", [
      next.title,
      next.severity,
      next.notes,
      now,
      id,
    ])
    return { ...current, ...next, updated_at: now }
  }

  saveEvidence(opId: string, captured: CapturedEvidence, content: string | Uint8Array): Evidence {
    const text = typeof content === "string" ? content : new TextDecoder().decode(content)
    this.db.run(
      "INSERT INTO evidence (id, operation_id, kind, sha256, size, created_at, meta, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [captured.id, opId, captured.kind, captured.sha256, captured.size, captured.created_at, JSON.stringify(captured.meta), text],
    )
    return { ...captured, operation_id: opId, content: text }
  }

  listEvidence(opId: string, findingId?: string): Evidence[] {
    const rows = findingId
      ? (this.db
          .query(
            "SELECT e.* FROM evidence e JOIN evidence_findings ef ON e.id = ef.evidence_id WHERE e.operation_id = ? AND ef.finding_id = ? ORDER BY e.created_at DESC",
          )
          .all(opId, findingId) as Array<Record<string, unknown>>)
      : (this.db
          .query("SELECT * FROM evidence WHERE operation_id = ? ORDER BY created_at DESC")
          .all(opId) as Array<Record<string, unknown>>)
    return rows.map(rowToEvidence)
  }

  attachEvidence(findingId: string, evidenceId: string): void {
    this.db.run(
      "INSERT OR IGNORE INTO evidence_findings (evidence_id, finding_id) VALUES (?, ?)",
      [evidenceId, findingId],
    )
  }
}

function rowToFinding(row: Record<string, unknown>): Finding {
  return {
    id: row.id as string,
    operation_id: row.operation_id as string,
    title: row.title as string,
    severity: row.severity as Severity,
    status: row.status as FindingStatus,
    target: row.target as string,
    notes: row.notes as string,
    created_at: row.created_at as string,
    updated_at: row.updated_at as string,
  }
}

function rowToEvidence(row: Record<string, unknown>): Evidence {
  return {
    id: row.id as string,
    operation_id: row.operation_id as string,
    kind: row.kind as EvidenceKind,
    sha256: row.sha256 as string,
    size: row.size as number,
    created_at: row.created_at as string,
    meta: JSON.parse((row.meta as string) ?? "{}") as Record<string, string>,
    content: row.content as string,
  }
}
