import { Database } from "bun:sqlite"
import { mkdirSync } from "node:fs"
import { join } from "node:path"
import { saveScope } from "./scope"
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
