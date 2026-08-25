/**
 * One opened kv unit over SQLite (vendored from
 * `@deepseek-ai/dsh-storage-sqlite`, MIT, upstream 0.1.1-rc.2).
 */

import type { DatabaseSync } from 'node:sqlite'
import { StorageError } from '@deepseek-ai/dsh-storage'
import type { KvUnit, KvUnitDescriptor } from '@deepseek-ai/dsh-storage'
import { recordTableName } from './schema.ts'

/** One prepared statement (avoids the value-side namespace of the class). */
type Stmt = ReturnType<DatabaseSync['prepare']>

/** Settle one sync statement into a never-sync-throwing promise. */
function settle<T>(run: () => T): Promise<T> {
  return new Promise((resolvePromise) => {
    try {
      resolvePromise(run())
    } catch (error) {
      resolvePromise(Promise.reject(error))
    }
  })
}

export class SqliteKvUnit implements KvUnit {
  private readonly puts = new Map<string, Stmt>()
  private readonly deletes = new Map<string, Stmt>()
  private readonly selectAll = new Map<string, Stmt>()
  private putGlobal: Stmt | undefined
  private closed = false

  constructor(
    private readonly db: DatabaseSync,
    private readonly descriptor: KvUnitDescriptor,
    private readonly onDispose: () => void,
  ) {}

  loadAll(): Promise<{ tables: Record<string, Record<string, unknown>>; global: unknown }> {
    return settle(() => this.loadAllSync())
  }

  private loadAllSync(): { tables: Record<string, Record<string, unknown>>; global: unknown } {
    const tables: Record<string, Record<string, unknown>> = Object.create(null)
    for (const table of this.descriptor.tables) {
      const rows = this.selectAllFor(table).all() as { key: string; value: string }[]
      const records: Record<string, unknown> = Object.create(null)
      for (const row of rows) records[row.key] = parseRecord(row.value, this.descriptor.name)
      tables[table] = records
    }
    let global: unknown
    if (this.descriptor.hasGlobal) {
      const row = this.db
        .prepare('SELECT value FROM unit_globals WHERE unit = ?')
        .get(this.descriptor.name) as { value: string } | undefined
      global = row === undefined ? null : parseRecord(row.value, this.descriptor.name)
    }
    return { tables, global }
  }

  private selectAllFor(table: string): Stmt {
    let statement = this.selectAll.get(table)
    if (statement === undefined) {
      statement = this.db.prepare(`SELECT key, value FROM "${recordTableName(this.descriptor.name, table)}"`)
      this.selectAll.set(table, statement)
    }
    return statement
  }

  putRecord(table: string, key: string, value: unknown): Promise<void> {
    return settle(() => {
      let statement = this.puts.get(table)
      if (statement === undefined) {
        statement = this.db.prepare(
          `INSERT INTO "${recordTableName(this.descriptor.name, table)}" (key, value) VALUES (?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        )
        this.puts.set(table, statement)
      }
      statement.run(key, JSON.stringify(value ?? null))
    })
  }

  deleteRecord(table: string, key: string): Promise<void> {
    return settle(() => {
      let statement = this.deletes.get(table)
      if (statement === undefined) {
        statement = this.db.prepare(`DELETE FROM "${recordTableName(this.descriptor.name, table)}" WHERE key = ?`)
        this.deletes.set(table, statement)
      }
      statement.run(key)
    })
  }

  setGlobal(value: unknown): Promise<void> {
    return settle(() => {
      this.putGlobal ??= this.db.prepare(
        `INSERT INTO unit_globals (unit, value) VALUES (?, ?)
         ON CONFLICT(unit) DO UPDATE SET value = excluded.value`,
      )
      this.putGlobal.run(this.descriptor.name, JSON.stringify(value ?? null))
    })
  }

  close(): Promise<void> {
    return settle(() => {
      if (!this.closed) {
        this.closed = true
        this.onDispose()
      }
    })
  }
}

function parseRecord(raw: string, unit: string): unknown {
  try {
    return JSON.parse(raw) as unknown
  } catch {
    throw new StorageError('malformed-medium', `unit '${unit}' holds a malformed record payload`)
  }
}
