/**
 * SQLite storage backend for the storage hub (vendored from
 * `@deepseek-ai/dsh-storage-sqlite`, MIT, upstream 0.1.1-rc.2): one database
 * file hosts every routed unit, document-per-row. Registers as backend
 * `sqlite`; the disposer unregisters first, then closes the medium.
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { DatabaseSync } from 'node:sqlite'
import { UNIT_NAME_RE, StorageError, storageBackendServiceKey } from '@deepseek-ai/dsh-storage'
import type { KvFacet, KvUnit, KvUnitDescriptor, StorageBackend, StorageHub } from '@deepseek-ai/dsh-storage'
import { openDatabase, recordTableName, type JournalMode } from './schema.ts'
import { SqliteKvUnit } from './unit.ts'

export { STORAGE_SQLITE_SCHEMA_VERSION, type JournalMode } from './schema.ts'

/** Cordis plugin name. */
export const name = 'storage-sqlite'
/** The backend registers on the storage hub. */
export const inject = ['storage'] as const

export interface Config {
  /**
   * Filesystem path to the SQLite database file; `:memory:` opens an
   * in-process database (tests). Missing directories and files are created
   * owner-only on POSIX modes.
   */
  path: string
  journalMode?: JournalMode
}

export const Config: z<Config> = z.object({
  path: z.string().required(),
  journalMode: z.union(['wal', 'delete', 'truncate', 'persist'] as const).default('wal'),
})

export class SqliteStorageBackend implements StorageBackend {
  /** The kv facet is the only shape this backend serves. */
  readonly kv: KvFacet = { open: (descriptor) => this.openUnit(descriptor) }

  private readonly ready: Promise<DatabaseSync>
  private readonly units = new Map<string, Promise<SqliteKvUnit>>()
  private closing: Promise<void> | undefined

  constructor(config: Config) {
    this.ready = openDatabase(config.path, config.journalMode ?? 'wal')
    // Open failures surface to every caller; prevent an unhandled rejection
    // when no unit is ever opened.
    this.ready.catch(() => {})
  }

  private openUnit(descriptor: KvUnitDescriptor): Promise<KvUnit> {
    if (this.closing !== undefined) {
      return Promise.reject(new StorageError('closed', 'sqlite storage backend is closed'))
    }
    if (!UNIT_NAME_RE.test(descriptor.name)) {
      return Promise.reject(new Error(`kv unit name '${descriptor.name}' violates ${UNIT_NAME_RE}`))
    }
    for (const table of descriptor.tables) {
      if (!UNIT_NAME_RE.test(table)) {
        return Promise.reject(new Error(`kv table name '${table}' violates ${UNIT_NAME_RE}`))
      }
    }
    if (this.units.has(descriptor.name)) {
      return Promise.reject(new Error(`kv unit '${descriptor.name}' is already open (double-open is a caller bug)`))
    }
    const pending = this.materializeUnit(descriptor)
    this.units.set(descriptor.name, pending)
    pending.catch(() => this.units.delete(descriptor.name))
    return pending
  }

  private async materializeUnit(descriptor: KvUnitDescriptor): Promise<SqliteKvUnit> {
    const db = await this.ready
    const row = db.prepare('SELECT version FROM units WHERE name = ?').get(descriptor.name) as
      | { version: number }
      | undefined
    if (row === undefined) {
      db.prepare('INSERT INTO units (name, version) VALUES (?, ?)').run(descriptor.name, descriptor.version)
    } else if (row.version !== descriptor.version) {
      throw new StorageError(
        'version-mismatch',
        `kv unit '${descriptor.name}' is stamped version ${row.version} on the medium, incompatible with descriptor version ${descriptor.version}`,
      )
    }
    for (const table of descriptor.tables) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS "${recordTableName(descriptor.name, table)}" (
          key   TEXT PRIMARY KEY,
          value TEXT NOT NULL
        ) STRICT
      `)
    }
    return new SqliteKvUnit(db, descriptor, () => { this.units.delete(descriptor.name) })
  }

  close(): Promise<void> {
    this.closing ??= this.doClose()
    return this.closing
  }

  private async doClose(): Promise<void> {
    let db: DatabaseSync
    try {
      db = await this.ready
    } catch {
      // Never opened: nothing to release.
      return
    }
    for (const pending of [...this.units.values()]) {
      const unit = await pending.catch(() => undefined)
      await unit?.close()
    }
    db.close()
  }
}

export function apply(ctx: Context, config: Config): void {
  const backend = new SqliteStorageBackend(config)
  ctx.effect(() => {
    const dispose = ctx.get<StorageHub>('storage')!.backend.register('sqlite', backend)
    return async () => {
      dispose()
      await backend.close()
    }
  }, 'storage-sqlite.registerBackend')
  ctx.provide?.(storageBackendServiceKey('sqlite'), backend)
}
