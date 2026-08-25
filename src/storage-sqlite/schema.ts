/**
 * Physical SQLite layout for the storage backend (vendored from
 * `@deepseek-ai/dsh-storage-sqlite`, MIT, upstream 0.1.1-rc.2).
 */

import { DatabaseSync } from 'node:sqlite'
import { mkdir, open } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { StorageError } from '@deepseek-ai/dsh-storage'

/** Layout version stamped into `PRAGMA user_version`; mismatch rejects open. */
export const STORAGE_SQLITE_SCHEMA_VERSION = 1

/** `wal` by default; network mounts should pick a rollback journal mode. */
export type JournalMode = 'wal' | 'delete' | 'truncate' | 'persist'

/** Create the database file owner-only; an existing file is kept as-is. */
async function createDatabaseFile(path: string): Promise<void> {
  try {
    const handle = await open(path, 'wx', 0o600)
    await handle.close()
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
}

export async function openDatabase(path: string, journalMode: JournalMode): Promise<DatabaseSync> {
  const actual = path === ':memory:' ? path : resolve(path)
  if (actual !== ':memory:') {
    await mkdir(dirname(actual), { recursive: true, mode: 0o700 })
    await createDatabaseFile(actual)
  }
  const db = new DatabaseSync(actual)
  try {
    configureDatabase(db, actual, journalMode)
    return db
  } catch (error) {
    db.close()
    throw error
  }
}

function configureDatabase(db: DatabaseSync, path: string, journalMode: JournalMode): void {
  db.exec('PRAGMA foreign_keys = ON')
  db.exec(`PRAGMA journal_mode = ${journalMode.toUpperCase()}`)
  const { user_version: onDisk } = db.prepare('PRAGMA user_version').get() as { user_version: number }
  if (onDisk !== 0 && onDisk !== STORAGE_SQLITE_SCHEMA_VERSION) {
    throw new StorageError(
      'version-mismatch',
      `storage database at "${path}" has schema version ${onDisk}, incompatible with this build (${STORAGE_SQLITE_SCHEMA_VERSION})`,
    )
  }
  db.exec(`CREATE TABLE IF NOT EXISTS units (
    name TEXT PRIMARY KEY, version INTEGER NOT NULL) STRICT`)
  db.exec(`CREATE TABLE IF NOT EXISTS unit_globals (
    unit TEXT PRIMARY KEY REFERENCES units(name), value TEXT NOT NULL) STRICT`)
  if (onDisk === 0) {
    // Stamp last: the stamp asserts a complete layout; failures above leave an
    // unstamped medium so a retry materializes from zero.
    db.exec(`PRAGMA user_version = ${STORAGE_SQLITE_SCHEMA_VERSION}`)
  }
}

/** Physical table name `u_<unit>_<table>`; identifiers pass UNIT_NAME_RE first. */
export function recordTableName(unit: string, table: string): string {
  return `u_${unit}_${table}`
}
