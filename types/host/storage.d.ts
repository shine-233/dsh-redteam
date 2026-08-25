/**
 * Narrow ambient surface of `@deepseek-ai/dsh-storage` (host-provided peer,
 * contract pinned against upstream 0.1.1-rc.2): the backend registry, the
 * kv-facet contracts, and the helpers the vendored sqlite backend needs.
 */

/** Error class shared by storage packages; `code` is a stable machine tag. */
export class StorageError extends Error {
  readonly code: string
  constructor(code: string, message: string)
}

/** Valid unit/table identifier: `/^[a-z][a-z0-9_]*$/`. */
export const UNIT_NAME_RE: RegExp

/** Service key under which a backend publishes itself for domain routing. */
export function storageBackendServiceKey(name: string): string

/** Descriptor handed to {@link KvFacet.open}. */
export interface KvUnitDescriptor {
  readonly name: string
  readonly version: number
  readonly tables: readonly string[]
  readonly hasGlobal: boolean
}

/** One opened unit at the backend layer (opaque JSON records). */
export interface KvUnit {
  loadAll(): Promise<{ tables: Record<string, Record<string, unknown>>; global: unknown }>
  putRecord(table: string, key: string, value: unknown): Promise<void>
  deleteRecord(table: string, key: string): Promise<void>
  setGlobal(value: unknown): Promise<void>
  close(): Promise<void>
}

/** The key-value facet a backend may serve. */
export interface KvFacet {
  open(descriptor: KvUnitDescriptor): Promise<KvUnit>
}

/** A storage backend; only the kv facet exists today. */
export interface StorageBackend {
  readonly kv?: KvFacet
  close(): Promise<void>
}

/** Registry of named backends on the storage hub service. */
export interface StorageHub {
  readonly backend: {
    register(name: string, backend: StorageBackend): () => void
    get(name: string): StorageBackend
    names(): string[]
  }
}
