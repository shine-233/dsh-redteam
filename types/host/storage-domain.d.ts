/**
 * Narrow ambient surface of `@deepseek-ai/dsh-storage-domain` (host-provided
 * peer, contract pinned against upstream 0.1.1-rc.2): domain specs and the
 * handle returned by the `storageDomain` facility's `open`.
 */

import type { KvTable } from './storage.js'

/** Zod schema type (structural — the real package uses zod v4 types). */
export interface ZodTypeLike<T = any> {
  parse(input: unknown): T
}

export interface DomainTableSpec<K extends string = string, V = any> {
  readonly valueSchema: ZodTypeLike<V>
  /** Key codec slots exist upstream; this bundle uses plain string keys. */
  readonly _key?: K
}

/** Declare one table: a zod value schema over string keys. */
export function domainTable<K extends string, V>(schema: ZodTypeLike<V>): DomainTableSpec<K, V>

export interface DomainGlobalSpec<G> {
  readonly schema: ZodTypeLike<G>
  readonly initial: G
}

export interface DomainSpec {
  /** `/^[a-z][a-z0-9_]*$/`. */
  readonly name: string
  /** Bumped on incompatible record changes; mismatched media reject at open. */
  readonly version: number
  readonly global?: DomainGlobalSpec<any>
  readonly tables: Record<string, DomainTableSpec<any, any>>
}

/** Validate a spec shape; returns it unchanged. */
export function defineDomain<S extends DomainSpec>(spec: S): S

export interface DomainGlobalHandle<G> {
  get(): G | undefined
  set(value: G): Promise<void>
}

/** One open domain, typed loosely over its declared spec. */
export interface Domain<S extends DomainSpec = DomainSpec> {
  readonly name: string
  close(): Promise<void>
  table<N extends keyof S['tables'] & string>(
    name: N,
  ): KvTable<string, any> & { __types?: S['tables'][N] }
  readonly global: S extends { global: DomainGlobalSpec<infer G> } ? DomainGlobalHandle<G> : never
}

/** Host facility opening domains over routed backends. */
export interface StorageDomainFacility {
  open<S extends DomainSpec>(spec: S): Promise<Domain<S>>
}
