/**
 * Test fakes for `@deepseek-ai/dsh-storage-domain`: passthrough spec helpers
 * and an in-memory Domain whose tables mirror the KvTable contract (get /
 * entries / keys / size / put / delete / update).
 */

export type ZodTypeLike<T = any> = { parse(input: unknown): T }

export interface DomainTableSpec {
  valueSchema: ZodTypeLike<any>
}

export function domainTable<K extends string = string, V = any>(schema: ZodTypeLike<V>): { valueSchema: ZodTypeLike<V>; __k?: K } {
  return { valueSchema: schema }
}

export interface DomainSpec {
  name: string
  version: number
  global?: { schema: ZodTypeLike<any>; initial: any }
  tables: Record<string, DomainTableSpec>
}

export function defineDomain<S extends DomainSpec>(spec: S): S {
  if (!/^[a-z][a-z0-9_]*$/.test(spec.name)) throw new Error(`bad domain name '${spec.name}'`)
  for (const table of Object.keys(spec.tables)) {
    if (!/^[a-z][a-z0-9_]*$/.test(table)) throw new Error(`bad table name '${table}'`)
  }
  return spec
}

class MemoryTable<K extends string, V> {
  readonly rows = new Map<K, V>()
  constructor(private readonly schema: ZodTypeLike<V>) {}

  get(key: K): V | undefined {
    return this.rows.get(key)
  }

  entries(): IterableIterator<[K, V]> {
    return this.rows.entries()
  }

  keys(): IterableIterator<K> {
    return this.rows.keys()
  }

  get size(): number {
    return this.rows.size
  }

  async put(key: K, value: V): Promise<void> {
    this.schema.parse(value)
    this.rows.set(key, structuredClone(value))
  }

  async delete(key: K): Promise<boolean> {
    return this.rows.delete(key)
  }

  async update(key: K, fn: (current: V) => V): Promise<V> {
    const current = this.rows.get(key)
    if (current === undefined) throw new Error('missing-key')
    const next = fn(current)
    this.schema.parse(next)
    this.rows.set(key, structuredClone(next))
    return next
  }
}

export class MemoryDomain {
  private readonly tables = new Map<string, MemoryTable<string, any>>()

  constructor(readonly spec: DomainSpec) {}

  table(name: string): MemoryTable<string, any> {
    let table = this.tables.get(name)
    if (table === undefined) {
      const declared = this.spec.tables[name]
      if (declared === undefined) throw new Error(`undeclared table '${name}'`)
      table = new MemoryTable(declared.valueSchema)
      this.tables.set(name, table)
    }
    return table
  }

  async close(): Promise<void> {}
}

/** Stand-in for the storageDomain facility. */
export class MemoryDomainFacility {
  open<S extends DomainSpec>(spec: S): Promise<MemoryDomain & { spec: S }> {
    return Promise.resolve(Object.assign(new MemoryDomain(spec), { spec }))
  }
}
