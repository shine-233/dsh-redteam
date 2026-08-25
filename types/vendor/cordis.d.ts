/**
 * Narrow ambient surface of `@deepseek-ai/cordis` (vendored Cordis) — only the
 * plugin-facing members dsh-redteam consumes. Runtime is host-provided.
 */

/** Minimal plugin context surface used by this bundle. */
export interface Context {
  /** Register a teardown-wrapped contribution; the disposer runs at unmount. */
  effect(effect: () => void | (() => void | Promise<void>), label?: string): () => void
  /** Wait for services, then run; returns a disposer for dynamic injections. */
  inject<T extends readonly string[]>(
    requires: T,
    callback: (ctx: Context, ...services: unknown[]) => void,
  ): () => void
  /** Subscribe to an event on this scope. */
  on(event: string, listener: (...args: any[]) => void): () => void
  /** Read one service without declaring a dependency (`undefined` when absent). */
  get<T = any>(name: string): T | undefined
  /** Publish one service implementation on this scope. */
  provide<T = any>(name: string, value: T): void
}

export interface EntryOptions {
  id?: string
  name?: string
  config?: any
  disabled?: boolean
}
