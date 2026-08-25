/** Cordis fake: minimal Context recording effects/injections for tests. */

export interface FakeContext {
  effects: { label?: string; dispose: () => void | Promise<void> }[]
  effect(effectFn: () => void | (() => void | Promise<void>), label?: string): () => void
  inject(requires: readonly string[], callback: (ctx: FakeContext) => void): () => void
  on(event: string, listener: (...args: any[]) => void): () => void
  get<T = any>(name: string): T | undefined
  provide<T = any>(name: string, value: T): void
}

export function createFakeContext(services: Record<string, any> = {}): FakeContext {
  const store = new Map<string, any>(Object.entries(services))
  const context: FakeContext = {
    effects: [],
    effect(effectFn, label) {
      const teardown = effectFn()
      const entry = {
        ...(label !== undefined ? { label } : {}),
        dispose: typeof teardown === 'function' ? teardown : () => {},
      }
      context.effects.push(entry)
      return () => void entry.dispose()
    },
    inject(requires, callback) {
      callback(context)
      void requires
      return () => {}
    },
    on() {
      return () => {}
    },
    get(name) {
      return store.get(name)
    },
    provide(name, value) {
      store.set(name, value)
    },
  }
  return context
}
