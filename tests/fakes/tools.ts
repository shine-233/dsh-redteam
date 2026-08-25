/**
 * Test fake for `@deepseek-ai/dsh-tools`: identity `defineTool` plus a
 * registry capturing definitions, mirroring the host contract (throw →
 * failure result) closely enough for tool-level behavior tests.
 */

export interface ContentBlock {
  type: 'text'
  text: string
}

export interface FakeToolDefinition {
  name: string
  description: string
  parameters: unknown
  output: { schema: unknown; render(args: any, value: any): ContentBlock[] }
  execute(args: any, exec: any): Promise<any>
}

export function defineTool<A = any, V = any>(options: {
  name: string
  description: string
  parameters: unknown
  output: { schema: unknown; render(args: A, value: V): ContentBlock[] }
  execute(args: A, exec: any): Promise<V>
}): FakeToolDefinition {
  return options as unknown as FakeToolDefinition
}

export class FakeToolsRegistry {
  readonly registered = new Map<string, FakeToolDefinition>()

  register(tool: FakeToolDefinition): () => void {
    if (this.registered.has(tool.name)) throw new Error(`duplicate tool '${tool.name}'`)
    this.registered.set(tool.name, tool)
    return () => this.registered.delete(tool.name)
  }

  async call(name: string, args: any, exec?: any): Promise<{ ok: boolean; value?: any; error?: Error }> {
    const tool = this.registered.get(name)
    if (tool === undefined) return { ok: false, error: new Error(`unknown tool '${name}'`) }
    try {
      const value = await tool.execute(args, exec ?? fakeExec())
      return { ok: true, value }
    } catch (error) {
      return { ok: false, error: error as Error }
    }
  }
}

export function fakeExec(sessionId = 'session-1'): {
  agent: { session: { id: string; append(event: string, data: unknown): void } }
  events: { event: string; data: unknown }[]
  deferred: { content: ContentBlock[] }[]
  deferContext(context: { content: ContentBlock[] }): void
  concludeTurn(): void
} {
  const events: { event: string; data: unknown }[] = []
  const deferred: { content: ContentBlock[] }[] = []
  return {
    events,
    deferred,
    agent: {
      session: {
        id: sessionId,
        append: (event, data) => events.push({ event, data }),
      },
    },
    deferContext: (context) => deferred.push(context),
    concludeTurn: () => {},
  }
}
