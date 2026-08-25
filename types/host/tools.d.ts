/**
 * Narrow ambient surface of `@deepseek-ai/dsh-tools` (host-provided peer,
 * contract pinned against upstream 0.1.1-rc.2). Only what this bundle uses:
 * `defineTool` plus the execution context handed to `execute`.
 *
 * Parameter schemas are declared as plain schema objects (unchecked here);
 * args/value type safety comes from explicit generics at each call site and
 * is exercised by the store/tool unit tests.
 */

/** One text content block (the only kind this bundle renders). */
export interface ContentBlock {
  type: 'text'
  text: string
}

/** Schema node for one tool parameter property (schematically checked by the host). */
export interface ParameterProperty {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object'
  required?: boolean
  description?: string
  enum?: readonly string[]
  items?: ParameterProperty
  properties?: Record<string, ParameterProperty>
  additionalProperties?: boolean
  default?: unknown
}

export type ParameterSchemaSpec = Record<string, ParameterProperty>

/** Output value schema (same shape family as parameters). */
export type ValueSchemaSpec = Record<string, ParameterProperty>

/** Execution context handed to a tool's `execute`. */
export interface ToolRunContext {
  /** The owning agent, when the tool runs inside an agent session. */
  readonly agent?: {
    session: {
      /** Stable session id (the engagement's scope key). */
      readonly id: string
      append(event: string, data: unknown): void
    }
  }
  /** Attach a user message delivered after the final result of this turn. */
  deferContext(context: { content: ContentBlock[] }): void
  /** Mark this successful result as the end of the current turn. */
  concludeTurn(): void
}

export interface DefineToolOptions<A, V> {
  name: string
  description: string
  parameters: ParameterSchemaSpec
  output: {
    schema: ValueSchemaSpec
    render(args: A, value: V): ContentBlock[]
  }
  timeoutMs?: number
  execute(args: A, exec: ToolRunContext): Promise<V>
}

export interface ToolDefinition {
  readonly name: string
}

/** Declare one model-facing tool. */
export function defineTool<A = Record<string, unknown>, V = unknown>(
  options: DefineToolOptions<A, V>,
): ToolDefinition

/** The tools registry service: model-facing tool catalog keyed per scope. */
export interface ToolsRegistry {
  register(tool: ToolDefinition): () => void
}
