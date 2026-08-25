/**
 * Host contract stub for the conversation client-ui module. The browser half
 * only needs the slot surface it merges into; the live host ships richer
 * declarations at runtime.
 */

declare module '@deepseek-ai/dsh-client-ui-conversation/client' {
  export interface ConversationClientSlots {
    inject(name: string, register: () => unknown): unknown
    register(options: Record<string, unknown>, component: unknown): unknown
  }
  export interface ConversationClientContext {
    slots: ConversationClientSlots
  }
}
