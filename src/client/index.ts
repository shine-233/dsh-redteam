/**
 * Browser half of the redteam Web surface: registers one `conversation.view`
 * tab per session. Data arrives exclusively through the `redteam` session
 * projection (`useProjection('redteam')`) — no store, no refresh chain, no
 * direct event listeners.
 */

// Type-only merges for the slot contract and runtime hook shares.
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client'
import { RedteamView } from './RedteamView.js'

interface ClientContextLike {
  slots: {
    inject(name: string, register: () => unknown): unknown
    register(options: Record<string, unknown>, component: unknown): unknown
  }
}

export const inject = ['slots'] as const

export function apply(ctx: ClientContextLike): void {
  const register = (): unknown =>
    ctx.slots.register(
      {
        name: 'conversation.view',
        id: 'redteam',
        order: 30,
        label: '红队',
      },
      RedteamView,
    )
  ctx.slots.inject('conversation.view', register)
}
