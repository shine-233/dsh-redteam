/**
 * Narrow ambient surface of `@deepseek-ai/dsh-session-projection` (host peer,
 * pinned against upstream 0.1.1-rc.2): the registry a plugin uses to declare
 * one per-session fold over logged events, plus the event envelope shapes it
 * folds (`tool/call` / `tool/result`).
 */

import type { ZodTypeLike } from './storage-domain.js'
import type { SessionProjectionStateMap } from './session-projection-types.js'

/** Minimal session-event envelope used by projection folds. */
export interface ProjectionSessionEvent {
  readonly type: string
  readonly seq: number
  readonly time: number
  readonly data: {
    /** `tool/call` only. */
    readonly callId?: string
    readonly name?: string
    readonly arguments?: string
    /** `tool/result` only. */
    readonly message?: { source?: { callId?: string } }
    readonly error?: { name: string; code: string }
  }
}

export interface ProjectionDefinition<K extends keyof SessionProjectionStateMap, S> {
  readonly key: K
  readonly stateSchema: ZodTypeLike<S>
  init(): S
  /** Pure fold; unrelated events must return the same reference. */
  apply(state: S, event: ProjectionSessionEvent): S
  wire?: {
    readonly viewSchema: ZodTypeLike<S>
    view(state: S): S
  }
  readonly stateVersion: number
}

export interface SessionProjectionRegistry {
  register<K extends keyof SessionProjectionStateMap, S extends SessionProjectionStateMap[K]>(
    definition: ProjectionDefinition<K, S>,
  ): () => void
}
