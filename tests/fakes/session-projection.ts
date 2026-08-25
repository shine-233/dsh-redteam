/** Type surface shim so type-only imports resolve in editors; no runtime use. */

export interface ProjectionSessionEvent {
  readonly type: string
  readonly seq: number
  readonly time: number
  readonly data: {
    readonly callId?: string
    readonly name?: string
    readonly arguments?: string
    readonly message?: { source?: { callId?: string } }
    readonly error?: { name: string; code: string }
  }
}

export interface ProjectionDefinitionLike {
  key: string
  init(): unknown
  apply(state: unknown, event: ProjectionSessionEvent): unknown
}
