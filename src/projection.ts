/**
 * The `redteam` session projection: folds logged redteam_* tool calls into a
 * windowed graph view for the Web tab. Folding is optimistic and purely
 * deterministic — ids are minted with per-session per-kind counters that
 * mirror {@link EngagementStore.nextId} over the same event stream — and each
 * speculative mutation is rolled back when the matching tool/result carries an
 * error, so failed calls never leave phantom nodes.
 */

import type { ProjectionSessionEvent } from '@deepseek-ai/dsh-session-projection'
import { z } from 'zod'
import type {
  EdgeRelation,
  EngagementCounts,
  GraphEdge,
  RedteamProjection,
  RedteamViewAsset,
  RedteamViewFinding,
  RedteamViewNode,
} from './types.js'

const WINDOW_CAP = 200

const edgeSchema = z.object({
  from: z.string(),
  to: z.string(),
  relation: z.enum(['spawns', 'yields', 'proves', 'parent']),
})

export const redteamProjectionSchema = z.object({
  goal: z.union([
    z.object({ objective: z.string(), authorization: z.string() }),
    z.null(),
  ]),
  nodes: z.array(z.object({
    id: z.string(),
    kind: z.enum(['goal', 'intent']),
    title: z.string(),
  })),
  assets: z.array(z.object({
    id: z.string(),
    type: z.string(),
    value: z.string(),
    parentId: z.union([z.string(), z.null()]),
  })),
  findings: z.array(z.object({
    id: z.string(),
    intentId: z.string(),
    title: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  })),
  edges: z.array(edgeSchema),
  counts: z.object({
    intents: z.number(),
    facts: z.number(),
    assets: z.number(),
    findings: z.number(),
    evidence: z.number(),
  }),
})

/** Mutable fold-state shape (the view projection stays readonly). */
export interface FoldState {
  goal: RedteamProjection['goal']
  nodes: RedteamViewNode[]
  assets: RedteamViewAsset[]
  findings: RedteamViewFinding[]
  edges: GraphEdge[]
  counts: EngagementCounts
  /** callId → full pre-call snapshot, for rollback on failed results. */
  pending: Record<string, FoldState>
}

export const redteamFoldStateSchema: z.ZodType<FoldState> = redteamProjectionSchema.extend({
  pending: z.record(z.string(), redteamProjectionSchema),
}) as never

const MUTATING = new Set([
  'redteam_add_goal',
  'redteam_add_intent',
  'redteam_add_evidence',
  'redteam_add_fact',
  'redteam_add_asset',
  'redteam_add_finding',
  'redteam_submit',
])

function emptyState(): FoldState {
  return {
    goal: null,
    nodes: [],
    assets: [],
    findings: [],
    edges: [],
    counts: { intents: 0, facts: 0, assets: 0, findings: 0, evidence: 0 },
    pending: {},
  }
}

/** Deterministic `<prefix>-<n>` mirroring the store's counting rule. */
function nextId(state: FoldState, prefix: string): string {
  const existing = new Set<string>([
    ...state.nodes.map((n) => n.id),
    ...state.assets.map((a) => a.id),
    ...state.edges.flatMap((e) => [e.from, e.to]),
  ])
  let n = 0
  while (existing.has(`${prefix}-${n + 1}`)) n += 1
  return `${prefix}-${n + 1}`
}

function pushEdge(edges: GraphEdgeLite[], from: string, to: string, relation: EdgeRelation): void {
  if (!edges.some((e) => e.from === from && e.to === to && e.relation === relation)) {
    edges.push({ from, to, relation })
  }
}

type GraphEdgeLite = FoldState['edges'][number]

function evictOldest<T>(list: T[], cap: number): T[] {
  return list.length > cap ? list.slice(list.length - cap) : list
}

function applyMutation(state: FoldState, name: string, args: any): void {
  switch (name) {
    case 'redteam_add_goal': {
      const id = nextId(state, 'goal')
      // A new engagement supersedes the old one: its header leaves the window.
      state.nodes = state.nodes.filter((n) => n.kind !== 'goal')
      state.edges = state.edges.filter((e) => e.relation === 'parent'
        || !state.nodes.every((n) => n.id !== e.from))
      state.nodes.push({ id, kind: 'goal', title: String(args?.objective ?? '') })
      state.goal = {
        objective: String(args?.objective ?? ''),
        authorization: String(args?.authorization ?? ''),
      }
      break
    }
    case 'redteam_add_intent': {
      const id = nextId(state, 'intent')
      const goalNode = state.nodes.find((n) => n.kind === 'goal')
      state.nodes.push({ id, kind: 'intent', title: String(args?.title ?? '') })
      if (goalNode !== undefined) pushEdge(state.edges, goalNode.id, id, 'spawns')
      state.nodes = evictOldest([...state.nodes], WINDOW_CAP)
      break
    }
    case 'redteam_add_evidence': {
      // Evidence is not rendered as a node; only the count moves.
      break
    }
    case 'redteam_add_asset': {
      const id = nextId(state, 'asset')
      const parent = typeof args?.parentId === 'string' && args.parentId !== '' ? args.parentId : null
      state.assets.push({ id, type: String(args?.type ?? ''), value: String(args?.value ?? ''), parentId: parent })
      if (parent !== null && state.assets.some((a) => a.id === parent)) {
        pushEdge(state.edges, parent, id, 'parent')
      }
      state.assets = evictOldest([...state.assets], WINDOW_CAP)
      break
    }
    case 'redteam_add_fact': {
      const id = nextId(state, 'fact')
      const intent = typeof args?.intentId === 'string' ? args.intentId : ''
      if (state.nodes.some((n) => n.id === intent)) pushEdge(state.edges, intent, id, 'yields')
      state.edges = evictOldest([...state.edges], WINDOW_CAP * 2)
      break
    }
    case 'redteam_add_finding': {
      const id = nextId(state, 'finding')
      const intent = typeof args?.intentId === 'string' ? args.intentId : ''
      if (state.nodes.some((n) => n.id === intent)) {
        pushEdge(state.edges, intent, id, 'proves')
      }
      state.findings.push({
        id,
        intentId: intent,
        title: String(args?.title ?? ''),
        severity: validateSeverity(args?.severity),
      })
      state.findings = evictOldest([...state.findings], WINDOW_CAP)
      state.edges = evictOldest([...state.edges], WINDOW_CAP * 2)
      break
    }
    case 'redteam_submit': {
      for (const item of args?.evidence ?? []) void item // count only
      for (const item of args?.assets ?? []) applyMutation(state, 'redteam_add_asset', item)
      for (const item of args?.facts ?? []) applyMutation(state, 'redteam_add_fact', { ...item, intentId: args?.intentId })
      for (const item of args?.findings ?? []) applyMutation(state, 'redteam_add_finding', { ...item, intentId: args?.intentId })
      break
    }
    default:
      break
  }
}

function validateSeverity(value: unknown): 'info' | 'low' | 'medium' | 'high' | 'critical' {
  return value === 'low' || value === 'medium' || value === 'high' || value === 'critical'
    ? value
    : 'info'
}

function recount(state: FoldState): FoldState['counts'] {
  const intentIds = new Set(state.nodes.filter((n) => n.kind === 'intent').map((n) => n.id))
  const yields = state.edges.filter((e) => e.relation === 'yields')
  const proves = state.edges.filter((e) => e.relation === 'proves')
  return {
    intents: intentIds.size,
    facts: yields.length,
    assets: state.assets.length,
    findings: proves.length,
    evidence: state.counts.evidence,
  }
}

/**
 * Pure fold over session events. Unrelated events must return the same
 * reference; mutations clone once and stash a rollback snapshot keyed by the
 * harness `callId`.
 */
export function fold(state: FoldState, event: ProjectionSessionEvent): FoldState {
  if (event.type === 'tool/call') {
    const name = event.data.name ?? ''
    if (!MUTATING.has(name)) return state
    let args: any = {}
    try { args = JSON.parse(event.data.arguments ?? '{}') } catch { args = {} }
    const draft: FoldState = {
      ...state,
      nodes: [...state.nodes],
      assets: [...state.assets],
      findings: [...state.findings],
      edges: [...state.edges],
      counts: { ...state.counts },
      pending: { ...state.pending },
    }
    applyMutation(draft, name, args)
    const evidenceDelta = name === 'redteam_submit'
      ? (Array.isArray(args?.evidence) ? args.evidence.length : 0)
      : name === 'redteam_add_evidence' ? 1 : 0
    draft.counts = { ...recount(draft), evidence: recount(draft).evidence + evidenceDelta }
    const callId = event.data.callId ?? `${event.seq}`
    draft.pending = { ...draft.pending, [callId]: state }
    return draft
  }
  if (event.type === 'tool/result') {
    const callId = event.data.message?.source?.callId
    if (callId === undefined || !(callId in state.pending)) return state
    const snapshot = state.pending[callId]
    const { [callId]: _drop, ...restPending } = state.pending
    if (snapshot === undefined) return state
    if (event.data.error !== undefined) {
      // Failed call: roll back to the pre-call snapshot.
      return { ...snapshot, pending: restPending }
    }
    return { ...state, pending: restPending }
  }
  return state
}

export const redteamProjectionDefinition = {
  key: 'redteam' as const,
  stateSchema: redteamFoldStateSchema,
  init: emptyState,
  apply: fold,
  wire: {
    viewSchema: redteamProjectionSchema,
    view: (state: FoldState): RedteamProjection => ({
      goal: state.goal,
      nodes: state.nodes,
      assets: state.assets,
      findings: state.findings,
      edges: state.edges,
      counts: state.counts,
    }),
  },
  stateVersion: 1,
}
