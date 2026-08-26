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
import { ATTACK_TECHNIQUE_RE, scoreVector } from './cvss.js'
import { scopeCheck } from './scope.js'
import { ARTIFACT_KINDS, CREDENTIAL_KINDS, CREDENTIAL_STATUSES, DETECTION_OUTCOMES, EVIDENCE_KINDS, HINT_SOURCES, INTENT_STATUSES, IOC_TYPES, PHASES, SAMPLE_KINDS, SCOPE_KINDS } from './types.js'
import type {
  EdgeRelation,
  EngagementCounts,
  GraphEdge,
  RedteamProjection,
  RedteamViewAsset,
  RedteamViewFinding,
  RedteamViewNode,
  RedteamViewScopeEntry,
  RedteamViewScopeIssue,
} from './types.js'

const WINDOW_CAP = 200

const edgeSchema = z.object({
  from: z.string(),
  to: z.string(),
  relation: z.enum(['spawns', 'yields', 'derived_from', 'proves', 'parent', 'depends_on']),
})

export const redteamProjectionSchema = z.object({
  goal: z.union([
    z.object({
      objective: z.string(),
      authorization: z.string(),
      outcome: z.enum(['achieved', 'partial', 'not-achieved']).nullable().default(null),
    }),
    z.null(),
  ]),
  nodes: z.array(z.object({
    id: z.string(),
    kind: z.enum(['goal', 'intent']),
    title: z.string(),
    status: z.enum(['active', 'done', 'blocked']).nullable().default(null),
    assetIds: z.array(z.string()).default([]),
    phase: z.enum(['recon', 'enumeration', 'exploitation', 'post-exploitation', 'reporting']).nullable().default(null),
    techniqueIds: z.array(z.string()).default([]),
  })),
  assets: z.array(z.object({
    id: z.string(),
    type: z.string(),
    value: z.string(),
    parentId: z.union([z.string(), z.null()]),
    tags: z.array(z.string()).default([]),
  })),
  findings: z.array(z.object({
    id: z.string(),
    intentId: z.string(),
    title: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    cvssScore: z.union([z.number(), z.null()]).default(null),
    techniqueIds: z.array(z.string()).default([]),
    status: z.enum(['confirmed', 'fixed']).nullable().default(null),
    affectedAssetId: z.union([z.string(), z.null()]).default(null),
    detected: z.enum(['undetected', 'logged', 'alerted', 'prevented']).nullable().default(null),
    duplicateOf: z.union([z.string(), z.null()]).default(null),
  })),
  credentials: z.array(z.object({
    id: z.string(),
    kind: z.enum(['password', 'hash', 'api-key', 'token', 'ssh-key', 'other']),
    username: z.union([z.string(), z.null()]),
    target: z.union([z.string(), z.null()]),
    assetId: z.union([z.string(), z.null()]),
    status: z.enum(['unverified', 'valid', 'invalid']),
  })).default([]),
  artifacts: z.array(z.object({
    id: z.string(),
    kind: z.enum(['file', 'screenshot', 'log', 'report', 'exploit', 'dump', 'other']),
    location: z.string(),
    intentId: z.union([z.string(), z.null()]),
    assetId: z.union([z.string(), z.null()]),
  })).default([]),
  hints: z.array(z.object({
    id: z.string(),
    text: z.string(),
    source: z.enum(['user', 'operator', 'client']),
    intentId: z.union([z.string(), z.null()]),
  })).default([]),
  samples: z.array(z.object({
    id: z.string(),
    kind: z.enum(['binary', 'document', 'script', 'archive', 'memory-dump', 'pcap', 'other']),
    location: z.string(),
    sha256: z.string(),
    fileType: z.union([z.string(), z.null()]),
  })).default([]),
  iocs: z.array(z.object({
    id: z.string(),
    type: z.enum(['ip', 'domain', 'url', 'hash', 'mutex', 'registry', 'filepath', 'user-agent', 'email', 'other']),
    value: z.string(),
    sampleId: z.union([z.string(), z.null()]),
  })).default([]),
  objectives: z.array(z.object({
    id: z.string(),
    title: z.string(),
    provenAt: z.union([z.number(), z.null()]),
  })).default([]),
  scope: z.array(z.object({
    id: z.string(),
    kind: z.enum(['in', 'out']),
    value: z.string(),
    note: z.union([z.string(), z.null()]).default(null),
  })).default([]),
  scopeIssues: z.array(z.object({
    recordId: z.string(),
    recordKind: z.enum(['asset', 'finding', 'ioc']),
    value: z.string(),
    reason: z.enum(['out-of-scope', 'unscoped']),
    matched: z.string(),
  })).default([]),
  facts: z.array(z.object({
    id: z.string(),
    intentId: z.string(),
    detail: z.string(),
    phase: z.enum(['recon', 'enumeration', 'exploitation', 'post-exploitation', 'reporting']).nullable().default(null),
    confidence: z.union([z.number(), z.null()]).default(null),
    evidenceIds: z.array(z.string()).default([]),
  })).default([]),
  evidence: z.array(z.object({
    id: z.string(),
    kind: z.enum(['command', 'output', 'screenshot', 'file', 'url', 'note']),
    label: z.string(),
  })).default([]),
  edges: z.array(edgeSchema),
  counts: z.object({
    intents: z.number(),
    facts: z.number(),
    assets: z.number(),
    findings: z.number(),
    evidence: z.number(),
    credentials: z.number().default(0),
    artifacts: z.number().default(0),
    hints: z.number().default(0),
    samples: z.number().default(0),
    iocs: z.number().default(0),
    objectives: z.number().default(0),
  }),
})

/** Mutable fold-state shape (the view projection stays readonly). */
export interface FoldState {
  goal: RedteamProjection['goal']
  nodes: RedteamViewNode[]
  assets: RedteamViewAsset[]
  findings: RedteamViewFinding[]
  credentials: import('./types.js').RedteamViewCredential[]
  artifacts: import('./types.js').RedteamViewArtifact[]
  hints: import('./types.js').RedteamViewHint[]
  objectives: import('./types.js').RedteamViewObjective[]
  samples: import('./types.js').RedteamViewSample[]
  iocs: import('./types.js').RedteamViewIoc[]
  scope: RedteamViewScopeEntry[]
  scopeIssues: RedteamViewScopeIssue[]
  facts: import('./types.js').RedteamViewFact[]
  evidence: import('./types.js').RedteamViewEvidenceMeta[]
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
  'redteam_add_credential',
  'redteam_add_artifact',
  'redteam_add_hint',
  'redteam_add_sample',
  'redteam_add_ioc',
  'redteam_add_objective',
  'redteam_prove_objective',
  'redteam_add_scope',
  'redteam_update_intent',
  'redteam_retest_finding',
  'redteam_update_credential',
  'redteam_close_goal',
  'redteam_submit',
])

function emptyState(): FoldState {
  return {
    goal: null,
    nodes: [],
    assets: [],
    findings: [],
    credentials: [],
    artifacts: [],
    hints: [],
    samples: [],
    iocs: [],
    objectives: [],
    scope: [],
    scopeIssues: [],
    facts: [],
    evidence: [],
    edges: [],
    counts: { intents: 0, facts: 0, assets: 0, findings: 0, evidence: 0, credentials: 0, artifacts: 0, hints: 0, samples: 0, iocs: 0, objectives: 0 },
    pending: {},
  }
}

/** Deterministic `<prefix>-<n>` mirroring the store's counting rule. */
function nextId(state: FoldState, prefix: string): string {
  const existing = new Set<string>([
    ...state.nodes.map((n) => n.id),
    ...state.assets.map((a) => a.id),
    // Findings and credentials never appear as nodes; without them a kind
    // whose edges were evicted (or that has no edges at all) mints repeats.
    ...state.findings.map((f) => f.id),
    ...state.credentials.map((c) => c.id),
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
      state.nodes.push({ id, kind: 'goal', title: String(args?.objective ?? ''), status: null, assetIds: [] })
      state.goal = {
        objective: String(args?.objective ?? ''),
        authorization: String(args?.authorization ?? ''),
        outcome: null,
      }
      break
    }
    case 'redteam_add_intent': {
      const id = nextId(state, 'intent')
      const goalNode = state.nodes.find((n) => n.kind === 'goal')
      const status = INTENT_STATUSES.includes(args?.status) ? args.status : 'active'
      const assetIds = Array.isArray(args?.assetIds)
        ? args.assetIds.filter((a: unknown) => typeof a === 'string')
        : []
      const phase = PHASES.includes(args?.phase) ? (args.phase as (typeof PHASES)[number]) : null
      const techniqueIds = Array.isArray(args?.techniqueIds)
        ? args.techniqueIds.filter((t: unknown) => typeof t === 'string' && ATTACK_TECHNIQUE_RE.test(t))
        : []
      state.nodes.push({ id, kind: 'intent', title: String(args?.title ?? ''), status, assetIds, phase, techniqueIds })
      if (goalNode !== undefined) pushEdge(state.edges, goalNode.id, id, 'spawns')
      for (const factId of Array.isArray(args?.derivedFrom) ? args.derivedFrom : []) {
        if (typeof factId === 'string') pushEdge(state.edges, factId, id, 'derived_from')
      }
      for (const depId of Array.isArray(args?.dependsOn) ? args.dependsOn : []) {
        if (typeof depId === 'string') pushEdge(state.edges, depId, id, 'depends_on')
      }
      state.nodes = evictOldest([...state.nodes], WINDOW_CAP)
      break
    }
    case 'redteam_add_evidence': {
      const id = nextId(state, 'ev')
      state.evidence.push({
        id,
        kind: EVIDENCE_KINDS.includes(args?.kind) ? args.kind : 'note',
        label: String(args?.label ?? ''),
      })
      state.evidence = evictOldest([...state.evidence], WINDOW_CAP)
      break
    }
    case 'redteam_add_asset': {
      const id = nextId(state, 'asset')
      const parent = typeof args?.parentId === 'string' && args.parentId !== '' ? args.parentId : null
      state.assets.push({
        id,
        type: String(args?.type ?? ''),
        value: String(args?.value ?? ''),
        parentId: parent,
        tags: Array.isArray(args?.tags) ? args.tags.filter((t: unknown) => typeof t === 'string') : [],
      })
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
      state.facts.push({
        id,
        intentId: intent,
        detail: String(args?.detail ?? '').slice(0, 240),
        phase: PHASES.includes(args?.phase) ? (args.phase as (typeof PHASES)[number]) : null,
        confidence: typeof args?.confidence === 'number' ? args.confidence : null,
        evidenceIds: Array.isArray(args?.evidenceIds)
          ? args.evidenceIds.filter((e: unknown) => typeof e === 'string')
          : [],
      })
      state.facts = evictOldest([...state.facts], WINDOW_CAP)
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
        cvssScore: typeof args?.cvssVector === 'string' ? scoreVector(args.cvssVector) : null,
        techniqueIds: Array.isArray(args?.techniqueIds)
          ? args.techniqueIds.filter((t: unknown) => typeof t === 'string' && ATTACK_TECHNIQUE_RE.test(t))
          : [],
        status: null,
        affectedAssetId: typeof args?.affectedAssetId === 'string' && args.affectedAssetId !== ''
          ? args.affectedAssetId
          : null,
        detected: DETECTION_OUTCOMES.includes(args?.detected) ? args.detected : null,
        duplicateOf: typeof args?.duplicateOf === 'string' && args.duplicateOf !== '' ? args.duplicateOf : null,
      })
      state.findings = evictOldest([...state.findings], WINDOW_CAP)
      state.edges = evictOldest([...state.edges], WINDOW_CAP * 2)
      break
    }
    case 'redteam_add_credential': {
      const id = nextId(state, 'cred')
      // Secrets never enter the projection — masked metadata only.
      state.credentials.push({
        id,
        kind: CREDENTIAL_KINDS.includes(args?.kind) ? args.kind : 'other',
        username: typeof args?.username === 'string' && args.username !== '' ? args.username : null,
        target: typeof args?.target === 'string' && args.target !== '' ? args.target : null,
        assetId: typeof args?.assetId === 'string' && args.assetId !== '' ? args.assetId : null,
        status: CREDENTIAL_STATUSES.includes(args?.status) ? args.status : 'unverified',
      })
      state.credentials = evictOldest([...state.credentials], WINDOW_CAP)
      break
    }
    case 'redteam_update_intent': {
      const node = state.nodes.find((n) => n.id === args?.intentId && n.kind === 'intent')
      if (node !== undefined) {
        if (typeof args?.title === 'string' && args.title !== '') {
          state.nodes = state.nodes.map((n) =>
            n.id === node.id ? { ...n, title: args.title } : n)
        }
        if (INTENT_STATUSES.includes(args?.status)) {
          state.nodes = state.nodes.map((n) =>
            n.id === node.id ? { ...n, status: args.status } : n)
        }
      }
      break
    }
    case 'redteam_retest_finding': {
      const finding = state.findings.find((f) => f.id === args?.findingId)
      if (finding !== undefined && args?.outcome === 'fixed') {
        state.findings = state.findings.map((f) =>
          f.id === finding.id ? { ...f, status: 'fixed' } : f)
      } else if (finding !== undefined && args?.outcome === 'still-vulnerable') {
        state.findings = state.findings.map((f) =>
          f.id === finding.id ? { ...f, status: null } : f)
      }
      break
    }
    case 'redteam_update_credential': {
      const credential = state.credentials.find((c) => c.id === args?.credentialId)
      if (credential !== undefined && CREDENTIAL_STATUSES.includes(args?.status)) {
        state.credentials = state.credentials.map((c) =>
          c.id === credential.id ? { ...c, status: args.status } : c)
      }
      break
    }
    case 'redteam_add_artifact': {
      const id = nextId(state, 'art')
      state.artifacts.push({
        id,
        kind: ARTIFACT_KINDS.includes(args?.kind) ? args.kind : 'other',
        location: String(args?.location ?? ''),
        intentId: typeof args?.intentId === 'string' && args.intentId !== '' ? args.intentId : null,
        assetId: typeof args?.assetId === 'string' && args.assetId !== '' ? args.assetId : null,
      })
      state.artifacts = evictOldest([...state.artifacts], WINDOW_CAP)
      break
    }
    case 'redteam_add_hint': {
      const id = nextId(state, 'hint')
      state.hints.push({
        id,
        text: String(args?.text ?? ''),
        source: HINT_SOURCES.includes(args?.source) ? args.source : 'operator',
        intentId: typeof args?.intentId === 'string' && args.intentId !== '' ? args.intentId : null,
      })
      state.hints = evictOldest([...state.hints], WINDOW_CAP)
      break
    }
    case 'redteam_add_sample': {
      const id = nextId(state, 'sample')
      state.samples.push({
        id,
        kind: SAMPLE_KINDS.includes(args?.kind) ? args.kind : 'other',
        location: String(args?.location ?? ''),
        sha256: String(args?.sha256 ?? ''),
        fileType: typeof args?.fileType === 'string' && args.fileType !== '' ? args.fileType : null,
      })
      state.samples = evictOldest([...state.samples], WINDOW_CAP)
      break
    }
    case 'redteam_add_ioc': {
      const id = nextId(state, 'ioc')
      state.iocs.push({
        id,
        type: IOC_TYPES.includes(args?.type) ? args.type : 'other',
        value: String(args?.value ?? ''),
        sampleId: typeof args?.sampleId === 'string' && args.sampleId !== '' ? args.sampleId : null,
      })
      state.iocs = evictOldest([...state.iocs], WINDOW_CAP)
      break
    }
    case 'redteam_add_objective': {
      const id = nextId(state, 'obj')
      state.objectives.push({ id, title: String(args?.title ?? ''), provenAt: null })
      state.objectives = evictOldest([...state.objectives], WINDOW_CAP)
      break
    }
    case 'redteam_prove_objective': {
      const obj = state.objectives.find((o) => o.id === args?.objectiveId)
      if (obj !== undefined) {
        const proven = args?.proven !== false
        state.objectives = state.objectives.map((o) =>
          o.id === obj.id ? { ...o, provenAt: proven ? (o.provenAt ?? Date.now()) : null } : o)
      }
      break
    }
    case 'redteam_add_scope': {
      const id = nextId(state, 'scope')
      state.scope.push({
        id,
        kind: SCOPE_KINDS.includes(args?.kind) ? args.kind : 'in',
        value: String(args?.value ?? ''),
        note: typeof args?.note === 'string' && args.note !== '' ? args.note : null,
      })
      state.scope = evictOldest([...state.scope], WINDOW_CAP)
      break
    }
    case 'redteam_close_goal': {
      if (state.goal !== null && ['achieved', 'partial', 'not-achieved'].includes(args?.outcome)) {
        state.goal = { ...state.goal, outcome: args.outcome }
      }
      break
    }
    case 'redteam_submit': {
      for (const item of args?.evidence ?? []) void item // count only
      for (const item of args?.assets ?? []) applyMutation(state, 'redteam_add_asset', item)
      for (const item of args?.credentials ?? []) applyMutation(state, 'redteam_add_credential', item)
      for (const item of args?.artifacts ?? []) applyMutation(state, 'redteam_add_artifact', item)
      for (const item of args?.samples ?? []) applyMutation(state, 'redteam_add_sample', item)
      for (const item of args?.iocs ?? []) applyMutation(state, 'redteam_add_ioc', item)
      // Objectives are commander-level; never minted from submit batches.
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

/** Re-evaluate scope compliance over the whole window (cheap, ≤ few hundred). */
function recomputeScopeIssues(state: FoldState): void {
  const entries = state.scope.map((s) => ({ kind: s.kind, value: s.value }))
  const assetValue = new Map(state.assets.map((a) => [a.id, a.value]))
  state.scopeIssues = entries.length === 0
    ? []
    : scopeCheck(
        entries,
        {
          assets: state.assets.map((a) => ({ id: a.id, value: a.value })),
          findings: state.findings.map((f) => ({
            id: f.id,
            assetValue: f.affectedAssetId !== null ? assetValue.get(f.affectedAssetId) ?? null : null,
          })),
          iocs: state.iocs.map((i) => ({ id: i.id, value: i.value })),
        },
      )
}

function recount(state: FoldState): FoldState['counts'] {  const intentIds = new Set(state.nodes.filter((n) => n.kind === 'intent').map((n) => n.id))
  const yields = state.edges.filter((e) => e.relation === 'yields')
  const proves = state.edges.filter((e) => e.relation === 'proves')
  return {
    intents: intentIds.size,
    facts: yields.length,
    assets: state.assets.length,
    findings: proves.length,
    evidence: state.counts.evidence,
    credentials: state.credentials.length,
    artifacts: state.artifacts.length,
    hints: state.hints.length,
    samples: state.samples.length,
    iocs: state.iocs.length,
    objectives: state.objectives.filter((o) => o.provenAt !== null).length,
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
      credentials: [...state.credentials],
      artifacts: [...state.artifacts],
      hints: [...state.hints],
      samples: [...state.samples],
      iocs: [...state.iocs],
      objectives: [...state.objectives],
      scope: [...state.scope],
      scopeIssues: [...state.scopeIssues],
      facts: [...state.facts],
      evidence: [...state.evidence],
      edges: [...state.edges],
      counts: { ...state.counts },
      pending: { ...state.pending },
    }
    applyMutation(draft, name, args)
    recomputeScopeIssues(draft)
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
      credentials: state.credentials,
      artifacts: state.artifacts,
      hints: state.hints,
      samples: state.samples,
      iocs: state.iocs,
      objectives: state.objectives,
      scope: state.scope,
      scopeIssues: state.scopeIssues,
      facts: state.facts,
      evidence: state.evidence,
      edges: state.edges,
      counts: state.counts,
    }),
  },
  stateVersion: 2,
}
