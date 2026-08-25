/**
 * Engagement store: the authoritative write/read surface over the open
 * `redteam` domain.
 *
 * Identity model: model-visible ids are deterministic per session
 * (`<kind>-<n>`, counted over that session's rows), so a session projection
 * replays identical ids from the log alone. Storage keys prefix the session
 * (`<sessionId>~<id>`), so two sessions sharing one database can never
 * overwrite each other's records. Writes are append-only; closing an
 * engagement stamps `closedAt` and deletes nothing.
 */

import type { Domain } from '@deepseek-ai/dsh-storage-domain'
import type {
  AssetRecord,
  CredentialRecord,
  EdgeRelation,
  EngagementCounts,
  EvidenceKind,
  EvidenceRecord,
  FactRecord,
  FindingRecord,
  GoalRecord,
  GraphEdge,
  IntentRecord,
  RedteamProjection,
  RedteamViewAsset,
  RedteamViewNode,
  Severity,
} from './types.js'
import {
  assetSchema,
  credentialSchema,
  evidenceSchema,
  factSchema,
  findingSchema,
  goalSchema,
  intentSchema,
} from './spec.js'
import { ATTACK_TECHNIQUE_RE, OWASP_CATEGORY_RE, scoreVector, validOwaspIds, validTechniqueIds } from './cvss.js'
import { maskSecret } from './secrets.js'

/** Machine-tagged store failure surfaced verbatim to the calling tool. */
export class StoreError extends Error {
  readonly code:
    | 'no-active-engagement'
    | 'missing-ref'
    | 'invalid-record'

  constructor(code: StoreError['code'], message: string) {
    super(message)
    this.code = code
  }
}

export interface NewEvidence {
  kind: EvidenceKind
  content: string
  label?: string
}

export interface NewFact {
  detail: string
  kind?: string
  target?: string
  confidence?: number
  phase?: import('./types.js').Phase
  evidenceIds?: string[]
}

export interface NewAsset {
  type: string
  value: string
  /** Parent asset id, or '' / undefined for a root asset. */
  parentId?: string
  notes?: string
  tags?: string[]
}

export interface NewFinding {
  title: string
  severity: Severity
  description: string
  reproducibleSteps: string[]
  affectedAssetId?: string
  evidenceIds?: string[]
  remediation?: string
  techniqueIds?: string[]
  owaspIds?: string[]
  /** CVSS v3.1 base vector; score derived automatically when it parses. */
  cvssVector?: string
}

export interface NewCredential {
  kind: import('./types.js').CredentialKind
  secret: string
  username?: string
  target?: string
  assetId?: string
  status?: import('./types.js').CredentialStatus
  notes?: string
  evidenceIds?: string[]
}

export interface SubmitBatch {
  intentId: string
  evidence?: NewEvidence[]
  facts?: NewFact[]
  assets?: NewAsset[]
  findings?: NewFinding[]
  credentials?: NewCredential[]
}

export interface SubmitResult {
  intentId: string
  evidence: string[]
  facts: string[]
  assets: string[]
  findings: string[]
  credentials: string[]
}

type RecordTable =
  | 'goals' | 'intents' | 'facts' | 'assets' | 'findings' | 'evidence' | 'credentials'

const ID_PREFIX: Record<Exclude<RecordTable, 'goals'>, string> = {
  intents: 'intent',
  facts: 'fact',
  assets: 'asset',
  findings: 'finding',
  evidence: 'ev',
  credentials: 'cred',
}

interface Sessioned {
  sessionId: string
  createdAt: number
}

export class EngagementStore {
  constructor(private readonly domain: Domain) {}

  // ── keying ───────────────────────────────────────────────────────────────

  private key(table: RecordTable, sessionId: string, id: string): string {
    void table
    return `${sessionId}~${id}`
  }

  private put<T extends Sessioned>(table: RecordTable, id: string, record: T): Promise<void> {
    return this.domain.table(table).put(this.key(table, record.sessionId, id), record)
  }

  private get<T extends Sessioned>(table: RecordTable, sessionId: string, id: string): T | undefined {
    return this.domain.table(table).get(this.key(table, sessionId, id)) as T | undefined
  }

  private rowsForSession<K extends RecordTable>(table: K, sessionId: string): [string, any][] {
    const prefix = `${sessionId}~`
    return [...this.domain.table(table).entries()]
      .filter(([key, record]) => key.startsWith(prefix) && (record as Sessioned).sessionId === sessionId)
      .map(([key, record]) => [key.slice(prefix.length), record])
  }

  // ── ids and guards ───────────────────────────────────────────────────────

  /** Next deterministic `<prefix>-<n>` for one kind within the session. */
  private nextId(table: Exclude<RecordTable, 'goals'>, sessionId: string): string {
    const prefix = ID_PREFIX[table]
    let count = 0
    for (const [id] of this.rowsForSession(table, sessionId)) {
      if (id.startsWith(`${prefix}-`)) count += 1
    }
    return `${prefix}-${count + 1}`
  }

  private requireActiveGoal(sessionId: string): GoalRecord & { id: string } {
    const goal = this.activeGoal(sessionId)
    if (goal === undefined) {
      throw new StoreError(
        'no-active-engagement',
        `no active engagement in this session — call redteam_add_goal first (当前会话没有进行中的 engagement，请先调用 redteam_add_goal)`,
      )
    }
    return goal
  }

  // ── writes ───────────────────────────────────────────────────────────────

  /**
   * Open a new engagement for the session. A still-open engagement is closed
   * first (`closedAt` stamped); nothing is deleted, so counters continue and
   * every past engagement stays reportable.
   */
  async openGoal(sessionId: string, input: {
    objective: string
    authorization: string
    scope?: string
  }): Promise<{ goalId: string; superseded: boolean }> {
    const now = Date.now()
    const previous = this.activeGoal(sessionId)
    if (previous !== undefined) {
      await this.put('goals', previous.id, { ...previous, closedAt: now })
    }
    const id = this.nextGoalId(sessionId)
    const parsed = goalSchema.parse({
      sessionId,
      objective: input.objective,
      authorization: input.authorization,
      scope: input.scope ?? '',
      createdAt: now,
    })
    await this.put('goals', id, parsed as GoalRecord)
    return { goalId: id, superseded: previous !== undefined }
  }

  private nextGoalId(sessionId: string): string {
    let count = 0
    for (const [id] of this.rowsForSession('goals', sessionId)) {
      if (id.startsWith('goal-')) count += 1
    }
    return `goal-${count + 1}`
  }

  /** The session's open engagement, if any (newest record without `closedAt`). */
  activeGoal(sessionId: string): (GoalRecord & { id: string }) | undefined {
    let found: (GoalRecord & { id: string }) | undefined
    for (const [id, goal] of this.rowsForSession('goals', sessionId)) {
      if (goal.closedAt !== undefined) continue
      if (found === undefined || goal.createdAt >= found.createdAt) found = { ...goal, id }
    }
    return found as (GoalRecord & { id: string }) | undefined
  }

  async addIntent(sessionId: string, input: {
    title: string
    rationale?: string
    phase?: import('./types.js').Phase
  }): Promise<string> {
    const goal = this.requireActiveGoal(sessionId)
    const id = this.nextId('intents', sessionId)
    const parsed = intentSchema.parse({
      sessionId,
      goalId: goal.id,
      title: input.title,
      rationale: input.rationale ?? '',
      ...(input.phase !== undefined ? { phase: input.phase } : {}),
      createdAt: Date.now(),
    })
    await this.put('intents', id, parsed as IntentRecord)
    return id
  }

  async addEvidence(sessionId: string, input: NewEvidence): Promise<string> {
    this.requireActiveGoal(sessionId)
    const id = this.nextId('evidence', sessionId)
    const parsed = evidenceSchema.parse({
      sessionId,
      kind: input.kind,
      label: input.label ?? '',
      content: input.content,
      createdAt: Date.now(),
    })
    await this.put('evidence', id, parsed as EvidenceRecord)
    return id
  }

  async addFact(sessionId: string, intentId: string, input: NewFact): Promise<string> {
    this.requireActiveGoal(sessionId)
    this.requireIntent(sessionId, intentId)
    this.requireEvidence(sessionId, input.evidenceIds ?? [])
    const id = this.nextId('facts', sessionId)
    const parsed = factSchema.parse({
      sessionId,
      intentId,
      detail: input.detail,
      ...(input.kind !== undefined ? { kind: input.kind } : {}),
      ...(input.target !== undefined ? { target: input.target } : {}),
      ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
      ...(input.phase !== undefined ? { phase: input.phase } : {}),
      evidenceIds: [...(input.evidenceIds ?? [])],
      createdAt: Date.now(),
    })
    await this.put('facts', id, parsed as FactRecord)
    return id
  }

  async addAsset(sessionId: string, input: NewAsset): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (input.parentId !== undefined && input.parentId !== '') {
      this.requireAsset(sessionId, input.parentId)
    }
    const id = this.nextId('assets', sessionId)
    const parsed = assetSchema.parse({
      sessionId,
      type: input.type,
      value: input.value,
      ...(input.parentId !== undefined && input.parentId !== '' ? { parentId: input.parentId } : {}),
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
      ...(input.tags !== undefined && input.tags.length > 0 ? { tags: [...input.tags] } : {}),
      createdAt: Date.now(),
    })
    await this.put('assets', id, parsed as AssetRecord)
    return id
  }

  async addFinding(sessionId: string, intentId: string, input: NewFinding): Promise<string> {
    this.requireActiveGoal(sessionId)
    this.requireIntent(sessionId, intentId)
    this.requireEvidence(sessionId, input.evidenceIds ?? [])
    if (input.affectedAssetId !== undefined && input.affectedAssetId !== '') {
      this.requireAsset(sessionId, input.affectedAssetId)
    }
    if (input.techniqueIds !== undefined && !validTechniqueIds(input.techniqueIds)) {
      throw new StoreError(
        'invalid-record',
        `techniqueIds must be MITRE ATT&CK ids like 'T1110' or 'T1110.003': ${input.techniqueIds.filter((id) => !ATTACK_TECHNIQUE_RE.test(id)).join(', ')}`,
      )
    }
    if (input.owaspIds !== undefined && !validOwaspIds(input.owaspIds)) {
      throw new StoreError(
        'invalid-record',
        `owaspIds must be OWASP Top 10 categories like 'A01:2021' or 'A05:2017': ${input.owaspIds.filter((id) => !OWASP_CATEGORY_RE.test(id)).join(', ')}`,
      )
    }
    const score = input.cvssVector !== undefined ? scoreVector(input.cvssVector) : null
    if (input.cvssVector !== undefined && score === null) {
      throw new StoreError('invalid-record', `cvssVector is not a parseable CVSS v3.x base vector: '${input.cvssVector}'`)
    }
    const id = this.nextId('findings', sessionId)
    const parsed = findingSchema.parse({
      sessionId,
      intentId,
      title: input.title,
      severity: input.severity,
      description: input.description,
      reproducibleSteps: [...input.reproducibleSteps],
      ...(input.affectedAssetId !== undefined && input.affectedAssetId !== ''
        ? { affectedAssetId: input.affectedAssetId }
        : {}),
      evidenceIds: [...(input.evidenceIds ?? [])],
      ...(input.remediation !== undefined ? { remediation: input.remediation } : {}),
      ...(input.techniqueIds !== undefined && input.techniqueIds.length > 0
        ? { techniqueIds: [...input.techniqueIds] }
        : {}),
      ...(score !== null ? { cvssVector: input.cvssVector, cvssScore: score } : {}),
      createdAt: Date.now(),
    })
    await this.put('findings', id, parsed as FindingRecord)
    return id
  }

  /** Register credential material; the raw secret stays in storage only. */
  async addCredential(sessionId: string, input: NewCredential): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (input.assetId !== undefined && input.assetId !== '') {
      this.requireAsset(sessionId, input.assetId)
    }
    const id = this.nextId('credentials', sessionId)
    const parsed = credentialSchema.parse({
      sessionId,
      kind: input.kind,
      secret: input.secret,
      ...(input.username !== undefined ? { username: input.username } : {}),
      ...(input.target !== undefined ? { target: input.target } : {}),
      ...(input.assetId !== undefined && input.assetId !== '' ? { assetId: input.assetId } : {}),
      status: input.status ?? 'unverified',
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
      ...(input.evidenceIds !== undefined ? { evidenceIds: [...input.evidenceIds] } : {}),
      createdAt: Date.now(),
    })
    await this.put('credentials', id, parsed as CredentialRecord)
    return id
  }

  /**
   * Task-tree transition on an intent (status/title/rationale). Only the
   * provided fields change; `closedAt`-style append-only history is not
   * needed because the session log already records every call.
   */
  async updateIntent(sessionId: string, intentId: string, patch: {
    status?: import('./types.js').IntentStatus
    title?: string
    rationale?: string
  }): Promise<IntentRecord & { id: string }> {
    const existing = this.get<IntentRecord>('intents', sessionId, intentId)
    if (existing === undefined) {
      throw new StoreError('missing-ref', `intent '${intentId}' does not exist in this session`)
    }
    const updated: IntentRecord = {
      ...existing,
      ...(patch.status !== undefined ? { status: patch.status } : {}),
      ...(patch.title !== undefined ? { title: patch.title } : {}),
      ...(patch.rationale !== undefined ? { rationale: patch.rationale } : {}),
    }
    await this.put('intents', intentId, updated)
    return { ...updated, id: intentId }
  }

  /**
   * Retest outcome for one finding: `fixed` stamps the resolution,
   * `still-vulnerable` keeps it confirmed with the latest retest note.
   */
  async retestFinding(sessionId: string, findingId: string, patch: {
    outcome: 'fixed' | 'still-vulnerable'
    notes?: string
    evidenceIds?: string[]
  }): Promise<FindingRecord & { id: string }> {
    this.requireActiveGoal(sessionId)
    const existing = this.get<FindingRecord>('findings', sessionId, findingId)
    if (existing === undefined) {
      throw new StoreError('missing-ref', `finding '${findingId}' does not exist in this session`)
    }
    let updated: FindingRecord = { ...existing }
    if (patch.outcome === 'fixed') {
      updated = { ...updated, status: 'fixed', resolvedAt: Date.now() }
    } else {
      // Still vulnerable: back to confirmed (clears a stale fixed stamp).
      updated = { ...updated, status: 'confirmed', resolvedAt: undefined }
    }
    if (patch.notes !== undefined) updated = { ...updated, retestNotes: patch.notes }
    await this.put('findings', findingId, updated)
    return { ...updated, id: findingId }
  }

  /** Verification transition on a credential (`valid` / `invalid` / reset). */
  async updateCredential(sessionId: string, credentialId: string, patch: {
    status: import('./types.js').CredentialStatus
    evidenceIds?: string[]
  }): Promise<CredentialRecord & { id: string }> {
    const existing = this.get<CredentialRecord>('credentials', sessionId, credentialId)
    if (existing === undefined) {
      throw new StoreError('missing-ref', `credential '${credentialId}' does not exist in this session`)
    }
    this.requireEvidence(sessionId, patch.evidenceIds ?? [])
    const updated: CredentialRecord = {
      ...existing,
      status: patch.status,
      ...(patch.evidenceIds !== undefined ? { evidenceIds: [...patch.evidenceIds] } : {}),
    }
    await this.put('credentials', credentialId, updated)
    return { ...updated, id: credentialId }
  }

  /**
   * Batch submit for execution subagents. Items may cross-reference within
   * one batch: evidence mints first, assets second, and facts/findings may
   * cite fresh evidence and asset ids.
   */
  async submit(sessionId: string, batch: SubmitBatch): Promise<SubmitResult> {
    this.requireActiveGoal(sessionId)
    this.requireIntent(sessionId, batch.intentId)

    const result: SubmitResult = { intentId: batch.intentId, evidence: [], facts: [], assets: [], findings: [], credentials: [] }
    for (const item of batch.evidence ?? []) {
      result.evidence.push(await this.addEvidence(sessionId, item))
    }
    for (const item of batch.assets ?? []) {
      result.assets.push(await this.addAsset(sessionId, item))
    }
    for (const item of batch.credentials ?? []) {
      result.credentials.push(await this.addCredential(sessionId, item))
    }
    for (const item of batch.facts ?? []) {
      result.facts.push(await this.addFact(sessionId, batch.intentId, item))
    }
    for (const item of batch.findings ?? []) {
      result.findings.push(await this.addFinding(sessionId, batch.intentId, item))
    }
    return result
  }

  // ── reads ────────────────────────────────────────────────────────────────

  private rowsInWindow<K extends RecordTable>(
    table: K,
    sessionId: string,
    win: { since: number; until: number },
  ): [string, any][] {
    return this.rowsForSession(table, sessionId).filter(([, record]) => {
      const createdAt = (record as Sessioned).createdAt ?? 0
      return createdAt >= win.since && createdAt <= win.until
    })
  }

  /** `[since, until]` covering the active engagement; `null` when none is open. */
  private windowOf(sessionId: string): { since: number; until: number } | null {
    const goal = this.activeGoal(sessionId)
    if (goal === undefined) return null
    return { since: goal.createdAt - 1, until: Number.MAX_SAFE_INTEGER }
  }

  private requireIntent(sessionId: string, intentId: string): void {
    const intent = this.get<IntentRecord>('intents', sessionId, intentId)
    if (intent === undefined) {
      throw new StoreError('missing-ref', `intent '${intentId}' does not exist in this session`)
    }
  }

  private requireAsset(sessionId: string, assetId: string): void {
    const asset = this.get<AssetRecord>('assets', sessionId, assetId)
    if (asset === undefined) {
      throw new StoreError('missing-ref', `asset '${assetId}' does not exist in this session`)
    }
  }

  private requireEvidence(sessionId: string, ids: readonly string[]): void {
    for (const id of ids) {
      if (this.get<EvidenceRecord>('evidence', sessionId, id) === undefined) {
        throw new StoreError('missing-ref', `evidence '${id}' does not exist in this session`)
      }
    }
  }

  /** Record counts inside one engagement window. */
  counts(sessionId: string, win?: { since: number; until: number }): EngagementCounts {
    const w = win ?? this.windowOf(sessionId) ?? { since: 0, until: -1 }
    return {
      intents: this.rowsInWindow('intents', sessionId, w).length,
      facts: this.rowsInWindow('facts', sessionId, w).length,
      assets: this.rowsInWindow('assets', sessionId, w).length,
      findings: this.rowsInWindow('findings', sessionId, w).length,
      evidence: this.rowsInWindow('evidence', sessionId, w).length,
      credentials: this.rowsInWindow('credentials', sessionId, w).length,
    }
  }

  state(sessionId: string): {
    goal: GoalRecord | null
    counts: EngagementCounts
    openIntents: { id: string; title: string }[]
    progress: { active: number; done: number; blocked: number }
  } {
    const goal = this.activeGoal(sessionId)
    const win = this.windowOf(sessionId)
    const intents = win === null
      ? [] as [string, IntentRecord][]
      : this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][]
    const progress = { active: 0, done: 0, blocked: 0 }
    for (const [, intent] of intents) progress[intent.status ?? 'active'] += 1
    return {
      goal: goal === undefined ? null : (({ id: _id, ...rest }) => rest)(goal),
      counts: this.counts(sessionId),
      openIntents: intents
        .filter(([, record]) => (record.status ?? 'active') === 'active')
        .map(([id, record]) => ({ id, title: record.title })),
      progress,
    }
  }

  /** Full engagement graph (active engagement only) with derived edges. */
  graph(sessionId: string): {
    nodes: RedteamViewNode[]
    assets: RedteamViewAsset[]
    edges: GraphEdge[]
    counts: EngagementCounts
  } {
    const win = this.windowOf(sessionId)
    if (win === null) {
      return { nodes: [], assets: [], edges: [], counts: { ...EMPTY_COUNTS } }
    }
    const goal = this.activeGoal(sessionId)!
    const nodes: RedteamViewNode[] = [{ id: goal.id, kind: 'goal', title: goal.objective, status: null }]
    const edges: GraphEdge[] = []

    const intents = this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][]
    const intentIds = new Set(intents.map(([id]) => id))
    for (const [id, intent] of intents) {
      nodes.push({ id, kind: 'intent', title: intent.title, status: intent.status ?? 'active' })
      edges.push({ from: intent.goalId, to: id, relation: 'spawns' })
    }
    for (const [id, fact] of this.rowsInWindow('facts', sessionId, win) as [string, FactRecord][]) {
      if (!intentIds.has(fact.intentId)) continue
      edges.push({ from: fact.intentId, to: id, relation: 'yields' })
    }
    for (const [id, finding] of this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][]) {
      if (!intentIds.has(finding.intentId)) continue
      edges.push({ from: finding.intentId, to: id, relation: 'proves' })
    }

    const assets = this.rowsInWindow('assets', sessionId, win) as [string, AssetRecord][]
    const assetIds = new Set(assets.map(([id]) => id))
    for (const [id, asset] of assets) {
      if (asset.parentId !== undefined && asset.parentId !== '' && assetIds.has(asset.parentId)) {
        edges.push({ from: asset.parentId, to: id, relation: 'parent' })
      }
    }

    return {
      nodes,
      assets: assets.map(([id, a]) => ({ id, type: a.type, value: a.value, parentId: a.parentId ?? null, tags: [...(a.tags ?? [])] })),
      edges,
      counts: this.counts(sessionId),
    }
  }

  /** Projection window delivered to the Web tab. */
  projection(sessionId: string): RedteamProjection {
    const graph = this.graph(sessionId)
    const goal = this.activeGoal(sessionId)
    const win = this.windowOf(sessionId)
    const findings = win === null
      ? []
      : (this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][])
        .map(([id, f]) => ({
          id,
          intentId: f.intentId,
          title: f.title,
          severity: f.severity,
          cvssScore: f.cvssScore ?? null,
          techniqueIds: [...(f.techniqueIds ?? [])],
          status: f.status === 'fixed' ? 'fixed' as const : null,
        }))
    const credentials = this.maskedCredentials(sessionId).map((c) => ({
      id: c.id,
      kind: c.kind as import('./types.js').CredentialKind,
      username: c.username ?? null,
      target: c.target ?? null,
      assetId: c.assetId ?? null,
      status: c.status as import('./types.js').CredentialStatus,
    }))
    return {
      goal: goal === undefined ? null : { objective: goal.objective, authorization: goal.authorization },
      nodes: graph.nodes,
      assets: graph.assets,
      findings,
      credentials,
      edges: graph.edges,
      counts: graph.counts,
    }
  }

  /** Every engagement ever recorded, newest first (cross-session history). */
  listEngagements(): {
    goalId: string
    sessionId: string
    objective: string
    authorization: string
    createdAt: number
    closedAt?: number
    counts: EngagementCounts
  }[] {
    const all: ReturnType<EngagementStore['listEngagements']> = []
    for (const [key, goal] of this.domain.table('goals').entries()) {
      const goalId = key.slice(key.indexOf('~') + 1)
      all.push({
        goalId,
        sessionId: goal.sessionId,
        objective: goal.objective,
        authorization: goal.authorization,
        createdAt: goal.createdAt,
        ...(goal.closedAt !== undefined ? { closedAt: goal.closedAt } : {}),
        counts: this.countsForGoal(key)!,
      })
    }
    return all.sort((a, b) => b.createdAt - a.createdAt)
  }

  /**
   * Counts for a stored (possibly closed) engagement — used by history views.
   */
  countsForGoal(storageKey: string): EngagementCounts | null {
    const goal = this.domain.table('goals').get(storageKey)
    if (goal === undefined) return null
    const win = { since: goal.createdAt - 1, until: goal.closedAt ?? Number.MAX_SAFE_INTEGER }
    const sid = goal.sessionId
    return {
      intents: this.rowsInWindow('intents', sid, win).length,
      facts: this.rowsInWindow('facts', sid, win).length,
      assets: this.rowsInWindow('assets', sid, win).length,
      findings: this.rowsInWindow('findings', sid, win).length,
      evidence: this.rowsInWindow('evidence', sid, win).length,
      credentials: this.rowsInWindow('credentials', sid, win).length,
    }
  }

  /** Records of the ACTIVE engagement for report rendering / JSON export. */
  engagementRecords(sessionId: string): {
    goal: GoalRecord | null
    intents: [string, IntentRecord][]
    facts: [string, FactRecord][]
    assets: [string, AssetRecord][]
    findings: [string, FindingRecord][]
    evidence: [string, EvidenceRecord][]
    credentials: [string, CredentialRecord][]
  } {
    const win = this.windowOf(sessionId)
    if (win === null) {
      return { goal: null, intents: [], facts: [], assets: [], findings: [], evidence: [], credentials: [] }
    }
    return {
      goal: (({ id: _id, ...rest }) => rest)(this.activeGoal(sessionId)!),
      intents: this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][],
      facts: this.rowsInWindow('facts', sessionId, win) as [string, FactRecord][],
      assets: this.rowsInWindow('assets', sessionId, win) as [string, AssetRecord][],
      findings: this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][],
      evidence: this.rowsInWindow('evidence', sessionId, win) as [string, EvidenceRecord][],
      credentials: this.rowsInWindow('credentials', sessionId, win) as [string, CredentialRecord][],
    }
  }

  /** Credentials of the ACTIVE engagement, secrets masked for display. */
  maskedCredentials(sessionId: string): { id: string; kind: string; username?: string; target?: string; assetId?: string; status: string; secretMasked: string }[] {
    const r = this.engagementRecords(sessionId)
    return r.credentials.map(([id, c]) => ({
      id,
      kind: c.kind,
      ...(c.username !== undefined ? { username: c.username } : {}),
      ...(c.target !== undefined ? { target: c.target } : {}),
      ...(c.assetId !== undefined ? { assetId: c.assetId } : {}),
      status: c.status,
      secretMasked: maskSecret(c.secret),
    }))
  }

  edgeRelations(): readonly EdgeRelation[] {
    return ['spawns', 'yields', 'proves', 'parent'] as const
  }
}

const EMPTY_COUNTS: EngagementCounts = {
  intents: 0,
  facts: 0,
  assets: 0,
  findings: 0,
  evidence: 0,
  credentials: 0,
}
