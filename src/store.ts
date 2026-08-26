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
  ArtifactRecord,
  AssetRecord,
  CredentialRecord,
  EdgeRelation,
  EngagementCounts,
  EvidenceKind,
  EvidenceRecord,
  FactRecord,
  FindingFlag,
  FindingRecord,
  GoalRecord,
  GraphEdge,
  HintRecord,
  IntentRecord,
  IocRecord,
  ObjectiveRecord,
  OperatorRecord,
  RedteamProjection,
  RedteamViewAsset,
  RedteamViewNode,
  SampleRecord,
  ScopeEntryRecord,
  Severity,
} from './types.js'
import { ARTIFACT_KINDS, CREDENTIAL_KINDS, CREDENTIAL_STATUSES, DETECTION_OUTCOMES, EVIDENCE_KINDS, FINDING_FLAGS, INTENT_STATUSES, IOC_TYPES, OPERATOR_ROLES, SAMPLE_KINDS, SCOPE_KINDS, SEVERITIES, SLA_POLICY_DAYS } from './types.js'
import {
  artifactSchema,
  assetSchema,
  credentialSchema,
  evidenceSchema,
  factSchema,
  findingSchema,
  goalSchema,
  hintSchema,
  intentSchema,
  iocSchema,
  objectiveSchema,
  sampleSchema,
  scopeEntrySchema,
  operatorSchema,
} from './spec.js'
import { scopeCheck } from './scope.js'
import { ATTACK_TECHNIQUE_RE, CVE_ID_RE, CWE_ID_RE, MD5_RE, OWASP_CATEGORY_RE, SHA1_RE, SHA256_RE, scoreVector, validCweIds, validOwaspIds, validTechniqueIds } from './cvss.js'
import { maskSecret } from './secrets.js'

/** Machine-tagged store failure surfaced verbatim to the calling tool. */
export class StoreError extends Error {
  readonly code:
    | 'no-active-engagement'
    | 'missing-ref'
    | 'invalid-record'
    | 'forbidden'

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
  /** Override the severity SLA policy with an explicit number of days. */
  slaDays?: number
  reproducibleSteps: string[]
  affectedAssetId?: string
  evidenceIds?: string[]
  remediation?: string
  techniqueIds?: string[]
  owaspIds?: string[]
  cweIds?: string[]
  cveIds?: string[]
  /** Blue-team feedback on this action (VECTR-style). */
  detected?: import('./types.js').DetectionOutcome
  /** CVSS v3.1 base vector; score derived automatically when it parses. */
  cvssVector?: string
  /** Mark this finding as a duplicate of an earlier one (dedup). */
  duplicateOf?: string
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

export interface NewArtifact {
  kind: import('./types.js').ArtifactKind
  /** Path / url / short identifier of the deliverable. */
  location: string
  description?: string
  intentId?: string
  assetId?: string
}

export interface NewHint {
  text: string
  source: import('./types.js').HintSource
  intentId?: string
}

export interface NewSample {
  kind: import('./types.js').SampleKind
  location: string
  sha256: string
  md5?: string
  sha1?: string
  fileType?: string
  arch?: string
  notes?: string
  intentId?: string
}

export interface NewObjective {
  title: string
}

export interface NewIoc {
  type: import('./types.js').IocType
  value: string
  context?: string
  sampleId?: string
  intentId?: string
}

export interface NewScopeEntry {
  kind: import('./types.js').ScopeKind
  value: string
  note?: string
}

export interface SubmitBatch {
  intentId: string
  evidence?: NewEvidence[]
  facts?: NewFact[]
  assets?: NewAsset[]
  findings?: NewFinding[]
  credentials?: NewCredential[]
  artifacts?: NewArtifact[]
  samples?: NewSample[]
  iocs?: NewIoc[]
}

export interface SubmitResult {
  intentId: string
  evidence: string[]
  facts: string[]
  assets: string[]
  findings: string[]
  credentials: string[]
  artifacts: string[]
  samples: string[]
  iocs: string[]
}

type RecordTable =
  | 'goals' | 'intents' | 'facts' | 'assets' | 'findings' | 'evidence'
  | 'credentials' | 'artifacts' | 'hints' | 'samples' | 'iocs' | 'objectives'
  | 'scope_entries'
  | 'operators'

const ID_PREFIX: Record<Exclude<RecordTable, 'goals'>, string> = {
  intents: 'intent',
  facts: 'fact',
  assets: 'asset',
  findings: 'finding',
  evidence: 'ev',
  credentials: 'cred',
  artifacts: 'art',
  hints: 'hint',
  samples: 'sample',
  iocs: 'ioc',
  objectives: 'obj',
  scope_entries: 'scope',
  operators: 'op',
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

  /**
   * The engagement reads/report render against: the open one when present,
   * otherwise the most recently closed — closing an engagement must not blank
   * out its state, graph, or final report.
   */
  currentGoal(sessionId: string): (GoalRecord & { id: string }) | undefined {
    return this.activeGoal(sessionId) ?? this.latestClosedGoal(sessionId)
  }

  latestClosedGoal(sessionId: string): (GoalRecord & { id: string }) | undefined {
    let found: (GoalRecord & { id: string }) | undefined
    for (const [id, goal] of this.rowsForSession('goals', sessionId)) {
      if (goal.closedAt === undefined) continue
      if (found === undefined || goal.closedAt! >= found.closedAt!) found = { ...goal, id }
    }
    return found as (GoalRecord & { id: string }) | undefined
  }

  /**
   * Stamp an explicit verdict on the active engagement and close it. Unlike
   * superseding via a new goal this records WHY the engagement ended.
   */
  async closeGoal(sessionId: string, input: {
    outcome: import('./types.js').GoalOutcome
    summary?: string
  }): Promise<{ goalId: string; outcome: import('./types.js').GoalOutcome }> {
    const goal = this.activeGoal(sessionId)
    if (goal === undefined) {
      throw new StoreError(
        'no-active-engagement',
        `no active engagement in this session — nothing to close`,
      )
    }
    const closed: GoalRecord = {
      ...goal,
      closedAt: Date.now(),
      outcome: input.outcome,
      ...(input.summary !== undefined ? { closingSummary: input.summary } : {}),
    }
    await this.put('goals', goal.id, closed)
    return { goalId: goal.id, outcome: input.outcome }
  }

  async addIntent(sessionId: string, input: {
    title: string
    rationale?: string
    phase?: import('./types.js').Phase
    /** Facts this direction derives from (must exist in the session). */
    derivedFrom?: string[]
    /** Prerequisite intents for multi-step chains (must exist). */
    dependsOn?: string[]
    /** Assets this direction anchors to (must exist). */
    assetIds?: string[]
    /** ATT&CK techniques this direction plans to exercise. */
    techniqueIds?: string[]
  }): Promise<string> {
    const goal = this.requireActiveGoal(sessionId)
    if (input.techniqueIds !== undefined && !validTechniqueIds(input.techniqueIds)) {
      throw new StoreError('invalid-record', `techniqueIds must be MITRE ATT&CK ids: ${input.techniqueIds.join(', ')}`)
    }
    for (const factId of input.derivedFrom ?? []) {
      if (this.get<FactRecord>('facts', sessionId, factId) === undefined) {
        throw new StoreError('missing-ref', `fact '${factId}' does not exist in this session`)
      }
    }
    for (const intentId of input.dependsOn ?? []) {
      if (this.get<IntentRecord>('intents', sessionId, intentId) === undefined) {
        throw new StoreError('missing-ref', `intent '${intentId}' does not exist in this session`)
      }
    }
    for (const assetId of input.assetIds ?? []) {
      if (this.get<AssetRecord>('assets', sessionId, assetId) === undefined) {
        throw new StoreError('missing-ref', `asset '${assetId}' does not exist in this session`)
      }
    }
    const id = this.nextId('intents', sessionId)
    const parsed = intentSchema.parse({
      sessionId,
      goalId: goal.id,
      title: input.title,
      rationale: input.rationale ?? '',
      ...(input.phase !== undefined ? { phase: input.phase } : {}),
      ...(input.derivedFrom !== undefined && input.derivedFrom.length > 0
        ? { derivedFrom: [...input.derivedFrom] }
        : {}),
      ...(input.dependsOn !== undefined && input.dependsOn.length > 0
        ? { dependsOn: [...input.dependsOn] }
        : {}),
      ...(input.assetIds !== undefined && input.assetIds.length > 0
        ? { assetIds: [...input.assetIds] }
        : {}),
      ...(input.techniqueIds !== undefined && input.techniqueIds.length > 0
        ? { techniqueIds: [...input.techniqueIds] }
        : {}),
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
    if (input.cweIds !== undefined && !validCweIds(input.cweIds)) {
      throw new StoreError(
        'invalid-record',
        `cweIds must be CWE weakness ids like 'CWE-79': ${input.cweIds.filter((id) => !CWE_ID_RE.test(id)).join(', ')}`,
      )
    }
    if (input.cveIds !== undefined && !input.cveIds.every((id) => CVE_ID_RE.test(id))) {
      throw new StoreError(
        'invalid-record',
        `cveIds must be CVE references like 'CVE-2024-12345': ${input.cveIds.filter((id) => !CVE_ID_RE.test(id)).join(', ')}`,
      )
    }
    if (
      input.detected !== undefined
      && !DETECTION_OUTCOMES.includes(input.detected)
    ) {
      throw new StoreError('invalid-record', `invalid detected outcome: '${input.detected}'`)
    }
    const score = input.cvssVector !== undefined ? scoreVector(input.cvssVector) : null
    if (input.cvssVector !== undefined && score === null) {
      throw new StoreError('invalid-record', `cvssVector is not a parseable CVSS vector (v3.1 or v4.0): '${input.cvssVector}'`)
    }
    if (input.duplicateOf !== undefined && input.duplicateOf !== '') {
      if (this.get<FindingRecord>('findings', sessionId, input.duplicateOf) === undefined) {
        throw new StoreError('missing-ref', `finding '${input.duplicateOf}' does not exist in this session`)
      }
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
      ...(input.cweIds !== undefined && input.cweIds.length > 0
        ? { cweIds: [...input.cweIds] }
        : {}),
      ...(input.cveIds !== undefined && input.cveIds.length > 0
        ? { cveIds: [...input.cveIds] }
        : {}),
      ...(input.detected !== undefined ? { detected: input.detected } : {}),
      ...(score !== null ? { cvssVector: input.cvssVector, cvssScore: score } : {}),
      ...(input.duplicateOf !== undefined && input.duplicateOf !== ''
        ? { duplicateOf: input.duplicateOf }
        : {}),
      createdAt: Date.now(),
    })
    // SLA stamp: explicit slaDays wins, else the severity policy; null = no deadline.
    const slaDays = input.slaDays !== undefined ? input.slaDays : SLA_POLICY_DAYS[input.severity]
    const record: FindingRecord = slaDays !== null && slaDays !== undefined
      ? { ...parsed, slaDueAt: (parsed.createdAt as number) + slaDays * 86_400_000 } as FindingRecord
      : parsed as FindingRecord
    await this.put('findings', id, record)
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

  /** Register a deliverable produced by the engagement (loot/exploit/dump…). */
  async addArtifact(sessionId: string, input: NewArtifact): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (input.intentId !== undefined && input.intentId !== '') {
      this.requireIntent(sessionId, input.intentId)
    }
    if (input.assetId !== undefined && input.assetId !== '') {
      this.requireAsset(sessionId, input.assetId)
    }
    const id = this.nextId('artifacts', sessionId)
    const parsed = artifactSchema.parse({
      sessionId,
      kind: input.kind,
      location: input.location,
      ...(input.description !== undefined ? { description: input.description } : {}),
      ...(input.intentId !== undefined && input.intentId !== '' ? { intentId: input.intentId } : {}),
      ...(input.assetId !== undefined && input.assetId !== '' ? { assetId: input.assetId } : {}),
      createdAt: Date.now(),
    })
    await this.put('artifacts', id, parsed as ArtifactRecord)
    return id
  }

  /** Record human steering (Cairn's Hint primitive) into the blackboard. */
  async addHint(sessionId: string, input: NewHint): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (input.intentId !== undefined && input.intentId !== '') {
      this.requireIntent(sessionId, input.intentId)
    }
    const id = this.nextId('hints', sessionId)
    const parsed = hintSchema.parse({
      sessionId,
      text: input.text,
      source: input.source,
      ...(input.intentId !== undefined && input.intentId !== '' ? { intentId: input.intentId } : {}),
      createdAt: Date.now(),
    })
    await this.put('hints', id, parsed as HintRecord)
    return id
  }

  /** Register a binary/document under analysis with chain-of-custody hashes. */
  async addSample(sessionId: string, input: NewSample): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (!SHA256_RE.test(input.sha256 ?? '')) {
      throw new StoreError('invalid-record', 'sample sha256 must be a 64-char hex digest')
    }
    if (input.md5 !== undefined && !MD5_RE.test(input.md5)) {
      throw new StoreError('invalid-record', 'sample md5 must be a 32-char hex digest')
    }
    if (input.sha1 !== undefined && !SHA1_RE.test(input.sha1)) {
      throw new StoreError('invalid-record', 'sample sha1 must be a 40-char hex digest')
    }
    if (!SAMPLE_KINDS.includes(input.kind)) {
      throw new StoreError('invalid-record', `invalid sample kind: '${input.kind}'`)
    }
    if (input.intentId !== undefined && input.intentId !== '') {
      this.requireIntent(sessionId, input.intentId)
    }
    const id = this.nextId('samples', sessionId)
    const parsed = sampleSchema.parse({
      sessionId,
      kind: input.kind,
      location: input.location,
      sha256: input.sha256.toLowerCase(),
      ...(input.md5 !== undefined ? { md5: input.md5.toLowerCase() } : {}),
      ...(input.sha1 !== undefined ? { sha1: input.sha1.toLowerCase() } : {}),
      ...(input.fileType !== undefined ? { fileType: input.fileType } : {}),
      ...(input.arch !== undefined ? { arch: input.arch } : {}),
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
      ...(input.intentId !== undefined && input.intentId !== '' ? { intentId: input.intentId } : {}),
      createdAt: Date.now(),
    })
    await this.put('samples', id, parsed as SampleRecord)
    return id
  }

  /** Record an indicator of compromise, optionally tied to a sample. */
  async addIoc(sessionId: string, input: NewIoc): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (!IOC_TYPES.includes(input.type)) {
      throw new StoreError('invalid-record', `invalid ioc type: '${input.type}'`)
    }
    if (input.sampleId !== undefined && input.sampleId !== '') {
      const sample = this.get<SampleRecord>('samples', sessionId, input.sampleId)
      if (sample === undefined) {
        throw new StoreError('missing-ref', `sample '${input.sampleId}' does not exist in this session`)
      }
    }
    if (input.intentId !== undefined && input.intentId !== '') {
      this.requireIntent(sessionId, input.intentId)
    }
    const id = this.nextId('iocs', sessionId)
    const parsed = iocSchema.parse({
      sessionId,
      type: input.type,
      value: input.value,
      ...(input.context !== undefined ? { context: input.context } : {}),
      ...(input.sampleId !== undefined && input.sampleId !== '' ? { sampleId: input.sampleId } : {}),
      ...(input.intentId !== undefined && input.intentId !== '' ? { intentId: input.intentId } : {}),
      createdAt: Date.now(),
    })
    await this.put('iocs', id, parsed as IocRecord)
    return id
  }

  /** Add one success criterion to the engagement checklist. */
  async addObjective(sessionId: string, input: NewObjective): Promise<string> {
    this.requireActiveGoal(sessionId)
    const id = this.nextId('objectives', sessionId)
    const parsed = objectiveSchema.parse({
      sessionId,
      title: input.title,
      createdAt: Date.now(),
    })
    await this.put('objectives', id, parsed as ObjectiveRecord)
    return id
  }

  /** Register one structured authorization-boundary entry (in/out scope). */
  async addScopeEntry(sessionId: string, input: NewScopeEntry): Promise<string> {
    this.requireActiveGoal(sessionId)
    if (!SCOPE_KINDS.includes(input.kind)) {
      throw new StoreError('invalid-record', `invalid scope kind: '${input.kind}'`)
    }
    const value = input.value.trim()
    if (value === '') {
      throw new StoreError('invalid-record', 'scope value must not be empty')
    }
    const id = this.nextId('scope_entries', sessionId)
    const parsed = scopeEntrySchema.parse({
      sessionId,
      kind: input.kind,
      value,
      ...(input.note !== undefined && input.note !== '' ? { note: input.note } : {}),
      createdAt: Date.now(),
    })
    await this.put('scope_entries', id, parsed as ScopeEntryRecord)
    return id
  }

  /** Prove/unprove a checklist entry; evidence ids document the proof. */
  async proveObjective(sessionId: string, objectiveId: string, patch: {
    proven?: boolean
    evidenceIds?: string[]
  }): Promise<ObjectiveRecord & { id: string }> {
    this.requireEvidence(sessionId, patch.evidenceIds ?? [])
    const existing = this.get<ObjectiveRecord>('objectives', sessionId, objectiveId)
    if (existing === undefined) {
      throw new StoreError('missing-ref', `objective '${objectiveId}' does not exist in this session`)
    }
    const updated: ObjectiveRecord = patch.proven === false
      ? { ...existing, provenAt: undefined, evidenceIds: undefined }
      : {
          ...existing,
          provenAt: existing.provenAt ?? Date.now(),
          ...(patch.evidenceIds !== undefined ? { evidenceIds: [...patch.evidenceIds] } : {}),
        }
    await this.put('objectives', objectiveId, updated)
    return { ...updated, id: objectiveId }
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
    if (patch.status !== undefined && !INTENT_STATUSES.includes(patch.status)) {
      throw new StoreError('invalid-record', `invalid intent status: '${patch.status}'`)
    }
    if (patch.title !== undefined && patch.title.trim() === '') {
      throw new StoreError('invalid-record', 'intent title must not be empty')
    }
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
    /** Blue-team feedback learned during/after the action (VECTR-style). */
    detected?: import('./types.js').DetectionOutcome
  }): Promise<FindingRecord & { id: string }> {
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
    if (patch.detected !== undefined) updated = { ...updated, detected: patch.detected }
    await this.put('findings', findingId, updated)
    return { ...updated, id: findingId }
  }

  /**
   * Triage state on a finding (DefectDojo-style): under-review /
   * false-positive / out-of-scope / risk-accepted; `none` clears the flag.
   * Flagged findings stay in records and reports — they are marked, not
   * deleted. SARIF suppresses false positives.
   */
  async flagFinding(sessionId: string, findingId: string, patch: {
    flag: FindingFlag | 'none'
    note?: string
    evidenceIds?: string[]
  }): Promise<FindingRecord & { id: string }> {
    this.requireEvidence(sessionId, patch.evidenceIds ?? [])
    if (patch.flag !== 'none' && !FINDING_FLAGS.includes(patch.flag)) {
      throw new StoreError('invalid-record', `invalid finding flag: '${patch.flag}'`)
    }
    const existing = this.get<FindingRecord>('findings', sessionId, findingId)
    if (existing === undefined) {
      throw new StoreError('missing-ref', `finding '${findingId}' does not exist in this session`)
    }
    const updated: FindingRecord = patch.flag === 'none'
      ? { ...existing, flag: undefined, flagNote: undefined, flaggedAt: undefined }
      : {
          ...existing,
          flag: patch.flag,
          ...(patch.note !== undefined && patch.note !== '' ? { flagNote: patch.note } : {}),
          flaggedAt: Date.now(),
        }
    await this.put('findings', findingId, updated)
    return { ...updated, id: findingId }
  }

  /**
   * Cross-table keyword search over the ACTIVE engagement window. Hits are
   * snippets grouped by record kind; credential raw secrets never match —
   * only username/target/masked material.
   */
  search(sessionId: string, query: string): { query: string; total: number; hits: { kind: string; id: string; snippet: string }[] } {
    const q = query.trim().toLowerCase()
    if (q === '') return { query, total: 0, hits: [] }
    const win = this.windowOf(sessionId)
    if (win === null) return { query, total: 0, hits: [] }
    const PER_KIND = 8
    const hits: { kind: string; id: string; snippet: string }[] = []
    const scan = (kind: string, rows: [string, string][]): void => {
      let n = 0
      for (const [id, text] of rows) {
        if (n >= PER_KIND) break
        const idx = text.toLowerCase().indexOf(q)
        if (idx === -1) continue
        const start = Math.max(0, idx - 40)
        const snippet = `${start > 0 ? '…' : ''}${text.slice(start, idx + q.length + 60)}${idx + q.length + 60 < text.length ? '…' : ''}`
        hits.push({ kind, id, snippet })
        n += 1
      }
    }
    const r = {
      intents: this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][],
      facts: this.rowsInWindow('facts', sessionId, win) as [string, FactRecord][],
      assets: this.rowsInWindow('assets', sessionId, win) as [string, AssetRecord][],
      findings: this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][],
      credentials: this.rowsInWindow('credentials', sessionId, win) as [string, CredentialRecord][],
      artifacts: this.rowsInWindow('artifacts', sessionId, win) as [string, ArtifactRecord][],
      samples: this.rowsInWindow('samples', sessionId, win) as [string, SampleRecord][],
      iocs: this.rowsInWindow('iocs', sessionId, win) as [string, IocRecord][],
      objectives: this.rowsInWindow('objectives', sessionId, win) as [string, ObjectiveRecord][],
      hints: this.rowsInWindow('hints', sessionId, win) as [string, HintRecord][],
      scopeEntries: this.rowsInWindow('scope_entries', sessionId, win) as [string, ScopeEntryRecord][],
      evidence: this.rowsInWindow('evidence', sessionId, win) as [string, EvidenceRecord][],
    }
    scan('intent', r.intents.map(([id, x]) => [id, `${x.title} ${x.rationale}`] as [string, string]))
    scan('fact', r.facts.map(([id, x]) => [id, `${x.detail} ${x.target ?? ''}`] as [string, string]))
    scan('asset', r.assets.map(([id, x]) => [id, `${x.type} ${x.value} ${(x.tags ?? []).join(' ')} ${x.notes ?? ''}`] as [string, string]))
    scan('finding', r.findings.map(([id, x]) => [id, `${x.title} ${x.description} ${x.remediation ?? ''}`] as [string, string]))
    // Credentials: masked material only — raw secrets never match.
    scan('credential', r.credentials.map(([id, x]) => [id, `${x.kind} ${x.username ?? ''} ${x.target ?? ''} ${maskSecret(x.secret)}`] as [string, string]))
    scan('artifact', r.artifacts.map(([id, x]) => [id, `${x.kind} ${x.location} ${x.description ?? ''}`] as [string, string]))
    scan('sample', r.samples.map(([id, x]) => [id, `${x.kind} ${x.location} ${x.fileType ?? ''}`] as [string, string]))
    scan('ioc', r.iocs.map(([id, x]) => [id, `${x.type} ${x.value} ${x.context ?? ''}`] as [string, string]))
    scan('objective', r.objectives.map(([id, x]) => [id, x.title] as [string, string]))
    scan('hint', r.hints.map(([id, x]) => [id, x.text] as [string, string]))
    scan('scope', r.scopeEntries.map(([id, x]) => [id, `${x.kind} ${x.value} ${x.note ?? ''}`] as [string, string]))
    // Evidence matches on label only; content is excluded by design.
    scan('evidence', r.evidence.map(([id, x]) => [id, `${x.kind} ${x.label}`] as [string, string]))
    return { query, total: hits.length, hits }
  }

  /**
   * Deployment-wide overview across every recorded engagement/session
   * (DefectDojo metrics-dashboard style): totals, severity distribution,
   * detection feedback, triage flags.
   */
  overview(): {
    engagements: number
    findings: number
    fixed: number
    severity: Record<string, number>
    detection: Record<string, number>
    flags: Record<string, number>
    tables: Record<string, number>
  } {
    const severity: Record<string, number> = {}
    for (const s of SEVERITIES) severity[s] = 0
    const detection: Record<string, number> = {}
    const flags: Record<string, number> = {}
    let findingsCount = 0
    let fixed = 0
    for (const [, f] of this.domain.table('findings').entries() as IterableIterator<[string, FindingRecord]>) {
      findingsCount += 1
      severity[f.severity] = (severity[f.severity] ?? 0) + 1
      if (f.status === 'fixed') fixed += 1
      if (f.detected !== undefined) detection[f.detected] = (detection[f.detected] ?? 0) + 1
      if (f.flag !== undefined) flags[f.flag] = (flags[f.flag] ?? 0) + 1
    }
    const tables: Record<string, number> = {}
    for (const t of ['goals', 'intents', 'facts', 'assets', 'findings', 'evidence', 'credentials', 'artifacts', 'hints', 'samples', 'iocs', 'objectives', 'scope_entries', 'operators'] as const) {
      tables[t] = [...this.domain.table(t).entries()].length
    }
    return { engagements: tables['goals']!, findings: findingsCount, fixed, severity, detection, flags, tables }
  }

  /**
   * ATT&CK technique coverage over the current engagement: `proven` =
   * techniques behind confirmed findings; `attempted` = planned on intents
   * or exercised without (yet) proving a finding.
   */
  techniqueCoverage(sessionId: string): { attempted: string[]; proven: string[] } {    const win = this.windowOf(sessionId)
    if (win === null) return { attempted: [], proven: [] }
    const proven = new Set<string>()
    for (const [, finding] of this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][]) {
      for (const t of finding.techniqueIds ?? []) proven.add(t)
    }
    const attempted = new Set<string>(proven)
    for (const [, intent] of this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][]) {
      for (const t of intent.techniqueIds ?? []) {
        if (!proven.has(t)) attempted.add(t)
      }
    }
    return { attempted: [...attempted], proven: [...proven] }
  }

  /** Verification transition on a credential (`valid` / `invalid` / reset). */
  async updateCredential(sessionId: string, credentialId: string, patch: {
    status: import('./types.js').CredentialStatus
    evidenceIds?: string[]
  }): Promise<CredentialRecord & { id: string }> {
    if (!CREDENTIAL_STATUSES.includes(patch.status)) {
      throw new StoreError('invalid-record', `invalid credential status: '${patch.status}'`)
    }
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
   * one batch: evidence mints first, then assets and credentials; facts/
   * findings may cite fresh evidence and asset ids.
   *
   * Two-phase: every item is validated (including prospective intra-batch
   * references) before the first write lands, so a malformed batch leaves no
   * partial records behind and a client retry cannot duplicate half a batch.
   */
  async submit(sessionId: string, batch: SubmitBatch): Promise<SubmitResult> {
    this.requireActiveGoal(sessionId)
    this.requireIntent(sessionId, batch.intentId)

    // ── phase 1: validate everything against session ∪ prospective ids ──
    const baseCount = (prefix: string, table: RecordTable): number => {
      let n = 0
      for (const [id] of this.rowsForSession(table, sessionId)) {
        if (id.startsWith(`${prefix}-`)) n += 1
      }
      return n
    }
    let evN = baseCount('ev', 'evidence')
    let assetN = baseCount('asset', 'assets')
    let credN = baseCount('cred', 'credentials')
    let factN = baseCount('fact', 'facts')
    let findingN = baseCount('finding', 'findings')

    const evidenceIds = new Set(this.rowsForSession('evidence', sessionId).map(([id]) => id))
    const assetIds = new Set(this.rowsForSession('assets', sessionId).map(([id]) => id))

    for (const item of batch.evidence ?? []) {
      if (!EVIDENCE_KINDS.includes(item.kind)) {
        throw new StoreError('invalid-record', `invalid evidence kind: '${item.kind}'`)
      }
      if (item.content === undefined || item.content === '') {
        throw new StoreError('invalid-record', 'evidence content must not be empty')
      }
      evN += 1
      evidenceIds.add(`ev-${evN}`)
    }
    for (const item of batch.assets ?? []) {
      if (item.type === undefined || item.type === '') throw new StoreError('invalid-record', 'asset type must not be empty')
      if (item.value === undefined || item.value === '') throw new StoreError('invalid-record', 'asset value must not be empty')
      if (item.parentId !== undefined && item.parentId !== '' && !assetIds.has(item.parentId)) {
        throw new StoreError('missing-ref', `asset '${item.parentId}' does not exist in this session`)
      }
      assetN += 1
      assetIds.add(`asset-${assetN}`)
    }
    for (const item of batch.credentials ?? []) {
      if (!CREDENTIAL_KINDS.includes(item.kind)) {
        throw new StoreError('invalid-record', `invalid credential kind: '${item.kind}'`)
      }
      if (item.secret === undefined || item.secret === '') {
        throw new StoreError('invalid-record', 'credential secret must not be empty')
      }
      if (item.assetId !== undefined && item.assetId !== '' && !assetIds.has(item.assetId)) {
        throw new StoreError('missing-ref', `asset '${item.assetId}' does not exist in this session`)
      }
      credN += 1
    }
    for (const item of batch.samples ?? []) {
      if (!SAMPLE_KINDS.includes(item.kind)) {
        throw new StoreError('invalid-record', `invalid sample kind: '${item.kind}'`)
      }
      if (item.location === undefined || item.location === '') {
        throw new StoreError('invalid-record', 'sample location must not be empty')
      }
      if (SHA256_RE.test(item.sha256 ?? '') === false) {
        throw new StoreError('invalid-record', 'sample sha256 must be a 64-char hex digest')
      }
    }
    for (const item of batch.iocs ?? []) {
      if (!IOC_TYPES.includes(item.type)) {
        throw new StoreError('invalid-record', `invalid ioc type: '${item.type}'`)
      }
      if (item.value === undefined || item.value === '') {
        throw new StoreError('invalid-record', 'ioc value must not be empty')
      }
    }
    for (const item of batch.artifacts ?? []) {
      if (!ARTIFACT_KINDS.includes(item.kind)) {
        throw new StoreError('invalid-record', `invalid artifact kind: '${item.kind}'`)
      }
      if (item.location === undefined || item.location === '') {
        throw new StoreError('invalid-record', 'artifact location must not be empty')
      }
      if (item.assetId !== undefined && item.assetId !== '' && !assetIds.has(item.assetId)) {
        throw new StoreError('missing-ref', `asset '${item.assetId}' does not exist in this session`)
      }
    }
    for (const item of batch.facts ?? []) {
      if (item.detail === undefined || item.detail === '') {
        throw new StoreError('invalid-record', 'fact detail must not be empty')
      }
      for (const evId of item.evidenceIds ?? []) {
        if (!evidenceIds.has(evId)) {
          throw new StoreError('missing-ref', `evidence '${evId}' does not exist in this session`)
        }
      }
      factN += 1
    }
    for (const item of batch.findings ?? []) {
      if ((item.reproducibleSteps ?? []).length < 1) {
        throw new StoreError('invalid-record', 'findings need at least one reproducible step')
      }
      for (const evId of item.evidenceIds ?? []) {
        if (!evidenceIds.has(evId)) {
          throw new StoreError('missing-ref', `evidence '${evId}' does not exist in this session`)
        }
      }
      if (item.affectedAssetId !== undefined && item.affectedAssetId !== '' && !assetIds.has(item.affectedAssetId)) {
        throw new StoreError('missing-ref', `asset '${item.affectedAssetId}' does not exist in this session`)
      }
      if (item.techniqueIds !== undefined && !validTechniqueIds(item.techniqueIds)) {
        throw new StoreError('invalid-record', `techniqueIds must be MITRE ATT&CK ids: ${item.techniqueIds.join(', ')}`)
      }
      if (item.owaspIds !== undefined && !validOwaspIds(item.owaspIds)) {
        throw new StoreError('invalid-record', `owaspIds must be OWASP Top 10 categories: ${item.owaspIds.join(', ')}`)
      }
      if (item.cvssVector !== undefined && scoreVector(item.cvssVector) === null) {
        throw new StoreError('invalid-record', `cvssVector is not a parseable CVSS vector (v3.1 or v4.0): '${item.cvssVector}'`)
      }
      findingN += 1
    }

    // ── phase 2: execute — phase 1 guarantees no mid-batch failure ──
    const result: SubmitResult = { intentId: batch.intentId, evidence: [], facts: [], assets: [], findings: [], credentials: [], artifacts: [], samples: [], iocs: [] }
    for (const item of batch.evidence ?? []) {
      result.evidence.push(await this.addEvidence(sessionId, item))
    }
    for (const item of batch.assets ?? []) {
      result.assets.push(await this.addAsset(sessionId, item))
    }
    for (const item of batch.credentials ?? []) {
      result.credentials.push(await this.addCredential(sessionId, item))
    }
    for (const item of batch.artifacts ?? []) {
      result.artifacts.push(await this.addArtifact(sessionId, item))
    }
    for (const item of batch.samples ?? []) {
      result.samples.push(await this.addSample(sessionId, item))
    }
    for (const item of batch.iocs ?? []) {
      result.iocs.push(await this.addIoc(sessionId, item))
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

  /** `[since, until]` covering the current (open or latest closed) engagement. */
  private windowOf(sessionId: string): { since: number; until: number } | null {
    const goal = this.currentGoal(sessionId)
    if (goal === undefined) return null
    return { since: goal.createdAt - 1, until: goal.closedAt ?? Number.MAX_SAFE_INTEGER }
  }

  private requireIntent(sessionId: string, intentId: string): void {
    const intent = this.get<IntentRecord>('intents', sessionId, intentId)
    if (intent === undefined) {
      throw new StoreError('missing-ref', `intent '${intentId}' does not exist in this session`)
    }
  }

  /** Public intent-existence check for tools that pre-validate before writing. */
  hasIntent(sessionId: string, intentId: string): boolean {
    return this.get<IntentRecord>('intents', sessionId, intentId) !== undefined
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
      artifacts: this.rowsInWindow('artifacts', sessionId, w).length,
      hints: this.rowsInWindow('hints', sessionId, w).length,
      samples: this.rowsInWindow('samples', sessionId, w).length,
      iocs: this.rowsInWindow('iocs', sessionId, w).length,
      objectives: this.rowsInWindow('objectives', sessionId, w).length,
    }
  }

  state(sessionId: string): {
    goal: GoalRecord | null
    counts: EngagementCounts
    openIntents: { id: string; title: string }[]
    progress: { active: number; done: number; blocked: number }
    coverage: { tested: string[]; untested: string[] }
    techniques: { attempted: string[]; proven: string[] }
    objectiveProgress: { total: number; proven: number }
    credentialReuse: { mask: string; targets: string[]; kinds: string[] }[]
    nextSteps: string[]
    scope: { entries: number; violations: import('./types.js').ScopeIssue[] }
    slaOverdue: { id: string; title: string; dueAt: number; daysOverdue: number }[]
  } {
    const goal = this.currentGoal(sessionId)
    const win = this.windowOf(sessionId)
    const intents = win === null
      ? [] as [string, IntentRecord][]
      : this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][]
    const progress = { active: 0, done: 0, blocked: 0 }
    for (const [, intent] of intents) progress[intent.status ?? 'active'] += 1
    const coverage = this.coverage(sessionId)
    const techniques = this.techniqueCoverage(sessionId)
    const objectiveProgress = this.objectiveProgress(sessionId)
    const credentialReuse = this.credentialReuse(sessionId)
    const issues = this.scopeIssues(sessionId)
    const slaOverdue = this.collectSlaOverdue(sessionId, win)
    const unverifiedCredentials = win === null
      ? 0
      : (this.rowsInWindow('credentials', sessionId, win) as [string, CredentialRecord][])
        .filter(([, c]) => c.status === 'unverified').length
    const findingsCount = this.counts(sessionId).findings
    const nextSteps: string[] = []
    if (slaOverdue.length > 0) {
      nextSteps.push(`SLA breach: ${slaOverdue.length} finding(s) past their remediation deadline (worst ${slaOverdue[0]!.daysOverdue}d overdue) — escalate or renegotiate`)
    }
    if (issues.some((i) => i.reason === 'out-of-scope')) {
      nextSteps.push(`scope violation(s) recorded — stop work on those targets and note the boundary (redteam_add_scope out)`)
    } else if (issues.some((i) => i.reason === 'unscoped')) {
      nextSteps.push(`${issues.filter((i) => i.reason === 'unscoped').length} target(s) match no in-scope entry — confirm the boundary via redteam_add_scope`)
    }
    if (coverage.untested.length > 0) {
      nextSteps.push(`覆盖缺口 / coverage gap: ${coverage.untested.length} asset(s) untouched — anchor them via redteam_add_intent assetIds`)
    }
    if (progress.blocked > 0) {
      nextSteps.push(`${progress.blocked} blocked intent(s) — revisit or redirect via redteam_update_intent`)
    }
    const openObjectives = objectiveProgress.total - objectiveProgress.proven
    if (openObjectives > 0) {
      nextSteps.push(`${openObjectives} objective(s) still open — prove with evidence via redteam_prove_objective`)
    }
    if (unverifiedCredentials > 0) {
      nextSteps.push(`${unverifiedCredentials} credential(s) unverified — validate via redteam_update_credential`)
    }
    if (credentialReuse.length > 0) {
      nextSteps.push(`credential material reused across ${credentialReuse.length} group(s) — try it on sibling targets and record hits`)
    }
    const attemptedOnly = techniques.attempted.length - techniques.proven.length
    if (attemptedOnly > 0) {
      nextSteps.push(`${attemptedOnly} ATT&CK technique(s) attempted without proof — dig deeper or log a finding`)
    }
    if (findingsCount === 0 && intents.length > 0) {
      nextSteps.push('no confirmed finding yet — capture successful actions via redteam_add_finding')
    }
    return {
      goal: goal === undefined ? null : (({ id: _id, ...rest }) => rest)(goal),
      counts: this.counts(sessionId),
      openIntents: intents
        .filter(([, record]) => (record.status ?? 'active') === 'active')
        .map(([id, record]) => ({ id, title: record.title })),
      progress,
      coverage,
      techniques,
      objectiveProgress,
      credentialReuse,
      nextSteps,
      scope: { entries: win === null ? 0 : (this.rowsInWindow('scope_entries', sessionId, win) as [string, ScopeEntryRecord][]).length, violations: issues },
      slaOverdue,
    }
  }

  /** Findings past their SLA deadline that are neither fixed nor accepted/FP. */
  private collectSlaOverdue(sessionId: string, win: { since: number; until: number } | null): { id: string; title: string; dueAt: number; daysOverdue: number }[] {
    if (win === null) return []
    const now = Date.now()
    return (this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][])
      .filter(([, f]) => f.slaDueAt !== undefined
        && f.slaDueAt <= now
        && f.status !== 'fixed'
        && f.flag !== 'risk-accepted'
        && f.flag !== 'false-positive'
        && f.flag !== 'out-of-scope')
      .map(([id, f]) => ({
        id,
        title: f.title,
        dueAt: f.slaDueAt!,
        daysOverdue: Math.floor((now - f.slaDueAt!) / 86_400_000),
      }))
      .sort((a, b) => b.daysOverdue - a.daysOverdue)
  }

  /** Register a collaboration participant with their role (upsert by handle). */
  async addOperator(sessionId: string, input: { handle: string; role: import('./types.js').OperatorRole }): Promise<string> {
    this.requireActiveGoal(sessionId)
    const handle = input.handle.trim()
    if (handle === '') throw new StoreError('invalid-record', 'operator handle must not be empty')
    if (!OPERATOR_ROLES.includes(input.role)) {
      throw new StoreError('invalid-record', `invalid role: '${input.role}'`)
    }
    const existing = (this.rowsForSession('operators', sessionId) as [string, OperatorRecord][])
      .find(([, o]) => o.handle === handle)
    if (existing !== undefined) {
      const updated: OperatorRecord = { ...existing[1], role: input.role }
      await this.put('operators', existing[0], updated)
      return existing[0]
    }
    const id = this.nextId('operators', sessionId)
    const parsed = operatorSchema.parse({ sessionId, handle, role: input.role, createdAt: Date.now() })
    await this.put('operators', id, parsed as OperatorRecord)
    return id
  }

  /**
   * Role gate for collaboration writes. No actor (or the implicit
   * 'commander') passes untouched — single-operator sessions keep working;
   * a named actor must be registered and hold at least `minRole`.
   */
  requireActor(sessionId: string, actor: string | undefined, minRole: import('./types.js').OperatorRole): void {
    if (actor === undefined || actor === '' || actor === 'commander') return
    const rank = OPERATOR_ROLES.indexOf(minRole)
    const existing = (this.rowsForSession('operators', sessionId) as [string, OperatorRecord][])
      .find(([, o]) => o.handle === actor)
    if (existing === undefined) {
      throw new StoreError('missing-ref', `actor '${actor}' is not registered — redteam_add_operator first`)
    }
    if (OPERATOR_ROLES.indexOf(existing[1].role) < rank) {
      throw new StoreError('forbidden', `actor '${actor}' (${existing[1].role}) lacks role '${minRole}'`)
    }
  }

  /**
   * Apply external-tracker updates (JIRA bridge, inbound direction): stamp
   * issue key/status per finding. A tracker-side Done does NOT auto-close —
   * retest via redteam_retest_finding keeps the evidence chain honest.
   */
  async applyTrackerUpdates(
    sessionId: string,
    updates: { findingId: string; jiraKey: string; jiraStatus?: string }[],
  ): Promise<{ updated: string[]; missing: string[] }> {
    const updated: string[] = []
    const missing: string[] = []
    for (const u of updates) {
      const existing = this.get<FindingRecord>('findings', sessionId, u.findingId)
      if (existing === undefined) { missing.push(u.findingId); continue }
      const rec: FindingRecord = {
        ...existing,
        jiraKey: u.jiraKey,
        ...(u.jiraStatus !== undefined ? { jiraStatus: u.jiraStatus } : {}),
        jiraSyncedAt: Date.now(),
      }
      await this.put('findings', u.findingId, rec)
      updated.push(u.findingId)
    }
    return { updated, missing }
  }

  /**
   * Structured scope compliance over the active engagement: assets by value,
   * findings via their affected asset, and IOCs judged against the registry
   * with the shared matcher (out-of-scope hits; unscoped when in-entries
   * exist and nothing matches).
   */
  scopeIssues(sessionId: string): import('./types.js').ScopeIssue[] {
    const win = this.windowOf(sessionId)
    if (win === null) return []
    const entries = (this.rowsInWindow('scope_entries', sessionId, win) as [string, ScopeEntryRecord][])
      .map(([, e]) => ({ kind: e.kind, value: e.value }))
    if (entries.length === 0) return []
    const assets = (this.rowsInWindow('assets', sessionId, win) as [string, AssetRecord][])
      .map(([id, a]) => ({ id, value: a.value }))
    const assetValue = new Map(assets.map((a) => [a.id, a.value]))
    const findings = (this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][])
      .map(([id, f]) => ({
        id,
        assetValue: f.affectedAssetId !== undefined ? assetValue.get(f.affectedAssetId) ?? null : null,
      }))
    const iocs = (this.rowsInWindow('iocs', sessionId, win) as [string, IocRecord][])
      .map(([id, i]) => ({ id, value: i.value }))
    return scopeCheck(entries, { assets, findings, iocs })
  }

  /**
   * Credential exposure analysis: same secret material observed on more than
   * one target/asset/account. Grouped by raw secret equality (store-side
   * only); the report shows the mask, never the material.
   */
  credentialReuse(sessionId: string): { mask: string; targets: string[]; kinds: string[] }[] {
    const win = this.windowOf(sessionId)
    if (win === null) return []
    const groups = new Map<string, { mask: string; targets: string[]; kinds: string[] }>()
    for (const [, cr] of this.rowsInWindow('credentials', sessionId, win) as [string, CredentialRecord][]) {
      const key = `${cr.kind}\u0000${cr.secret}`
      const entry = groups.get(key) ?? { mask: maskSecret(cr.secret), targets: [], kinds: [] }
      const where = cr.target ?? (cr.assetId !== '' ? cr.assetId : undefined) ?? cr.username ?? '(unbound)'
      if (!entry.targets.includes(where)) entry.targets.push(where)
      if (!entry.kinds.includes(cr.kind)) entry.kinds.push(cr.kind)
      groups.set(key, entry)
    }
    return [...groups.values()]
      .filter((g) => g.targets.length > 1)
      .sort((a, b) => b.targets.length - a.targets.length)
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
    const goal = this.currentGoal(sessionId)!
    const nodes: RedteamViewNode[] = [{ id: goal.id, kind: 'goal', title: goal.objective, status: null, assetIds: [] }]
    const edges: GraphEdge[] = []

    const intents = this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][]
    const intentIds = new Set(intents.map(([id]) => id))
    for (const [id, intent] of intents) {
      nodes.push({ id, kind: 'intent', title: intent.title, status: intent.status ?? 'active', assetIds: [...(intent.assetIds ?? [])] })
      edges.push({ from: intent.goalId, to: id, relation: 'spawns' })
    }
    // Fact→intent lineage and chain prerequisites (only when both ends exist).
    const factIds = new Set(this.rowsInWindow('facts', sessionId, win).map(([id]) => id))
    for (const [id, intent] of intents) {
      for (const factId of intent.derivedFrom ?? []) {
        if (factIds.has(factId)) edges.push({ from: factId, to: id, relation: 'derived_from' })
      }
      for (const depId of intent.dependsOn ?? []) {
        if (intentIds.has(depId)) edges.push({ from: depId, to: id, relation: 'depends_on' })
      }
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

  /**
   * Asset test coverage for the active engagement: an asset counts as tested
   * when any anchored intent targets it or a finding cites it as affected.
   */
  coverage(sessionId: string): { tested: string[]; untested: string[] } {
    const win = this.windowOf(sessionId)
    if (win === null) return { tested: [], untested: [] }
    const assetIds = new Set(this.rowsInWindow('assets', sessionId, win).map(([id]) => id))
    const tested = new Set<string>()
    for (const [, intent] of this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][]) {
      for (const assetId of intent.assetIds ?? []) {
        if (assetIds.has(assetId)) tested.add(assetId)
      }
    }
    for (const [, finding] of this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][]) {
      if (finding.affectedAssetId !== undefined && assetIds.has(finding.affectedAssetId)) {
        tested.add(finding.affectedAssetId)
      }
    }
    return {
      tested: [...tested],
      untested: [...assetIds].filter((id) => !tested.has(id)),
    }
  }

  /** Projection window delivered to the Web tab. */
  projection(sessionId: string): RedteamProjection {
    const graph = this.graph(sessionId)
    const goal = this.currentGoal(sessionId)
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
          affectedAssetId: f.affectedAssetId ?? null,
          detected: f.detected ?? null,
          duplicateOf: f.duplicateOf ?? null,
          flag: f.flag ?? null,
          slaDueAt: f.slaDueAt ?? null,
          jiraKey: f.jiraKey ?? null,
          jiraStatus: f.jiraStatus ?? null,
        }))
    const credentials = this.maskedCredentials(sessionId).map((c) => ({
      id: c.id,
      kind: c.kind as import('./types.js').CredentialKind,
      username: c.username ?? null,
      target: c.target ?? null,
      assetId: c.assetId ?? null,
      status: c.status as import('./types.js').CredentialStatus,
    }))
    const records = this.engagementRecords(sessionId)
    const artifacts = records.artifacts.map(([id, a]) => ({
      id,
      kind: a.kind,
      location: a.location,
      intentId: a.intentId ?? null,
      assetId: a.assetId ?? null,
    }))
    const hints = records.hints.map(([id, h]) => ({
      id,
      text: h.text,
      source: h.source,
      intentId: h.intentId ?? null,
    }))
    const samples = records.samples.map(([id, sp]) => ({
      id,
      kind: sp.kind,
      location: sp.location,
      sha256: sp.sha256,
      fileType: sp.fileType ?? null,
    }))
    const iocs = records.iocs.map(([id, i]) => ({
      id,
      type: i.type,
      value: i.value,
      sampleId: i.sampleId ?? null,
    }))
    const objectives = records.objectives.map(([id, o]) => ({
      id,
      title: o.title,
      provenAt: o.provenAt ?? null,
    }))
    const scopeEntries = (this.rowsForSession('scope_entries', sessionId) as [string, ScopeEntryRecord][])
      .map(([id, s]) => ({ id, kind: s.kind, value: s.value, note: s.note ?? null }))
    const facts = records.facts.map(([id, f]) => ({
      id,
      intentId: f.intentId,
      detail: f.detail.slice(0, 240),
      phase: f.phase ?? null,
      confidence: f.confidence ?? null,
      evidenceIds: [...f.evidenceIds],
    }))
    const evidence = records.evidence.map(([id, ev]) => ({ id, kind: ev.kind, label: ev.label }))
    return {
      goal: goal === undefined
        ? null
        : {
            objective: goal.objective,
            authorization: goal.authorization,
            outcome: goal.outcome ?? null,
            closingSummary: goal.closingSummary ?? null,
          },
      nodes: graph.nodes,
      assets: graph.assets,
      findings,
      credentials,
      artifacts,
      hints,
      samples,
      iocs,
      objectives,
      scope: scopeEntries,
      scopeIssues: this.scopeIssues(sessionId),
      facts,
      evidence,
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
    outcome?: import('./types.js').GoalOutcome
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
        ...(goal.outcome !== undefined ? { outcome: goal.outcome } : {}),
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
      artifacts: this.rowsInWindow('artifacts', sid, win).length,
      hints: this.rowsInWindow('hints', sid, win).length,
      samples: this.rowsInWindow('samples', sid, win).length,
      iocs: this.rowsInWindow('iocs', sid, win).length,
      objectives: this.rowsInWindow('objectives', sid, win).length,
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
    artifacts: [string, ArtifactRecord][]
    hints: [string, HintRecord][]
    samples: [string, SampleRecord][]
    iocs: [string, IocRecord][]
    objectives: [string, ObjectiveRecord][]
    scopeEntries: [string, ScopeEntryRecord][]
  } {
    const win = this.windowOf(sessionId)
    if (win === null) {
      return { goal: null, intents: [], facts: [], assets: [], findings: [], evidence: [], credentials: [], artifacts: [], hints: [], samples: [], iocs: [], objectives: [], scopeEntries: [] }
    }
    return {
      goal: (({ id: _id, ...rest }) => rest)(this.currentGoal(sessionId)!),
      intents: this.rowsInWindow('intents', sessionId, win) as [string, IntentRecord][],
      facts: this.rowsInWindow('facts', sessionId, win) as [string, FactRecord][],
      assets: this.rowsInWindow('assets', sessionId, win) as [string, AssetRecord][],
      findings: this.rowsInWindow('findings', sessionId, win) as [string, FindingRecord][],
      evidence: this.rowsInWindow('evidence', sessionId, win) as [string, EvidenceRecord][],
      credentials: this.rowsInWindow('credentials', sessionId, win) as [string, CredentialRecord][],
      artifacts: this.rowsInWindow('artifacts', sessionId, win) as [string, ArtifactRecord][],
      hints: this.rowsInWindow('hints', sessionId, win) as [string, HintRecord][],
      samples: this.rowsInWindow('samples', sessionId, win) as [string, SampleRecord][],
      iocs: this.rowsInWindow('iocs', sessionId, win) as [string, IocRecord][],
      objectives: this.rowsInWindow('objectives', sessionId, win) as [string, ObjectiveRecord][],
      scopeEntries: this.rowsInWindow('scope_entries', sessionId, win) as [string, ScopeEntryRecord][],
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

  /** Checklist progress over the current engagement. */
  objectiveProgress(sessionId: string): { total: number; proven: number } {
    const win = this.windowOf(sessionId)
    if (win === null) return { total: 0, proven: 0 }
    const rows = this.rowsInWindow('objectives', sessionId, win) as [string, ObjectiveRecord][]
    return { total: rows.length, proven: rows.filter(([, o]) => o.provenAt !== undefined).length }
  }

  edgeRelations(): readonly EdgeRelation[] {
    return ['spawns', 'yields', 'derived_from', 'proves', 'parent', 'depends_on'] as const
  }
}

const EMPTY_COUNTS: EngagementCounts = {
  intents: 0,
  facts: 0,
  assets: 0,
  findings: 0,
  evidence: 0,
  credentials: 0,
  artifacts: 0,
  hints: 0,
  samples: 0,
  iocs: 0,
  objectives: 0,
}
