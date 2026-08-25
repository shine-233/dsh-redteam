/**
 * Shared record and view types for the redteam domain. Types only — no
 * runtime code (package rule).
 */

/** Severity ladder for findings, ordered low → critical. */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const
export type Severity = (typeof SEVERITIES)[number]

/** Evidence kinds; `content` carries the captured payload verbatim. */
export const EVIDENCE_KINDS = ['command', 'output', 'screenshot', 'file', 'url', 'note'] as const
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number]

/** Kill-chain phases for intents/facts (PTES-flavoured, coarse on purpose). */
export const PHASES = [
  'recon',
  'enumeration',
  'exploitation',
  'post-exploitation',
  'reporting',
] as const
export type Phase = (typeof PHASES)[number]

/** Credential material kinds the tracker accepts. */
export const CREDENTIAL_KINDS = ['password', 'hash', 'api-key', 'token', 'ssh-key', 'other'] as const
export type CredentialKind = (typeof CREDENTIAL_KINDS)[number]

/** Verification lifecycle of one credential. */
export const CREDENTIAL_STATUSES = ['unverified', 'valid', 'invalid'] as const
export type CredentialStatus = (typeof CREDENTIAL_STATUSES)[number]

/** Task-tree lifecycle of an intent (PentestGPT-style PTT states). */
export const INTENT_STATUSES = ['active', 'done', 'blocked'] as const
export type IntentStatus = (typeof INTENT_STATUSES)[number]

/** Retest lifecycle of a finding (Strix-style find-and-fix loop). */
export const FINDING_STATUSES = ['confirmed', 'fixed'] as const
export type FindingStatus = (typeof FINDING_STATUSES)[number]

/** Explicit objective outcome stamped when an engagement closes. */
export const GOAL_OUTCOMES = ['achieved', 'partial', 'not-achieved'] as const
export type GoalOutcome = (typeof GOAL_OUTCOMES)[number]

export interface GoalRecord {
  readonly sessionId: string
  readonly objective: string
  /** Audit fact recorded on the engagement and echoed in every report. */
  readonly authorization: string
  readonly scope: string
  readonly createdAt: number
  readonly closedAt?: number | undefined
  /** Verdict stamped by redteam_close_goal. */
  readonly outcome?: GoalOutcome | undefined
  readonly closingSummary?: string | undefined
}

export interface IntentRecord {
  readonly sessionId: string
  readonly goalId: string
  readonly title: string
  readonly rationale: string
  readonly phase?: Phase | undefined
  /** Omitted means `active` — records written before v0.3 stay active. */
  readonly status?: IntentStatus | undefined
  /** Facts this direction was derived from (fact→intent lineage). */
  readonly derivedFrom?: readonly string[] | undefined
  /** Prerequisite intents for multi-step exploit chains. */
  readonly dependsOn?: readonly string[] | undefined
  /** Assets this direction targets — the coverage anchor set. */
  readonly assetIds?: readonly string[] | undefined
  readonly createdAt: number
}

export interface FactRecord {
  readonly sessionId: string
  readonly intentId: string
  readonly detail: string
  readonly kind?: string | undefined
  readonly target?: string | undefined
  /** 0–1 confidence the fact is confirmed; omitted means asserted only. */
  readonly confidence?: number | undefined
  readonly phase?: Phase | undefined
  readonly evidenceIds: readonly string[]
  readonly createdAt: number
}

export interface AssetRecord {
  readonly sessionId: string
  readonly type: string
  readonly value: string
  /** Parent asset id; '' declares a root asset. */
  readonly parentId?: string | undefined
  readonly notes?: string | undefined
  /** Free-form fingerprint labels (service names, components, versions). */
  readonly tags?: readonly string[] | undefined
  readonly createdAt: number
}

export interface FindingRecord {
  readonly sessionId: string
  readonly intentId: string
  readonly title: string
  readonly severity: Severity
  readonly description: string
  /** At least one reproducible step — enforced at write time. */
  readonly reproducibleSteps: readonly string[]
  readonly affectedAssetId?: string | undefined
  readonly evidenceIds: readonly string[]
  readonly remediation?: string | undefined
  /** MITRE ATT&CK technique ids (`T1110`, `T1110.003`). */
  readonly techniqueIds?: readonly string[] | undefined
  /** OWASP Top 10 category ids (`A01:2021`, `A05:2017`). */
  readonly owaspIds?: readonly string[] | undefined
  /** CVSS v3.1 base vector; `cvssScore` is derived at write time. */
  readonly cvssVector?: string | undefined
  readonly cvssScore?: number | undefined
  /** Retest lifecycle; omitted means `confirmed`. */
  readonly status?: FindingStatus | undefined
  readonly resolvedAt?: number | undefined
  readonly retestNotes?: string | undefined
  readonly createdAt: number
}

export interface EvidenceRecord {
  readonly sessionId: string
  readonly kind: EvidenceKind
  readonly label: string
  readonly content: string
  readonly createdAt: number
}

/** Discovered credential material; `secret` never leaves the store unmasked. */
export interface CredentialRecord {
  readonly sessionId: string
  readonly kind: CredentialKind
  readonly secret: string
  readonly username?: string | undefined
  readonly target?: string | undefined
  readonly assetId?: string | undefined
  readonly status: CredentialStatus
  readonly notes?: string | undefined
  /** Evidence ids backing the current status (how it was verified). */
  readonly evidenceIds?: readonly string[] | undefined
  readonly createdAt: number
}

/** Edge relations derived from record references at read time. */
export type EdgeRelation = 'spawns' | 'yields' | 'derived_from' | 'proves' | 'parent' | 'depends_on'

export interface GraphEdge {
  readonly from: string
  readonly to: string
  readonly relation: EdgeRelation
}

export interface EngagementCounts {
  readonly intents: number
  readonly facts: number
  readonly assets: number
  readonly findings: number
  readonly evidence: number
  readonly credentials: number
}

/** Summary returned by `redteam_state`. */
export interface EngagementState {
  readonly goal: GoalRecord | null
  readonly counts: EngagementCounts
  readonly openIntents: readonly { id: string; title: string }[]
  /** Intent task-tree progress (omitted-status records count as active). */
  readonly progress: { active: number; done: number; blocked: number }
  /** Asset test coverage: assets touched by anchored intents/findings vs not. */
  readonly coverage: { tested: string[]; untested: string[] }
}

/** Windowed view delivered to the Web tab via the session projection. */
export interface RedteamViewNode {
  readonly id: string
  readonly kind: 'goal' | 'intent'
  readonly title: string
  /** Intent lifecycle badge; null on goal nodes and legacy records. */
  readonly status: IntentStatus | null
  /** Assets this intent targets (empty on goal nodes). */
  readonly assetIds: readonly string[]
}

export interface RedteamViewAsset {
  readonly id: string
  readonly type: string
  readonly value: string
  readonly parentId: string | null
  readonly tags: readonly string[]
}

/** Finding summary carried in the projection window (no bodies). */
export interface RedteamViewFinding {
  readonly id: string
  readonly intentId: string
  readonly title: string
  readonly severity: Severity
  readonly cvssScore: number | null
  readonly techniqueIds: readonly string[]
  readonly status: FindingStatus | null
  /** Asset this finding was proven against, when registered. */
  readonly affectedAssetId: string | null
}

/** Credential as seen by the Web tab — masked, never the raw secret. */
export interface RedteamViewCredential {
  readonly id: string
  readonly kind: CredentialKind
  readonly username: string | null
  readonly target: string | null
  readonly assetId: string | null
  readonly status: CredentialStatus
}

export interface RedteamProjection {
  readonly goal: {
    objective: string
    authorization: string
    outcome: GoalOutcome | null
  } | null
  readonly nodes: readonly RedteamViewNode[]
  readonly assets: readonly RedteamViewAsset[]
  readonly findings: readonly RedteamViewFinding[]
  readonly credentials: readonly RedteamViewCredential[]
  readonly edges: readonly GraphEdge[]
  readonly counts: EngagementCounts
}
