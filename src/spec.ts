/**
 * The `redteam` storage domain: append-only engagement records over the
 * storage hub. One unit per database, routed to the bundle's sqlite backend;
 * keys are deterministic record ids (`<kind>-<n>`) except goals, keyed by
 * session id. Edge relations are not stored — they derive from references
 * (intent.goalId / fact.intentId / finding.intentId / asset.parentId) at read
 * time, so a record can never dangle without its edge.
 *
 * Version stays at 1 across additive schema evolution (new optional fields,
 * the credentials table): sqlite record tables materialize with CREATE TABLE
 * IF NOT EXISTS at open, and optional columns only ever appear on records
 * written after the upgrade — older databases open unchanged.
 */

import { z } from 'zod'
import { defineDomain, domainTable } from '@deepseek-ai/dsh-storage-domain'
import type {
  ArtifactRecord,
  AssetRecord,
  CredentialRecord,
  EvidenceRecord,
  FactRecord,
  FindingRecord,
  GoalRecord,
  HintRecord,
  IntentRecord,
  IocRecord,
  SampleRecord,
} from './types.js'
import {
  ARTIFACT_KINDS,
  CREDENTIAL_KINDS,
  CREDENTIAL_STATUSES,
  DETECTION_OUTCOMES,
  EVIDENCE_KINDS,
  FINDING_STATUSES,
  GOAL_OUTCOMES,
  HINT_SOURCES,
  INTENT_STATUSES,
  IOC_TYPES,
  PHASES,
  SAMPLE_KINDS,
  SEVERITIES,
} from './types.js'
import { ATTACK_TECHNIQUE_RE, CWE_ID_RE, MD5_RE, OWASP_CATEGORY_RE, SHA1_RE, SHA256_RE } from './cvss.js'

export const REDTEAM_DOMAIN_VERSION = 1

const isoTime = z.number().int().nonnegative()

export const goalSchema = z.object({
  sessionId: z.string(),
  objective: z.string().min(1),
  authorization: z.string().min(1),
  scope: z.string(),
  createdAt: isoTime,
  closedAt: isoTime.optional(),
  outcome: z.enum(GOAL_OUTCOMES).optional(),
  closingSummary: z.string().optional(),
})

export const intentSchema = z.object({
  sessionId: z.string(),
  goalId: z.string(),
  title: z.string().min(1),
  rationale: z.string(),
  phase: z.enum(PHASES).optional(),
  status: z.enum(INTENT_STATUSES).optional(),
  derivedFrom: z.array(z.string()).optional(),
  dependsOn: z.array(z.string()).optional(),
  assetIds: z.array(z.string()).optional(),
  techniqueIds: z.array(z.string().regex(ATTACK_TECHNIQUE_RE)).optional(),
  createdAt: isoTime,
})

export const factSchema = z.object({
  sessionId: z.string(),
  intentId: z.string(),
  detail: z.string().min(1),
  kind: z.string().optional(),
  target: z.string().optional(),
  confidence: z.number().min(0).max(1).optional(),
  phase: z.enum(PHASES).optional(),
  evidenceIds: z.array(z.string()),
  createdAt: isoTime,
})

export const assetSchema = z.object({
  sessionId: z.string(),
  type: z.string().min(1),
  value: z.string().min(1),
  parentId: z.string().optional(),
  notes: z.string().optional(),
  tags: z.array(z.string().min(1)).optional(),
  createdAt: isoTime,
})

export const findingSchema = z.object({
  sessionId: z.string(),
  intentId: z.string(),
  title: z.string().min(1),
  severity: z.enum(SEVERITIES),
  description: z.string(),
  reproducibleSteps: z.array(z.string().min(1)).min(1),
  affectedAssetId: z.string().optional(),
  evidenceIds: z.array(z.string()),
  remediation: z.string().optional(),
  techniqueIds: z.array(z.string().regex(ATTACK_TECHNIQUE_RE)).optional(),
  owaspIds: z.array(z.string().regex(OWASP_CATEGORY_RE)).optional(),
  cweIds: z.array(z.string().regex(CWE_ID_RE)).optional(),
  detected: z.enum(DETECTION_OUTCOMES).optional(),
  cvssVector: z.string().optional(),
  cvssScore: z.number().min(0).max(10).optional(),
  status: z.enum(FINDING_STATUSES).optional(),
  resolvedAt: isoTime.optional(),
  retestNotes: z.string().optional(),
  duplicateOf: z.string().optional(),
  createdAt: isoTime,
})

export const evidenceSchema = z.object({
  sessionId: z.string(),
  kind: z.enum(EVIDENCE_KINDS),
  label: z.string(),
  content: z.string().min(1),
  createdAt: isoTime,
})

export const credentialSchema = z.object({
  sessionId: z.string(),
  kind: z.enum(CREDENTIAL_KINDS),
  secret: z.string().min(1),
  username: z.string().optional(),
  target: z.string().optional(),
  assetId: z.string().optional(),
  status: z.enum(CREDENTIAL_STATUSES),
  notes: z.string().optional(),
  evidenceIds: z.array(z.string()).optional(),
  createdAt: isoTime,
})

export const artifactSchema = z.object({
  sessionId: z.string(),
  kind: z.enum(ARTIFACT_KINDS),
  location: z.string().min(1),
  description: z.string().optional(),
  intentId: z.string().optional(),
  assetId: z.string().optional(),
  createdAt: isoTime,
})

export const hintSchema = z.object({
  sessionId: z.string(),
  text: z.string().min(1),
  source: z.enum(HINT_SOURCES),
  intentId: z.string().optional(),
  createdAt: isoTime,
})

export const sampleSchema = z.object({
  sessionId: z.string(),
  kind: z.enum(SAMPLE_KINDS),
  location: z.string().min(1),
  sha256: z.string().regex(SHA256_RE),
  md5: z.string().regex(MD5_RE).optional(),
  sha1: z.string().regex(SHA1_RE).optional(),
  fileType: z.string().optional(),
  arch: z.string().optional(),
  notes: z.string().optional(),
  intentId: z.string().optional(),
  createdAt: isoTime,
})

export const iocSchema = z.object({
  sessionId: z.string(),
  type: z.enum(IOC_TYPES),
  value: z.string().min(1),
  context: z.string().optional(),
  sampleId: z.string().optional(),
  intentId: z.string().optional(),
  createdAt: isoTime,
})

export const redteamDomainSpec = defineDomain({
  name: 'redteam',
  version: REDTEAM_DOMAIN_VERSION,
  tables: {
    goals: domainTable<string, GoalRecord>(goalSchema),
    intents: domainTable<string, IntentRecord>(intentSchema),
    facts: domainTable<string, FactRecord>(factSchema),
    assets: domainTable<string, AssetRecord>(assetSchema),
    findings: domainTable<string, FindingRecord>(findingSchema),
    evidence: domainTable<string, EvidenceRecord>(evidenceSchema),
    credentials: domainTable<string, CredentialRecord>(credentialSchema),
    artifacts: domainTable<string, ArtifactRecord>(artifactSchema),
    hints: domainTable<string, HintRecord>(hintSchema),
    samples: domainTable<string, SampleRecord>(sampleSchema),
    iocs: domainTable<string, IocRecord>(iocSchema),
  },
})
