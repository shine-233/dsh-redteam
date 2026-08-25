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
  AssetRecord,
  CredentialRecord,
  EvidenceRecord,
  FactRecord,
  FindingRecord,
  GoalRecord,
  IntentRecord,
} from './types.js'
import {
  CREDENTIAL_KINDS,
  CREDENTIAL_STATUSES,
  EVIDENCE_KINDS,
  PHASES,
  SEVERITIES,
} from './types.js'
import { ATTACK_TECHNIQUE_RE } from './cvss.js'

export const REDTEAM_DOMAIN_VERSION = 1

const isoTime = z.number().int().nonnegative()

export const goalSchema = z.object({
  sessionId: z.string(),
  objective: z.string().min(1),
  authorization: z.string().min(1),
  scope: z.string(),
  createdAt: isoTime,
  closedAt: isoTime.optional(),
})

export const intentSchema = z.object({
  sessionId: z.string(),
  goalId: z.string(),
  title: z.string().min(1),
  rationale: z.string(),
  phase: z.enum(PHASES).optional(),
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
  cvssVector: z.string().optional(),
  cvssScore: z.number().min(0).max(10).optional(),
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
  },
})
