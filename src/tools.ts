/**
 * The eleven model-facing `redteam_*` tools. Every tool resolves the shared
 * {@link EngagementStore} (opened once by the plugin) and maps store
 * failures to thrown errors — the host registry converts those into failure
 * results for the model. `redteam_report` defers a delivery notice after the
 * turn's final result via `deferContext`.
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition, ToolRunContext } from '@deepseek-ai/dsh-tools'
import { randomUUID } from 'node:crypto'
import { ARTIFACT_KINDS, CREDENTIAL_KINDS, CREDENTIAL_STATUSES, DETECTION_OUTCOMES, EVIDENCE_KINDS, FINDING_STATUSES, GOAL_OUTCOMES, HINT_SOURCES, INTENT_STATUSES, IOC_TYPES, PHASES, SAMPLE_KINDS, SCOPE_KINDS, SEVERITIES } from './types.js'
import type { EngagementStore, NewArtifact, NewAsset, NewCredential, NewEvidence, NewFinding, NewFact, NewHint, NewIoc, NewObjective, NewSample, NewScopeEntry, SubmitResult } from './store.js'
import { maskSecret } from './secrets.js'
import { scopeMatches } from './scope.js'

export interface ToolDeps {
  store: () => Promise<EngagementStore>
}

function sessionId(exec: ToolRunContext): string {
  const id = exec.agent?.session.id
  if (id === undefined || id === '') {
    throw new Error('redteam tools require an owning agent session')
  }
  return id
}

type StateView = ReturnType<EngagementStore['state']>
type GraphView = ReturnType<EngagementStore['graph']>
type EngagementsList = ReturnType<EngagementStore['listEngagements']>

// ── schema fragments (schematic; arg types come from generics + tests) ──────

const evidenceItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    kind: { type: 'string', required: true, enum: [...EVIDENCE_KINDS], description: 'Evidence kind.' },
    content: { type: 'string', required: true, description: 'Captured payload verbatim (command line, response excerpt, file path…).' },
    label: { type: 'string', description: 'Short caption shown in views and reports.' },
  },
} as const

const factItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    detail: { type: 'string', required: true, description: 'One confirmed observation.' },
    kind: { type: 'string', description: 'Optional classification (e.g. recon, auth, config).' },
    target: { type: 'string', description: 'What the observation is about (host/url/endpoint).' },
    confidence: { type: 'number', description: '0–1 confirmation level; omit when asserted only.' },
    phase: { type: 'string', enum: [...PHASES], description: 'Kill-chain phase of this observation.' },
    evidenceIds: { type: 'array', items: { type: 'string' }, description: 'Evidence ids minted earlier in this batch.' },
  },
} as const

const assetItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    type: { type: 'string', required: true, description: 'Asset type (host/service/account/domain/app).' },
    value: { type: 'string', required: true, description: 'Asset identifier (ip:host, url, name…).' },
    parentId: { type: 'string', description: "Parent asset id; '' or omitted declares a root asset." },
    notes: { type: 'string', description: 'Free-form context.' },
    tags: { type: 'array', items: { type: 'string' }, description: 'Fingerprint labels (service names, components, versions).' },
  },
} as const

const findingItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    title: { type: 'string', required: true },
    severity: { type: 'string', required: true, enum: [...SEVERITIES] },
    description: { type: 'string', required: true, description: 'Impact-oriented description.' },
    reproducibleSteps: {
      type: 'array', required: true, minItems: 1,
      items: { type: 'string', required: true },
      description: 'At least one concrete reproducible step.',
    },
    affectedAssetId: { type: 'string', description: 'Asset id minted earlier in this batch or before.' },
    evidenceIds: { type: 'array', items: { type: 'string' } },
    remediation: { type: 'string', description: 'Fix suggestion.' },
    techniqueIds: {
      type: 'array', items: { type: 'string' },
      description: "MITRE ATT&CK technique ids, e.g. ['T1110','T1110.003'].",
    },
    owaspIds: {
      type: 'array', items: { type: 'string' },
      description: "OWASP Top 10 categories, e.g. ['A01:2021','A05:2017'].",
    },
    cweIds: {
      type: 'array', items: { type: 'string' },
      description: "CWE weakness ids, e.g. ['CWE-79','CWE-89'].",
    },
    cveIds: {
      type: 'array', items: { type: 'string' },
      description: "CVE references for known vulns, e.g. ['CVE-2024-12345'].",
    },
    detected: {
      type: 'string', enum: [...DETECTION_OUTCOMES],
      description: 'Blue-team feedback (VECTR-style): did defenses notice? undetected/logged/alerted/prevented.',
    },
    cvssVector: {
      type: 'string',
      description: "CVSS v3.1 base vector, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; score derived automatically.",
    },
    duplicateOf: {
      type: 'string',
      description: 'Finding id this duplicates (subagent double-report dedup); the copy stays on record but is marked.',
    },
  },
} as const

const credentialItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    kind: { type: 'string', required: true, enum: [...CREDENTIAL_KINDS], description: 'Credential material kind.' },
    secret: { type: 'string', required: true, description: 'The secret itself (stored; masked in all views and reports).' },
    username: { type: 'string', description: 'Login name if known.' },
    target: { type: 'string', description: 'Where the credential applies (host/service/realm).' },
    assetId: { type: 'string', description: 'Asset id the credential belongs to.' },
    status: { type: 'string', enum: [...CREDENTIAL_STATUSES], description: 'Default unverified.' },
    notes: { type: 'string' },
  },
} as const

const artifactItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    kind: {
      type: 'string', required: true, enum: [...ARTIFACT_KINDS],
      description: 'Deliverable kind: file / screenshot / log / report / exploit / dump / other.',
    },
    location: { type: 'string', required: true, description: 'Path, url, or short identifier of the deliverable.' },
    description: { type: 'string', description: 'What it is and why it matters.' },
    intentId: { type: 'string', description: 'Intent that produced it.' },
    assetId: { type: 'string', description: 'Asset it belongs to.' },
  },
} as const

const sampleItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    kind: {
      type: 'string', required: true, enum: [...SAMPLE_KINDS],
      description: 'Sample kind: binary / document / script / archive / memory-dump / pcap / other.',
    },
    location: { type: 'string', required: true, description: 'Path or url where the sample lives.' },
    sha256: { type: 'string', required: true, description: 'SHA-256 hex digest (64 chars, mandatory custody anchor).' },
    md5: { type: 'string', description: 'MD5 hex digest (32 chars).' },
    sha1: { type: 'string', description: 'SHA-1 hex digest (40 chars).' },
    fileType: { type: 'string', description: "Detected format, e.g. 'PE32 executable'." },
    arch: { type: 'string', description: "Architecture, e.g. 'x86-64'." },
    notes: { type: 'string' },
    intentId: { type: 'string', description: 'Intent that acquired/analyses it.' },
  },
} as const

const iocItems = {
  type: 'object', required: true, additionalProperties: false,
  properties: {
    type: {
      type: 'string', required: true, enum: [...IOC_TYPES],
      description: 'Indicator category: ip / domain / url / hash / mutex / registry / filepath / user-agent / email / other.',
    },
    value: { type: 'string', required: true, description: 'The indicator itself (defang when sharing externally).' },
    context: { type: 'string', description: 'Where/how it was observed.' },
    sampleId: { type: 'string', description: 'Sample it was extracted from.' },
    intentId: { type: 'string', description: 'Intent that observed it.' },
  },
} as const

// ── tool definitions ────────────────────────────────────────────────────────

export function redteamTools(deps: ToolDeps): ToolDefinition[] {
  const withStore = async <A, V>(
    exec: ToolRunContext,
    run: (store: EngagementStore, sid: string, args: A) => Promise<V>,
    args: A,
  ): Promise<V> => {
    const store = await deps.store()
    return run(store, sessionId(exec), args)
  }

  const addGoal = defineTool<{
    objective: string; authorization: string; scope?: string
  }, { goalId: string; superseded: boolean; note: string }>({
    name: 'redteam_add_goal',
    description:
      'Open a red-team engagement for this session: records objective, authorization reference, and scope. Closes any still-open engagement of this session first (nothing is deleted). Required before any other redteam write.',
    parameters: {
      objective: { type: 'string', required: true, description: 'Engagement objective.' },
      authorization: { type: 'string', required: true, description: 'Authorization reference (who approved / written permission).' },
      scope: { type: 'string', description: 'In-scope ranges, domains, applications.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `engagement ${v.goalId} opened${v.superseded ? ' (previous engagement closed)' : ''}` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => {
      const { goalId, superseded } = await store.openGoal(sid, args)
      return { goalId, superseded, note: 'authorization recorded as an audit fact; it does not widen sandbox permissions' }
    }, args),
  })

  const addIntent = defineTool<{
    title: string; rationale?: string; phase?: (typeof PHASES)[number]
    derivedFrom?: string[]; dependsOn?: string[]; assetIds?: string[]
  }, { intentId: string }>({
    name: 'redteam_add_intent',
    description:
      'Declare one exploration intent under the active engagement. Intents are the anchor nodes facts/findings attach to. Anchor to assets with assetIds (drives coverage), cite motivating facts with derivedFrom, and order multi-step chains with dependsOn.',
    parameters: {
      title: { type: 'string', required: true, description: 'Short direction title.' },
      rationale: { type: 'string', description: 'Why this direction matters.' },
      phase: { type: 'string', enum: [...PHASES], description: 'Kill-chain phase this direction serves.' },
      techniqueIds: {
        type: 'array', items: { type: 'string' },
        description: "ATT&CK techniques this direction plans to exercise, e.g. ['T1110'] — feeds the technique coverage summary.",
      },
      derivedFrom: {
        type: 'array', items: { type: 'string' },
        description: "Fact ids this direction was derived from, e.g. ['fact-3'].",
      },
      dependsOn: {
        type: 'array', items: { type: 'string' },
        description: "Prerequisite intent ids for multi-step exploit chains, e.g. ['intent-2'].",
      },
      assetIds: {
        type: 'array', items: { type: 'string' },
        description: "Asset ids this direction targets, e.g. ['asset-1'].",
      },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `intent ${v.intentId} created` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ intentId: await store.addIntent(sid, args) }), args),
  })

  const addEvidence = defineTool<{ kind: NewEvidence['kind']; content: string; label?: string }, { evidenceId: string }>({
    name: 'redteam_add_evidence',
    description:
      'Capture one piece of evidence (executed command, key response excerpt, screenshot path, file path, url, or note). Facts and findings cite these ids.',
    parameters: {
      kind: { type: 'string', required: true, enum: [...EVIDENCE_KINDS] },
      content: { type: 'string', required: true, description: 'Verbatim captured content.' },
      label: { type: 'string' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `evidence ${v.evidenceId} stored` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ evidenceId: await store.addEvidence(sid, args) }), args),
  })

  const addFact = defineTool<NewFact & { intentId: string }, { factId: string }>({
    name: 'redteam_add_fact',
    description:
      'Record one confirmed observation under an intent. Cite evidence ids captured during the engagement.',
    parameters: {
      intentId: { type: 'string', required: true, description: 'Anchor intent id returned by redteam_add_intent.' },
      ...factItems.properties,
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `fact ${v.factId} recorded` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => ({ factId: await store.addFact(sid, a.intentId, a) }), args),
  })

  const addAsset = defineTool<NewAsset, { assetId: string }>({
    name: 'redteam_add_asset',
    description:
      'Register a discovered asset. Root assets pass parentId "" ; children cite their parent id. Findings later cite affectedAssetId.',
    parameters: { ...assetItems.properties },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `asset ${v.assetId} registered` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ assetId: await store.addAsset(sid, args) }), args),
  })

  const addFinding = defineTool<NewFinding & { intentId: string }, { findingId: string }>({
    name: 'redteam_add_finding',
    description:
      'Record one CONFIRMED vulnerability under an intent. At least one reproducible step is mandatory.',
    parameters: {
      intentId: { type: 'string', required: true },
      ...findingItems.properties,
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `finding ${v.findingId} recorded` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => ({ findingId: await store.addFinding(sid, a.intentId, a) }), args),
  })

  const addCredential = defineTool<NewCredential, { credentialId: string }>({
    name: 'redteam_add_credential',
    description:
      'Register discovered credential material (password, hash, api-key, token, ssh-key). Raw secret is stored but every view and report shows it masked. Cite assetId when the credential belongs to a registered asset. Verify later with redteam_update_credential.',
    parameters: { ...credentialItems.properties },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `credential ${v.credentialId} stored (secret masked in views/reports)` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ credentialId: await store.addCredential(sid, args) }), args),
  })

  const addArtifact = defineTool<NewArtifact, { artifactId: string }>({
    name: 'redteam_add_artifact',
    description:
      'Register a deliverable produced by the engagement: loot file, saved screenshot, log, report draft, exploit script, data dump. Distinct from evidence — artifacts are outputs of the work; evidence backs claims about it.',
    parameters: { ...artifactItems.properties },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `artifact ${v.artifactId} registered` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ artifactId: await store.addArtifact(sid, args) }), args),
  })

  const addHint = defineTool<NewHint, { hintId: string }>({
    name: 'redteam_add_hint',
    description:
      "Record human steering into the engagement blackboard (Cairn's Hint primitive): scope adjustments, priority calls, known credentials, 'skip this host' instructions. Hints are read-side input — quote the user verbatim and attribute the source.",
    parameters: {
      text: { type: 'string', required: true, description: 'The steering statement (verbatim when possible).' },
      source: { type: 'string', required: true, enum: [...HINT_SOURCES], description: 'user = target owner in chat; operator = you/the tester; client = written client instruction.' },
      intentId: { type: 'string', description: 'Intent this steering applies to.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `hint ${v.hintId} recorded` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ hintId: await store.addHint(sid, args) }), args),
  })

  const addSample = defineTool<NewSample, { sampleId: string }>({
    name: 'redteam_add_sample',
    description:
      'Register a binary/document under analysis with chain-of-custody hashes: sha256 mandatory (64 hex), md5/sha1 optional. Sample registry is the malware-analysis convention for reproducible reports.',
    parameters: { ...sampleItems.properties },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `sample ${v.sampleId} registered` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ sampleId: await store.addSample(sid, args) }), args),
  })

  const addIoc = defineTool<NewIoc, { iocId: string }>({
    name: 'redteam_add_ioc',
    description:
      'Record an indicator of compromise observed during analysis or exploration: ip / domain / url / hash / mutex / registry key / filepath / user-agent. Optionally tie to a sample id and an intent.',
    parameters: { ...iocItems.properties },
    output: {
      schema: {},
      render: (a, v) => [{ type: 'text', text: `ioc ${v.iocId} recorded (${(a as NewIoc).type})` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ iocId: await store.addIoc(sid, args) }), args),
  })

  const addObjective = defineTool<NewObjective, { objectiveId: string }>({
    name: 'redteam_add_objective',
    description:
      "Declare one success criterion of the engagement (red-team crown jewel / CTF flag): 'reach domain admin', 'read PII table'. Independent checklist — prove each via redteam_prove_objective.",
    parameters: {
      title: { type: 'string', required: true, description: 'The criterion, outcome-phrased.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `objective ${v.objectiveId} added to checklist` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid) => ({ objectiveId: await store.addObjective(sid, args) }), args),
  })

  const addScopeEntry = defineTool<NewScopeEntry, { scopeId: string; violations: number }>({
    name: 'redteam_add_scope',
    description:
      "Register one structured authorization-boundary entry: kind=in ('*.example.net', '10.0.0.0/24 note: internal range') or kind=out ('prod-db.example.net'). Assets/findings/IOCs are then judged against the registry — out-of-scope hits and unscoped targets surface in redteam_state, the Web 统计 tab and every report.",
    parameters: {
      kind: { type: 'string', required: true, enum: [...SCOPE_KINDS], description: "'in' allows, 'out' forbids." },
      value: { type: 'string', required: true, description: 'Target pattern: host/domain/ip/url.' },
      note: { type: 'string', description: 'Why this boundary exists (ROE clause reference).' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{
        type: 'text',
        text: v.violations > 0
          ? `scope ${v.scopeId} registered — ⚠ ${v.violations} existing record(s) now violate it`
          : `scope ${v.scopeId} registered, no violations`,
      }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const scopeId = await store.addScopeEntry(sid, a)
      return { scopeId, violations: store.scopeIssues(sid).length }
    }, args),
  })

  const proveObjective = defineTool<{
    objectiveId: string; proven?: boolean; evidenceIds?: string[]
  }, { objectiveId: string; provenAt: number | null }>({
    name: 'redteam_prove_objective',
    description:
      'Mark a checklist criterion as achieved (or retract with proven=false). Cite evidenceIds proving it — the report checklist shows proof timestamps.',
    parameters: {
      objectiveId: { type: 'string', required: true },
      proven: { type: 'boolean', description: 'Default true; false retracts.' },
      evidenceIds: { type: 'array', items: { type: 'string' }, description: 'Evidence backing the proof.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `objective ${v.objectiveId} → ${v.provenAt !== null ? 'proven' : 'retracted'}` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const updated = await store.proveObjective(sid, a.objectiveId, a)
      return { objectiveId: updated.id, provenAt: updated.provenAt ?? null }
    }, args),
  })

  const updateIntent = defineTool<{
    intentId: string; status?: (typeof INTENT_STATUSES)[number]; title?: string; rationale?: string
  }, { intentId: string; status: string }>({
    name: 'redteam_update_intent',
    description:
      'Move an intent through the task tree: status active→done (verified direction) or blocked (needs decision/access), optionally retitle. Keeps the engagement progress board truthful.',
    parameters: {
      intentId: { type: 'string', required: true, description: 'Intent id to update.' },
      status: { type: 'string', enum: [...INTENT_STATUSES], description: 'New lifecycle state.' },
      title: { type: 'string' },
      rationale: { type: 'string' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `intent ${v.intentId} → ${v.status}` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const updated = await store.updateIntent(sid, a.intentId, a)
      return { intentId: updated.id, status: updated.status ?? 'active' }
    }, args),
  })

  const retestFinding = defineTool<{
    findingId: string; outcome: 'fixed' | 'still-vulnerable'; notes?: string
  }, { findingId: string; status: string }>({
    name: 'redteam_retest_finding',
    description:
      'Record a retest outcome for one finding after remediation: fixed stamps the resolution time; still-vulnerable returns it to confirmed with the latest retest note.',
    parameters: {
      findingId: { type: 'string', required: true },
      outcome: { type: 'string', required: true, enum: ['fixed', 'still-vulnerable'] },
      notes: { type: 'string', description: 'Retest observation (what was tried this round).' },
      detected: { type: 'string', enum: [...DETECTION_OUTCOMES], description: 'Blue-team feedback learned during the action.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `finding ${v.findingId} retest → ${v.status}` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const updated = await store.retestFinding(sid, a.findingId, a)
      return { findingId: updated.id, status: updated.status ?? 'confirmed' }
    }, args),
  })

  const updateCredential = defineTool<{
    credentialId: string; status: (typeof CREDENTIAL_STATUSES)[number]; evidenceIds?: string[]
  }, { credentialId: string; status: string }>({
    name: 'redteam_update_credential',
    description:
      'Verify one credential: valid (worked against its target), invalid, or back to unverified. Cite evidenceIds proving the verification attempt.',
    parameters: {
      credentialId: { type: 'string', required: true },
      status: { type: 'string', required: true, enum: [...CREDENTIAL_STATUSES] },
      evidenceIds: { type: 'array', items: { type: 'string' }, description: 'Evidence backing the new status.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `credential ${v.credentialId} → ${v.status}` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const updated = await store.updateCredential(sid, a.credentialId, a)
      return { credentialId: updated.id, status: updated.status }
    }, args),
  })

  const closeGoal = defineTool<{
    outcome: (typeof GOAL_OUTCOMES)[number]; summary?: string
  }, { goalId: string; outcome: string }>({
    name: 'redteam_close_goal',
    description:
      'Close the active engagement with an explicit verdict: achieved / partial / not-achieved plus a closing summary. Prefer this over opening a new goal when the engagement simply ends — the verdict lands in the report header and the history list.',
    parameters: {
      outcome: { type: 'string', required: true, enum: [...GOAL_OUTCOMES] },
      summary: { type: 'string', description: 'One-paragraph closing summary.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `engagement ${v.goalId} closed — outcome: ${v.outcome}` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => await store.closeGoal(sid, a), args),
  })

  const submit = defineTool<{
    intentId: string; evidence?: NewEvidence[]; facts?: NewFact[]; assets?: NewAsset[]
    findings?: NewFinding[]; credentials?: NewCredential[]; artifacts?: NewArtifact[]
    samples?: NewSample[]; iocs?: NewIoc[]
  }, SubmitResult>({
    name: 'redteam_submit',
    description:
      'Batch-write confirmed results to one parent intent (subagent entry point). Within one batch: evidence mints first, then assets, credentials and artifacts; facts/findings may cite fresh evidenceIds and asset ids. Never resubmit duplicates.',
    parameters: {
      intentId: { type: 'string', required: true, description: 'Parent intent id assigned by the commander.' },
      evidence: { type: 'array', items: evidenceItems, description: 'New evidence created before facts/findings.' },
      facts: { type: 'array', items: factItems },
      assets: { type: 'array', items: assetItems },
      credentials: { type: 'array', items: credentialItems },
      artifacts: { type: 'array', items: artifactItems },
      samples: { type: 'array', items: sampleItems },
      iocs: { type: 'array', items: iocItems },
      findings: { type: 'array', items: findingItems },
    },
    output: {
      schema: {},
      render: (_a, v) => [{
        type: 'text',
        text: `submitted → evidence ${v.evidence.length}, assets ${v.assets.length}, credentials ${v.credentials.length}, artifacts ${v.artifacts.length}, samples ${v.samples.length}, iocs ${v.iocs.length}, facts ${v.facts.length}, findings ${v.findings.length}`,
      }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => await store.submit(sid, a), args),
  })

  const state = defineTool<Record<string, never>, StateView>({
    name: 'redteam_state',
    description: 'Current engagement summary: active goal, record counts, open intents, coverage/technique gaps, credential reuse, and suggested next steps.',
    parameters: {},
    output: {
      schema: {},
      render: (_a, v) => [{
        type: 'text',
        text: JSON.stringify({
          counts: v.counts,
          progress: v.progress,
          coverage: { tested: v.coverage.tested.length, untested: v.coverage.untested },
          credentialReuse: v.credentialReuse,
          nextSteps: v.nextSteps,
        }),
      }],
    },
    execute: (_args, exec) => withStore(exec, async (store, sid) => await store.state(sid), {} as Record<string, never>),
  })

  const graph = defineTool<Record<string, never>, GraphView>({
    name: 'redteam_graph',
    description:
      'Full engagement graph: nodes (goal/intents), assets, derived edges (spawns/yields/proves/parent), counts.',
    parameters: {},
    output: { schema: {}, render: (_a, v) => [{ type: 'text', text: `${v.nodes.length} nodes, ${v.edges.length} edges` }] },
    execute: (_args, exec) => withStore(exec, async (store, sid) => await store.graph(sid), {} as Record<string, never>),
  })

  const report = defineTool<{
    format?: 'markdown' | 'json' | 'sarif' | 'navlayer' | 'stix' | 'taxii' | 'ioc-csv' | 'html'
    includeEvidence?: boolean
  }, { format: string; body: string }>({
    name: 'redteam_report',
    description:
      'Render the engagement report for the current engagement (open or just closed). format=markdown (default) for humans, html for a styled standalone page, json for machines, sarif for GitHub/GitLab code-scanning ingestion, navlayer for MITRE ATT&CK Navigator layers, stix for a STIX 2.1 bundle, taxii for the TAXII 2.1 collection envelope around those objects, ioc-csv for spreadsheet-friendly IOC rows; includeEvidence embeds raw evidence content in markdown/html.',
    parameters: {
      format: { type: 'string', enum: ['markdown', 'json', 'sarif', 'navlayer', 'stix', 'taxii', 'ioc-csv', 'html'], description: 'Default markdown.' },
      includeEvidence: { type: 'boolean', description: 'Markdown/html only: append raw evidence appendix.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `report rendered (${v.format}), ${v.body.length} chars — deliver via conversation or save to a file` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const format = a.format ?? 'markdown'
      const body = format === 'json'
        ? JSON.stringify(await jsonReport(store, sid), null, 2)
        : format === 'sarif'
          ? await sarifReport(store, sid)
          : format === 'navlayer'
            ? await navLayerReport(store, sid)
            : format === 'stix'
              ? await stixReport(store, sid)
              : format === 'taxii'
                ? await taxiiReport(store, sid)
                : format === 'ioc-csv'
                  ? await iocCsvReport(store, sid)
                  : format === 'html'
                    ? await htmlReport(store, sid, a.includeEvidence ?? false)
                    : await markdownReport(store, sid, a.includeEvidence ?? false)
      if (format === 'markdown') exec.deferContext(reportDeferredNotice())
      return { format, body }
    }, args),
  })

  const engagements = defineTool<Record<string, never>, { length: number }>({
    name: 'redteam_engagements',
    description:
      'List every engagement ever recorded on this deployment (all sessions), newest first, with per-engagement counts.',
    parameters: {},
    output: { schema: {}, render: (_a, v) => [{ type: 'text', text: `${v.length} engagements listed (newest first)` }] },
    execute: (_args, exec) => withStore(exec, async (store) => await store.listEngagements() as unknown as { length: number }, {} as Record<string, never>),
  })

  return [
    addGoal, addIntent, addEvidence, addFact, addAsset, addFinding,
    addCredential, addArtifact, addHint, addSample, addIoc, addObjective,
    addScopeEntry,
    proveObjective, updateIntent, retestFinding, updateCredential, closeGoal,
    submit, state, graph, report, engagements,
  ]
}

function reportDeferredNotice(): { content: { type: 'text'; text: string }[] } {
  return {
    content: [{
      type: 'text',
      text: 'Markdown report exported. Offer the user the Web 报告 tab or ask whether to save it into the workspace as a file.',
    }],
  }
}

async function jsonReport(store: import('./store.js').EngagementStore, sid: string): Promise<unknown> {
  const records = store.engagementRecords(sid)
  const evById = new Map(records.evidence)
  return {
    generatedAt: new Date().toISOString(),
    engagement: records.goal,
    counts: store.counts(sid),
    intents: Object.fromEntries(records.intents),
    facts: Object.fromEntries(records.facts),
    assets: Object.fromEntries(records.assets),
    findings: Object.fromEntries(records.findings),
    evidence: Object.fromEntries([...evById].map(([id, e]) => [id, e])),
    credentials: store.maskedCredentials(sid),
    artifacts: Object.fromEntries(records.artifacts),
    hints: Object.fromEntries(records.hints),
    samples: Object.fromEntries(records.samples),
    iocs: Object.fromEntries(records.iocs),
    objectives: store.state(sid).objectiveProgress,
    scopeEntries: Object.fromEntries(records.scopeEntries),
    scopeViolations: store.state(sid).scope.violations,
  }
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/** SARIF level + GitHub security-severity fallback per finding severity. */
const SEV_TO_SARIF: Record<string, { level: 'error' | 'warning' | 'note'; severity: string }> = {
  critical: { level: 'error', severity: '9.5' },
  high: { level: 'error', severity: '7.5' },
  medium: { level: 'warning', severity: '4.5' },
  low: { level: 'note', severity: '2.5' },
  info: { level: 'note', severity: '0.0' },
}

/**
 * Minimal valid SARIF 2.1.0 run: one rule per finding (id-keyed), CVSS-backed
 * `security-severity` so GitHub raises the right alert severity, and
 * ATT&CK/OWASP ids as tags.
 */
async function sarifReport(store: import('./store.js').EngagementStore, sid: string): Promise<string> {
  const r = store.engagementRecords(sid)
  const sorted = [...r.findings].sort((a, b) =>
    (SEV_ORDER[a[1].severity] ?? 9) - (SEV_ORDER[b[1].severity] ?? 9))
  const goal = r.goal
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dsh-redteam',
          informationUri: 'https://github.com/shine-233/dsh-redteam',
          rules: sorted.map(([id, f]) => ({
            id,
            shortDescription: { text: f.title },
            defaultConfiguration: { level: SEV_TO_SARIF[f.severity]?.level ?? 'note' },
            properties: {
              ...(f.cvssScore !== undefined ? { 'security-severity': f.cvssScore.toFixed(1) } : {}),
              tags: [...(f.techniqueIds ?? []), ...(f.owaspIds ?? []), ...(f.cweIds ?? []), ...(f.cveIds ?? [])],
              ...(goal !== null ? { authorization: goal.authorization } : {}),
            },
          })),
        },
      },
      results: sorted.map(([id, f]) => ({
        ruleId: id,
        level: SEV_TO_SARIF[f.severity]?.level ?? 'note',
        message: {
          text: [
            `[${f.severity.toUpperCase()}] ${f.title}`,
            f.description,
            'Reproduction:',
            ...f.reproducibleSteps.map((s, i) => `${i + 1}. ${s}`),
          ].filter((part) => part !== '').join('\n'),
        },
        properties: {
          'security-severity': f.cvssScore?.toFixed(1) ?? SEV_TO_SARIF[f.severity]?.severity ?? '0.0',
          intentId: f.intentId,
          ...(f.affectedAssetId !== undefined ? { affectedAssetId: f.affectedAssetId } : {}),
          ...(f.status === 'fixed' ? { retestStatus: 'fixed' } : {}),
          ...(f.detected !== undefined ? { detectionOutcome: f.detected } : {}),
        },
        partialFingerprints: { 'redteamFindingId/v1': id },
      })),
    }],
  }
  return JSON.stringify(sarif, null, 2)
}

/**
 * ATT&CK Navigator layer (format v4.5): proven techniques score 100 (green),
 * attempted-only score 50 (amber). Importable via Navigator "Open Existing
 * Layer" or the attack-scripts tooling.
 */
async function navLayerReport(store: import('./store.js').EngagementStore, sid: string): Promise<string> {
  const st = store.state(sid)
  const r = store.engagementRecords(sid)
  const proven = new Set(st.techniques.proven)
  const comments = new Map<string, string[]>()
  for (const [, intent] of r.intents) {
    for (const t of intent.techniqueIds ?? []) {
      const list = comments.get(t) ?? []
      list.push(`${intent.title} (${intent.status ?? 'active'})`)
      comments.set(t, list)
    }
  }
  for (const [, f] of r.findings) {
    for (const t of f.techniqueIds ?? []) {
      const list = comments.get(t) ?? []
      list.push(`proven by ${f.title}`)
      comments.set(t, list)
    }
  }
  const seen = new Set<string>()
  const techniques: { techniqueID: string; score: number; color: string; comment: string }[] = []
  for (const t of st.techniques.attempted) {
    if (seen.has(t)) continue
    seen.add(t)
    techniques.push({
      techniqueID: t,
      score: proven.has(t) ? 100 : 50,
      color: proven.has(t) ? '#7fb069' : '#e0c04e',
      comment: (comments.get(t) ?? []).join('; ').slice(0, 400),
    })
  }
  const goal = r.goal
  const layer = {
    name: goal !== null ? goal.objective.slice(0, 120) : 'dsh-redteam coverage',
    versions: { attack: '18', navigator: '5.2.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: goal !== null ? `Authorization: ${goal.authorization}` : 'Generated by dsh-redteam',
    techniques,
    gradient: { colors: ['#e0c04e', '#7fb069'], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: '证实 / proven', color: '#7fb069' },
      { label: '尝试 / attempted', color: '#e0c04e' },
    ],
    metadata: [
      { name: 'generator', value: 'dsh-redteam' },
      ...(goal !== null ? [{ name: 'authorization', value: goal.authorization }] : []),
    ],
  }
  return JSON.stringify(layer, null, 2)
}

/** STIX pattern for a stored IOC; null when the type has no standard object. */
function stixPattern(type: string, value: string): string | null {
  switch (type) {
    case 'ip':
      return value.includes(':') ? `[ipv6-addr:value = '${value}']` : `[ipv4-addr:value = '${value}']`
    case 'domain':
      return `[domain-name:value = '${value}']`
    case 'url':
      return `[url:value = '${value}']`
    case 'hash': {
      const algo = value.length === 64 ? 'SHA-256' : value.length === 40 ? 'SHA-1' : value.length === 32 ? 'MD5' : null
      return algo === null ? null : `[file:hashes.'${algo}' = '${value}']`
    }
    case 'email':
      return `[email-addr:value = '${value}']`
    case 'mutex':
      return `[mutex:name = '${value}']`
    case 'registry':
      return `[windows-registry-key:key = '${value}']`
    default:
      return null
  }
}

function stixId(prefix: string): string {
  return `${prefix}--${randomUUID()}`
}

/** Shared STIX 2.1 object builder (identity + vulnerabilities + indicators). */
async function buildStixObjects(
  store: import('./store.js').EngagementStore,
  sid: string,
): Promise<Record<string, unknown>[]> {
  const r = store.engagementRecords(sid)
  const now = new Date()
  const identityId = stixId('identity')
  const identity = {
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now.toISOString(),
    modified: now.toISOString(),
    name: 'dsh-redteam engagement',
    description: r.goal !== null ? `${r.goal.objective} — authorization: ${r.goal.authorization}` : 'dsh-redteam',
    identity_class: 'individual',
  }
  const objects: Record<string, unknown>[] = [identity]
  for (const [, f] of r.findings) {
    const created = new Date(f.createdAt).toISOString()
    objects.push({
      type: 'vulnerability',
      spec_version: '2.1',
      id: stixId('vulnerability'),
      created_by_ref: identityId,
      created,
      modified: created,
      name: f.title.slice(0, 200),
      description: [f.description, ...f.reproducibleSteps.map((s, i) => `${i + 1}. ${s}`)].join('\n'),
      labels: [`severity:${f.severity}`, ...(f.status === 'fixed' ? ['retest:fixed'] : [])],
      ...(f.cveIds !== undefined && f.cveIds.length > 0
        ? { external_references: f.cveIds.map((cve) => ({ source_name: 'cve', external_id: cve })) }
        : {}),
      custom_properties: {
        ...(f.cvssScore !== undefined ? { x_dsh_cvss_score: f.cvssScore } : {}),
        ...(f.detected !== undefined ? { x_dsh_detection: f.detected } : {}),
      },
    })
  }
  for (const [, ioc] of r.iocs) {
    const pattern = stixPattern(ioc.type, ioc.value)
    if (pattern === null) continue
    const created = new Date(ioc.createdAt).toISOString()
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: stixId('indicator'),
      created_by_ref: identityId,
      created,
      modified: created,
      name: `${ioc.type}: ${ioc.value.slice(0, 120)}`,
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: created,
    })
  }
  return objects
}

/**
 * STIX 2.1 bundle: one identity, one vulnerability per finding, and one
 * indicator per IOC with a standard capture pattern.
 */
async function stixReport(store: import('./store.js').EngagementStore, sid: string): Promise<string> {
  const bundle = { type: 'bundle', id: stixId('bundle'), objects: await buildStixObjects(store, sid) }
  return JSON.stringify(bundle, null, 2)
}

/**
 * TAXII 2.1 collection-response envelope (`application/taxii+json`) wrapping
 * the same STIX objects — drop-in body for a TAXII collection or for tools
 * that speak the envelope shape (OpenCTI/MISP connectors).
 */
async function taxiiReport(store: import('./store.js').EngagementStore, sid: string): Promise<string> {
  const envelope = { more: false, next: null, data: await buildStixObjects(store, sid) }
  return JSON.stringify(envelope, null, 2)
}

/** CSV escape: quote when the cell contains separator/quote/newline. */
function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value
}

/**
 * Spreadsheet-friendly IOC rows: one line per indicator with sample/intent
 * linkage and timestamps — MISP/Cuckoo extraction workflows.
 */
async function iocCsvReport(store: import('./store.js').EngagementStore, sid: string): Promise<string> {
  const r = store.engagementRecords(sid)
  const lines = ['id,type,value,sample_id,intent_id,created_at,context']
  for (const [id, i] of r.iocs) {
    lines.push([
      id, i.type, i.value, i.sampleId ?? '', i.intentId ?? '',
      new Date(i.createdAt).toISOString(), i.context ?? '',
    ].map(csvCell).join(','))
  }
  return `${lines.join('\n')}\n`
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ff5c5c', high: '#ff9350', medium: '#e0c04e', low: '#7fb069', info: '#8b95a1',
}

function htmlEscape(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/**
 * Standalone HTML report: single self-contained page (inline CSS, no JS,
 * system fonts) mirroring the markdown sections plus animated-free severity
 * bars and a scope-compliance panel. Opens anywhere, prints fine.
 */
async function htmlReport(
  store: import('./store.js').EngagementStore,
  sid: string,
  includeEvidence: boolean,
): Promise<string> {
  const r = store.engagementRecords(sid)
  const st = store.state(sid)
  const c = store.counts(sid)
  const e = htmlEscape
  const bySev = new Map<string, number>()
  for (const [, f] of r.findings) bySev.set(f.severity, (bySev.get(f.severity) ?? 0) + 1)
  const maxSev = Math.max(1, ...[...bySev.values()])
  const totalAssets = st.coverage.tested.length + st.coverage.untested.length
  const covPct = totalAssets > 0 ? Math.round(st.coverage.tested.length / totalAssets * 100) : null

  const sevBars = SEVERITIES.map((s) => {
    const n = bySev.get(s) ?? 0
    return `<div class="bar-row"><span class="bar-label">${s}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.round(n / maxSev * 100)}%;background:${SEV_COLOR[s]}"></div></div><span class="bar-n">${n}</span></div>`
  }).join('')

  const findingsHtml = [...r.findings]
    .sort((a, b) => (SEV_ORDER[a[1].severity] ?? 9) - (SEV_ORDER[b[1].severity] ?? 9))
    .map(([id, f]) => `
      <article class="card finding">
        <header><span class="sev" style="color:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span>
          <strong>${e(f.title)}</strong>
          ${f.status === 'fixed' ? '<span class="tag ok">✅ fixed</span>' : ''}
          ${f.duplicateOf !== undefined ? `<span class="tag">dup of ${e(f.duplicateOf)}</span>` : ''}
          ${f.cvssScore !== undefined ? `<span class="tag">CVSS ${f.cvssScore}</span>` : ''}
        </header>
        <p class="desc">${e(f.description)}</p>
        <ol class="steps">${f.reproducibleSteps.map((s) => `<li>${e(s)}</li>`).join('')}</ol>
        <p class="meta"><code>${id}</code>${f.affectedAssetId !== undefined ? ` · asset <code>${e(f.affectedAssetId)}</code>` : ''}
          ${(f.techniqueIds ?? []).length > 0 ? ` · ATT&CK ${f.techniqueIds!.map((t) => `<code>${t}</code>`).join(' ')}` : ''}
          ${(f.cveIds ?? []).length > 0 ? ` · ${f.cveIds!.map((c) => `<code>${c}</code>`).join(' ')}` : ''}</p>
        ${f.remediation !== undefined ? `<p class="remediation">修复建议 / Remediation: ${e(f.remediation)}</p>` : ''}
      </article>`).join('')

  const intentBlocks = [...r.intents].map(([id, i]) => {
    const facts = r.facts.filter(([, f]) => f.intentId === id)
    return `<section class="intent">
      <h4><code>${id}</code> ${e(i.title)}${i.status !== undefined && i.status !== 'active' ? ` <span class="tag">${i.status}</span>` : ''}
        ${i.phase !== undefined ? `<span class="tag">${i.phase}</span>` : ''}</h4>
      ${i.rationale !== '' ? `<p class="meta">${e(i.rationale)}</p>` : ''}
      ${facts.length > 0 ? `<ul class="facts">${facts.map(([fid, f]) => `<li><code>${fid}</code> ${e(f.detail.slice(0, 220))}</li>`).join('')}</ul>` : ''}
    </section>`
  }).join('')

  const table = (headers: string[], rows: string[][]): string => rows.length === 0 ? '<p class="none">(none)</p>' : `
    <table><thead><tr>${headers.map((x) => `<th>${x}</th>`).join('')}</tr></thead>
    <tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody></table>`

  const reuseRows = st.credentialReuse.map((g) => [`<code>${e(g.mask)}</code>`, g.kinds.join(', '), g.targets.map((t) => `<code>${e(t)}</code>`).join(', ')])
  const issueRows = st.scope.violations.map((v) => [
    `<code>${e(v.recordId)}</code>`, v.recordKind, `<code>${e(v.value)}</code>`,
    v.reason === 'out-of-scope' ? `<span class="bad">out-of-scope → ${e(v.matched)}</span>` : '<span class="warn">unscoped</span>',
  ])

  const timeline = (() => {
    type Entry = { at: number; line: string }
    const t: Entry[] = []
    for (const [id, i] of r.intents) t.push({ at: i.createdAt, line: `${id} 意图 — ${i.title}` })
    for (const [id, a] of r.assets) t.push({ at: a.createdAt, line: `${id} 资产 — ${a.type} ${a.value}` })
    for (const [id, cr] of r.credentials) t.push({ at: cr.createdAt, line: `${id} 凭据 — ${cr.kind} (${maskSecret(cr.secret)})` })
    for (const [id, sp] of r.samples) t.push({ at: sp.createdAt, line: `${id} 样本 — ${sp.sha256.slice(0, 16)}…` })
    for (const [id, i] of r.iocs) t.push({ at: i.createdAt, line: `${id} IOC [${i.type}] — ${i.value}` })
    for (const [id, f] of r.findings) t.push({ at: f.createdAt, line: `${id} 漏洞 [${f.severity.toUpperCase()}] — ${f.title}` })
    t.sort((a, b) => a.at - b.at)
    return `<ul class="timeline">${t.map((x) => `<li><span class="ts">${new Date(x.at).toISOString()}</span> ${e(x.line)}</li>`).join('') || '<li class="none">(none)</li>'}</ul>`
  })()

  const evidenceHtml = includeEvidence && r.evidence.length > 0
    ? `<section><h3>附录：证据 / Evidence appendix</h3>${r.evidence.map(([id, ev]) => `
        <details><summary><code>${id}</code> ${ev.kind} — ${e(ev.label)}</summary><pre>${e(ev.content.slice(0, 4000))}</pre></details>`).join('')}</section>`
    : ''

  const goalHeader = r.goal === null ? '' : `
    <div class="goal">
      <p><strong>${e(r.goal.objective)}</strong></p>
      <p class="auth">授权 / Authorization: ${e(r.goal.authorization)}${r.goal.scope !== '' ? ` · 范围 / Scope: ${e(r.goal.scope)}` : ''}</p>
      ${r.goal.outcome !== undefined ? `<p class="outcome">${r.goal.outcome === 'achieved' ? '✅' : r.goal.outcome === 'partial' ? '◐' : '✗'} ${r.goal.outcome}</p>` : ''}
      ${r.goal.closingSummary !== undefined ? `<p class="meta">${e(r.goal.closingSummary)}</p>` : ''}
    </div>`

  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>红队报告 / Red-Team Report</title>
<style>
:root { color-scheme: dark; }
* { box-sizing:border-box; }
body { margin:0 auto; max-width:960px; padding:24px 20px 60px; font:14px/1.6 system-ui,"Segoe UI",sans-serif;
  background:#12161b; color:#dbe2ea; }
h1 { font-size:22px; border-bottom:2px solid #2a3138; padding-bottom:10px; }
h2 { font-size:16px; margin-top:34px; color:#aab4bf; letter-spacing:.04em; border-bottom:1px solid #232a31; padding-bottom:6px; }
h3 { font-size:14px; color:#aab4bf; }
h4 { font-size:13px; margin:14px 0 4px; }
code { background:#1b2026; border:1px solid #2a3138; border-radius:4px; padding:0 5px; font-size:12px; word-break:break-all; }
pre { background:#1b2026; border-radius:8px; padding:10px; overflow:auto; }
table { width:100%; border-collapse:collapse; margin:8px 0; font-size:13px; }
th,td { text-align:left; padding:6px 10px; border-bottom:1px solid #232a31; }
th { color:#8b95a1; font-weight:500; }
.goal { border:1px solid #2a3138; border-radius:10px; padding:12px 14px; }
.goal .auth { color:#e0a94e; font-size:12px; }
.goal .outcome { font-weight:700; color:#7fb069; }
.card { border:1px solid #2a3138; border-radius:10px; padding:12px 14px; margin:10px 0; break-inside:avoid; }
.card header { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.sev { font-weight:800; letter-spacing:.06em; }
.tag { background:#1b2026; border:1px solid #2a3138; border-radius:10px; padding:1px 8px; font-size:11px; color:#8b95a1; }
.tag.ok { color:#7fb069; border-color:#4f7a55; }
.desc { white-space:pre-wrap; }
.steps,.facts,.timeline { padding-left:20px; }
.meta { color:#8b95a1; font-size:12px; }
.none { color:#8b95a1; }
.bad { color:#ff5c5c; font-weight:600; } .warn { color:#e0c04e; }
.bar-row { display:flex; align-items:center; gap:10px; margin:5px 0; }
.bar-label { width:70px; color:#8b95a1; text-align:right; }
.bar-track { flex:1; height:9px; background:#1b2026; border-radius:6px; overflow:hidden; }
.bar-fill { height:100%; border-radius:6px; }
.bar-n { width:30px; color:#8b95a1; font-variant-numeric:tabular-nums; }
.chips { display:flex; gap:8px; flex-wrap:wrap; }
.chip { background:#1b2026; border:1px solid #2a3138; border-radius:8px; padding:4px 10px; font-size:12px; color:#aab4bf; }
.chip b { color:#dbe2ea; }
details summary { cursor:pointer; margin:6px 0; }
.ts { color:#8b95a1; font-family:ui-monospace,monospace; font-size:11px; }
footer { margin-top:40px; color:#8b95a1; font-size:11px; }
@media print { body { background:#fff; color:#111; } .card,.goal { border-color:#ccc; } code { background:#eee; } }
</style></head><body>
<h1>红队测试报告 / Red-Team Engagement Report</h1>
${goalHeader}
<h2>执行摘要 / Executive summary</h2>
<p>意图 <b>${c.intents}</b> · 事实 <b>${c.facts}</b> · 资产 <b>${c.assets}</b> · 漏洞 <b>${c.findings}</b> · 凭据 <b>${c.credentials}</b> · IOC <b>${c.iocs}</b></p>
<div class="chips">
  <span class="chip">资产覆盖 <b>${covPct === null ? '—' : `${covPct}%`}</b></span>
  <span class="chip">ATT&CK 证实 <b>${st.techniques.proven.length}</b> / 尝试 ${st.techniques.attempted.length}</span>
  <span class="chip">凭据复用 <b>${st.credentialReuse.length}</b> 组</span>
  <span class="chip">范围问题 <b>${st.scope.violations.length}</b></span>
</div>
${sevBars}
<h2>探索链路 / Exploration chain</h2>
${intentBlocks || '<p class="none">(none)</p>'}
<h2>资产 / Assets</h2>
${table(['id', 'type', 'value', 'parent', 'tags'], r.assets.map(([id, a]) => [`<code>${id}</code>`, a.type, e(a.value), a.parentId ?? '', (a.tags ?? []).join(', ')]))}
<h2>漏洞 / Findings</h2>
${findingsHtml || '<p class="none">(none)</p>'}
<h2>凭据 / Credentials</h2>
${table(['id', 'kind', 'username', 'target', 'status', 'secret'], r.credentials.map(([id, cr]) => [`<code>${id}</code>`, cr.kind, cr.username ?? '', cr.target ?? '', cr.status, maskSecret(cr.secret)]))}
${reuseRows.length > 0 ? `<h3>凭据复用 / Credential reuse</h3>${table(['secret (masked)', 'kinds', 'targets'], reuseRows)}` : ''}
<h2>产物 / Artifacts</h2>
${table(['id', 'kind', 'location'], r.artifacts.map(([id, a]) => [`<code>${id}</code>`, a.kind, e(a.location)]))}
<h2>样本 / Samples</h2>
${table(['id', 'kind', 'location', 'sha256', 'type'], r.samples.map(([id, s]) => [`<code>${id}</code>`, s.kind, e(s.location), `<code>${s.sha256.slice(0, 16)}…</code>`, s.fileType ?? '']))}
<h2>IOC 指标 / Indicators</h2>
${table(['id', 'type', 'value', 'sample'], r.iocs.map(([id, i]) => [`<code>${id}</code>`, i.type, `<code>${e(i.value)}</code>`, i.sampleId ?? '']))}
<h2>目标核对单 / Objectives</h2>
<ul>${r.objectives.map(([id, o]) => `<li>${o.provenAt !== undefined ? '✅' : '⬜'} <code>${id}</code> ${e(o.title)}</li>`).join('') || '<li class="none">(none)</li>'}</ul>
<h2>范围合规 / Scope compliance</h2>
<p class="meta">登记条目 ${st.scope.entries}${issueRows.length > 0 ? ` · 问题 <b class="bad">${issueRows.length}</b>` : ' · 无问题'}</p>
${table(['record', 'kind', 'value', '判定'], issueRows)}
<h2>人工转向 / Human steering</h2>
<ul>${r.hints.map(([id, h]) => `<li><code>${id}</code> [${h.source}] ${e(h.text)}</li>`).join('') || '<li class="none">(none)</li>'}</ul>
<h2>时间线 / Timeline</h2>
${timeline}
${evidenceHtml}
<footer>Generated ${new Date().toISOString()} · dsh-redteam · 记录以本地存储层为准，本页为窗口快照</footer>
</body></html>
`
}

async function markdownReport(
  store: import('./store.js').EngagementStore,
  sid: string,
  includeEvidence: boolean,
): Promise<string> {
  const r = store.engagementRecords(sid)
  const lines: string[] = []
  const now = new Date().toISOString()
  lines.push('# 红队测试报告 / Red-Team Engagement Report')
  lines.push('')
  if (r.goal !== null) {
    lines.push(`- **目标 / Objective**: ${r.goal.objective}`)
    lines.push(`- **授权 / Authorization**: ${r.goal.authorization}`)
    if (r.goal.scope !== '') lines.push(`- **范围 / Scope**: ${r.goal.scope}`)
    lines.push(`- **开始 / Started**: ${new Date(r.goal.createdAt).toISOString()}`)
    if (r.goal.outcome !== undefined) {
      const verdict: Record<string, string> = {
        achieved: '✅ 达成 / ACHIEVED',
        partial: '◐ 部分达成 / PARTIAL',
        'not-achieved': '✗ 未达成 / NOT ACHIEVED',
      }
      lines.push(`- **结论 / Outcome**: ${verdict[r.goal.outcome] ?? r.goal.outcome}`)
    }
    if (r.goal.closingSummary !== undefined) lines.push(`- **收尾摘要 / Closing summary**: ${r.goal.closingSummary}`)
  }
  lines.push(`- **生成 / Generated**: ${now}`)
  lines.push('')

  const c = store.counts(sid)
  const stEarly = store.state(sid)
  lines.push('## 执行摘要 / Executive summary')
  lines.push('')
  const bySeverityEarly = new Map<string, number>()
  for (const [, f] of r.findings) bySeverityEarly.set(f.severity, (bySeverityEarly.get(f.severity) ?? 0) + 1)
  const headline = SEVERITIES
    .map((s) => ({ s, n: bySeverityEarly.get(s) ?? 0 }))
    .find(({ n }) => n > 0)
  if (r.goal !== null && r.goal.outcome !== undefined) {
    const verdict: Record<string, string> = {
      achieved: '目标达成 / objective ACHIEVED',
      partial: '部分达成 / objective PARTIALLY achieved',
      'not-achieved': '未达成 / objective NOT achieved',
    }
    lines.push(verdict[r.goal.outcome] ?? r.goal.outcome)
  }
  lines.push(
    headline === undefined
      ? `本次 engagement 记录了 ${c.intents} 个意图、${c.assets} 个资产，尚未确认漏洞。`
      : `最严重风险 / top risk: ${headline.s.toUpperCase()} × ${headline.n}（共 ${r.findings.length} 个漏洞）。`,
  )
  const totalAssetsEarly = stEarly.coverage.tested.length + stEarly.coverage.untested.length
  if (totalAssetsEarly > 0) {
    lines.push(
      `资产覆盖 / asset coverage: ${Math.round(stEarly.coverage.tested.length / totalAssetsEarly * 100)}%` +
      ` (${stEarly.coverage.tested.length}/${totalAssetsEarly})；ATT&CK 证实 ${stEarly.techniques.proven.length} 项。`,
    )
  }
  if (stEarly.credentialReuse.length > 0) {
    lines.push(`⚠ 凭据复用 / credential reuse: ${stEarly.credentialReuse.length} 组口令材料跨目标复用，建议横向排查。`)
  }
  for (const step of stEarly.nextSteps.slice(0, 3)) {
    lines.push(`- 下一步 / next: ${step}`)
  }
  lines.push('')

  lines.push('## 概览 / Overview')
  lines.push('')
  lines.push(`| intents | facts | assets | findings | evidence | credentials | artifacts | hints | samples | iocs |`)
  lines.push(`|---|---|---|---|---|---|---|---|---|---|`)
  lines.push(`| ${c.intents} | ${c.facts} | ${c.assets} | ${c.findings} | ${c.evidence} | ${c.credentials} | ${c.artifacts} | ${c.hints} |`)
  lines.push('')

  const bySeverity = new Map<string, number>()
  for (const [, f] of r.findings) bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + 1)
  lines.push(
    `严重度分布 / Severity: ` +
    SEVERITIES.map((s) => `${s} ${bySeverity.get(s) ?? 0}`).join(' · '),
  )
  const st = store.state(sid)
  const fixed = r.findings.filter(([, f]) => f.status === 'fixed').length
  lines.push(
    `意图进度 / Intent progress: ${st.progress.done} done · ${st.progress.active} active · ${st.progress.blocked} blocked — 已修复 / fixed findings: ${fixed}/${r.findings.length}`,
  )
  const cov = st.coverage
  const totalAssets = cov.tested.length + cov.untested.length
  if (totalAssets > 0) {
    lines.push(`资产覆盖 / Coverage: ${cov.tested.length}/${totalAssets} tested` +
      (cov.untested.length > 0 ? ` — 未测 / untested: ${cov.untested.join(', ')}` : ''))
  }
  const tech = st.techniques
  if (tech.attempted.length > 0 || tech.proven.length > 0) {
    lines.push(`ATT&CK 覆盖 / Technique coverage: ${tech.proven.length} proven · ${(tech.attempted.length - tech.proven.length)} attempted-only`)
    lines.push(`  已证实 / Proven: ${tech.proven.map((t) => `\`${t}\``).join(', ') || '(none)'}`)
    const onlyAttempted = tech.attempted.filter((t) => !tech.proven.includes(t))
    if (onlyAttempted.length > 0) {
      lines.push(`  仅尝试 / Attempted only: ${onlyAttempted.map((t) => `\`${t}\``).join(', ')}`)
    }
  }
  const detectionCounts = new Map<string, number>()
  for (const [, f] of r.findings) {
    if (f.detected !== undefined) detectionCounts.set(f.detected, (detectionCounts.get(f.detected) ?? 0) + 1)
  }
  const detectedTotal = [...detectionCounts.values()].reduce((a, b) => a + b, 0)
  if (detectedTotal > 0) {
    lines.push(
      `检测反馈 / Detection: ` +
      DETECTION_OUTCOMES.map((d) => `${d} ${detectionCounts.get(d) ?? 0}`).join(' · ') +
      ` — 防御触达率 / noticed: ${Math.round(((detectionCounts.get('alerted') ?? 0) + (detectionCounts.get('prevented') ?? 0)) / detectedTotal * 100)}%`,
    )
  }
  lines.push('')

  lines.push('## 探索链路 / Exploration chain')
  lines.push('')
  for (const [id, intent] of r.intents) {
    const statusTag = intent.status === undefined || intent.status === 'active'
      ? ''
      : ` [${intent.status.toUpperCase()}]`
    lines.push(`### ${id} — ${intent.title}${statusTag}`)
    if (intent.rationale !== '') lines.push('', intent.rationale)
    if ((intent.derivedFrom?.length ?? 0) > 0) {
      lines.push('', `- 派生自 / Derived from: ${intent.derivedFrom!.map((f) => `\`${f}\``).join(', ')}`)
    }
    if ((intent.dependsOn?.length ?? 0) > 0) {
      lines.push(`- 前置步骤 / Depends on: ${intent.dependsOn!.map((i) => `\`${i}\``).join(', ')}`)
    }
    const facts = r.facts.filter(([, f]) => f.intentId === id)
    if (facts.length > 0) {
      lines.push('', '**事实 / Facts**')
      for (const [fid, f] of facts) {
        const conf = f.confidence !== undefined ? ` (confidence ${f.confidence})` : ''
        const refs = f.evidenceIds.length > 0 ? ` 〔${f.evidenceIds.join(', ')}〕` : ''
        lines.push(`- \`${fid}\` ${f.detail}${conf}${refs}`)
      }
    }
    lines.push('')
  }

  lines.push('## 资产 / Assets')
  lines.push('')
  if (r.assets.length === 0) lines.push('(none)')
  else {
    lines.push('| id | type | value | parent | tags |')
    lines.push('|---|---|---|---|---|')
    for (const [id, a] of r.assets) {
      lines.push(`| \`${id}\` | ${a.type} | ${a.value} | ${a.parentId ?? ''} | ${(a.tags ?? []).join(', ')} |`)
    }
  }
  lines.push('')

  lines.push('## 漏洞 / Findings')
  lines.push('')
  if (r.findings.length === 0) lines.push('(none)')
  else {
    const sorted = [...r.findings].sort((a, b) =>
      (SEV_ORDER[a[1].severity] ?? 9) - (SEV_ORDER[b[1].severity] ?? 9))
    for (const [id, f] of sorted) {
      const fixedTag = f.status === 'fixed' ? ' ✅ 已修复 / FIXED' : ''
      const dupTag = f.duplicateOf !== undefined ? ` （重复 / dup of \`${f.duplicateOf}\`）` : ''
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title} (\`${id}\`)${fixedTag}${dupTag}`)
      lines.push('', f.description)
      if (f.affectedAssetId !== undefined) lines.push('', `- 受影响资产 / Affected asset: \`${f.affectedAssetId}\``)
      if (f.cvssVector !== undefined && f.cvssScore !== undefined) {
        lines.push(`- CVSS v3.1: **${f.cvssScore}** \`${f.cvssVector}\``)
      }
      if (f.techniqueIds !== undefined && f.techniqueIds.length > 0) {
        lines.push(`- MITRE ATT&CK: ${f.techniqueIds.map((t) => `\`${t}\``).join(', ')}`)
      }
      if (f.owaspIds !== undefined && f.owaspIds.length > 0) {
        lines.push(`- OWASP Top 10: ${f.owaspIds.join(', ')}`)
      }
      if (f.cweIds !== undefined && f.cweIds.length > 0) {
        lines.push(`- CWE: ${f.cweIds.map((c) => `\`${c}\``).join(', ')}`)
      }
      if (f.detected !== undefined) {
        const detectedTag: Record<string, string> = {
          undetected: '🫥 未被检测',
          logged: '📝 仅日志',
          alerted: '🔔 触发告警',
          prevented: '⛔ 被阻断',
        }
        lines.push(`- 检测反馈 / Detection: ${detectedTag[f.detected] ?? f.detected}`)
      }
      lines.push('', '**复现步骤 / Reproduction**')
      f.reproducibleSteps.forEach((step, i) => lines.push(`${i + 1}. ${step}`))
      if (f.evidenceIds.length > 0) lines.push('', `- 证据 / Evidence: ${f.evidenceIds.map((e) => `\`${e}\``).join(', ')}`)
      if (f.remediation !== undefined) lines.push('', `**修复建议 / Remediation**: ${f.remediation}`)
      if (f.status === 'fixed' && f.resolvedAt !== undefined) {
        lines.push('', `✅ 复测通过 / Retest passed at: ${new Date(f.resolvedAt).toISOString()}`)
      }
      if (f.retestNotes !== undefined && f.retestNotes !== '') {
        lines.push(`最近复测 / Latest retest note: ${f.retestNotes}`)
      }
      lines.push('')
    }
  }

  lines.push('## 凭据 / Credentials')
  lines.push('')
  if (r.credentials.length === 0) lines.push('(none)')
  else {
    lines.push('| id | kind | username | target | asset | status | secret |')
    lines.push('|---|---|---|---|---|---|---|')
    for (const [id, cr] of r.credentials) {
      lines.push(
        `| \`${id}\` | ${cr.kind} | ${cr.username ?? ''} | ${cr.target ?? ''} | ${cr.assetId ?? ''} | ${cr.status} | ${maskSecret(cr.secret)} |`,
      )
    }
  }
  lines.push('')
  const reuse = store.credentialReuse(sid)
  if (reuse.length > 0) {
    lines.push('### 凭据复用 / Credential reuse')
    lines.push('')
    lines.push('| secret (masked) | kinds | targets |')
    lines.push('|---|---|---|')
    for (const g of reuse) {
      lines.push(`| ${g.mask} | ${g.kinds.join(', ')} | ${g.targets.map((t) => `\`${t}\``).join(', ')} |`)
    }
    lines.push('')
  }

  const scopeIssueRows = store.scopeIssues(sid)
  lines.push('## 范围合规 / Scope compliance')
  lines.push('')
  if (r.goal !== null && r.goal.scope !== '') lines.push(`声明范围 / Declared scope: ${r.goal.scope}`)
  if (scopeIssueRows.length === 0) {
    lines.push('(registry empty or no violations — register boundaries via redteam_add_scope)')
  } else {
    lines.push('| record | kind | value | 判定 |')
    lines.push('|---|---|---|---|')
    for (const v of scopeIssueRows) {
      const verdict = v.reason === 'out-of-scope' ? `⛔ 越界 → \`${v.matched}\`` : '⚠ 未在 in-scope 清单'
      lines.push(`| \`${v.recordId}\` | ${v.recordKind} | \`${v.value}\` | ${verdict} |`)
    }
  }
  lines.push('')

  lines.push('## 产物 / Artifacts')
  lines.push('')
  if (r.artifacts.length === 0) lines.push('(none)')
  else {
    lines.push('| id | kind | location | intent | asset | description |')
    lines.push('|---|---|---|---|---|---|')
    for (const [id, a] of r.artifacts) {
      const desc = (a.description ?? '').replace(/\|/g, '\\|').slice(0, 120)
      lines.push(`| \`${id}\` | ${a.kind} | ${a.location} | ${a.intentId ?? ''} | ${a.assetId ?? ''} | ${desc} |`)
    }
  }
  lines.push('')

  lines.push('## 目标核对单 / Objectives checklist')
  lines.push('')
  if (r.objectives.length === 0) lines.push('(none)')
  else for (const [id, o] of r.objectives) {
    lines.push(`- ${o.provenAt !== undefined ? '✅' : '⬜'} \`${id}\` ${o.title}${o.provenAt !== undefined ? ` — proven ${new Date(o.provenAt).toISOString()}` : ''}`)
  }
  lines.push('')

  lines.push('## 样本 / Samples')
  lines.push('')
  if (r.samples.length === 0) lines.push('(none)')
  else {
    lines.push('| id | kind | location | sha256 | md5 | type | arch |')
    lines.push('|---|---|---|---|---|---|---|')
    for (const [id, sp] of r.samples) {
      const md5Cell = sp.md5 !== undefined ? `${sp.md5.slice(0, 8)}…` : ''
      lines.push(`| \`${id}\` | ${sp.kind} | ${sp.location} | \`${sp.sha256.slice(0, 16)}…\` | ${md5Cell} | ${sp.fileType ?? ''} | ${sp.arch ?? ''} |`)
    }
  }
  lines.push('')

  lines.push('## IOC 指标 / Indicators of compromise')
  lines.push('')
  if (r.iocs.length === 0) lines.push('(none)')
  else {
    lines.push('| id | type | value | sample | context |')
    lines.push('|---|---|---|---|---|')
    for (const [id, i] of r.iocs) {
      const ctx = (i.context ?? '').replace(/\|/g, '\\|').slice(0, 100)
      lines.push(`| \`${id}\` | ${i.type} | \`${i.value}\` | ${i.sampleId ?? ''} | ${ctx} |`)
    }
  }
  lines.push('')

  lines.push('## 人工转向 / Human steering')
  lines.push('')
  if (r.hints.length === 0) lines.push('(none)')
  else for (const [id, h] of r.hints) {
    lines.push(`- \`${id}\` [${h.source}] ${h.text}${h.intentId !== undefined ? `（针对 / re: \`${h.intentId}\`）` : ''}`)
  }
  lines.push('')

  lines.push('## 时间线 / Timeline')
  lines.push('')
  type TimelineEntry = { at: number; line: string }
  const timeline: TimelineEntry[] = []
  for (const [id, i] of r.intents) timeline.push({ at: i.createdAt, line: `\`${id}\` 意图 / intent — ${i.title}` })
  for (const [id, a] of r.assets) timeline.push({ at: a.createdAt, line: `\`${id}\` 资产 / asset — ${a.type} ${a.value}` })
  for (const [id, f] of r.facts) timeline.push({ at: f.createdAt, line: `\`${id}\` 事实 / fact — ${f.detail.slice(0, 120)}` })
  for (const [id, cr] of r.credentials) timeline.push({ at: cr.createdAt, line: `\`${id}\` 凭据 / credential — ${cr.kind} (${maskSecret(cr.secret)})` })
  for (const [id, a] of r.artifacts) timeline.push({ at: a.createdAt, line: `\`${id}\` 产物 / artifact — ${a.kind} ${a.location}` })
  for (const [id, sp] of r.samples) timeline.push({ at: sp.createdAt, line: `\`${id}\` 样本 / sample — ${sp.kind} ${sp.sha256.slice(0, 16)}…` })
  for (const [id, i] of r.iocs) timeline.push({ at: i.createdAt, line: `\`${id}\` IOC — [${i.type}] ${i.value}` })
  for (const [id, f] of r.findings) timeline.push({ at: f.createdAt, line: `\`${id}\` 漏洞 / finding — [${f.severity.toUpperCase()}] ${f.title}` })
  timeline.sort((a, b) => a.at - b.at)
  if (timeline.length === 0) lines.push('(none)')
  else for (const entry of timeline) lines.push(`- ${new Date(entry.at).toISOString()} — ${entry.line}`)
  lines.push('')

  if (includeEvidence && r.evidence.length > 0) {
    lines.push('## 附录：证据 / Appendix: Evidence')
    lines.push('')
    for (const [id, e] of r.evidence) {
      lines.push(`### ${id} — ${e.kind}${e.label !== '' ? ` (${e.label})` : ''}`)
      lines.push('', '```', e.content.slice(0, 2000), '```', '')
    }
  }
  return lines.join('\n')
}
