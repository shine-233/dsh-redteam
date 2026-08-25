/**
 * The eleven model-facing `redteam_*` tools. Every tool resolves the shared
 * {@link EngagementStore} (opened once by the plugin) and maps store
 * failures to thrown errors — the host registry converts those into failure
 * results for the model. `redteam_report` defers a delivery notice after the
 * turn's final result via `deferContext`.
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition, ToolRunContext } from '@deepseek-ai/dsh-tools'
import { CREDENTIAL_KINDS, CREDENTIAL_STATUSES, EVIDENCE_KINDS, FINDING_STATUSES, GOAL_OUTCOMES, INTENT_STATUSES, PHASES, SEVERITIES } from './types.js'
import type { EngagementStore, NewAsset, NewCredential, NewEvidence, NewFinding, NewFact, SubmitResult } from './store.js'
import { maskSecret } from './secrets.js'

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
    cvssVector: {
      type: 'string',
      description: "CVSS v3.1 base vector, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; score derived automatically.",
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
    findings?: NewFinding[]; credentials?: NewCredential[]
  }, SubmitResult>({
    name: 'redteam_submit',
    description:
      'Batch-write confirmed results to one parent intent (subagent entry point). Within one batch: evidence mints first, then assets and credentials; facts/findings may cite fresh evidenceIds and asset ids. Never resubmit duplicates.',
    parameters: {
      intentId: { type: 'string', required: true, description: 'Parent intent id assigned by the commander.' },
      evidence: { type: 'array', items: evidenceItems, description: 'New evidence created before facts/findings.' },
      facts: { type: 'array', items: factItems },
      assets: { type: 'array', items: assetItems },
      credentials: { type: 'array', items: credentialItems },
      findings: { type: 'array', items: findingItems },
    },
    output: {
      schema: {},
      render: (_a, v) => [{
        type: 'text',
        text: `submitted → evidence ${v.evidence.length}, assets ${v.assets.length}, credentials ${v.credentials.length}, facts ${v.facts.length}, findings ${v.findings.length}`,
      }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => await store.submit(sid, a), args),
  })

  const state = defineTool<Record<string, never>, StateView>({
    name: 'redteam_state',
    description: 'Current engagement summary: active goal, record counts, open intents.',
    parameters: {},
    output: { schema: {}, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.counts) }] },
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
    format?: 'markdown' | 'json'; includeEvidence?: boolean
  }, { format: string; body: string }>({
    name: 'redteam_report',
    description:
      'Render the engagement report for the active session. format=markdown (default) for humans, json for machines; includeEvidence embeds raw evidence content in markdown.',
    parameters: {
      format: { type: 'string', enum: ['markdown', 'json'], description: 'Default markdown.' },
      includeEvidence: { type: 'boolean', description: 'Markdown only: append raw evidence appendix.' },
    },
    output: {
      schema: {},
      render: (_a, v) => [{ type: 'text', text: `report rendered (${v.format}), ${v.body.length} chars — deliver via conversation or save to a file` }],
    },
    execute: (args, exec) => withStore(exec, async (store, sid, a) => {
      const format = a.format ?? 'markdown'
      const body = format === 'json'
        ? JSON.stringify(await jsonReport(store, sid), null, 2)
        : await markdownReport(store, sid, a.includeEvidence ?? false)
      if (format !== 'json') exec.deferContext(reportDeferredNotice())
      return { format, body }
    }, args),
  })

  const engagements = defineTool<Record<string, never>, Record<string, unknown>>({
    name: 'redteam_engagements',
    description:
      'List every engagement ever recorded on this deployment (all sessions), newest first, with per-engagement counts.',
    parameters: {},
    output: { schema: {}, render: () => [{ type: 'text', text: 'engagement history listed' }] },
    execute: (_args, exec) => withStore(exec, async (store) => await store.listEngagements() as unknown as Record<string, unknown>, {} as Record<string, never>),
  })

  return [
    addGoal, addIntent, addEvidence, addFact, addAsset, addFinding,
    addCredential, updateIntent, retestFinding, updateCredential, closeGoal,
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
  }
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

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
  lines.push('## 概览 / Overview')
  lines.push('')
  lines.push(`| intents | facts | assets | findings | evidence | credentials |`)
  lines.push(`|---|---|---|---|---|---|`)
  lines.push(`| ${c.intents} | ${c.facts} | ${c.assets} | ${c.findings} | ${c.evidence} | ${c.credentials} |`)
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
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title} (\`${id}\`)${fixedTag}`)
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

  lines.push('## 时间线 / Timeline')
  lines.push('')
  type TimelineEntry = { at: number; line: string }
  const timeline: TimelineEntry[] = []
  for (const [id, i] of r.intents) timeline.push({ at: i.createdAt, line: `\`${id}\` 意图 / intent — ${i.title}` })
  for (const [id, a] of r.assets) timeline.push({ at: a.createdAt, line: `\`${id}\` 资产 / asset — ${a.type} ${a.value}` })
  for (const [id, f] of r.facts) timeline.push({ at: f.createdAt, line: `\`${id}\` 事实 / fact — ${f.detail.slice(0, 120)}` })
  for (const [id, cr] of r.credentials) timeline.push({ at: cr.createdAt, line: `\`${id}\` 凭据 / credential — ${cr.kind} (${maskSecret(cr.secret)})` })
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
