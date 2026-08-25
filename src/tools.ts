/**
 * The eleven model-facing `redteam_*` tools. Every tool resolves the shared
 * {@link EngagementStore} (opened once by the plugin) and maps store
 * failures to thrown errors — the host registry converts those into failure
 * results for the model. `redteam_report` defers a delivery notice after the
 * turn's final result via `deferContext`.
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition, ToolRunContext } from '@deepseek-ai/dsh-tools'
import { EVIDENCE_KINDS, SEVERITIES } from './types.js'
import type { EngagementStore, NewAsset, NewEvidence, NewFinding, NewFact, SubmitResult } from './store.js'

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

  const addIntent = defineTool<{ title: string; rationale?: string }, { intentId: string }>({
    name: 'redteam_add_intent',
    description:
      'Declare one exploration intent under the active engagement. Intents are the anchor nodes facts/findings attach to.',
    parameters: {
      title: { type: 'string', required: true, description: 'Short direction title.' },
      rationale: { type: 'string', description: 'Why this direction matters.' },
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

  const submit = defineTool<{
    intentId: string; evidence?: NewEvidence[]; facts?: NewFact[]; assets?: NewAsset[]; findings?: NewFinding[]
  }, SubmitResult>({
    name: 'redteam_submit',
    description:
      'Batch-write confirmed results to one parent intent (subagent entry point). Within one batch: evidence mints first, then assets; facts/findings may cite fresh evidenceIds and asset ids. Never resubmit duplicates.',
    parameters: {
      intentId: { type: 'string', required: true, description: 'Parent intent id assigned by the commander.' },
      evidence: { type: 'array', items: evidenceItems, description: 'New evidence created before facts/findings.' },
      facts: { type: 'array', items: factItems },
      assets: { type: 'array', items: assetItems },
      findings: { type: 'array', items: findingItems },
    },
    output: {
      schema: {},
      render: (_a, v) => [{
        type: 'text',
        text: `submitted → evidence ${v.evidence.length}, assets ${v.assets.length}, facts ${v.facts.length}, findings ${v.findings.length}`,
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

  return [addGoal, addIntent, addEvidence, addFact, addAsset, addFinding, submit, state, graph, report, engagements]
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
  }
  lines.push(`- **生成 / Generated**: ${now}`)
  lines.push('')

  const c = store.counts(sid)
  lines.push('## 概览 / Overview')
  lines.push('')
  lines.push(`| intents | facts | assets | findings | evidence |`)
  lines.push(`|---|---|---|---|---|`)
  lines.push(`| ${c.intents} | ${c.facts} | ${c.assets} | ${c.findings} | ${c.evidence} |`)
  lines.push('')

  lines.push('## 探索链路 / Exploration chain')
  lines.push('')
  for (const [id, intent] of r.intents) {
    lines.push(`### ${id} — ${intent.title}`)
    if (intent.rationale !== '') lines.push('', intent.rationale)
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
    lines.push('| id | type | value | parent |')
    lines.push('|---|---|---|---|')
    for (const [id, a] of r.assets) {
      lines.push(`| \`${id}\` | ${a.type} | ${a.value} | ${a.parentId ?? ''} |`)
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
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title} (\`${id}\`)`)
      lines.push('', f.description)
      if (f.affectedAssetId !== undefined) lines.push('', `- 受影响资产 / Affected asset: \`${f.affectedAssetId}\``)
      lines.push('', '**复现步骤 / Reproduction**')
      f.reproducibleSteps.forEach((step, i) => lines.push(`${i + 1}. ${step}`))
      if (f.evidenceIds.length > 0) lines.push('', `- 证据 / Evidence: ${f.evidenceIds.map((e) => `\`${e}\``).join(', ')}`)
      if (f.remediation !== undefined) lines.push('', `**修复建议 / Remediation**: ${f.remediation}`)
      lines.push('')
    }
  }

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
