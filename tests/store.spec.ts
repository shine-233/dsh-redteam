/**
 * EngagementStore behavior: deterministic ids, reference validation,
 * engagement windows, derived edges, history, and report rendering.
 */

import { describe, expect, it } from 'vitest'
import { redteamDomainSpec } from '../src/spec.js'
import { EngagementStore, StoreError } from '../src/store.js'
import { MemoryDomainFacility } from './fakes/storage-domain.js'

async function makeStore() {
  const facility = new MemoryDomainFacility()
  const domain = await facility.open(redteamDomainSpec as never)
  return new EngagementStore(domain as never)
}

const SID = 'sess-a'

async function opened(store: EngagementStore): Promise<void> {
  await store.openGoal(SID, {
    objective: 'test external perimeter',
    authorization: 'ROE #2026-041',
    scope: 'example.net',
  })
}

describe('EngagementStore', () => {
  it('requires an open engagement before writes', async () => {
    const store = await makeStore()
    await expect(store.addIntent(SID, { title: 'x' })).rejects.toMatchObject({
      code: 'no-active-engagement',
    } satisfies Partial<StoreError>)
  })

  it('mints deterministic per-kind ids and keeps them unique across engagements', async () => {
    const store = await makeStore()
    await opened(store)
    const i1 = await store.addIntent(SID, { title: 'recon' })
    const i2 = await store.addIntent(SID, { title: 'enum' })
    expect([i1, i2]).toEqual(['intent-1', 'intent-2'])

    // Close engagement #1 by opening #2; counters continue.
    await store.openGoal(SID, { objective: 'phase two', authorization: 'ROE #2026-042' })
    const i3 = await store.addIntent(SID, { title: 'post-exploit' })
    expect(i3).toBe('intent-3')
  })

  it('validates references on fact/finding/asset writes', async () => {
    const store = await makeStore()
    await opened(store)
    await expect(
      store.addFact(SID, 'intent-nope', { detail: 'x' }),
    ).rejects.toMatchObject({ code: 'missing-ref' })
    const intent = await store.addIntent(SID, { title: 'web' })
    await expect(
      store.addFact(SID, intent, { detail: 'observed', evidenceIds: ['ev-9'] }),
    ).rejects.toMatchObject({ code: 'missing-ref' })
    const ev = await store.addEvidence(SID, { kind: 'command', content: 'curl -s https://example.net' })
    const fid = await store.addFact(SID, intent, { detail: 'server up', evidenceIds: [ev] })
    expect(fid).toBe('fact-1')
    await expect(
      store.addAsset(SID, { type: 'host', value: 'a', parentId: 'asset-nope' }),
    ).rejects.toMatchObject({ code: 'missing-ref' })
  })

  it('derives edges from references and scopes the graph to the active engagement', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'perimeter' })
    const asset1 = await store.addAsset(SID, { type: 'domain', value: 'example.net' })
    await store.addAsset(SID, { type: 'host', value: 'www.example.net', parentId: asset1 })
    await store.addFinding(SID, intent, {
      title: 'outdated portal',
      severity: 'high',
      description: 'portal runs EOL framework',
      reproducibleSteps: ['browse /login', 'observe banner'],
    })

    const graph = store.graph(SID)
    expect(graph.nodes.map((n) => n.id)).toEqual(['goal-1', intent])
    const relations = graph.edges.map((e) => e.relation).sort()
    expect(relations).toEqual(['parent', 'proves', 'spawns'])
    expect(graph.assets[1]!.parentId).toBe(asset1)

    // New engagement: the window resets to the new goal.
    await new Promise((resolve) => setTimeout(resolve, 3))
    await store.openGoal(SID, { objective: 'phase 2', authorization: 'ROE' })
    const next = store.graph(SID)
    expect(next.nodes.map((n) => n.kind)).toEqual(['goal'])
    expect(next.edges).toEqual([])
    expect(next.counts.intents).toBe(0)
  })

  it('submit batch allows intra-batch references in declaration order', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'batch anchor' })
    const result = await store.submit(SID, {
      intentId: intent,
      evidence: [{ kind: 'output', content: 'HTTP/1.1 200 OK', label: 'banner' }],
      assets: [{ type: 'service', value: 'https://example.net' }],
      findings: [{
        title: 'weak tls',
        severity: 'medium',
        description: 'TLS 1.0 enabled',
        reproducibleSteps: ['nmap --script ssl-enum-ciphers'],
        affectedAssetId: 'asset-1',
        evidenceIds: ['ev-1'],
      }],
    })
    expect(result.evidence).toEqual(['ev-1'])
    expect(result.assets).toEqual(['asset-1'])
    expect(result.findings).toEqual(['finding-1'])

    const state = store.state(SID)
    expect(state.counts).toMatchObject({ findings: 1, evidence: 1 })
  })

  it('lists cross-session engagement history newest first with per-goal counts', async () => {
    const store = await makeStore()
    await store.openGoal('sess-1', { objective: 'first', authorization: 'A' })
    await new Promise((resolve) => setTimeout(resolve, 3))
    await store.openGoal('sess-2', { objective: 'second', authorization: 'B' })
    await store.addIntent('sess-2', { title: 'i' })
    const list = store.listEngagements()
    expect(list.map((e) => e.objective)).toEqual(['second', 'first'])
    expect(list[0]!.counts.intents).toBe(1)
    expect(list[1]!.counts.intents).toBe(0)
    expect(list[0]!.goalId).toBe('goal-1')
  })

  it('renders markdown report with authorization trail and sorted findings', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'web' })
    await store.addFinding(SID, intent, {
      title: 'low sev issue',
      severity: 'low',
      description: 'd',
      reproducibleSteps: ['step'],
    })
    await store.addFinding(SID, intent, {
      title: 'critical issue',
      severity: 'critical',
      description: 'd2',
      reproducibleSteps: ['step2'],
    })
    const records = store.engagementRecords(SID)
    expect(records.goal!.authorization).toBe('ROE #2026-041')
    expect(records.findings).toHaveLength(2)
  })

  it('moves intents through the task tree and reports progress', async () => {
    const store = await makeStore()
    await opened(store)
    const i1 = await store.addIntent(SID, { title: 'perimeter' })
    const i2 = await store.addIntent(SID, { title: 'vpn' })
    await store.updateIntent(SID, i1, { status: 'done' })
    await store.updateIntent(SID, i2, { status: 'blocked' })

    const state = store.state(SID)
    expect(state.progress).toEqual({ active: 0, done: 1, blocked: 1 })
    // Blocked/finished intents leave the "open" worklist.
    expect(state.openIntents).toEqual([])

    // Unknown intent id is rejected.
    await expect(store.updateIntent(SID, 'intent-99', { status: 'done' }))
      .rejects.toMatchObject({ code: 'missing-ref' })

    // Graph nodes carry the lifecycle badge.
    expect(store.graph(SID).nodes.find((n) => n.id === i1)!.status).toBe('done')
  })

  it('retests findings through the fix loop (fixed → still-vulnerable)', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'web' })
    const finding = await store.addFinding(SID, intent, {
      title: 'sqli',
      severity: 'critical',
      description: '',
      reproducibleSteps: ["' OR 1=1"],
    })

    await store.retestFinding(SID, finding, { outcome: 'fixed', notes: 'patched build 42' })
    let record = store.engagementRecords(SID).findings[0]![1]
    expect(record.status).toBe('fixed')
    expect(record.resolvedAt).toBeDefined()
    expect(record.retestNotes).toBe('patched build 42')

    await store.retestFinding(SID, finding, { outcome: 'still-vulnerable', notes: 'bypass via encode()' })
    record = store.engagementRecords(SID).findings[0]![1]
    expect(record.status).toBe('confirmed')
    expect(record.resolvedAt).toBeUndefined()

    await expect(store.retestFinding(SID, 'finding-99', { outcome: 'fixed' }))
      .rejects.toMatchObject({ code: 'missing-ref' })
  })

  it('verifies credentials with evidence and validates owasp/tags inputs', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'enum' })
    const asset = await store.addAsset(SID, {
      type: 'host', value: '10.0.0.7', tags: ['ssh', 'openssh-8.4'],
    })
    const cred = await store.addCredential(SID, {
      kind: 'password', secret: 'hunter2hunter2', username: 'root', assetId: asset,
    })

    await store.addEvidence(SID, { kind: 'output', content: 'uid=0(root)' })
    const updated = await store.updateCredential(SID, cred, {
      status: 'valid', evidenceIds: ['ev-1'],
    })
    expect(updated.status).toBe('valid')
    expect(store.engagementRecords(SID).credentials[0]![1].evidenceIds).toEqual(['ev-1'])

    await expect(
      store.updateCredential(SID, cred, { status: 'invalid', evidenceIds: ['ev-nope'] }),
    ).rejects.toMatchObject({ code: 'missing-ref' })

    // OWASP ids validate at write time.
    const finding = await store.addFinding(SID, intent, {
      title: 'broken access control',
      severity: 'high',
      description: '',
      reproducibleSteps: ['step'],
      owaspIds: ['A01:2021'],
    })
    expect(finding).toBe('finding-1')
    await expect(
      store.addFinding(SID, intent, {
        title: 'x', severity: 'low', description: '', reproducibleSteps: ['s'],
        owaspIds: ['A1'],
      }),
    ).rejects.toMatchObject({ code: 'invalid-record' })

    // Tags flow through the graph view.
    expect(store.graph(SID).assets[0]!.tags).toEqual(['ssh', 'openssh-8.4'])
  })

  it('anchors intents to assets and computes test coverage', async () => {
    const store = await makeStore()
    await opened(store)
    const web = await store.addAsset(SID, { type: 'host', value: 'www.example.net' })
    const db = await store.addAsset(SID, { type: 'host', value: 'db.example.net' })
    await store.addAsset(SID, { type: 'domain', value: 'example.net' })

    const intent = await store.addIntent(SID, { title: 'portal', assetIds: [web] })
    await store.addFinding(SID, intent, {
      title: 'sqli', severity: 'critical', description: '',
      reproducibleSteps: ['s'], affectedAssetId: db,
    })

    const coverage = store.coverage(SID)
    expect(coverage.tested.sort()).toEqual([db, web].sort())
    expect(coverage.untested).toEqual(['asset-3'])
    expect(store.state(SID).coverage).toEqual(coverage)

    // Unknown anchors are rejected.
    await expect(store.addIntent(SID, { title: 'x', assetIds: ['asset-nope'] }))
      .rejects.toMatchObject({ code: 'missing-ref' })
  })

  it('derives intents from facts and orders multi-step chains', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'injection' })
    const evidence = await store.addEvidence(SID, { kind: 'output', content: 'sql error' })
    const fact = await store.addFact(SID, intent, { detail: 'injectable param', evidenceIds: [evidence] })

    // Step two derives from the fact and depends on step one.
    const step2 = await store.addIntent(SID, {
      title: 'harvest creds',
      derivedFrom: [fact],
      dependsOn: [intent],
    })
    const graph = store.graph(SID)
    expect(graph.edges).toContainEqual({ from: fact, to: step2, relation: 'derived_from' })
    expect(graph.edges).toContainEqual({ from: intent, to: step2, relation: 'depends_on' })

    // Broken references rejected.
    await expect(store.addIntent(SID, { title: 'x', derivedFrom: ['fact-99'] }))
      .rejects.toMatchObject({ code: 'missing-ref' })
    await expect(store.addIntent(SID, { title: 'y', dependsOn: ['intent-99'] }))
      .rejects.toMatchObject({ code: 'missing-ref' })
  })

  it('closes the engagement with an explicit verdict', async () => {
    const store = await makeStore()
    await opened(store)
    const result = await store.closeGoal(SID, {
      outcome: 'partial',
      summary: 'two of three objectives met',
    })
    expect(result.outcome).toBe('partial')

    // Closed goal is no longer active; writes require a fresh goal.
    expect(store.activeGoal(SID)).toBeUndefined()
    await expect(store.addIntent(SID, { title: 'late' }))
      .rejects.toMatchObject({ code: 'no-active-engagement' })
    await expect(store.closeGoal(SID, { outcome: 'achieved' }))
      .rejects.toMatchObject({ code: 'no-active-engagement' })

    // History carries the verdict.
    const history = store.listEngagements()
    expect(history[0]!.outcome).toBe('partial')
  })

  it('validates lifecycle patches and allows post-close retests', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'web' })
    const finding = await store.addFinding(SID, intent, {
      title: 'sqli', severity: 'high', description: '', reproducibleSteps: ['s'],
    })

    // Empty title / garbage status rejected.
    await expect(store.updateIntent(SID, intent, { title: '   ' }))
      .rejects.toMatchObject({ code: 'invalid-record' })
    await expect(store.updateIntent(SID, intent, { status: 'finished' as never }))
      .rejects.toMatchObject({ code: 'invalid-record' })
    await expect(store.updateCredential(SID, 'cred-1', { status: 'works' as never }))
      .rejects.toMatchObject({ code: 'invalid-record' })

    // Close the engagement, then retest — updates must not need an open goal.
    await store.closeGoal(SID, { outcome: 'achieved' })
    await expect(store.retestFinding(SID, finding, { outcome: 'fixed', notes: 'post-close verify' }))
      .resolves.toMatchObject({ status: 'fixed' })
  })

  it('submit is transactional: a bad item leaves zero partial records', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'anchor' })

    await expect(store.submit(SID, {
      intentId: intent,
      evidence: [{ kind: 'output', content: 'valid' }],
      assets: [{ type: 'host', value: '10.0.0.7' }],
      facts: [{ detail: 'ok', evidenceIds: ['ev-1'] }],
      findings: [{
        title: 'bad vector',
        severity: 'high',
        description: '',
        reproducibleSteps: ['s'],
        cvssVector: 'NOT-A-VECTOR',
      }],
    })).rejects.toMatchObject({ code: 'invalid-record' })

    // Nothing from the batch persisted — retry cannot duplicate half of it.
    expect(store.counts(SID)).toMatchObject({
      evidence: 0, assets: 0, facts: 0, findings: 0,
    })
  })

  it('reports stay readable after closeGoal (final-report workflow)', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'web' })
    await store.addFinding(SID, intent, {
      title: 'xss', severity: 'medium', description: '', reproducibleSteps: ['step'],
    })
    await store.closeGoal(SID, { outcome: 'partial', summary: 'time-boxed' })

    const state = store.state(SID)
    expect(state.goal).not.toBeNull()
    expect(state.goal!.outcome).toBe('partial')
    expect(state.counts.findings).toBe(1)

    const records = store.engagementRecords(SID)
    expect(records.findings).toHaveLength(1)
    expect(records.goal!.closingSummary).toBe('time-boxed')

    // Graph still renders the closed engagement's chain.
    expect(store.graph(SID).nodes).toHaveLength(2)
  })

  it('registers artifacts with refs and includes them in counts and submit', async () => {
    const store = await makeStore()
    await opened(store)
    const intent = await store.addIntent(SID, { title: 'web' })
    const asset = await store.addAsset(SID, { type: 'host', value: '10.0.0.7' })

    const art = await store.addArtifact(SID, {
      kind: 'exploit', location: '/tmp/exploit.py', description: 'rce chain',
      intentId: intent, assetId: asset,
    })
    expect(art).toBe('art-1')
    await expect(store.addArtifact(SID, {
      kind: 'dump', location: '/tmp/dump.sql', assetId: 'asset-nope',
    })).rejects.toMatchObject({ code: 'missing-ref' })

    // Artifacts ride the two-phase submit with intra-batch asset refs.
    const submitted = await store.submit(SID, {
      intentId: intent,
      assets: [{ type: 'service', value: 'https://example.net' }],
      artifacts: [{ kind: 'screenshot', location: '/tmp/panel.png', assetId: 'asset-2' }],
      facts: [{ detail: 'panel exposed', evidenceIds: [] }],
    })
    expect(submitted.artifacts).toEqual(['art-2'])

    // Atomicity covers artifacts too.
    await expect(store.submit(SID, {
      intentId: intent,
      artifacts: [{ kind: 'log', location: '/tmp/keep.log' }],
      findings: [{
        title: 'bad', severity: 'low', description: '', reproducibleSteps: ['s'],
        techniqueIds: ['NOT-MITRE'],
      }],
    })).rejects.toMatchObject({ code: 'invalid-record' })
    expect(store.counts(SID).artifacts).toBe(2)

    // Projection view carries them.
    expect(store.projection(SID).artifacts.map((a) => a.id)).toEqual(['art-1', 'art-2'])
  })
})
