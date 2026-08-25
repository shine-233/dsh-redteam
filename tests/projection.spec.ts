/**
 * Projection fold: deterministic replay parity with the store, rollback on
 * tool failure, and window eviction.
 */

import { describe, expect, it } from 'vitest'
import { fold, redteamProjectionDefinition, type FoldState } from '../src/projection.js'
import { EngagementStore } from '../src/store.js'
import { redteamDomainSpec } from '../src/spec.js'
import { MemoryDomainFacility } from './fakes/storage-domain.js'

const SID = 'sess-1'

function call(seq: number, name: string, args: unknown): Parameters<typeof fold>[1] {
  return {
    type: 'tool/call',
    seq,
    time: seq,
    data: { callId: `c${seq}`, name, arguments: JSON.stringify(args) },
  }
}

function result(seq: number, callId: string, error?: { name: string; code: string }): Parameters<typeof fold>[1] {
  return {
    type: 'tool/result',
    seq,
    time: seq,
    data: {
      message: { source: { callId } },
      ...(error !== undefined ? { error } : {}),
    },
  }
}

function initState(): FoldState {
  return redteamProjectionDefinition.init() as FoldState
}

describe('redteam projection', () => {
  it('replays the same ids the store would mint', async () => {
    const facility = new MemoryDomainFacility()
    const domain = await facility.open(redteamDomainSpec as never)
    const store = new EngagementStore(domain as never)

    await store.openGoal(SID, { objective: 'obj', authorization: 'auth' })
    const intent = await store.addIntent(SID, { title: 'recon' })
    const asset = await store.addAsset(SID, { type: 'domain', value: 'example.net' })
    await store.addFinding(SID, intent, {
      title: 't',
      severity: 'high',
      description: '',
      reproducibleSteps: ['s'],
      affectedAssetId: asset,
    })

    // Same sequence through the pure fold:
    let state = initState()
    state = fold(state, call(1, 'redteam_add_goal', { objective: 'obj', authorization: 'auth' }))
    state = fold(state, result(2, 'c1'))
    state = fold(state, call(3, 'redteam_add_intent', { title: 'recon' }))
    state = fold(state, result(4, 'c3'))
    state = fold(state, call(5, 'redteam_add_asset', { type: 'domain', value: 'example.net' }))
    state = fold(state, result(6, 'c5'))
    state = fold(state, call(7, 'redteam_add_finding', {
      intentId: 'intent-1', title: 't', severity: 'high', description: '', reproducibleSteps: ['s'],
    }))
    state = fold(state, result(8, 'c7'))

    const projectedIds = [
      ...state.nodes.map((n) => n.id),
      ...state.assets.map((a) => a.id),
      ...state.findings.map((f) => f.id),
    ]
    expect(projectedIds).toEqual(['goal-1', intent, asset, 'finding-1'])
    expect(state.edges.map((e) => `${e.from}->${e.to}:${e.relation}`)).toContain(
      `intent-1->finding-1:proves`,
    )
    expect(state.counts).toMatchObject({ intents: 1, assets: 1, findings: 1 })
  })

  it('rolls back a speculative mutation when the tool result fails', () => {
    let state = initState()
    state = fold(state, call(1, 'redteam_add_intent', { title: 'ghost' }))
    state = fold(state, result(2, 'c1', { name: 'Error', code: '' }))
    expect(state.nodes.filter((n) => n.kind === 'intent')).toHaveLength(0)
    expect(Object.keys(state.pending)).toHaveLength(0)
  })

  it('ignores unrelated tools and events by reference stability', () => {
    const state = initState()
    expect(fold(state, call(1, 'read_file', {}))).toBe(state)
    const unrelated = { type: 'turn/start', seq: 9, time: 9, data: {} } as never
    expect(fold(state, unrelated)).toBe(state)
  })

  it('submit folds evidence count and batch items in order', () => {
    let state = initState()
    state = fold(state, call(1, 'redteam_add_goal', { objective: 'o', authorization: 'a' }))
    state = fold(state, call(2, 'redteam_add_intent', { title: 'i' }))
    state = fold(state, call(3, 'redteam_submit', {
      intentId: 'intent-1',
      evidence: [{ kind: 'output', content: 'x' }, { kind: 'note', content: 'y' }],
      assets: [{ type: 'host', value: 'h1' }],
      findings: [{ title: 'f1', severity: 'low', description: '', reproducibleSteps: ['s'] }],
    }))
    expect(state.counts.evidence).toBe(2)
    expect(state.assets.map((a) => a.id)).toEqual(['asset-1'])
    expect(state.findings[0]).toMatchObject({ id: 'finding-1', severity: 'low', intentId: 'intent-1' })
  })

  it('folds credentials without their secrets and derives finding cvss scores', () => {
    let state = initState()
    state = fold(state, call(1, 'redteam_add_goal', { objective: 'o', authorization: 'a' }))
    state = fold(state, result(2, 'c1'))
    const before = state
    state = fold(state, call(3, 'redteam_add_credential', {
      kind: 'password', secret: 'Sup3rS3cretValue!', username: 'admin',
    }))
    expect(state.credentials).toEqual([{
      id: 'cred-1', kind: 'password', username: 'admin', target: null, assetId: null,
      status: 'unverified',
    }])
    // The raw secret never enters the fold state.
    expect(JSON.stringify(state)).not.toContain('S3cret')
    expect(before.credentials).toHaveLength(0)

    state = fold(state, call(4, 'redteam_add_finding', {
      intentId: '', title: 'rce', severity: 'critical', description: '',
      reproducibleSteps: ['s'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      techniqueIds: ['T1505.003', 'bogus'],
    }))
    expect(state.findings[0]).toMatchObject({ cvssScore: 9.8, techniqueIds: ['T1505.003'] })
    expect(state.counts.credentials).toBe(1)
  })

  it('folds lifecycle updates: intent status, finding retest, credential verify', () => {
    let state = initState()
    state = fold(state, call(1, 'redteam_add_goal', { objective: 'o', authorization: 'a' }))
    state = fold(state, call(2, 'redteam_add_intent', { title: 'vpn' }))
    state = fold(state, result(3, 'c2'))
    state = fold(state, call(4, 'redteam_update_intent', { intentId: 'intent-1', status: 'done' }))
    expect(state.nodes.find((n) => n.id === 'intent-1')!.status).toBe('done')

    state = fold(state, call(5, 'redteam_retest_finding', { findingId: 'finding-99', outcome: 'fixed' }))
    // Unknown id → no-op, no crash.
    expect(state.findings).toHaveLength(0)

    state = fold(state, call(6, 'redteam_update_credential', { credentialId: 'cred-1', status: 'valid' }))
    expect(state.credentials).toHaveLength(0)

    // Rollback of an update restores the previous node status.
    const beforeUpdate = state
    state = fold(state, call(7, 'redteam_update_intent', { intentId: 'intent-1', status: 'active' }, ))
    state = fold(state, result(8, 'c7', { name: 'Error', code: '' }))
    expect(state.nodes.find((n) => n.id === 'intent-1')!.status)
      .toBe(beforeUpdate.nodes.find((n) => n.id === 'intent-1')!.status)
  })

  it('folds anchors, lineage edges, chain deps, and the closing verdict', () => {
    let state = initState()
    state = fold(state, call(1, 'redteam_add_goal', { objective: 'o', authorization: 'a' }))
    state = fold(state, call(2, 'redteam_add_asset', { type: 'host', value: 'h1' }))
    state = fold(state, call(3, 'redteam_add_intent', {
      title: 'chain step',
      assetIds: ['asset-1'],
      dependsOn: [],
      derivedFrom: [],
    }))
    expect(state.nodes.find((n) => n.id === 'intent-1')!.assetIds).toEqual(['asset-1'])

    // A second intent deriving from a fact and depending on intent-1.
    state = fold(state, call(4, 'redteam_add_fact', { intentId: 'intent-1', detail: 'd' }))
    state = fold(state, call(5, 'redteam_add_intent', {
      title: 'step two',
      derivedFrom: ['fact-1'],
      dependsOn: ['intent-1'],
      assetIds: ['asset-1'],
    }))
    expect(state.edges).toContainEqual({ from: 'fact-1', to: 'intent-2', relation: 'derived_from' })
    expect(state.edges).toContainEqual({ from: 'intent-1', to: 'intent-2', relation: 'depends_on' })

    state = fold(state, call(6, 'redteam_close_goal', { outcome: 'partial' }))
    expect(state.goal).toMatchObject({ objective: 'o', outcome: 'partial' })
  })

  it('mints distinct credential ids even without edges (regression)', () => {
    let state = initState()
    state = fold(state, call(1, 'redteam_add_goal', { objective: 'o', authorization: 'a' }))
    for (let i = 0; i < 3; i++) {
      state = fold(state, call(2 + i, 'redteam_add_credential', { kind: 'password', secret: `s${i}` }))
    }
    expect(state.credentials.map((c) => c.id)).toEqual(['cred-1', 'cred-2', 'cred-3'])
    // Findings whose intent is absent from the window must still mint fresh ids.
    state = fold(state, call(9, 'redteam_add_finding', {
      intentId: 'intent-gone', title: 't', severity: 'low', description: '', reproducibleSteps: ['s'],
    }))
    expect(state.findings.map((f) => f.id)).toEqual(['finding-1'])
    state = fold(state, call(10, 'redteam_add_finding', {
      intentId: 'intent-gone', title: 'u', severity: 'low', description: '', reproducibleSteps: ['s'],
    }))
    expect(state.findings.map((f) => f.id)).toEqual(['finding-1', 'finding-2'])
  })
})
