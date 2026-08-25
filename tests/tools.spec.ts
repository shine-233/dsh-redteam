/**
 * Tool-surface behavior through the fake registry: session requirement,
 * store error propagation, deferContext on markdown report, and the full
 * commander→submit flow.
 */

import { describe, expect, it } from 'vitest'
import { redteamDomainSpec } from '../src/spec.js'
import { EngagementStore } from '../src/store.js'
import { redteamTools } from '../src/tools.js'
import { FakeToolsRegistry, fakeExec } from './fakes/tools.js'
import { MemoryDomainFacility } from './fakes/storage-domain.js'

async function makeRegistry() {
  const facility = new MemoryDomainFacility()
  const domain = await facility.open(redteamDomainSpec as never)
  const store = new EngagementStore(domain as never)
  const registry = new FakeToolsRegistry()
  for (const tool of redteamTools({ store: () => Promise.resolve(store) })) {
    registry.register(tool as never)
  }
  return { store, registry }
}

describe('redteam tools', () => {
  it('rejects writes without an engagement and reports the fix', async () => {
    const { registry } = await makeRegistry()
    const exec = fakeExec()
    const result = await registry.call('redteam_add_intent', { title: 'x' }, exec)
    expect(result.ok).toBe(false)
    expect(result.error!.message).toContain('redteam_add_goal')
  })

  it('requires an owning agent session', async () => {
    const { registry } = await makeRegistry()
    const result = await registry.call('redteam_add_goal', { objective: 'o', authorization: 'a' }, {})
    expect(result.ok).toBe(false)
    expect(result.error!.message).toContain('owning agent session')
  })

  it('runs goal→intent→evidence→finding and renders ids for cross-calls', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()

    const goal = await registry.call(
      'redteam_add_goal',
      { objective: 'perimeter', authorization: 'ROE-1', scope: 'example.net' },
      exec,
    )
    expect(goal.ok).toBe(true)

    const intent = await registry.call('redteam_add_intent', { title: 'edge' }, exec)
    expect(intent.value).toMatchObject({ intentId: 'intent-1' })

    const evidence = await registry.call(
      'redteam_add_evidence',
      { kind: 'command', content: 'dig example.net' },
      exec,
    )
    const finding = await registry.call(
      'redteam_add_finding',
      {
        intentId: 'intent-1',
        title: 'zone transfer',
        severity: 'high',
        description: 'AXFR allowed',
        reproducibleSteps: ['dig axfr example.net'],
        evidenceIds: ['ev-1'],
      },
      exec,
    )
    expect(finding.value).toEqual({ findingId: 'finding-1' })
    expect(evidence.value).toEqual({ evidenceId: 'ev-1' })

    // Empty reproducibleSteps must fail (schema min(1)).
    const badFinding = await registry.call(
      'redteam_add_finding',
      { intentId: 'intent-1', title: 'x', severity: 'low', description: '', reproducibleSteps: [] },
      exec,
    )
    expect(badFinding.ok).toBe(false)

    expect(store.state('session-1').counts.findings).toBe(1)
  })

  it('defers a delivery notice after a markdown report, not json', async () => {
    const { registry } = await makeRegistry()
    const mdExec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'o', authorization: 'a' }, mdExec)
    const md = await registry.call('redteam_report', { format: 'markdown' }, mdExec)
    expect(md.ok).toBe(true)
    expect(mdExec.deferred).toHaveLength(1)

    const jsonExec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'o2', authorization: 'b' }, jsonExec)
    const json = await registry.call('redteam_report', { format: 'json' }, jsonExec)
    expect(json.ok).toBe(true)
    expect(jsonExec.deferred).toHaveLength(0)
    const parsedBody = JSON.parse((json.value as { body: string }).body) as Record<string, unknown>
    expect(parsedBody).toHaveProperty('engagement')
    expect(parsedBody).toHaveProperty('findings')
  })

  it('subagent submit lands in the parent intent with intra-batch refs', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'o', authorization: 'a' }, exec)
    await registry.call('redteam_add_intent', { title: 'anchor' }, exec)

    const submitted = await registry.call(
      'redteam_submit',
      {
        intentId: 'intent-1',
        evidence: [{ kind: 'screenshot', content: '/tmp/shot.png', label: 'login page' }],
        assets: [{ type: 'host', value: '10.0.0.7' }],
        credentials: [{ kind: 'password', secret: 'Sup3rS3cretValue!', username: 'admin', assetId: 'asset-1' }],
        facts: [{ detail: 'ssh exposed', phase: 'exploitation', evidenceIds: ['ev-1'] }],
        findings: [{
          title: 'default creds',
          severity: 'critical',
          description: 'admin:admin works',
          reproducibleSteps: ['ssh admin@10.0.0.7', 'type admin/admin'],
          affectedAssetId: 'asset-1',
          evidenceIds: ['ev-1'],
        }],
      },
      exec,
    )
    expect(submitted.ok).toBe(true)
    expect(submitted.value).toEqual({
      intentId: 'intent-1',
      evidence: ['ev-1'],
      assets: ['asset-1'],
      credentials: ['cred-1'],
      facts: ['fact-1'],
      findings: ['finding-1'],
    })
    expect(exec.events.filter((e) => e.event.startsWith('redteam'))).toHaveLength(0)

    const masked = store.maskedCredentials('session-1')
    expect(masked[0]!.secretMasked).not.toContain('S3cret')
    expect(JSON.stringify(store.projection('session-1').credentials)).not.toContain('S3cret')
  })

  it('derives cvssScore from cvssVector and rejects bad ATT&CK ids', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'o', authorization: 'a' }, exec)
    await registry.call('redteam_add_intent', { title: 'i' }, exec)

    const scored = await registry.call(
      'redteam_add_finding',
      {
        intentId: 'intent-1',
        title: 'rce',
        severity: 'critical',
        description: '',
        reproducibleSteps: ['step'],
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        techniqueIds: ['T1505.003'],
      },
      exec,
    )
    expect(scored.ok).toBe(true)
    const records = store.engagementRecords('session-1')
    expect(records.findings[0]![1].cvssScore).toBe(9.8)
    expect(records.findings[0]![1].techniqueIds).toEqual(['T1505.003'])

    const badTech = await registry.call(
      'redteam_add_finding',
      {
        intentId: 'intent-1', title: 'x', severity: 'low', description: '',
        reproducibleSteps: ['s'], techniqueIds: ['NOT-MITRE'],
      },
      exec,
    )
    expect(badTech.ok).toBe(false)

    const badVector = await registry.call(
      'redteam_add_finding',
      {
        intentId: 'intent-1', title: 'y', severity: 'low', description: '',
        reproducibleSteps: ['s'], cvssVector: 'AV:ZZZ',
      },
      exec,
    )
    expect(badVector.ok).toBe(false)
  })

  it('stores credentials through the dedicated tool with masking at every read surface', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'o', authorization: 'a' }, exec)
    await registry.call('redteam_add_asset', { type: 'host', value: '10.0.0.7' }, exec)

    const cred = await registry.call(
      'redteam_add_credential',
      { kind: 'password', secret: 'Sup3rS3cretValue!', username: 'admin', assetId: 'asset-1' },
      exec,
    )
    expect(cred.ok).toBe(true)
    expect(cred.value).toEqual({ credentialId: 'cred-1' })

    const badRef = await registry.call(
      'redteam_add_credential',
      { kind: 'api-key', secret: 'k', assetId: 'asset-nope' },
      exec,
    )
    expect(badRef.ok).toBe(false)

    const masked = store.maskedCredentials('session-1')
    expect(masked[0]!.secretMasked).toBe('Su••••e!')
    expect(masked[0]!).toMatchObject({ username: 'admin', status: 'unverified' })

    const projection = store.projection('session-1')
    expect(projection.credentials[0]).toMatchObject({ id: 'cred-1', username: 'admin' })
    expect(JSON.stringify(projection)).not.toContain('S3cret')
  })
})
