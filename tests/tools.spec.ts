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
      artifacts: [],
      samples: [],
      iocs: [],
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

  it('projects fact summaries and evidence metadata without content bodies', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'facts/evidence view', authorization: 'ROE-16' }, exec)
    await registry.call('redteam_add_intent', { title: 'recon direction' }, exec)
    const ev = await registry.call(
      'redteam_add_evidence',
      { kind: 'command', content: 'SECRET-RESPONSE-BODY do-not-project', label: 'nmap scan' },
      exec,
    )
    expect(ev.value).toEqual({ evidenceId: 'ev-1' })
    await registry.call(
      'redteam_add_fact',
      { intentId: 'intent-1', detail: 'vpn gateway open', phase: 'recon', confidence: 0.9, evidenceIds: ['ev-1'] },
      exec,
    )

    const projection = store.projection('session-1')
    expect(projection.facts[0]).toMatchObject({
      id: 'fact-1',
      intentId: 'intent-1',
      detail: 'vpn gateway open',
      phase: 'recon',
      confidence: 0.9,
      evidenceIds: ['ev-1'],
    })
    expect(projection.evidence[0]).toEqual({ id: 'ev-1', kind: 'command', label: 'nmap scan' })
    // The captured content body never enters the projection.
    expect(JSON.stringify(projection)).not.toContain('SECRET-RESPONSE-BODY')
  })

  it('exports SARIF 2.1.0 with levels and security-severity, no defer', async () => {
    const { registry } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'o', authorization: 'ROE-9' }, exec)
    await registry.call('redteam_add_intent', { title: 'i' }, exec)
    await registry.call('redteam_add_finding', {
      intentId: 'intent-1', title: 'rce', severity: 'critical', description: 'desc',
      reproducibleSteps: ['s1'], cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      techniqueIds: ['T1505.003'],
    }, exec)
    await registry.call('redteam_add_finding', {
      intentId: 'intent-1', title: 'info leak', severity: 'info', description: '',
      reproducibleSteps: ['s2'],
    }, exec)

    const sarif = await registry.call('redteam_report', { format: 'sarif' }, exec)
    expect(sarif.ok).toBe(true)
    expect(exec.deferred).toHaveLength(0) // only markdown defers

    const doc = JSON.parse((sarif.value as { body: string }).body)
    expect(doc.version).toBe('2.1.0')
    expect(doc.runs).toHaveLength(1)
    const run = doc.runs[0]
    expect(run.tool.driver.name).toBe('dsh-redteam')
    expect(run.results).toHaveLength(2)
    // Severity sort: critical first with error level; info last as note.
    expect(run.results[0].level).toBe('error')
    expect(run.results[0].properties['security-severity']).toBe('9.8')
    expect(run.results[1].level).toBe('note')
    expect(run.results[1].properties['security-severity']).toBe('0.0')
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id))
      .toEqual(['finding-1', 'finding-2'])
    // Authorization audit fact rides along in rule properties.
    expect(run.tool.driver.rules[0].properties.authorization).toBe('ROE-9')
  })

  it('exports an ATT&CK Navigator layer scoring proven vs attempted', async () => {
    const { registry } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'nav layer test', authorization: 'ROE-10' }, exec)
    await registry.call('redteam_add_intent', { title: 'bruteforce', techniqueIds: ['T1110.003'] }, exec)
    await registry.call('redteam_add_intent', { title: 'scan', techniqueIds: ['T1046'] }, exec)
    await registry.call('redteam_add_finding', {
      intentId: 'intent-1', title: 'weak ssh', severity: 'high', description: '',
      reproducibleSteps: ['hydra'], techniqueIds: ['T1110.003'],
    }, exec)

    const result = await registry.call('redteam_report', { format: 'navlayer' }, exec)
    expect(result.ok).toBe(true)
    const layer = JSON.parse((result.value as { body: string }).body)
    expect(layer.versions.layer).toBe('4.5')
    expect(layer.domain).toBe('enterprise-attack')
    expect(layer.metadata).toContainEqual({ name: 'authorization', value: 'ROE-10' })
    const byId = new Map<string, { score: number; color: string; comment: string }>(
      layer.techniques.map((t: { techniqueID: string; score: number; color: string; comment: string }) => [t.techniqueID, t]),
    )
    expect(byId.get('T1110.003')).toMatchObject({ score: 100, color: '#7fb069' })
    expect(byId.get('T1046')!.score).toBe(50)
    expect(byId.get('T1110.003')!.comment).toContain('proven by weak ssh')
  })

  it('exports a STIX 2.1 bundle with vulnerabilities and IOC indicators', async () => {
    const { registry } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'stix test', authorization: 'ROE-11' }, exec)
    await registry.call('redteam_add_intent', { title: 'i' }, exec)
    await registry.call('redteam_add_finding', {
      intentId: 'intent-1', title: 'sqli', severity: 'critical', description: 'union sqli',
      reproducibleSteps: ["' UNION SELECT"], cveIds: ['CVE-2024-12345'],
    }, exec)
    await registry.call('redteam_add_ioc', { type: 'ip', value: '203.0.113.9' }, exec)
    await registry.call('redteam_add_ioc', { type: 'domain', value: 'evil.example.net' }, exec)
    await registry.call('redteam_add_ioc', { type: 'hash', value: 'a'.repeat(64) }, exec)
    await registry.call('redteam_add_ioc', { type: 'user-agent', value: 'sqlmap/1.8' }, exec)

    const result = await registry.call('redteam_report', { format: 'stix' }, exec)
    expect(result.ok).toBe(true)
    const bundle = JSON.parse((result.value as { body: string }).body)
    expect(bundle.type).toBe('bundle')
    const types = new Map<string, any[]>()
    for (const obj of bundle.objects) types.set(obj.type, [...(types.get(obj.type) ?? []), obj])
    expect(types.get('identity')).toHaveLength(1)
    const vulns = types.get('vulnerability')!
    expect(vulns).toHaveLength(1)
    expect(vulns[0].labels).toContain('severity:critical')
    expect(vulns[0].external_references).toEqual([{ source_name: 'cve', external_id: 'CVE-2024-12345' }])
    const indicators = types.get('indicator')!
    // ip/domain/hash map to standard STIX objects; user-agent has none and is skipped.
    expect(indicators).toHaveLength(3)
    expect(indicators.map((i: { pattern: string }) => i.pattern)).toEqual([
      "[ipv4-addr:value = '203.0.113.9']",
      "[domain-name:value = 'evil.example.net']",
      `[file:hashes.'SHA-256' = '${'a'.repeat(64)}']`,
    ])
  })

  it('flags credential reuse across targets and suggests next steps', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'reuse', authorization: 'ROE-12' }, exec)
    await registry.call('redteam_add_asset', { type: 'host', value: 'a.corp' }, exec)
    await registry.call('redteam_add_asset', { type: 'host', value: 'b.corp' }, exec)
    await registry.call('redteam_add_asset', { type: 'host', value: 'c.corp' }, exec)
    await registry.call('redteam_add_credential', { kind: 'password', secret: 'P@ssw0rdX', target: 'a.corp' }, exec)
    await registry.call('redteam_add_credential', { kind: 'password', secret: 'P@ssw0rdX', target: 'b.corp' }, exec)
    await registry.call('redteam_add_credential', { kind: 'api-key', secret: 'unique-key-material', target: 'c.corp' }, exec)

    const state = store.state('session-1')
    expect(state.credentialReuse).toEqual([
      { mask: expect.any(String), targets: ['a.corp', 'b.corp'], kinds: ['password'] },
    ])
    expect(state.nextSteps.some((s) => s.includes('credential(s) unverified'))).toBe(true)
    expect(state.nextSteps.some((s) => s.includes('coverage gap'))).toBe(true)
    expect(state.nextSteps.some((s) => s.includes('reused across'))).toBe(true)

    const md = await registry.call('redteam_report', {}, exec)
    expect(md.ok).toBe(true)
    const body = (md.value as { body: string }).body
    expect(body).toContain('执行摘要 / Executive summary')
    expect(body).toContain('凭据复用 / Credential reuse')
    expect(body).not.toContain('P@ssw0rdX')
  })

  it('judges records against the structured scope registry', async () => {
    const { registry, store } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'scoped', authorization: 'ROE-13' }, exec)
    await registry.call('redteam_add_asset', { type: 'host', value: 'app.example.net' }, exec)
    await registry.call('redteam_add_asset', { type: 'host', value: 'prod-db.example.net' }, exec)

    const scope = await registry.call('redteam_add_scope', { kind: 'in', value: 'example.net' }, exec)
    expect(scope.ok).toBe(true)
    // Everything under example.net is in-scope so far.
    expect(store.state('session-1').scope.violations).toEqual([])

    const out = await registry.call(
      'redteam_add_scope',
      { kind: 'out', value: 'prod-db.example.net', note: 'ROE clause 4.2' },
      exec,
    )
    expect(out.ok).toBe(true)
    expect(out.value).toMatchObject({ violations: 1 })

    const issues = store.state('session-1').scope.violations
    expect(issues[0]).toMatchObject({
      recordId: 'asset-2',
      recordKind: 'asset',
      value: 'prod-db.example.net',
      reason: 'out-of-scope',
      matched: 'prod-db.example.net',
    })
    expect(store.state('session-1').nextSteps.some((s) => s.includes('scope violation'))).toBe(true)

    await registry.call('redteam_add_ioc', { type: 'domain', value: 'external.other.org' }, exec)
    // With only an out entry present (plus in), external.other.org matches no
    // in-entry → unscoped.
    const after = store.state('session-1').scope.violations
    expect(after.some((v) => v.recordKind === 'ioc' && v.reason === 'unscoped')).toBe(true)

    const md = await registry.call('redteam_report', {}, exec)
    expect((md.value as { body: string }).body).toContain('范围合规 / Scope compliance')
    expect((md.value as { body: string }).body).toContain('⛔ 越界')

    // Empty scope values are rejected.
    const bad = await registry.call('redteam_add_scope', { kind: 'in', value: '   ' }, exec)
    expect(bad.ok).toBe(false)
  })

  it('exports IOCs as CSV and a TAXII 2.1 envelope', async () => {
    const { registry } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'csv/taxii', authorization: 'ROE-14' }, exec)
    await registry.call('redteam_add_intent', { title: 'i' }, exec)
    await registry.call('redteam_add_ioc', { type: 'ip', value: '198.51.100.7', context: 'c2, beaconing' }, exec)
    await registry.call('redteam_add_ioc', { type: 'url', value: 'http://x.example/p?a=1' }, exec)

    const csv = await registry.call('redteam_report', { format: 'ioc-csv' }, exec)
    expect(csv.ok).toBe(true)
    const csvBody = (csv.value as { body: string }).body
    const csvLines = csvBody.trim().split('\n')
    expect(csvLines[0]).toBe('id,type,value,sample_id,intent_id,created_at,context')
    expect(csvLines).toHaveLength(3)
    expect(csvLines[1]).toContain('198.51.100.7')
    // Context containing a comma must be quoted.
    expect(csvLines[1]).toContain('"c2, beaconing"')

    const taxii = await registry.call('redteam_report', { format: 'taxii' }, exec)
    expect(taxii.ok).toBe(true)
    const envelope = JSON.parse((taxii.value as { body: string }).body)
    expect(envelope.more).toBe(false)
    expect(envelope.data.filter((o: { type: string }) => o.type === 'indicator')).toHaveLength(2)
    expect(envelope.data.some((o: { type: string }) => o.type === 'identity')).toBe(true)
  })

  it('renders a standalone HTML report with all sections', async () => {
    const { registry } = await makeRegistry()
    const exec = fakeExec()
    await registry.call('redteam_add_goal', { objective: 'html page', authorization: 'ROE-15', scope: '*.example.net' }, exec)
    await registry.call('redteam_add_intent', { title: 'probe', phase: 'recon' }, exec)
    await registry.call('redteam_add_finding', {
      intentId: 'intent-1', title: 'open redirect', severity: 'medium', description: '<script> alert',
      reproducibleSteps: ['visit /?next=//evil.example'],
    }, exec)
    const html = await registry.call('redteam_report', { format: 'html', includeEvidence: true }, exec)
    expect(html.ok).toBe(true)
    const body = (html.value as { body: string }).body
    expect(body.startsWith('<!DOCTYPE html>')).toBe(true)
    expect(body).toContain('执行摘要 / Executive summary')
    expect(body).toContain('范围合规 / Scope compliance')
    expect(body).toContain('html page')
    expect(body).toContain('ROE-15')
    // User content is escaped.
    expect(body).toContain('&lt;script&gt;')
    expect(body).not.toContain('<script>')
  })
})
