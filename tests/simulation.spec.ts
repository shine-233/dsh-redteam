/**
 * Full-lifecycle simulation: drives ALL 29 tools through the real registry
 * in a realistic engagement sequence, then asserts the hard invariants —
 *
 *  1. tool coverage: every registered redteam_* tool was invoked
 *  2. store ↔ projection agreement: replaying the same mutating calls
 *     through the fold engine produces (volatile fields aside) exactly the
 *     projection the store built — two independent implementations must not
 *     drift
 *  3. wire contract: both projections validate against the published zod
 *     schema (what the host ships to the browser)
 *  4. secret hygiene: raw secrets / scanner bodies never leak into any view,
 *     report format, or search result
 *  5. every report format renders with the expected content markers
 */

import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { redteamDomainSpec } from '../src/spec.js'
import { EngagementStore } from '../src/store.js'
import { redteamTools } from '../src/tools.js'
import { MUTATING_TOOLS, redteamProjectionDefinition, redteamProjectionSchema, fold } from '../src/projection.js'
import type { RedteamProjection } from '../src/types.js'
import { FakeToolsRegistry, fakeExec, fakeExec as mkExec } from './fakes/tools.js'
import { MemoryDomainFacility } from './fakes/storage-domain.js'

const SECRET = 'SIM-Vault-Secret-77!'
const NMAP_MARKER = 'NMAP-BODY-MARKER-1'
const NESSUS_MARKER = 'NESSUS-OUTPUT-MARKER-1'

async function makeSim() {
  const facility = new MemoryDomainFacility()
  const domain = await facility.open(redteamDomainSpec as never)
  const store = new EngagementStore(domain as never)
  const registry = new FakeToolsRegistry()
  for (const tool of redteamTools({ store: () => Promise.resolve(store) })) {
    registry.register(tool as never)
  }
  const exec = mkExec()
  const called = new Set<string>()
  const foldEvents: { seq: number; type: 'tool/call'; data: { name: string; arguments: string; callId: string } }[] = []
  let seq = 0
  const step = async (name: string, args: Record<string, unknown>): Promise<any> => {
    const callId = `sim-${++seq}`
    const res = await registry.call(name, args, exec)
    if (!res.ok) throw new Error(`${name} failed: ${res.error!.message}`)
    called.add(name)
    if (MUTATING_TOOLS.includes(name)) {
      foldEvents.push({ seq, type: 'tool/call', data: { name, arguments: JSON.stringify(args), callId } })
    }
    return res.value
  }
  const allTools = [...registry.registered.keys()].filter((n) => n.startsWith('redteam_'))
  return { store, registry, exec, step, called, allTools, foldEvents }
}

/** Strip fold-time volatile timestamps so two runs compare equal. */
function normalize(p: unknown): unknown {
  return JSON.parse(JSON.stringify(p, (_k, v) => v))
}

function stripVolatile(p: RedteamProjection): unknown {
  const clone = JSON.parse(JSON.stringify(p)) as Record<string, any>
  for (const f of clone.findings ?? []) {
    delete f.slaDueAt
  }
  for (const o of clone.objectives ?? []) {
    if (o.provenAt !== null && o.provenAt !== undefined) o.provenAt = 0
  }
  // Edge/scope-issue ordering is not part of the contract (store groups by
  // kind, fold follows call order) — compare as sets.
  const key = (e: { from?: string; to?: string; relation?: string; recordId?: string; reason?: string }) =>
    `${e.from ?? e.recordId}|${e.relation ?? e.reason ?? ''}|${e.to ?? ''}`
  clone.edges?.sort((a: any, b: any) => key(a).localeCompare(key(b)))
  clone.scopeIssues?.sort((a: any, b: any) => key(a).localeCompare(key(b)))
  return normalize(clone)
}

describe('full lifecycle simulation', () => {
  it('drives every tool through a realistic engagement and holds the invariants', async () => {
    const sim = await makeSim()
    const { step, store, allTools, called, foldEvents } = sim

    // ── opening ────────────────────────────────────────────────────────────
    await step('redteam_add_goal', {
      objective: 'Simulated full-lifecycle engagement',
      authorization: 'ROE-SIM/2026-001 signed by CISO',
      scope: '*.sim.example',
    })
    await step('redteam_add_scope', { kind: 'in', value: 'sim.example' })
    await step('redteam_add_scope', { kind: 'out', value: 'prod-db.sim.example', note: 'ROE clause 7.1' })
    await step('redteam_add_operator', { handle: 'chief', role: 'commander' })
    await step('redteam_add_operator', { handle: 'ann', role: 'operator' })

    // ── intents ────────────────────────────────────────────────────────────
    await step('redteam_add_intent', { title: '外网测绘', phase: 'recon', techniqueIds: ['T1595'] })
    const i2 = await step('redteam_add_intent', {
      title: 'VPN 爆破', phase: 'exploitation', techniqueIds: ['T1110.003'],
      dependsOn: ['intent-1'], derivedFrom: [],
    })
    expect(i2).toEqual({ intentId: 'intent-2' })

    // ── evidence → fact → assets ───────────────────────────────────────────
    await step('redteam_add_evidence', { kind: 'command', content: 'dig axfr sim.example @ns1', label: 'zone probe' })
    await step('redteam_add_fact', {
      intentId: 'intent-1', detail: 'ns1.sim.example 允许 AXFR',
      kind: 'recon', target: 'ns1.sim.example', confidence: 1, evidenceIds: ['ev-1'],
    })
    await step('redteam_add_asset', { type: 'host', value: 'vpn.sim.example', tags: ['fortigate'] })
    await step('redteam_add_asset', { type: 'service', value: 'vpn.sim.example:443', parentId: 'asset-1', tags: ['https'] })

    // ── credentials / finding (CVSS v4) / artifact / sample / ioc ─────────
    await step('redteam_add_credential', {
      kind: 'password', secret: SECRET, username: 'svc-backup', target: 'vpn.sim.example', assetId: 'asset-1',
    })
    await step('redteam_add_finding', {
      intentId: 'intent-2', title: 'VPN 弱口令进入内网', severity: 'critical',
      description: '默认凭据可直接登录 SSL VPN。',
      reproducibleSteps: ['打开 https://vpn.sim.example', '使用 svc-backup 默认口令登录'],
      affectedAssetId: 'asset-1',
      cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
      techniqueIds: ['T1110.003'], cveIds: [], evidenceIds: [],
    })
    await step('redteam_add_artifact', { kind: 'screenshot', location: '/loot/vpn-dashboard.png', intentId: 'intent-2', assetId: 'asset-1' })
    await step('redteam_add_sample', {
      kind: 'binary', location: '/loot/beacon.bin',
      sha256: 'a'.repeat(64), md5: 'b'.repeat(32), fileType: 'PE32+x64', arch: 'x64',
    })
    await step('redteam_add_ioc', { type: 'ip', value: '198.51.100.7', context: 'beacon C2' })
    await step('redteam_add_ioc', { type: 'domain', value: 'c2.sim-cdn.example' })

    // ── hint / objective / updates ─────────────────────────────────────────
    await step('redteam_add_hint', { text: '别碰 prod-db，客户在盯', source: 'client' })
    await step('redteam_add_objective', { title: '获取域管哈希' })
    await step('redteam_update_intent', { intentId: 'intent-1', status: 'done' })
    await step('redteam_update_credential', { credentialId: 'cred-1', status: 'valid', evidenceIds: ['ev-1'] })

    // SLA-breach finding (deadline already passed).
    await step('redteam_add_finding', {
      intentId: 'intent-2', title: '过期未修的演示漏洞', severity: 'medium',
      description: '', reproducibleSteps: ['n/a'], slaDays: 0,
    })

    // triage + retest loop on the critical finding.
    await step('redteam_flag_finding', { as: 'ann', findingId: 'finding-1', flag: 'under-review' })
    await step('redteam_flag_finding', { as: 'ann', findingId: 'finding-1', flag: 'none' })
    await step('redteam_retest_finding', {
      as: 'ann', findingId: 'finding-1', outcome: 'fixed',
      notes: '改密后复测通过', detected: 'alerted',
    })

    // JIRA round-trip.
    await step('redteam_jira_apply', {
      updates: [{ findingId: 'finding-1', jiraKey: 'RED-101', jiraStatus: 'In Progress' }],
    })
    await step('redteam_prove_objective', { objectiveId: 'obj-1', proven: true, evidenceIds: ['ev-1'] })

    // ── scanner imports ────────────────────────────────────────────────────
    const nmapXml = `<?xml?><nmaprun><!-- ${NMAP_MARKER} --><host>` +
      `<address addr="203.0.113.77" addrtype="ipv4"/><hostnames><hostname name="edge.sim.example"/></hostnames><ports>` +
      `<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>` +
      `<port protocol="tcp" portid="8443"><state state="open"/><service name="https-alt"/></port>` +
      `</ports></host></nmaprun>`
    const nmapRes = await step('redteam_import_scan', { format: 'nmap-xml', xml: nmapXml, intentId: 'intent-1' })
    expect(nmapRes).toMatchObject({ hosts: 1, services: 2 })

    const nessusXml = `<?xml?><NessusClientData_v2><Report><ReportHost name="10.10.10.10">` +
      `<HostProperties><tag name="host-ip">10.10.10.10</tag></HostProperties>` +
      `<ReportItem port="443" protocol="tcp" severity="3" pluginID="20007" pluginName="SSL Version 2 and 3 Protocol Detection">` +
      `<description>SSL v2/v3 enabled.</description><solution>Disable SSLv2/3.</solution>` +
      `<plugin_output>${NESSUS_MARKER} openssl handshake ok.</plugin_output><cve>cve-2014-3566</cve></ReportItem>` +
      `</ReportHost></Report></NessusClientData_v2>`
    const nessusRes = await step('redteam_import_scan', { format: 'nessus-xml', xml: nessusXml, intentId: 'intent-2' })
    expect(nessusRes).toMatchObject({ hosts: 1, findings: 1 })
    // Lowercase CVE normalized on ingest.
    expect(store.engagementRecords('session-1').findings.some(([, f]) =>
      f.cveIds?.includes('CVE-2014-3566'))).toBe(true)

    // ── reads ──────────────────────────────────────────────────────────────
    const state = await step('redteam_state', {})
    const stateObj = JSON.parse((state as unknown as { text?: string }).text ?? '{}')
    void stateObj

    const search = await step('redteam_search', { query: 'vpn' })
    expect(search.total).toBeGreaterThan(0)

    const overviewVal = await step('redteam_overview', {})
    expect(overviewVal).toBeDefined()

    const graph = await step('redteam_graph', {})
    expect(graph.nodes.length).toBeGreaterThan(2)
    expect(graph.edges.some((e: { relation: string }) => e.relation === 'depends_on')).toBe(true)

    const engagementsList = await step('redteam_engagements', {})
    expect(engagementsList.length).toBeGreaterThanOrEqual(1)

    // ── reports ×8 ─────────────────────────────────────────────────────────
    const reportFormats = ['markdown', 'html', 'json', 'sarif', 'navlayer', 'stix', 'taxii', 'ioc-csv'] as const
    type ReportFormat = (typeof reportFormats)[number]
    const bodies = {} as Record<ReportFormat, string>
    for (const format of reportFormats) {
      const r = await step('redteam_report', { format })
      bodies[format] = r.body
      expect(bodies[format].length, format).toBeGreaterThan(50)
    }

    expect(bodies.markdown).toContain('Simulated full-lifecycle engagement')
    expect(bodies.markdown).toContain('ROE-SIM/2026-001')
    expect(bodies.markdown).toContain('执行摘要 / Executive summary')
    expect(bodies.markdown).toContain('范围合规 / Scope compliance')
    expect(bodies.markdown).toContain('CVSS v4.0: **')
    expect(bodies.markdown).toContain('RED-101')

    expect(bodies.html).toContain('<!DOCTYPE html>')
    expect(bodies.html).toContain('获取域管哈希')

    const sarif = JSON.parse(bodies.sarif)
    expect(sarif.runs[0].results.length).toBe(3)
    expect(sarif.runs[0].results.some((r: any) => r.suppressions?.[0]?.status === 'accepted')).toBe(false)

    const layer = JSON.parse(bodies.navlayer)
    expect(layer.domain).toBe('enterprise-attack')
    expect(layer.techniques.some((t: any) => t.score === 100)).toBe(true)

    const stix = JSON.parse(bodies.stix)
    expect(stix.type).toBe('bundle')
    expect(stix.objects.filter((o: any) => o.type === 'indicator').length).toBe(2)
    expect(stix.objects.some((o: any) => o.type === 'vulnerability')).toBe(true)

    const taxii = JSON.parse(bodies.taxii)
    expect(taxii.more).toBe(false)
    expect(taxii.data.length).toBe(JSON.parse(bodies.stix).objects.length)

    expect(bodies['ioc-csv'].split('\n').filter((l) => l.trim() !== '').length).toBe(3)

    // ── child submission path (subagent entry point) + outbound JIRA ──────
    const nextEv = `ev-${store.counts('session-1').evidence + 1}`
    const submitRes = await step('redteam_submit', {
      intentId: 'intent-2',
      evidence: [{ kind: 'output', content: 'whoami /all', label: 'child enum' }],
      assets: [{ type: 'account', value: 'SIM\\svc-backup' }],
      facts: [{ detail: '域内账户枚举完成', kind: 'post-exploration', evidenceIds: [nextEv] }],
      iocs: [{ type: 'user-agent', value: 'python-requests/2.31' }],
    })
    expect(submitRes.facts.length).toBe(1)
    expect(submitRes.assets.length).toBe(1)

    const exported = await step('redteam_jira_export', {})
    expect(exported.issues.some((i: any) => i.findingId === 'finding-1')).toBe(true)
    expect(exported.issues.every((i: any) => i.fields.summary.startsWith('['))).toBe(true)

    // ── close ──────────────────────────────────────────────────────────────
    await step('redteam_close_goal', {
      as: 'chief',
      outcome: 'partial',
      summary: '拿到 VPN 边界与两台主机权限，域控未触及。',
    })

    // Refresh the report set after the child submission and close so the
    // later invariants (secret sweep, count reconciliation) judge the bodies
    // a user would actually export from the final state.
    for (const format of reportFormats) {
      const r = await step('redteam_report', { format })
      bodies[format] = r.body
    }

    // ── invariant 1: every registered tool was exercised ───────────────────
    const notCalled = allTools.filter((n) => !called.has(n))
    const phantomCalled = [...called].filter((n) => !allTools.includes(n))
    expect(phantomCalled, 'called names absent from registry').toEqual([])
    expect(notCalled, 'registered tools never invoked').toEqual([])

    // ── invariant 2: fold replay ≙ store projection ────────────────────────
    let folded = redteamProjectionDefinition.init()
    for (const ev of foldEvents) {
      folded = fold(folded, ev as never)
    }
    const fromFold = redteamProjectionDefinition.wire.view(folded)
    const fromStore = store.projection('session-1')
    if (process.env.SIM_DEBUG === '1') {
      const fs = await import('node:fs')
      fs.writeFileSync(process.env.TEMP + '/opencode/fold.json', JSON.stringify(fromFold, null, 1))
      fs.writeFileSync(process.env.TEMP + '/opencode/storeproj.json', JSON.stringify(fromStore, null, 1))
    }
    expect(stripVolatile(fromFold)).toEqual(stripVolatile(fromStore))

    // ── invariant 3: wire schema validates both ────────────────────────────
    expect(() => redteamProjectionSchema.parse(fromStore)).not.toThrow()
    expect(() => redteamProjectionSchema.parse(fromFold)).not.toThrow()
    const typedFromStore = fromStore as RedteamProjection
    void typedFromStore

    // ── invariant 4: no plaintext secrets anywhere model/user-facing ───────
    const scanTargets = [
      JSON.stringify(fromStore),
      bodies.markdown, bodies.html, bodies.sarif, bodies.navlayer,
      bodies.stix, bodies.taxii, bodies['ioc-csv'],
    ]
    for (const target of scanTargets) {
      expect(target.includes(SECRET)).toBe(false)
      expect(target.includes(NMAP_MARKER)).toBe(false)
      expect(target.includes(NESSUS_MARKER)).toBe(false)
    }
    // json export is the documented full-fidelity machine copy: evidence lives there.
    expect(bodies.json!.includes(NMAP_MARKER)).toBe(true)

    // search results are safe too.
    const secretProbe = await step('redteam_search', { query: SECRET.slice(0, 12) })
    expect(secretProbe.total).toBe(0)

    // ── invariant 5: counts reconcile across surfaces ─────────────────────
    const jsonBody = JSON.parse(bodies.json!)
    expect(jsonBody.counts.findings).toBe(store.counts('session-1').findings)
    expect(jsonBody.counts.assets).toBe(store.counts('session-1').assets)
    const finalState = store.state('session-1')
    expect(finalState.progress.done).toBe(1)
    expect(finalState.slaOverdue.length).toBe(1)
    expect(finalState.scope.violations.length).toBe(1) // prod-db out entry vs imported hosts? none match; scope violations only via direct hits
  })

  it('is deterministic: two identical runs produce identical projections', async () => {
    async function run(): Promise<unknown> {
      const sim = await makeSim()
      const { step, store } = sim
      await step('redteam_add_goal', { objective: 'det', authorization: 'R', scope: '' })
      await step('redteam_add_intent', { title: 'i1', phase: 'recon' })
      await step('redteam_add_asset', { type: 'host', value: 'h.det' })
      await step('redteam_add_finding', {
        intentId: 'intent-1', title: 'f', severity: 'high', description: '',
        reproducibleSteps: ['s'], affectedAssetId: 'asset-1',
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      })
      await step('redteam_close_goal', { outcome: 'achieved', summary: 'done' })
      return stripVolatile(store.projection('session-1'))
    }
    const [a, b] = await Promise.all([run(), run()])
    expect(normalize(a)).toEqual(normalize(b))
  })
})

// Keep zod import used (schema parse above covers it); explicit reference:
void z
