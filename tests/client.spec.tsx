/**
 * @vitest-environment jsdom
 * Client smoke: RedteamView mounts against a rich projection and every one
 * of the eleven sub-tabs renders without throwing (canvas contexts degrade
 * to no-ops under jsdom).
 */
import { describe, expect, it } from 'vitest'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { RedteamView } from '../src/client/RedteamView.js'
import type { RedteamProjection } from '../src/types.js'

;(globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true

const projection: RedteamProjection = {
  goal: { objective: '拿下核心域控', authorization: '授权书 #2024-001', outcome: null },
  nodes: [
    { id: 'goal-1', kind: 'goal', title: '拿下核心域控', status: null, assetIds: [], phase: null, techniqueIds: [] },
    { id: 'intent-1', kind: 'intent', title: '外网侦察', status: 'done', assetIds: ['asset-1'], phase: 'recon', techniqueIds: ['T1595'] },
    { id: 'intent-2', kind: 'intent', title: '爆破 VPN', status: 'active', assetIds: [], phase: 'exploitation', techniqueIds: ['T1110.003'], },
  ],
  assets: [
    { id: 'asset-1', type: 'host', value: 'vpn.corp.example', parentId: null, tags: ['fortigate'] },
    { id: 'asset-2', type: 'service', value: 'portal.corp.example', parentId: 'asset-1', tags: [] },
  ],
  findings: [
    { id: 'finding-1', intentId: 'intent-2', title: 'VPN 弱口令', severity: 'critical', cvssScore: 9.8,
      techniqueIds: ['T1110.003'], status: null, affectedAssetId: 'asset-1',
      detected: 'alerted' as const, duplicateOf: null },
    { id: 'finding-2', intentId: 'intent-1', title: '目录遍历', severity: 'medium', cvssScore: 6.5,
      techniqueIds: [], status: 'fixed' as const, affectedAssetId: 'asset-2',
      detected: null, duplicateOf: 'finding-1' },
  ],
  credentials: [
    { id: 'cred-1', kind: 'password', username: 'admin', target: 'vpn.corp.example', assetId: 'asset-1', status: 'valid' },
  ],
  artifacts: [
    { id: 'art-1', kind: 'screenshot', location: '/loot/vpn.png', intentId: 'intent-2', assetId: 'asset-1' },
  ],
  hints: [
    { id: 'hint-1', text: '优先打 portal，别动生产库', source: 'client', intentId: null },
  ],
  samples: [
    { id: 'sample-1', kind: 'binary', location: '/loot/beacon.bin', sha256: 'a'.repeat(64), fileType: 'PE32' },
  ],
  iocs: [
    { id: 'ioc-1', type: 'ip', value: '203.0.113.7', sampleId: null },
    { id: 'ioc-2', type: 'domain', value: 'c2.example.net', sampleId: 'sample-1' },
  ],
  objectives: [
    { id: 'obj-1', title: '获取域管哈希', provenAt: 1720000000000 },
    { id: 'obj-2', title: '持久化驻留', provenAt: null },
  ],
  scope: [
    { id: 'scope-1', kind: 'in' as const, value: '*.corp.example', note: null },
    { id: 'scope-2', kind: 'out' as const, value: 'prod-db.corp.example', note: null },
  ],
  scopeIssues: [
    { recordId: 'asset-2', recordKind: 'finding' as const, value: 'portal.corp.example', reason: 'unscoped' as const, matched: '' },
  ],
  facts: [
    { id: 'fact-1', intentId: 'intent-1', detail: 'vpn.corp.example 开放 443/1194', phase: 'recon' as const, confidence: 1, evidenceIds: ['ev-1'] },
  ],
  evidence: [
    { id: 'ev-1', kind: 'command' as const, label: 'nmap top-ports' },
  ],
  edges: [
    { from: 'goal-1', to: 'intent-1', relation: 'spawns' },
    { from: 'goal-1', to: 'intent-2', relation: 'spawns' },
    { from: 'intent-1', to: 'fact-1', relation: 'yields' },
    { from: 'intent-2', to: 'finding-1', relation: 'proves' },
    { from: 'intent-1', to: 'intent-2', relation: 'depends_on' },
    { from: 'asset-1', to: 'asset-2', relation: 'parent' },
  ],
  counts: {
    intents: 2, facts: 1, assets: 2, findings: 2, evidence: 3, credentials: 1,
    artifacts: 1, hints: 1, samples: 1, iocs: 2, objectives: 1,
  },
}

const TAB_IDS = [
  'chain', 'stats', 'view3d', 'findings', 'assets',
  'credentials', 'artifacts', 'evidence', 'samples', 'iocs', 'objectives', 'report',
]

describe('RedteamView client smoke', () => {
  it('renders header, counts, and all eleven sub-tabs without throwing', () => {
    const container = document.createElement('div')
    document.body.append(container)
    const root: Root = createRoot(container)
    const useProjection = () => projection
    act(() => {
      root.render(<RedteamView sessionId="s1" useProjection={useProjection as never} />)
    })
    expect(container.textContent).toContain('拿下核心域控')
    expect(container.textContent).toContain('授权书 #2024-001')
    for (const label of ['链路', '统计', '立体', '漏洞', '资产', '凭据', '产物', '证据', '样本', 'IOC', '目标', '报告']) {
      expect([...container.querySelectorAll('.rt-tab')].some((b) => b.textContent === label), `tab ${label}`).toBe(true)
    }
    root.unmount()
    container.remove()
  })

  it('switches through every sub-tab rendering its body', () => {
    const container = document.createElement('div')
    document.body.append(container)
    const root = createRoot(container)
    const useProjection = () => projection
    act(() => {
      root.render(<RedteamView sessionId="s1" useProjection={useProjection as never} />)
    })
    const tabs = [...container.querySelectorAll('.rt-tab')]
    for (let i = 0; i < TAB_IDS.length; i++) {
      const button = tabs[i]
      if (button === undefined) throw new Error(`missing tab ${i}`)
      act(() => { (button as HTMLElement).click() })
      const body = container.querySelector('.rt-body')
      expect(body, `body for ${TAB_IDS[i]}`).not.toBeNull()
      expect(body!.childElementCount).toBeGreaterThan(0)
    }
    root.unmount()
    container.remove()
  })

  it('shows the empty state when there is no engagement', () => {
    const container = document.createElement('div')
    document.body.append(container)
    const root = createRoot(container)
    const useProjection = () => ({ ...projection, goal: null })
    act(() => {
      root.render(<RedteamView sessionId="s1" useProjection={useProjection as never} />)
    })
    expect(container.textContent).toContain('还没有红队 engagement')
    root.unmount()
    container.remove()
  })
})
