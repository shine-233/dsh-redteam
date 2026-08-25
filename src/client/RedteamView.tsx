/**
 * The 红队 tab shell: sub-tab strip (链路 / 漏洞 / 资产 / 报告) over the
 * session's `redteam` projection. All data comes from the `useProjection`
 * share; the component holds only its active sub-tab locally.
 */

import { useState } from 'react'
import type { RedteamProjection } from '../types.js'
import { ChainGraph } from './ChainGraph.js'
import { FindingsView } from './FindingsView.js'
import { AssetsView } from './AssetsView.js'
import { ReportView } from './ReportView.js'

export interface RedteamViewProps {
  sessionId: string
  useProjection: <V>(key: string, selector?: (value: unknown) => V) => V
}

const TABS = [
  { id: 'chain', label: '链路' },
  { id: 'findings', label: '漏洞' },
  { id: 'assets', label: '资产' },
  { id: 'report', label: '报告' },
] as const

export function injectStylesOnce(): void {
  if (typeof document === 'undefined') return
  if (document.getElementById('dsh-redteam-styles') !== null) return
  const style = document.createElement('style')
  style.id = 'dsh-redteam-styles'
  style.textContent = styles
  document.head.append(style)
}

const styles = `
.rt-root { display:flex; flex-direction:column; height:100%; min-height:0;
  font-size:13px; color:var(--dsw-text, #dbe2ea); }
.rt-tabs { display:flex; gap:4px; padding:8px 12px; border-bottom:1px solid var(--dsw-border, #2a3138); }
.rt-tab { border:none; background:transparent; color:var(--dsw-text-secondary,#8b95a1);
  padding:4px 10px; border-radius:6px; cursor:pointer; }
.rt-tab[data-active="true"] { background:var(--dsw-accent-soft, rgba(80,140,255,.16));
  color:var(--dsw-accent, #6aa2ff); font-weight:600; }
.rt-body { flex:1; min-height:0; overflow:auto; padding:12px; }
.rt-empty { color:var(--dsw-text-secondary, #8b95a1); padding:24px 0; text-align:center; }
.rt-counts { display:flex; gap:14px; padding:0 0 10px; color:var(--dsw-text-secondary,#8b95a1); }
.rt-counts b { color:var(--dsw-text,#dbe2ea); margin-left:4px; }
.rt-goal { padding:8px 10px; border:1px solid var(--dsw-border,#2a3138); border-radius:8px; margin-bottom:10px; }
.rt-goal .auth { color:var(--dsw-warning,#e0a94e); font-size:12px; margin-top:4px; word-break:break-all; }
.rt-svg { width:100%; height:auto; display:block; }
.rt-node rect { fill:var(--dsw-surface,#1b2026); stroke:var(--dsw-border,#39424c); rx:8; }
.rt-node.goal rect { stroke:var(--dsw-accent,#6aa2ff); stroke-width:2; }
.rt-node.intent rect { stroke:#7f8fa0; }
.rt-node text { fill:var(--dsw-text,#dbe2ea); font-size:12px; }
.rt-edge { stroke:var(--dsw-border,#46505c); fill:none; stroke-width:1.5; }
.rt-edge.spawns { stroke-dasharray:none; }
.rt-edge.yields { stroke:#5b87c7; }
.rt-edge.proves { stroke:#c75b5b; stroke-width:2; }
.rt-edge.parent { stroke:#4f7a55; stroke-dasharray:4 3; }
.rt-pill { font-size:10px; fill:var(--dsw-text-secondary,#8b95a1); }
.rt-finding { border:1px solid var(--dsw-border,#2a3138); border-radius:8px; padding:10px 12px; margin-bottom:10px; }
.rt-sev { font-weight:700; margin-right:6px; }
.rt-sev.critical{color:#ff5c5c} .rt-sev.high{color:#ff9350} .rt-sev.medium{color:#e0c04e}
.rt-sev.low{color:#7fb069} .rt-sev.info{color:#8b95a1}
.rt-steps { margin:6px 0 0 18px; padding:0; }
.rt-steps li { margin:2px 0; }
.rt-meta { color:var(--dsw-text-secondary,#8b95a1); font-size:12px; margin-top:6px; }
.rt-assets { width:100%; border-collapse:collapse; }
.rt-assets th,.rt-assets td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--dsw-border,#242b32); }
.rt-assets th { color:var(--dsw-text-secondary,#8b95a1); font-weight:500; }
.rt-md h1,.rt-md h2,.rt-md h3 { line-height:1.3; }
.rt-md code { background:var(--dsw-surface,#1b2026); padding:1px 5px; border-radius:4px; }
.rt-md pre { background:var(--dsw-surface,#1b2026); padding:10px; border-radius:8px; overflow:auto; }
.rt-hint { color:var(--dsw-text-secondary,#8b95a1); }
`

export function RedteamView(props: RedteamViewProps): React.ReactNode {
  const [tab, setTab] = useState<string>('chain')
  const projection = props.useProjection('redteam', (value) => value as RedteamProjection | undefined)
  injectStylesOnce()

  if (projection === undefined || projection === null || projection.goal === null) {
    return (
      <div className="rt-root">
        <p className="rt-empty">
          当前会话还没有红队 engagement —— 在对话里给出目标与授权，指挥官会调用 redteam_add_goal 开始记录。
        </p>
      </div>
    )
  }

  const counts = projection.counts
  return (
    <div className="rt-root">
      <div className="rt-goal">
        <strong>{projection.goal.objective}</strong>
        <div className="auth">授权 / Authorization: {projection.goal.authorization}</div>
      </div>
      <div className="rt-counts">
        <span>意图<b>{counts.intents}</b></span>
        <span>事实<b>{counts.facts}</b></span>
        <span>资产<b>{counts.assets}</b></span>
        <span>漏洞<b>{counts.findings}</b></span>
        <span>证据<b>{counts.evidence}</b></span>
      </div>
      <div className="rt-tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            data-active={tab === t.id}
            className="rt-tab"
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="rt-body">
        {tab === 'chain' && <ChainGraph projection={projection} />}
        {tab === 'findings' && <FindingsView projection={projection} />}
        {tab === 'assets' && <AssetsView projection={projection} />}
        {tab === 'report' && <ReportView projection={projection} sessionId={props.sessionId} />}
      </div>
    </div>
  )
}
