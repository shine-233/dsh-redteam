/**
 * The 红队 tab shell: sub-tab strip over the session's `redteam` projection.
 * All data comes from the `useProjection` share; the component holds only its
 * active sub-tab locally. Every projection domain has a dedicated sub-view,
 * plus animated stats and a 3D attack-terrain renderer.
 */

import { useEffect, useRef, useState } from 'react'
import type { RedteamProjection } from '../types.js'
import { ChainGraph } from './ChainGraph.js'
import { FindingsView } from './FindingsView.js'
import { CredentialsView } from './CredentialsView.js'
import { AssetsView } from './AssetsView.js'
import { ArtifactsView } from './ArtifactsView.js'
import { EvidenceView } from './EvidenceView.js'
import { SamplesView } from './SamplesView.js'
import { IocsView } from './IocsView.js'
import { ObjectivesView } from './ObjectivesView.js'
import { StatsView } from './StatsView.js'
import { View3D } from './View3D.js'
import { ReportView } from './ReportView.js'

export interface RedteamViewProps {
  sessionId: string
  useProjection: <V>(key: string, selector?: (value: unknown) => V) => V
}

const TABS = [
  { id: 'chain', label: '链路' },
  { id: 'stats', label: '统计' },
  { id: 'view3d', label: '立体' },
  { id: 'findings', label: '漏洞' },
  { id: 'assets', label: '资产' },
  { id: 'credentials', label: '凭据' },
  { id: 'artifacts', label: '产物' },
  { id: 'evidence', label: '证据' },
  { id: 'samples', label: '样本' },
  { id: 'iocs', label: 'IOC' },
  { id: 'objectives', label: '目标' },
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

/** Rolling count-up for the header stat row. */
function useCountUp(value: number): number {
  const [shown, setShown] = useState(value)
  const prevRef = useRef(value)
  useEffect(() => {
    const from = prevRef.current
    prevRef.current = value
    if (from === value) return undefined
    let raf = 0
    const start = performance.now()
    const tick = () => {
      const t = Math.min(1, (performance.now() - start) / 450)
      setShown(Math.round(from + (value - from) * (1 - Math.pow(1 - t, 3))))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value])
  return shown
}

const styles = `
@keyframes rtFadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
@keyframes rtPulse { 0%,100% { box-shadow:0 0 0 0 rgba(255,92,92,.45);} 50% { box-shadow:0 0 0 5px rgba(255,92,92,0);} }
@keyframes rtBlink { 0%,100% { opacity:1;} 50% { opacity:.35;} }
.rt-root { display:flex; flex-direction:column; height:100%; min-height:0;
  font-size:13px; color:var(--dsw-text, #dbe2ea); }
.rt-tabs { display:flex; gap:4px; padding:8px 12px; border-bottom:1px solid var(--dsw-border, #2a3138);
  flex-wrap:wrap; }
.rt-tab { border:none; background:transparent; color:var(--dsw-text-secondary,#8b95a1);
  padding:4px 10px; border-radius:6px; cursor:pointer; transition:background .18s, color .18s, transform .12s; }
.rt-tab:hover { background:var(--dsw-surface,#1b2026); color:var(--dsw-text,#dbe2ea); }
.rt-tab:active { transform:scale(.94); }
.rt-tab[data-active="true"] { background:var(--dsw-accent-soft, rgba(80,140,255,.16));
  color:var(--dsw-accent, #6aa2ff); font-weight:600; }
.rt-body { flex:1; min-height:0; overflow:auto; padding:12px; }
.rt-body > * { animation:rtFadeUp .32s cubic-bezier(.22,.61,.36,1) both; }
.rt-empty { color:var(--dsw-text-secondary, #8b95a1); padding:24px 0; text-align:center; animation:rtFadeUp .4s both; }
.rt-counts { display:flex; gap:14px; padding:0 0 10px; color:var(--dsw-text-secondary,#8b95a1); flex-wrap:wrap; }
.rt-counts b { color:var(--dsw-text,#dbe2ea); margin-left:4px; font-variant-numeric:tabular-nums; }
.rt-goal { padding:8px 10px; border:1px solid var(--dsw-border,#2a3138); border-radius:8px; margin-bottom:10px;
  animation:rtFadeUp .35s both; }
.rt-goal .auth { color:var(--dsw-warning,#e0a94e); font-size:12px; margin-top:4px; word-break:break-all; }
.rt-scope-alert { margin-top:6px; padding:4px 8px; border:1px solid #ff5c5c66; border-radius:6px;
  background:rgba(255,92,92,.08); color:#ff5c5c; font-size:12px; font-weight:600; animation:rtFadeUp .3s both; }
.rt-chip-bad { border-color:#ff5c5c88 !important; color:#ff5c5c !important; }
.rt-scope-out { color:#ff5c5c; font-size:11px; }

.rt-canvas-wrap { position:relative; height:min(62vh, 520px); min-height:340px;
  border:1px solid var(--dsw-border,#2a3138); border-radius:10px; overflow:hidden;
  background:radial-gradient(ellipse at 50% 30%, rgba(80,140,255,.05), transparent 65%), var(--dsw-bg,#12161b); }
.rt-canvas { width:100%; height:100%; display:block; touch-action:none; cursor:grab; }
.rt-legend { display:flex; gap:14px; flex-wrap:wrap; padding:8px 2px 0;
  color:var(--dsw-text-secondary,#8b95a1); font-size:12px; }
.rt-legend-item { display:inline-flex; align-items:center; gap:5px; }
.rt-legend-item i, .rt-dot { display:inline-block; width:9px; height:9px; border-radius:50%; }
.rt-drawer { border:1px solid var(--dsw-border,#2a3138); border-top:2px solid var(--dsw-accent,#6aa2ff);
  border-radius:0 0 10px 10px; margin-top:-1px; overflow:hidden;
  max-height:0; opacity:0; transition:max-height .28s ease, opacity .24s ease; }
.rt-drawer-open { max-height:280px; opacity:1; }
.rt-drawer-head { display:flex; justify-content:space-between; align-items:center;
  padding:8px 12px; background:var(--dsw-surface,#1b2026); }
.rt-drawer-body { padding:8px 12px 12px; }

.rt-stats { display:flex; flex-direction:column; gap:12px; }
.rt-panel { border:1px solid var(--dsw-border,#2a3138); border-radius:10px; padding:12px 14px;
  background:var(--dsw-bg,#12161b); }
.rt-panel h3 { margin:0 0 10px; font-size:13px; color:var(--dsw-text-secondary,#aab4bf);
  letter-spacing:.04em; }
.rt-anim { animation:rtFadeUp .38s cubic-bezier(.22,.61,.36,1) both; }
.rt-donut-row { display:flex; align-items:center; gap:20px; flex-wrap:wrap; }
.rt-donut { width:130px; height:130px; filter:drop-shadow(0 2px 8px rgba(0,0,0,.35)); }
.rt-donut circle { transition:stroke-dashoffset .9s cubic-bezier(.22,.61,.36,1); }
.rt-donut-num { fill:var(--dsw-text,#dbe2ea); font-size:26px; font-weight:700; }
.rt-donut-label { fill:var(--dsw-text-secondary,#8b95a1); font-size:10px; }
.rt-legend-col { display:flex; flex-direction:column; gap:6px; }
.rt-bar-row { display:flex; align-items:center; gap:10px; margin:6px 0; }
.rt-bar-label { width:120px; color:var(--dsw-text-secondary,#8b95a1); font-size:12px; text-align:right; }
.rt-bar-track { flex:1; height:10px; border-radius:6px; background:var(--dsw-surface,#1b2026); overflow:hidden; }
.rt-bar-fill { height:100%; border-radius:6px; transition:width .8s cubic-bezier(.22,.61,.36,1); }
.rt-bar-pct { width:42px; font-size:11px; color:var(--dsw-text-secondary,#8b95a1); font-variant-numeric:tabular-nums; }
.rt-wall { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }
.rt-cell { border-radius:5px; padding:3px 8px; font-size:11px; font-weight:600;
  border:1px solid transparent; transition:transform .15s; cursor:default; }
.rt-cell:hover { transform:translateY(-2px); }
.rt-cell-proven { background:rgba(127,176,105,.16); border-color:#4f7a55; color:#7fb069; }
.rt-cell-attempted { background:rgba(224,192,78,.12); border-color:#c7895b66; color:#e0c04e; }
.rt-lanes { display:flex; gap:8px; overflow-x:auto; padding-bottom:4px; }
.rt-lane { flex:1 0 118px; border:1px solid var(--dsw-border,#2a3138); border-radius:8px; padding:8px;
  min-height:86px; position:relative; background:var(--dsw-surface,#1b2026); transition:border-color .2s; }
.rt-lane:hover { border-color:var(--dsw-accent,#6aa2ff); }
.rt-lane-empty { opacity:.45; }
.rt-lane header { font-size:12px; font-weight:600; margin-bottom:6px; }
.rt-lane header code { font-weight:400; font-size:10px; color:var(--dsw-text-secondary,#8b95a1); }
.rt-lane-count { position:absolute; top:6px; right:8px; font-size:16px; font-weight:700;
  color:var(--dsw-accent,#6aa2ff); font-variant-numeric:tabular-nums; }
.rt-lane-item { font-size:11px; color:var(--dsw-text-secondary,#8b95a1); margin:3px 0;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

.rt-finding { border:1px solid var(--dsw-border,#2a3138); border-radius:8px; padding:10px 12px;
  margin-bottom:10px; transition:border-color .2s, transform .15s; animation:rtFadeUp .35s both; }
.rt-finding:hover { border-color:#c75b5b88; transform:translateX(2px); }
.rt-sev { font-weight:700; margin-right:6px; }
.rt-sev.critical{color:#ff5c5c; animation:rtPulse 2.2s infinite;}
.rt-sev.high{color:#ff9350} .rt-sev.medium{color:#e0c04e}
.rt-sev.low{color:#7fb069} .rt-sev.info{color:#8b95a1}
.rt-meta { color:var(--dsw-text-secondary,#8b95a1); font-size:12px; margin-top:6px; }
.rt-assets { width:100%; border-collapse:collapse; }
.rt-assets th,.rt-assets td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--dsw-border,#242b32); }
.rt-assets th { color:var(--dsw-text-secondary,#8b95a1); font-weight:500; }
.rt-assets tbody tr { transition:background .16s; }
.rt-assets tbody tr:hover { background:rgba(106,162,255,.05); }
.rt-md h1,.rt-md h2,.rt-md h3 { line-height:1.3; }
.rt-md code { background:var(--dsw-surface,#1b2026); padding:1px 5px; border-radius:4px; }
.rt-md pre { background:var(--dsw-surface,#1b2026); padding:10px; border-radius:8px; overflow:auto; }
.rt-hints { border:1px dashed var(--dsw-border,#2a3138); border-radius:8px; padding:8px 10px;
  margin-bottom:10px; font-size:12px; animation:rtFadeUp .4s both; }
.rt-hint-item { margin:2px 0; word-break:break-all; }
.rt-hint-src { font-weight:700; margin-right:4px; }
.rt-hint-user { color:#6aa2ff; } .rt-hint-client { color:#e0a94e; } .rt-hint-operator { color:#8b95a1; }
.rt-progress { display:flex; gap:14px; padding:0 0 8px; font-size:12px; color:var(--dsw-text-secondary,#8b95a1); }
.rt-progress b { color:#7fb069; margin-left:2px; }
.rt-outcome { font-size:12px; margin-top:4px; font-weight:600; }
.rt-outcome-achieved { color:#7fb069; }
.rt-outcome-partial { color:#e0c04e; }
.rt-outcome-not-achieved { color:#ff5c5c; }
.rt-tested { color:#7fb069; font-size:11px; }
.rt-untested { color:var(--dsw-text-secondary,#8b95a1); font-size:11px; opacity:.7; }
.rt-hint { color:var(--dsw-text-secondary,#8b95a1); }
.rt-cvss { margin-left:8px; padding:1px 7px; border-radius:10px; font-size:11px; font-weight:700; }
.rt-cvss-crit { background:rgba(255,92,92,.18); color:#ff5c5c; }
.rt-cvss-high { background:rgba(255,147,80,.16); color:#ff9350; }
.rt-cvss-mid { background:rgba(224,192,78,.14); color:#e0c04e; }
.rt-techs { margin-top:6px; display:flex; gap:6px; flex-wrap:wrap; }
.rt-tech { background:var(--dsw-surface,#1b2026); border:1px solid var(--dsw-border,#2a3138);
  border-radius:4px; padding:1px 6px; font-size:11px; color:var(--dsw-text-secondary,#8b95a1);
  transition:border-color .18s, color .18s; }
.rt-tech:hover { border-color:#6aa2ff88; color:var(--dsw-text,#dbe2ea); }
.rt-fixed { margin-left:8px; font-size:11px; font-weight:700; color:#7fb069; }
.rt-tag { margin-left:8px; background:var(--dsw-surface,#1b2026); border:1px solid var(--dsw-border,#2a3138);
  border-radius:10px; padding:1px 8px; font-size:11px; color:var(--dsw-text-secondary,#8b95a1); }
.rt-detected { margin-left:8px; font-size:11px; font-weight:600; }
.rt-det-undetected { color:#7fb069; }
.rt-det-logged { color:#6aa2ff; }
.rt-det-alerted { color:#e0c04e; }
.rt-det-prevented { color:#ff5c5c; }
.rt-flagged { margin-left:8px; font-size:11px; font-weight:700; padding:1px 7px; border-radius:10px; }
.rt-flag-under-review { background:rgba(106,162,255,.14); color:#6aa2ff; }
.rt-flag-false-positive { background:rgba(139,149,161,.16); color:#8b95a1; text-decoration:line-through; }
.rt-flag-out-of-scope { background:rgba(255,92,92,.12); color:#ff5c5c; }
.rt-flag-risk-accepted { background:rgba(224,192,78,.14); color:#e0c04e; }
.rt-tags { display:flex; gap:4px; flex-wrap:wrap; }
.rt-kind-chips { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; align-items:center; }
.rt-chip-active { background:var(--dsw-accent-soft, rgba(80,140,255,.16)) !important; color:var(--dsw-accent,#6aa2ff) !important; }
@keyframes rtRowIn { from { opacity:0; transform:translateX(-8px);} to { opacity:1; transform:none;} }
.rt-row-anim { animation:rtRowIn .34s cubic-bezier(.22,.61,.36,1) both; }
.rt-objectives { display:flex; flex-direction:column; gap:8px; }
.rt-objective { display:flex; align-items:center; gap:10px; border:1px solid var(--dsw-border,#2a3138);
  border-radius:8px; padding:9px 12px; transition:border-color .2s, background .2s; }
.rt-objective-proven { border-color:#4f7a55aa; background:rgba(79,122,85,.08); }
.rt-check { width:22px; height:22px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center;
  border:1.5px solid var(--dsw-border,#39424c); font-size:12px; color:var(--dsw-text-secondary,#8b95a1); flex:none;
  transition:all .25s cubic-bezier(.34,1.56,.64,1); }
.rt-check-on { background:#7fb069; border-color:#7fb069; color:#10151a; transform:scale(1.08); }
.rt-objective-title { flex:1; }
.rt-cred-status-valid { color:#7fb069; }
.rt-cred-status-invalid { color:#ff5c5c; }
.rt-cred-status-unverified { color:var(--dsw-text-secondary,#8b95a1); animation:rtBlink 2.6s infinite; }
.rt-facts { display:flex; flex-direction:column; gap:6px; }
.rt-fact { border:1px solid var(--dsw-border,#2a3138); border-radius:8px; padding:7px 10px;
  display:flex; align-items:center; gap:8px; flex-wrap:wrap; transition:border-color .18s; }
.rt-fact:hover { border-color:#5b87c788; }
.rt-fact-detail { flex:1 1 auto; min-width:160px; }
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

  return (
    <div className="rt-root">
      <div className="rt-goal">
        <strong>{projection.goal.objective}</strong>
        <div className="auth">授权 / Authorization: {projection.goal.authorization}</div>
        {projection.scopeIssues.some((v) => v.reason === 'out-of-scope') && (
          <div className="rt-scope-alert">⛔ {projection.scopeIssues.filter((v) => v.reason === 'out-of-scope').length} 条记录越界 — 详见「统计」范围合规面板</div>
        )}
        {projection.goal.outcome !== null && (
          <div className={`rt-outcome rt-outcome-${projection.goal.outcome}`}>
            结论 / Outcome: {projection.goal.outcome}
          </div>
        )}
      </div>
      {projection.hints.length > 0 && (
        <div className="rt-hints">
          {projection.hints.slice(-3).map((h) => (
            <div className="rt-hint-item" key={h.id}>
              <span className={`rt-hint-src rt-hint-${h.source}`}>[{h.source}]</span> {h.text}
            </div>
          ))}
          {projection.hints.length > 3 && (
            <div className="rt-hint-more">… 共 {projection.hints.length} 条转向记录，完整清单见报告</div>
          )}
        </div>
      )}
      <CountRow projection={projection} />
      {(projection.nodes.some((n) => n.kind === 'intent' && n.status !== 'active') ||
        projection.findings.some((f) => f.status === 'fixed')) && (
        <ProgressRow projection={projection} />
      )}
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
      <div className="rt-body" key={tab}>
        {tab === 'chain' && <ChainGraph projection={projection} />}
        {tab === 'stats' && <StatsView projection={projection} />}
        {tab === 'view3d' && <View3D projection={projection} />}
        {tab === 'findings' && <FindingsView projection={projection} />}
        {tab === 'assets' && <AssetsView projection={projection} />}
        {tab === 'credentials' && <CredentialsView projection={projection} />}
        {tab === 'artifacts' && <ArtifactsView projection={projection} />}
        {tab === 'evidence' && <EvidenceView projection={projection} />}
        {tab === 'samples' && <SamplesView projection={projection} />}
        {tab === 'iocs' && <IocsView projection={projection} />}
        {tab === 'objectives' && <ObjectivesView projection={projection} />}
        {tab === 'report' && <ReportView projection={projection} sessionId={props.sessionId} />}
      </div>
    </div>
  )
}

function CountRow({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const counts = projection.counts
  const intents = useCountUp(counts.intents)
  const facts = useCountUp(counts.facts)
  const assets = useCountUp(counts.assets)
  const findings = useCountUp(counts.findings)
  const credentials = useCountUp(counts.credentials)
  const evidence = useCountUp(counts.evidence)
  const artifacts = useCountUp(counts.artifacts)
  const samples = useCountUp(counts.samples)
  const iocs = useCountUp(counts.iocs)
  const objectives = useCountUp(counts.objectives)
  return (
    <div className="rt-counts">
      <span>意图<b>{intents}</b></span>
      <span>事实<b>{facts}</b></span>
      <span>资产<b>{assets}</b></span>
      <span>漏洞<b>{findings}</b></span>
      <span>凭据<b>{credentials}</b></span>
      <span>证据<b>{evidence}</b></span>
      <span>产物<b>{artifacts}</b></span>
      <span>样本<b>{samples}</b></span>
      <span>IOC<b>{iocs}</b></span>
      <span>目标<b>{objectives}/{projection.objectives.length}</b></span>
    </div>
  )
}

function ProgressRow({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const done = projection.nodes.filter((n) => n.kind === 'intent' && n.status === 'done').length
  const blocked = projection.nodes.filter((n) => n.kind === 'intent' && n.status === 'blocked').length
  const total = projection.nodes.filter((n) => n.kind === 'intent').length
  const fixed = projection.findings.filter((f) => f.status === 'fixed').length
  return (
    <div className="rt-progress">
      <span>任务树 / Task tree: <b>{done}/{total}</b> done{blocked > 0 ? <> · <b>{blocked}</b> blocked</> : null}</span>
      <span>已修复 / Fixed: <b>{fixed}/{projection.findings.length}</b></span>
    </div>
  )
}
