/**
 * Stats sub-view: animated severity donut, task-tree / coverage progress
 * bars, ATT&CK technique wall (attempted vs proven) and kill-chain phase
 * swimlanes — all derived from the projection window.
 */

import { useEffect, useState } from 'react'
import type { RedteamProjection } from '../types.js'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const SEV_COLOR: Record<string, string> = {
  critical: '#ff5c5c', high: '#ff9350', medium: '#e0c04e', low: '#7fb069', info: '#8b95a1',
}
const PHASE_LANES = ['recon', 'enumeration', 'exploitation', 'post-exploitation', 'reporting'] as const
const PHASE_ZH: Record<string, string> = {
  recon: '侦察', enumeration: '枚举', exploitation: '利用', 'post-exploitation': '后渗透', reporting: '报告',
}

export function StatsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    const t = window.setTimeout(() => setMounted(true), 30)
    return () => window.clearTimeout(t)
  }, [])

  const sevCounts = new Map<string, number>()
  for (const s of SEV_ORDER) sevCounts.set(s, 0)
  for (const f of projection.findings) sevCounts.set(f.severity, (sevCounts.get(f.severity) ?? 0) + 1)
  const totalFindings = projection.findings.length

  const intents = projection.nodes.filter((n) => n.kind === 'intent')
  const done = intents.filter((n) => n.status === 'done').length
  const blocked = intents.filter((n) => n.status === 'blocked').length
  const activeCount = intents.length - done - blocked

  const testedAssets = new Set<string>()
  for (const n of projection.nodes) for (const a of n.assetIds ?? []) testedAssets.add(a)
  for (const f of projection.findings) if (f.affectedAssetId !== null) testedAssets.add(f.affectedAssetId)
  const tested = projection.assets.filter((a) => testedAssets.has(a.id)).length
  const assetTotal = projection.assets.length

  const attempted = new Set<string>()
  const proven = new Set<string>()
  for (const n of projection.nodes) for (const t of n.techniqueIds ?? []) attempted.add(t)
  for (const f of projection.findings) {
    for (const t of f.techniqueIds) { attempted.add(t); proven.add(t) }
  }
  const techniques = [...attempted].sort()

  const objectivesDone = projection.objectives.filter((o) => o.provenAt !== null).length

  return (
    <div className="rt-stats">
      <section className="rt-panel rt-anim" style={{ animationDelay: '0ms' }}>
        <h3>漏洞严重度分布</h3>
        {totalFindings === 0 ? (
          <p className="rt-empty">暂无漏洞数据。</p>
        ) : (
          <div className="rt-donut-row">
            <svg viewBox="0 0 120 120" className="rt-donut" role="img" aria-label="严重度分布环形图">
              {(() => {
                let acc = 0
                const R = 46
                const C = 2 * Math.PI * R
                return SEV_ORDER.map((s) => {
                  const count = sevCounts.get(s) ?? 0
                  if (count === 0 && totalFindings > 0) return null
                  const frac = totalFindings === 0 ? 0 : count / totalFindings
                  const seg = (
                    <circle
                      key={s}
                      cx="60" cy="60" r={R}
                      fill="none"
                      stroke={SEV_COLOR[s]}
                      strokeWidth={16}
                      strokeDasharray={`${frac * C} ${C}`}
                      strokeDashoffset={mounted ? -acc * C : C}
                      transform="rotate(-90 60 60)"
                      style={{ transition: 'stroke-dashoffset .9s cubic-bezier(.22,.61,.36,1)' }}
                    >
                      <title>{`${s}: ${count}`}</title>
                    </circle>
                  )
                  acc += frac
                  return seg
                })
              })()}
              <text x="60" y="57" textAnchor="middle" className="rt-donut-num">{totalFindings}</text>
              <text x="60" y="72" textAnchor="middle" className="rt-donut-label">漏洞</text>
            </svg>
            <div className="rt-legend-col">
              {SEV_ORDER.map((s) => {
                const count = sevCounts.get(s) ?? 0
                if (count === 0) return null
                return (
                  <span key={s} className="rt-legend-item">
                    <i style={{ background: SEV_COLOR[s] }} /> {s} · {count}
                  </span>
                )
              })}
            </div>
          </div>
        )}
      </section>

      <section className="rt-panel rt-anim" style={{ animationDelay: '60ms' }}>
        <h3>任务树推进</h3>
        <Bar label={`完成 ${done}`} value={done} max={Math.max(1, intents.length)} color="#4f7a55" mounted={mounted} />
        <Bar label={`受阻 ${blocked}`} value={blocked} max={Math.max(1, intents.length)} color="#c7895b" mounted={mounted} />
        <Bar label={`进行中 ${activeCount}`} value={activeCount} max={Math.max(1, intents.length)} color="#6aa2ff" mounted={mounted} />
      </section>

      {assetTotal > 0 && (
        <section className="rt-panel rt-anim" style={{ animationDelay: '120ms' }}>
          <h3>资产覆盖度</h3>
          <Bar label={`已测 ${tested}/${assetTotal}`} value={tested} max={assetTotal} color="#7fb069" mounted={mounted} />
          <Bar label={`未测 ${assetTotal - tested}`} value={assetTotal - tested} max={assetTotal} color="#46505c" mounted={mounted} />
        </section>
      )}

      {projection.objectives.length > 0 && (
        <section className="rt-panel rt-anim" style={{ animationDelay: '160ms' }}>
          <h3>目标达成（crown jewels）</h3>
          <Bar label={`已证实 ${objectivesDone}/${projection.objectives.length}`} value={objectivesDone} max={projection.objectives.length} color="#c9a2ff" mounted={mounted} />
        </section>
      )}

      {(techniques.length > 0 || intents.some((n) => n.phase != null)) && (
        <section className="rt-panel rt-anim" style={{ animationDelay: '200ms' }}>
          <h3>ATT&CK 技术覆盖</h3>
          {techniques.length === 0 ? (
            <p className="rt-hint">意图/漏洞尚未标注技术。</p>
          ) : (
            <div className="rt-wall">
              {techniques.map((t) => (
                <span
                  key={t}
                  className={`rt-cell ${proven.has(t) ? 'rt-cell-proven' : 'rt-cell-attempted'}`}
                  title={proven.has(t) ? `${t} — 已有漏洞证实` : `${t} — 仅尝试`}
                >
                  {t}{proven.has(t) ? ' ✓' : ''}
                </span>
              ))}
            </div>
          )}
          <div className="rt-meta">
            <span className="rt-tested">✓ 绿色 = 有漏洞证实</span> · <span className="rt-untested">琥珀 = 仅计划/尝试</span>
          </div>
        </section>
      )}

      <section className="rt-panel rt-anim" style={{ animationDelay: '240ms' }}>
        <h3>Kill-chain 阶段分布</h3>
        <div className="rt-lanes">
          {PHASE_LANES.map((p) => {
            const lane = intents.filter((n) => n.phase === p)
            return (
              <div key={p} className={`rt-lane ${lane.length === 0 ? 'rt-lane-empty' : ''}`}>
                <header>{PHASE_ZH[p]} <code>{p}</code></header>
                <span className="rt-lane-count">{lane.length}</span>
                {lane.slice(0, 3).map((n) => (
                  <div key={n.id} className="rt-lane-item" title={`${n.id} ${n.title}`}>{truncate(n.title, 14)}</div>
                ))}
                {lane.length > 3 && <div className="rt-hint">…共 {lane.length}</div>}
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}

function Bar({ label, value, max, color, mounted }: {
  label: string; value: number; max: number; color: string; mounted: boolean
}): React.ReactNode {
  const pct = Math.min(100, Math.round((value / Math.max(1, max)) * 100))
  return (
    <div className="rt-bar-row">
      <span className="rt-bar-label">{label}</span>
      <div className="rt-bar-track">
        <div
          className="rt-bar-fill"
          style={{ width: mounted ? `${pct}%` : '0%', background: color }}
        />
      </div>
      <span className="rt-bar-pct">{pct}%</span>
    </div>
  )
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}
