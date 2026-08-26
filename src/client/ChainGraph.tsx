/**
 * Interactive chain graph: canvas force layout (see ChainCanvas) plus a
 * detail drawer for the selected node and a relation legend. Facts/findings
 * appear as physics-driven leaf nodes; intents stay draggable chips.
 */

import { useEffect, useState } from 'react'
import type { RedteamProjection } from '../types.js'
import { ChainCanvas } from './ChainCanvas.js'

const RELATION_LEGEND: { id: string; label: string; color: string }[] = [
  { id: 'spawns', label: '派生意图', color: '#6aa2ff' },
  { id: 'yields', label: '产出事实', color: '#5b87c7' },
  { id: 'proves', label: '证实漏洞', color: '#e05c5c' },
  { id: 'depends_on', label: '链依赖', color: '#e0975b' },
  { id: 'derived_from', label: '血缘', color: '#8a7fc7' },
]

export function ChainGraph({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const [selected, setSelected] = useState<string | null>(null)
  useEffect(() => {
    if (selected !== null && !chainNodeExists(projection, selected)) setSelected(null)
  }, [projection, selected])

  const goal = projection.nodes.find((n) => n.kind === 'goal')
  if (goal === undefined) return <p className="rt-empty">(no engagement)</p>

  const node = projection.nodes.find((n) => n.id === selected)
  const finding = projection.findings.find((f) => f.id === selected)
  const fact = projection.facts.find((f) => f.id === selected)

  return (
    <div>
      <ChainCanvas projection={projection} selectedId={selected} onSelect={setSelected} />
      <div className="rt-legend">
        {RELATION_LEGEND.map((r) => (
          <span key={r.id} className="rt-legend-item">
            <i style={{ background: r.color }} /> {r.label}
          </span>
        ))}
      </div>
      {selected !== null && (
        <div className={`rt-drawer ${selected !== null ? 'rt-drawer-open' : ''}`}>
          <div className="rt-drawer-head">
            <strong>{node !== undefined ? truncate(node.title, 40) : finding !== undefined ? finding.title : fact !== undefined ? truncate(fact.detail, 40) : selected}</strong>
            <button className="rt-tab" onClick={() => setSelected(null)}>×</button>
          </div>
          <div className="rt-drawer-body">
            <code>{selected}</code>
            {node !== undefined && (
              <>
                {node.status !== null && <div className="rt-meta">状态 / Status: {node.status}</div>}
                {node.phase != null && <div className="rt-meta">阶段 / Phase: {node.phase}</div>}
                {node.assetIds.length > 0 && (
                  <div className="rt-meta">锚定资产: {node.assetIds.map((a) => <code key={a}>{a} </code>)}</div>
                )}
                {(node.techniqueIds ?? []).length > 0 && (
                  <div className="rt-techs">
                    {(node.techniqueIds ?? []).map((t) => <span className="rt-tech" key={t}>{t}</span>)}
                  </div>
                )}
              </>
            )}
            {finding !== undefined && (
              <>
                <div className="rt-meta">
                  <span className={`rt-sev ${finding.severity}`}>{finding.severity.toUpperCase()}</span>
                  {finding.cvssScore !== null && <> · CVSS {finding.cvssScore.toFixed(1)}</>}
                  {finding.status === 'fixed' && <> · ✅ 已修复</>}
                </div>
                {finding.affectedAssetId !== null && <div className="rt-meta">影响资产: <code>{finding.affectedAssetId}</code></div>}
                {finding.techniqueIds.length > 0 && (
                  <div className="rt-techs">
                    {finding.techniqueIds.map((t) => <span className="rt-tech" key={t}>{t}</span>)}
                  </div>
                )}
              </>
            )}
            {fact !== undefined && (
              <>
                <div className="rt-meta">{fact.detail}</div>
                {fact.phase != null && <div className="rt-meta">阶段 / Phase: {fact.phase}</div>}
                {fact.confidence !== null && <div className="rt-meta">置信度 / Confidence: {fact.confidence}</div>}
                {fact.evidenceIds.length > 0 && (
                  <div className="rt-meta">
                    证据 / Evidence:{' '}
                    {fact.evidenceIds.map((eid) => {
                      const ev = projection.evidence.find((x) => x.id === eid)
                      return <code key={eid} title={ev?.label ?? ''}>{eid}{ev !== undefined ? ` (${ev.kind})` : ''} </code>
                    })}
                  </div>
                )}
              </>
            )}
            <div className="rt-meta rt-hint">完整复现步骤与证据见「报告」标签或 redteam_report 导出。</div>
          </div>
        </div>
      )}
    </div>
  )
}

function chainNodeExists(projection: RedteamProjection, id: string): boolean {
  if (projection.nodes.some((n) => n.id === id)) return true
  if (projection.findings.some((f) => f.id === id)) return true
  return projection.edges.some((e) => e.from === id || e.to === id)
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}
