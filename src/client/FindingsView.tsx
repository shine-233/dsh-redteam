/**
 * Findings sub-view: severity-sorted cards from the projection window. The
 * window carries title/severity/intent per finding; full reproducible steps
 * and evidence bodies live in the record system (report exports them).
 */

import type { RedteamProjection } from '../types.js'

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function FindingsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.findings.length === 0) {
    return <p className="rt-empty">还没有已确认的漏洞。漏洞需要至少一条可复现步骤才能写入记录。</p>
  }
  const sorted = [...projection.findings].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9),
  )
  return (
    <div>
      {sorted.map((finding) => {
        const intent = projection.nodes.find((n) => n.id === finding.intentId)
        return (
          <div className="rt-finding" key={finding.id}>
            <span className={`rt-sev ${finding.severity}`}>{finding.severity.toUpperCase()}</span>
            <strong>{finding.title}</strong>
            <div className="rt-meta">
              <code>{finding.id}</code>
              {intent !== undefined ? <> · 由意图「{intent.title}」证实</> : null}
            </div>
          </div>
        )
      })}
      <p className="rt-hint">复现步骤、影响资产与证据引用见报告导出（redteam_report）。</p>
    </div>
  )
}
