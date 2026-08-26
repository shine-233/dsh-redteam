/**
 * Findings sub-view: severity-sorted cards from the projection window. The
 * window carries title/severity/intent per finding; full reproducible steps
 * and evidence bodies live in the record system (report exports them).
 */

import type { RedteamProjection } from '../types.js'

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const DETECTED_BADGE: Record<string, { icon: string; label: string; cls: string }> = {
  undetected: { icon: '🫥', label: '未被检测', cls: 'rt-det-undetected' },
  logged: { icon: '📝', label: '仅日志', cls: 'rt-det-logged' },
  alerted: { icon: '🔔', label: '触发告警', cls: 'rt-det-alerted' },
  prevented: { icon: '⛔', label: '被阻断', cls: 'rt-det-prevented' },
}

const FLAG_BADGE: Record<string, { label: string; cls: string }> = {
  'under-review': { label: '🔎 审核中', cls: 'rt-flag-under-review' },
  'false-positive': { label: '🚫 误报', cls: 'rt-flag-false-positive' },
  'out-of-scope': { label: '⛔ 范围外', cls: 'rt-flag-out-of-scope' },
  'risk-accepted': { label: '🤝 风险接受', cls: 'rt-flag-risk-accepted' },
}

export function FindingsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.findings.length === 0) {
    return <p className="rt-empty">还没有已确认的漏洞。漏洞需要至少一条可复现步骤才能写入记录。</p>
  }
  const sorted = [...projection.findings].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9),
  )
  return (
    <div>
      {sorted.map((finding, i) => {
        const intent = projection.nodes.find((n) => n.id === finding.intentId)
        return (
          <div className="rt-finding" key={finding.id} style={{ animationDelay: `${Math.min(i * 50, 400)}ms` }}>
            <span className={`rt-sev ${finding.severity}`}>{finding.severity.toUpperCase()}</span>
            <strong>{finding.title}</strong>
            {finding.status === 'fixed' && <span className="rt-fixed">✅ 已修复</span>}
            {finding.duplicateOf !== null && <span className="rt-tag">重复 / dup of <code>{finding.duplicateOf}</code></span>}
            {finding.cvssScore !== null && (
              <span className={`rt-cvss rt-cvss-${finding.cvssScore >= 9 ? 'crit' : finding.cvssScore >= 7 ? 'high' : 'mid'}`}>
                CVSS {finding.cvssScore.toFixed(1)}
              </span>
            )}
            {finding.detected !== null && DETECTED_BADGE[finding.detected] !== undefined && (
              <span className={`rt-detected ${DETECTED_BADGE[finding.detected]!.cls}`}>
                {DETECTED_BADGE[finding.detected]!.icon} {DETECTED_BADGE[finding.detected]!.label}
              </span>
            )}
            {finding.flag !== null && FLAG_BADGE[finding.flag] !== undefined && (
              <span className={`rt-flagged ${FLAG_BADGE[finding.flag]!.cls}`}>
                {FLAG_BADGE[finding.flag]!.label}
              </span>
            )}
            <div className="rt-meta">
              <code>{finding.id}</code>
              {intent !== undefined ? <> · 由意图「{intent.title}」证实</> : null}
            </div>
            {finding.techniqueIds.length > 0 && (
              <div className="rt-techs">
                {finding.techniqueIds.map((t) => (
                  <span className="rt-tech" key={t}>{t}</span>
                ))}
              </div>
            )}
          </div>
        )
      })}
      <p className="rt-hint">复现步骤、影响资产与证据引用见报告导出（redteam_report）。</p>
    </div>
  )
}
