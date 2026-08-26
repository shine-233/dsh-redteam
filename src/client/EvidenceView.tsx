/**
 * Evidence & facts sub-view: evidence metadata (kind/label — the captured
 * content never enters the projection) and fact summaries with their
 * evidence citations. Closes the last two record domains without a surface.
 */

import type { RedteamProjection } from '../types.js'

const KIND_ICON: Record<string, string> = {
  command: '⌨', output: '📄', screenshot: '🖼', file: '🗂', url: '🔗', note: '✏',
}

export function EvidenceView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.evidence.length === 0 && projection.facts.length === 0) {
    return <p className="rt-empty">还没有证据与事实。redteam_add_evidence 留证、redteam_add_fact 记录确认观察；证据内容不进 Web 视图，只在本地记录库与报告附录中。</p>
  }
  const evidenceById = new Map(projection.evidence.map((e) => [e.id, e]))
  return (
    <div>
      <section className="rt-panel rt-anim">
        <h3>证据 / Evidence · {projection.evidence.length}</h3>
        {projection.evidence.length === 0 ? <p className="rt-empty">（无）</p> : (
          <table className="rt-assets">
            <thead>
              <tr><th>id</th><th>类型</th><th>标签</th></tr>
            </thead>
            <tbody>
              {projection.evidence.map((ev, i) => (
                <tr key={ev.id} className="rt-row-anim" style={{ animationDelay: `${Math.min(i * 35, 350)}ms` }}>
                  <td><code>{ev.id}</code></td>
                  <td><span className="rt-tech">{KIND_ICON[ev.kind] ?? '•'} {ev.kind}</span></td>
                  <td>{ev.label !== '' ? ev.label : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section className="rt-panel rt-anim" style={{ animationDelay: '80ms' }}>
        <h3>事实 / Facts · {projection.facts.length}</h3>
        {projection.facts.length === 0 ? <p className="rt-empty">（无）</p> : (
          <div className="rt-facts">
            {projection.facts.map((f, i) => (
              <div key={f.id} className="rt-fact rt-row-anim" style={{ animationDelay: `${Math.min(i * 40, 400)}ms` }}>
                <code>{f.id}</code>
                {f.phase != null && <span className="rt-tech">{f.phase}</span>}
                {f.confidence !== null && f.confidence < 1 && <span className="rt-untested">置信 {f.confidence}</span>}
                <span className="rt-fact-detail">{f.detail}</span>
                {f.evidenceIds.length > 0 && (
                  <span className="rt-meta">
                    〔{f.evidenceIds.map((eid) => {
                      const ev = evidenceById.get(eid)
                      return <code key={eid} title={ev?.label ?? ''}>{eid}{ev !== undefined ? ` ${KIND_ICON[ev.kind] ?? ''}` : ''}</code>
                    })}〕
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
