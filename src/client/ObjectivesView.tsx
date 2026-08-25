/**
 * Objectives sub-view: crown-jewel checklist. Proven entries light up with a
 * staggered check animation; open ones stay as pulsing targets.
 */

import type { RedteamProjection } from '../types.js'

export function ObjectivesView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.objectives.length === 0) {
    return <p className="rt-empty">还没有登记目标。redteam_add_objective 定义 crown-jewel 成功判据，redteam_prove_objective 以证据证实。</p>
  }
  const proven = projection.objectives.filter((o) => o.provenAt !== null).length
  return (
    <div>
      <div className="rt-progress">
        <span>已证实 / Proven: <b>{proven}/{projection.objectives.length}</b></span>
      </div>
      <div className="rt-objectives">
        {projection.objectives.map((o, i) => (
          <div
            key={o.id}
            className={`rt-objective ${o.provenAt !== null ? 'rt-objective-proven' : ''} rt-row-anim`}
            style={{ animationDelay: `${i * 60}ms` }}
            title={o.provenAt !== null ? `证实于 ${new Date(o.provenAt).toLocaleString()}` : '尚未证实'}
          >
            <span className={`rt-check ${o.provenAt !== null ? 'rt-check-on' : ''}`}>
              {o.provenAt !== null ? '✓' : '○'}
            </span>
            <span className="rt-objective-title">{o.title}</span>
            <code>{o.id}</code>
          </div>
        ))}
      </div>
      <p className="rt-hint">目标独立于 goal 结论：每项目标各自证实或保持开放，报告头部引用。</p>
    </div>
  )
}
