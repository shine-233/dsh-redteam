/**
 * IOCs sub-view: indicators of compromise grouped by type with per-type
 * colour chips, staggered row entrance, and sample linkage.
 */

import { useState } from 'react'
import type { RedteamProjection } from '../types.js'

const IOC_COLOR: Record<string, string> = {
  ip: '#6aa2ff', domain: '#7fb069', url: '#e0c04e', hash: '#c7895b',
  mutex: '#8a7fc7', registry: '#5b87c7', filepath: '#7f8fa0',
  'user-agent': '#c75b5b', email: '#e0975b', other: '#8b95a1',
}

export function IocsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const [filter, setFilter] = useState<string | null>(null)
  if (projection.iocs.length === 0) {
    return <p className="rt-empty">还没有登记 IOC。redteam_add_ioc 按 ip/domain/url/hash 等分类记录攻击指标。</p>
  }
  const types = [...new Set(projection.iocs.map((i) => i.type))]
  const shown = filter === null ? projection.iocs : projection.iocs.filter((i) => i.type === filter)
  return (
    <div>
      <div className="rt-kind-chips rt-anim">
        <button
          className={`rt-tab ${filter === null ? 'rt-chip-active' : ''}`}
          onClick={() => setFilter(null)}
        >
          全部 · {projection.iocs.length}
        </button>
        {types.map((t) => (
          <button
            key={t}
            className={`rt-tab ${filter === t ? 'rt-chip-active' : ''}`}
            onClick={() => setFilter(filter === t ? null : t)}
          >
            <i className="rt-dot" style={{ background: IOC_COLOR[t] ?? IOC_COLOR.other }} /> {t} · {projection.iocs.filter((i) => i.type === t).length}
          </button>
        ))}
      </div>
      <table className="rt-assets">
        <thead>
          <tr><th>id</th><th>类型</th><th>指标值</th><th>关联样本</th></tr>
        </thead>
        <tbody>
          {shown.map((ioc, i) => (
            <tr key={ioc.id} className="rt-row-anim" style={{ animationDelay: `${i * 35}ms` }}>
              <td><code>{ioc.id}</code></td>
              <td><span className="rt-tech" style={{ borderColor: IOC_COLOR[ioc.type] ?? IOC_COLOR.other }}>{ioc.type}</span></td>
              <td><code>{ioc.value}</code></td>
              <td>{ioc.sampleId !== null ? <code>{ioc.sampleId}</code> : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="rt-hint">点击上方类型徽章可筛选；IOC 附录表随报告导出。</p>
    </div>
  )
}
