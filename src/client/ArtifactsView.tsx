/**
 * Artifacts sub-view: deliverables produced by the engagement (loot files,
 * screenshots, exploit scripts, dumps) from the projection window.
 */

import type { RedteamProjection } from '../types.js'

export function ArtifactsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.artifacts.length === 0) {
    return <p className="rt-empty">还没有登记产物。redteam_add_artifact 记录战利品文件、截图、exp 脚本、数据转储等交付物。</p>
  }
  return (
    <table className="rt-assets">
      <thead>
        <tr>
          <th>id</th>
          <th>类型</th>
          <th>位置</th>
          <th>意图</th>
          <th>资产</th>
        </tr>
      </thead>
      <tbody>
        {projection.artifacts.map((a) => (
          <tr key={a.id}>
            <td><code>{a.id}</code></td>
            <td><span className="rt-tech">{a.kind}</span></td>
            <td><code>{a.location}</code></td>
            <td>{a.intentId !== null ? <code>{a.intentId}</code> : '—'}</td>
            <td>{a.assetId !== null ? <code>{a.assetId}</code> : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
