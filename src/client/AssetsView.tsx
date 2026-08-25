/** Assets sub-view: flat table of the projection window's assets, with a
 * tested badge computed from intent anchors (assetIds) and finding targets. */

import type { RedteamProjection } from '../types.js'

function testedAssetIds(projection: RedteamProjection): Set<string> {
  const tested = new Set<string>()
  for (const node of projection.nodes) {
    for (const assetId of node.assetIds ?? []) tested.add(assetId)
  }
  for (const finding of projection.findings) {
    if (finding.affectedAssetId !== null) tested.add(finding.affectedAssetId)
  }
  return tested
}

export function AssetsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.assets.length === 0) {
    return <p className="rt-empty">还没有登记资产。</p>
  }
  const tested = testedAssetIds(projection)
  return (
    <table className="rt-assets">
      <thead>
        <tr>
          <th>id</th>
          <th>类型</th>
          <th>标识</th>
          <th>父资产</th>
          <th>标签</th>
          <th>覆盖</th>
        </tr>
      </thead>
      <tbody>
        {projection.assets.map((asset) => (
          <tr key={asset.id}>
            <td><code>{asset.id}</code></td>
            <td>{asset.type}</td>
            <td>{asset.value}</td>
            <td>{asset.parentId === null ? '' : <code>{asset.parentId}</code>}</td>
            <td>{asset.tags.length > 0
              ? <span className="rt-tags">{asset.tags.map((t) => <span className="rt-tech" key={t}>{t}</span>)}</span>
              : '—'}</td>
            <td>{tested.has(asset.id)
              ? <span className="rt-tested">✓ 已测</span>
              : <span className="rt-untested">未测</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
