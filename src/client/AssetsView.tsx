/** Assets sub-view: flat table of the projection window's assets. */

import type { RedteamProjection } from '../types.js'

export function AssetsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.assets.length === 0) {
    return <p className="rt-empty">还没有登记资产。</p>
  }
  return (
    <table className="rt-assets">
      <thead>
        <tr>
          <th>id</th>
          <th>类型</th>
          <th>标识</th>
          <th>父资产</th>
        </tr>
      </thead>
      <tbody>
        {projection.assets.map((asset) => (
          <tr key={asset.id}>
            <td><code>{asset.id}</code></td>
            <td>{asset.type}</td>
            <td>{asset.value}</td>
            <td>{asset.parentId === null ? '' : <code>{asset.parentId}</code>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
