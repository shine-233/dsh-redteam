/**
 * Credentials sub-view: masked credential material from the projection
 * window. Raw secrets never leave the record system.
 */

import type { RedteamProjection } from '../types.js'

export function CredentialsView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.credentials.length === 0) {
    return <p className="rt-empty">还没有登记的凭据。redteam_add_credential 写入后在此展示（密文脱敏）。</p>
  }
  return (
    <div>
      <table className="rt-assets">
        <thead>
          <tr>
            <th>id</th><th>类型</th><th>用户名</th><th>目标</th><th>资产</th><th>状态</th>
          </tr>
        </thead>
        <tbody>
          {projection.credentials.map((c) => (
            <tr key={c.id}>
              <td><code>{c.id}</code></td>
              <td>{c.kind}</td>
              <td>{c.username ?? '—'}</td>
              <td>{c.target ?? '—'}</td>
              <td>{c.assetId !== null ? <code>{c.assetId}</code> : '—'}</td>
              <td className={`rt-cred-status rt-cred-status-${c.status}`}>{c.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="rt-hint">密文永不进入本视图；明文仅存于本地记录库，报告导出同样脱敏。</p>
    </div>
  )
}
