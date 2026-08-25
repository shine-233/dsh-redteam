/**
 * Samples sub-view: analysed binaries/documents under chain of custody.
 * sha256 is the custody anchor — shown shortened with the full hash on hover.
 */

import type { RedteamProjection } from '../types.js'

export function SamplesView({ projection }: { projection: RedteamProjection }): React.ReactNode {
  if (projection.samples.length === 0) {
    return <p className="rt-empty">还没有登记样本。redteam_add_sample 以 sha256 为保管链锚点登记二进制/文档/内存转储。</p>
  }
  return (
    <div>
      <div className="rt-kind-chips rt-anim">
        {kindCounts(projection.samples.map((s) => s.kind)).map(([k, n]) => (
          <span className="rt-tech" key={k}>{k} · {n}</span>
        ))}
      </div>
      <table className="rt-assets">
        <thead>
          <tr><th>id</th><th>类型</th><th>位置</th><th>文件类型</th><th>sha256</th></tr>
        </thead>
        <tbody>
          {projection.samples.map((s, i) => (
            <tr key={s.id} className="rt-row-anim" style={{ animationDelay: `${i * 40}ms` }}>
              <td><code>{s.id}</code></td>
              <td><span className="rt-tech">{s.kind}</span></td>
              <td><code>{s.location}</code></td>
              <td>{s.fileType ?? '—'}</td>
              <td><code title={s.sha256}>{shortHash(s.sha256)}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="rt-hint">保管链以 sha256 为锚点；完整 md5/sha1/架构信息见报告导出。</p>
    </div>
  )
}

function kindCounts(kinds: string[]): [string, number][] {
  const m = new Map<string, number>()
  for (const k of kinds) m.set(k, (m.get(k) ?? 0) + 1)
  return [...m.entries()].sort((a, b) => b[1] - a[1])
}

function shortHash(hash: string): string {
  return hash.length > 18 ? `${hash.slice(0, 8)}…${hash.slice(-6)}` : hash
}
