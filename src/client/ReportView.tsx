/**
 * Report sub-view. The browser cannot invoke host tools directly, so this
 * view renders the engagement summary and the exact ask that makes the model
 * export a full report; the conversation carries the rendered markdown.
 */

import type { RedteamProjection } from '../types.js'

export function ReportView({ projection }: { projection: RedteamProjection & { sessionId?: string } }): React.ReactNode {
  const c = projection.counts
  return (
    <div className="rt-md">
      <h2>报告 / Report</h2>
      <p>
        当前窗口：意图 <b>{c.intents}</b> · 事实 <b>{c.facts}</b> · 资产 <b>{c.assets}</b> · 漏洞{' '}
        <b>{c.findings}</b> · 证据 <b>{c.evidence}</b>
      </p>
      <p>
        在对话里发送以下指令即可生成完整报告（含授权留痕、探索链路、资产清单、按严重度排序的漏洞与复现步骤）：
      </p>
      <pre>{`导出红队测试报告（redteam_report，format=markdown，includeEvidence=true）`}</pre>
      <p>
        程序化消费使用 <code>format=json</code>。历史 engagement 用 <code>redteam_engagements</code> 查看。
      </p>
      <p className="rt-hint">
        说明：Web 标签页读取会话投影（最近 200 条窗口），完整记录以存储层为准。
      </p>
    </div>
  )
}
