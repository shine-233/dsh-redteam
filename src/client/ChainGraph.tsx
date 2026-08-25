/**
 * Static layered chain graph in plain SVG: goal on top, intents below, and
 * yields/proves edges fanning out. No graph library — layout is a two-pass
 * column assignment over the derived edges.
 */

import type { RedteamProjection } from '../types.js'

const NODE_W = 170
const NODE_H = 38
const GAP_X = 56
const GAP_Y = 18

interface Placed {
  id: string
  kind: 'goal' | 'intent'
  title: string
  x: number
  y: number
}

export function ChainGraph({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const goal = projection.nodes.find((n) => n.kind === 'goal')
  const intents = projection.nodes.filter((n) => n.kind === 'intent')

  if (goal === undefined) return <p className="rt-empty">(no engagement)</p>

  // Column per intent; the goal column is centered above them.
  const columns = intents.map((intent) => ({
    intent,
    children: projection.edges.filter(
      (e) => e.relation !== 'parent' && e.relation !== 'spawns' && e.from === intent.id,
    ),
  }))

  const width = Math.max(1, intents.length) * (NODE_W + GAP_X)
  const maxStack = Math.max(1, ...columns.map((c) => c.children.length))
  const height = NODE_H + 70 + maxStack * (NODE_H + GAP_Y)

  const placed: Placed[] = []
  const goalX = (width - NODE_W) / 2
  placed.push({ id: goal.id, kind: 'goal', title: goal.title, x: goalX, y: 8 })

  const edgeLines: { d: string; relation: string; midX: number; midY: number; label: string }[] = []

  columns.forEach((col, i) => {
    const x = i * (NODE_W + GAP_X) + GAP_X / 2
    const yTop = NODE_H + 54
    placed.push({ id: col.intent.id, kind: 'intent', title: col.intent.title, x, y: yTop })
    edgeLines.push({
      d: curve(goalX + NODE_W / 2, 8 + NODE_H, x + NODE_W / 2, yTop),
      relation: 'spawns',
      midX: (goalX + NODE_W / 2 + x + NODE_W / 2) / 2,
      midY: (8 + NODE_H + yTop) / 2,
      label: '意图',
    })
    col.children.forEach((edge, j) => {
      const cy = yTop + NODE_H + GAP_Y + j * (NODE_H + GAP_Y)
      const label = edge.relation === 'proves' ? `漏洞 ${edge.to}` : `事实 ${edge.to}`
      placed.push({
        id: edge.to,
        kind: 'intent',
        title: label,
        x,
        y: cy,
      })
      edgeLines.push({
        d: curve(x + NODE_W / 2, yTop + NODE_H, x + NODE_W / 2, cy),
        relation: edge.relation,
        midX: x + NODE_W / 2,
        midY: (yTop + NODE_H + cy) / 2,
        label: edge.relation === 'proves' ? '证实' : '产出',
      })
    })
  })

  return (
    <div>
      <svg className="rt-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="探索链路图">
        {edgeLines.map((e, i) => (
          <g key={i}>
            <path className={`rt-edge ${e.relation}`} d={e.d} />
            <text className="rt-pill" x={e.midX + 6} y={e.midY}>{e.label}</text>
          </g>
        ))}
        {placed.map((n) => (
          <g key={n.id} className={`rt-node ${n.kind}`}>
            <rect x={n.x} y={n.y} width={NODE_W} height={NODE_H} rx={8} />
            <text x={n.x + 10} y={n.y + 17}>
              <tspan fontWeight="600">{truncate(n.title, 18)}</tspan>
            </text>
            <text x={n.x + 10} y={n.y + 30} fill="#8b95a1">
              {n.id}
            </text>
            <title>{`${n.id}\n${n.title}`}</title>
          </g>
        ))}
      </svg>
      {projection.assets.length > 0 && (
        <p className="rt-hint">资产以列表与父子关系呈现在「资产」子标签；链路图聚焦目标→意图→产出。</p>
      )}
    </div>
  )
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

function curve(x1: number, y1: number, x2: number, y2: number): string {
  if (Math.abs(x1 - x2) < 4) return `M ${x1} ${y1} L ${x2} ${y2}`
  const my = (y1 + y2) / 2
  return `M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`
}
