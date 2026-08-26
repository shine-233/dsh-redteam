/**
 * Canvas force-directed chain graph, zero-dependency. Hand-rolled physics
 * (repulsion + springs + centering), pointer interactions (wheel zoom around
 * cursor, background pan, node drag with reheated simulation), hover
 * neighbour highlighting, click selection, and directional particles that
 * flow along edges to visualise attack-chain direction.
 */

import { useEffect, useRef } from 'react'
import type { RedteamProjection } from '../types.js'

interface GraphNode {
  id: string
  kind: 'goal' | 'intent' | 'fact' | 'finding'
  label: string
  status: string | null
  severity?: string | undefined
  x: number
  y: number
  vx: number
  vy: number
  fixed: boolean
}

interface SimEdge {
  from: string
  to: string
  relation: string
}

const RELATION_STYLE: Record<string, { color: string; dash: number[]; speed: number; width: number }> = {
  spawns: { color: '#6aa2ff', dash: [], speed: 0.5, width: 1.6 },
  yields: { color: '#5b87c7', dash: [], speed: 0.9, width: 1.2 },
  proves: { color: '#e05c5c', dash: [], speed: 1.2, width: 2 },
  derived_from: { color: '#8a7fc7', dash: [3, 4], speed: 0.7, width: 1 },
  depends_on: { color: '#e0975b', dash: [6, 4], speed: 1.6, width: 1.4 },
  parent: { color: '#4f7a55', dash: [4, 3], speed: 0.5, width: 1 },
}

const SEVERITY_FILL: Record<string, string> = {
  critical: '#ff5c5c',
  high: '#ff9350',
  medium: '#e0c04e',
  low: '#7fb069',
  info: '#8b95a1',
}

const KIND_COLOR: Record<string, string> = {
  goal: '#6aa2ff',
  intent: '#7f8fa0',
  fact: '#5b87c7',
  finding: '#c75b5b',
}

function statusColor(status: string | null): string {
  if (status === 'done') return '#4f7a55'
  if (status === 'blocked') return '#c7895b'
  return KIND_COLOR.intent ?? '#7f8fa0'
}

export function buildGraph(projection: RedteamProjection): { nodes: GraphNode[]; edges: SimEdge[] } {
  const nodes: GraphNode[] = []
  const edges: SimEdge[] = projection.edges.map((e) => ({ from: e.from, to: e.to, relation: e.relation }))
  const seen = new Set<string>()
  const push = (n: Omit<GraphNode, 'x' | 'y' | 'vx' | 'vy' | 'fixed'>) => {
    if (seen.has(n.id)) return
    seen.add(n.id)
    nodes.push({ ...n, x: 0, y: 0, vx: 0, vy: 0, fixed: false })
  }
  for (const n of projection.nodes) {
    push({ id: n.id, kind: n.kind === 'goal' ? 'goal' : 'intent', label: n.title, status: n.status })
  }
  for (const e of edges) {
    if ((e.relation === 'yields')) {
      const f = projection.facts.find((x) => x.id === e.to)
      push({ id: e.to, kind: 'fact', label: f !== undefined ? f.detail : e.to, status: null })
    }
    if ((e.relation === 'proves')) {
      const f = projection.findings.find((x) => x.id === e.to)
      push({ id: e.to, kind: 'finding', label: f !== undefined ? `${f.severity.toUpperCase()} ${f.title}` : e.to, status: f?.status ?? null, severity: f?.severity })
    }
    if (e.relation === 'derived_from' && !projection.nodes.some((n) => n.id === e.from)) {
      const f = projection.facts.find((x) => x.id === e.from)
      push({ id: e.from, kind: 'fact', label: f !== undefined ? f.detail : e.from, status: null })
    }
    if (e.relation === 'depends_on') {
      if (!seen.has(e.from)) push({ id: e.from, kind: 'intent', label: e.from, status: null })
      if (!seen.has(e.to)) push({ id: e.to, kind: 'intent', label: e.to, status: null })
    }
  }
  return { nodes, edges }
}

interface InteractionState {
  dragging: GraphNode | null
  panning: boolean
  lastX: number
  lastY: number
  moved: boolean
  hoverId: string | null
  k: number
  tx: number
  ty: number
  alpha: number
}

export function ChainCanvas({
  projection,
  selectedId,
  onSelect,
}: {
  projection: RedteamProjection
  selectedId: string | null
  onSelect: (id: string | null) => void
}): React.ReactNode {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const simRef = useRef<{ nodes: GraphNode[]; edges: SimEdge[] }>({ nodes: [], edges: [] })
  const interRef = useRef<InteractionState>({ dragging: null, panning: false, lastX: 0, lastY: 0, moved: false, hoverId: null, k: 1, tx: 0, ty: 0, alpha: 1 })

  useEffect(() => {
    const { nodes, edges } = buildGraph(projection)
    const prev = new Map(simRef.current.nodes.map((n) => [n.id, n]))
    let i = 0
    const ring = Math.max(1, nodes.length)
    for (const n of nodes) {
      const old = prev.get(n.id)
      if (old !== undefined) {
        n.x = old.x
        n.y = old.y
      } else {
        const a = (i / ring) * Math.PI * 2
        n.x = Math.cos(a) * 140 + (i % 7) * 13
        n.y = Math.sin(a) * 140 + (i % 5) * 11
        i += 1
      }
    }
    simRef.current = { nodes, edges }
    interRef.current.alpha = 1
  }, [projection])

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (canvas === null || wrap === null) return
    const ctx = canvas.getContext('2d')
    if (ctx === null) return

    let raf = 0
    let width = wrap.clientWidth
    let height = Math.max(320, wrap.clientHeight || 420)

    const resize = () => {
      const dpr = window.devicePixelRatio || 1
      width = wrap.clientWidth
      height = Math.max(320, wrap.clientHeight || 420)
      canvas.width = Math.max(1, Math.round(width * dpr))
      canvas.height = Math.max(1, Math.round(height * dpr))
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resize) : null
    if (ro !== null) ro.observe(wrap)

    const step = () => {
      const { nodes, edges } = simRef.current
      const it = interRef.current
      const ids = new Map(nodes.map((n) => [n.id, n]))
      if (it.alpha > 0.005) {
        const rep = 2600 / Math.max(1, Math.sqrt(nodes.length))
        for (let i = 0; i < nodes.length; i++) {
          const a = nodes[i]!
          for (let j = i + 1; j < nodes.length; j++) {
            const b = nodes[j]!
            let dx = b.x - a.x
            let dy = b.y - a.y
            let d2 = dx * dx + dy * dy
            if (d2 < 1) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1 }
            const d = Math.sqrt(d2)
            const f = (rep / d2) * it.alpha
            const fx = (dx / d) * f
            const fy = (dy / d) * f
            a.vx -= fx; a.vy -= fy
            b.vx += fx; b.vy += fy
          }
          a.vx -= a.x * 0.0008 * it.alpha
          a.vy -= a.y * 0.0008 * it.alpha
        }
        for (const e of edges) {
          const a = ids.get(e.from)
          const b = ids.get(e.to)
          if (a === undefined || b === undefined) continue
          const rest = e.relation === 'spawns' ? 130 : e.relation === 'depends_on' ? 90 : 105
          let dx = b.x - a.x
          let dy = b.y - a.y
          const d = Math.sqrt(dx * dx + dy * dy) || 1
          const f = ((d - rest) / d) * 0.03 * it.alpha
          dx *= f; dy *= f
          if (!a.fixed) { a.vx += dx; a.vy += dy }
          if (!b.fixed) { b.vx -= dx; b.vy -= dy }
        }
        for (const n of nodes) {
          if (n.fixed) { n.vx = 0; n.vy = 0; continue }
          n.vx *= 0.86
          n.vy *= 0.86
          n.x += Math.max(-14, Math.min(14, n.vx))
          n.y += Math.max(-14, Math.min(14, n.vy))
        }
        it.alpha *= 0.985
      }

      ctx.clearRect(0, 0, width, height)
      ctx.save()
      ctx.translate(width / 2 + it.tx, height / 2 + it.ty)
      ctx.scale(it.k, it.k)

      const focus = it.hoverId ?? selectedId
      const neighbours = new Set<string>()
      if (focus !== null) {
        neighbours.add(focus)
        for (const e of edges) {
          if (e.from === focus) neighbours.add(e.to)
          if (e.to === focus) neighbours.add(e.from)
        }
      }
      const dimmed = focus !== null ? (id: string) => !neighbours.has(id) : (_id: string) => false

      const t = performance.now() / 1000
      for (let ei = 0; ei < edges.length; ei++) {
        const e = edges[ei]!
        const a = ids.get(e.from)
        const b = ids.get(e.to)
        if (a === undefined || b === undefined) continue
        const st = RELATION_STYLE[e.relation] ?? RELATION_STYLE.yields!
        const active = focus === null || e.from === focus || e.to === focus
        ctx.globalAlpha = active ? 0.95 : 0.15
        ctx.strokeStyle = st.color
        ctx.lineWidth = st.width
        ctx.setLineDash(st.dash)
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()
        ctx.setLineDash([])
        if (active && !dimmed(a.id) && !dimmed(b.id)) {
          const dotCount = e.relation === 'depends_on' || e.relation === 'proves' ? 2 : 1
          for (let p = 0; p < dotCount; p++) {
            const phase = (t * st.speed + ei * 0.37 + p / dotCount) % 1
            const px = a.x + (b.x - a.x) * phase
            const py = a.y + (b.y - a.y) * phase
            ctx.fillStyle = st.color
            ctx.beginPath()
            ctx.arc(px, py, 2.2, 0, Math.PI * 2)
            ctx.fill()
          }
          const mx = (a.x + b.x) / 2
          const my = (a.y + b.y) / 2
          ctx.save()
          ctx.translate(mx, my)
          const ang = Math.atan2(b.y - a.y, b.x - a.x)
          ctx.rotate(ang)
          ctx.fillStyle = st.color
          ctx.globalAlpha = active ? 0.8 : 0.15
          ctx.beginPath()
          ctx.moveTo(6, 0)
          ctx.lineTo(-4, -3.4)
          ctx.lineTo(-4, 3.4)
          ctx.closePath()
          ctx.fill()
          ctx.restore()
        }
      }
      ctx.globalAlpha = 1

      for (const n of nodes) {
        const dim = dimmed(n.id)
        ctx.globalAlpha = dim ? 0.18 : 1
        const isSel = selectedId === n.id
        const isHover = it.hoverId === n.id
        if (n.kind === 'goal' || n.kind === 'intent') {
          const w = Math.min(190, 26 + n.label.length * 6.4)
          const h = 34
          const color = n.kind === 'goal' ? KIND_COLOR.goal! : statusColor(n.status)
          ctx.fillStyle = '#1b2026'
          ctx.strokeStyle = isSel || isHover ? '#ffffff88' : color
          ctx.lineWidth = n.kind === 'goal' ? 2 : 1.5
          roundRect(ctx, n.x - w / 2, n.y - h / 2, w, h, 8)
          ctx.fill()
          ctx.stroke()
          if (n.kind === 'goal') {
            ctx.save()
            ctx.shadowColor = '#6aa2ff66'
            ctx.shadowBlur = 12
            ctx.stroke()
            ctx.restore()
          }
          ctx.fillStyle = '#dbe2ea'
          ctx.font = '600 11px system-ui, sans-serif'
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillText(truncate(n.label, 22), 0 + n.x, -3 + n.y)
          ctx.fillStyle = '#8b95a1'
          ctx.font = '10px system-ui, sans-serif'
          const badge = n.status === 'done' ? '✓ done' : n.status === 'blocked' ? '⏸ blocked' : n.kind === 'goal' ? '目标' : n.id
          ctx.fillText(badge, n.x, n.y + 10)
        } else {
          const r = n.kind === 'finding' ? 7 : 5
          const fill = n.kind === 'finding' ? (SEVERITY_FILL[n.severity ?? 'info'] ?? '#c75b5b') : '#5b87c7'
          if (isSel || isHover) {
            ctx.strokeStyle = fill
            ctx.lineWidth = 1.4
            ctx.beginPath()
            ctx.arc(n.x, n.y, r + 3.5, 0, Math.PI * 2)
            ctx.stroke()
          }
          ctx.fillStyle = fill
          ctx.beginPath()
          ctx.arc(n.x, n.y, r, 0, Math.PI * 2)
          ctx.fill()
          if (n.kind === 'finding' && (isSel || isHover)) {
            ctx.font = '10px system-ui, sans-serif'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'top'
            ctx.fillStyle = '#dbe2ea'
            ctx.fillText(truncate(n.label, 30), n.x, n.y + r + 5)
          }
        }
      }
      ctx.globalAlpha = 1
      ctx.restore()

      ctx.fillStyle = '#8b95a1'
      ctx.font = '11px system-ui, sans-serif'
      ctx.textAlign = 'left'
      ctx.textBaseline = 'bottom'
      ctx.fillText(`节点 ${nodes.length} · 边 ${edges.length} · 滚轮缩放 / 拖拽平移 / 点选查看`, 10, height - 8)

      raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)

    const pick = (ev: PointerEvent | WheelEvent): GraphNode | null => {
      const rect = canvas.getBoundingClientRect()
      const it = interRef.current
      const x = (ev.clientX - rect.left - width / 2 - it.tx) / it.k
      const y = (ev.clientY - rect.top - height / 2 - it.ty) / it.k
      let best: GraphNode | null = null
      let bestD = Infinity
      for (const n of simRef.current.nodes) {
        const r = n.kind === 'goal' || n.kind === 'intent' ? 46 : 12
        const d = (n.x - x) ** 2 + (n.y - y) ** 2
        if (d < r * r && d < bestD) { best = n; bestD = d }
      }
      return best
    }

    const onPointerDown = (ev: PointerEvent) => {
      canvas.setPointerCapture(ev.pointerId)
      const it = interRef.current
      it.moved = false
      const hit = pick(ev)
      if (hit !== null) {
        it.dragging = hit
        hit.fixed = true
        interRef.current.alpha = Math.max(interRef.current.alpha, 0.35)
      } else {
        it.panning = true
      }
      it.lastX = ev.clientX
      it.lastY = ev.clientY
    }
    const onPointerMove = (ev: PointerEvent) => {
      const it = interRef.current
      const dx = ev.clientX - it.lastX
      const dy = ev.clientY - it.lastY
      if (Math.abs(dx) + Math.abs(dy) > 2) it.moved = true
      if (it.dragging !== null) {
        it.dragging.x += dx / it.k
        it.dragging.y += dy / it.k
      } else if (it.panning) {
        it.tx += dx
        it.ty += dy
      } else {
        const hit = pick(ev)
        it.hoverId = hit?.id ?? null
        canvas.style.cursor = hit !== null ? 'pointer' : 'grab'
      }
      it.lastX = ev.clientX
      it.lastY = ev.clientY
    }
    const onPointerUp = () => {
      const it = interRef.current
      if (it.dragging !== null) {
        it.dragging.fixed = false
        if (!it.moved) onSelect(it.dragging.id)
      } else if (!it.moved) {
        onSelect(null)
      }
      it.dragging = null
      it.panning = false
    }
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault()
      const it = interRef.current
      const rect = canvas.getBoundingClientRect()
      const mx = ev.clientX - rect.left - width / 2
      const my = ev.clientY - rect.top - height / 2
      const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12
      const k2 = Math.min(4, Math.max(0.25, it.k * factor))
      it.tx = mx - ((mx - it.tx) * k2) / it.k
      it.ty = my - ((my - it.ty) * k2) / it.k
      it.k = k2
    }

    canvas.addEventListener('pointerdown', onPointerDown)
    canvas.addEventListener('pointermove', onPointerMove)
    canvas.addEventListener('pointerup', onPointerUp)
    canvas.addEventListener('wheel', onWheel, { passive: false })

    return () => {
      cancelAnimationFrame(raf)
      if (ro !== null) ro.disconnect()
      canvas.removeEventListener('pointerdown', onPointerDown)
      canvas.removeEventListener('pointermove', onPointerMove)
      canvas.removeEventListener('pointerup', onPointerUp)
      canvas.removeEventListener('wheel', onWheel)
    }
  }, [])

  return (
    <div ref={wrapRef} className="rt-canvas-wrap">
      <canvas ref={canvasRef} className="rt-canvas" aria-label="探索链路力导向图" role="img" />
    </div>
  )
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  ctx.beginPath()
  ctx.moveTo(x + r, y)
  ctx.arcTo(x + w, y, x + w, y + h, r)
  ctx.arcTo(x + w, y + h, x, y + h, r)
  ctx.arcTo(x, y + h, x, y, r)
  ctx.arcTo(x, y, x + w, y, r)
  ctx.closePath()
}
