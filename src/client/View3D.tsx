/**
 * Zero-dependency 3D attack-terrain view: goal / intents / facts+findings /
 * assets are laid out as layered constellations in 3-space and rendered with
 * a hand-rolled perspective projector (orbit drag, wheel dolly, idle
 * auto-rotate, depth-sorted painter's order, hover labels).
 */

import { useEffect, useRef } from 'react'
import type { RedteamProjection } from '../types.js'

interface P3 {
  id: string
  label: string
  kind: 'goal' | 'intent' | 'fact' | 'finding' | 'asset'
  severity?: string
  status?: string | null
  x: number
  y: number
  z: number
}

const LAYER_Y: Record<P3['kind'], number> = {
  goal: -170,
  intent: -40,
  fact: 60,
  finding: 60,
  asset: 165,
}

const KIND_COLOR: Record<P3['kind'], string> = {
  goal: '#6aa2ff',
  intent: '#7f8fa0',
  fact: '#5b87c7',
  finding: '#e05c5c',
  asset: '#7fb069',
}

const KIND_ZH: Record<string, string> = {
  goal: '目标',
  intent: '意图',
  fact: '事实',
  finding: '漏洞',
  asset: '资产',
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ff5c5c', high: '#ff9350', medium: '#e0c04e', low: '#7fb069', info: '#8b95a1',
}

function buildPoints(projection: RedteamProjection): { points: P3[]; links: [string, string, string][] } {
  const points: P3[] = []
  const links: [string, string, string][] = []
  const ring = (n: number, r: number, i: number): { x: number; z: number } => {
    if (n <= 1) return { x: 0, z: 0 }
    const a = (i / n) * Math.PI * 2
    return { x: Math.cos(a) * r, z: Math.sin(a) * r }
  }

  const goalNode = projection.nodes.find((n) => n.kind === 'goal')
  if (goalNode !== undefined) points.push({ id: goalNode.id, kind: 'goal', label: goalNode.title, x: 0, y: LAYER_Y.goal!, z: 0 })

  const intents = projection.nodes.filter((n) => n.kind === 'intent')
  intents.forEach((n, i) => {
    const p = ring(intents.length, 95, i)
    points.push({ id: n.id, kind: 'intent', label: n.title, status: n.status, x: p.x, y: LAYER_Y.intent! + (i % 3) * 14, z: p.z })
    if (goalNode !== undefined) links.push([goalNode.id, n.id, 'spawns'])
  })

  let li = 0
  for (const e of projection.edges) {
    const fromP = points.find((p) => p.id === e.from)
    if ((e.relation === 'yields' || e.relation === 'proves') && fromP !== undefined && !points.some((p) => p.id === e.to)) {
      const isFinding = e.relation === 'proves'
      const f = projection.findings.find((x) => x.id === e.to)
      const p = ring(Math.max(6, intents.length * 2), 175, li++)
      points.push({
        id: e.to,
        kind: isFinding ? 'finding' : 'fact',
        label: isFinding ? (f !== undefined ? `${f.severity.toUpperCase()} ${f.title}` : e.to) : e.to,
        severity: f?.severity,
        x: p.x,
        y: LAYER_Y.finding!,
        z: p.z,
      })
      links.push([e.from, e.to, e.relation])
    }
    if (e.relation === 'depends_on' || e.relation === 'derived_from') links.push([e.from, e.to, e.relation])
  }

  projection.assets.forEach((a, i) => {
    const p = ring(projection.assets.length, 130, i)
    points.push({ id: a.id, kind: 'asset', label: a.value, x: p.x, y: LAYER_Y.asset!, z: p.z })
  })
  const pointIds = new Set(points.map((p) => p.id))
  for (const n of intents) {
    for (const aid of n.assetIds ?? []) {
      if (pointIds.has(aid)) links.push([n.id, aid, 'targets'])
    }
  }
  return { points, links }
}

export function View3D({ projection }: { projection: RedteamProjection }): React.ReactNode {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const dataRef = useRef<{ points: P3[]; links: [string, string, string][] }>({ points: [], links: [] })
  const camRef = useRef({ yaw: 0.6, pitch: 0.42, dist: 460, autoAt: performance.now() })
  const hoverRef = useRef<string | null>(null)

  useEffect(() => {
    dataRef.current = buildPoints(projection)
    camRef.current.autoAt = performance.now()
  }, [projection])

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (canvas === null || wrap === null) return
    const ctx = canvas.getContext('2d')
    if (ctx === null) return

    let raf = 0
    let width = wrap.clientWidth
    let height = Math.max(320, wrap.clientHeight || 460)
    const resize = () => {
      const dpr = window.devicePixelRatio || 1
      width = wrap.clientWidth
      height = Math.max(320, wrap.clientHeight || 460)
      canvas.width = Math.max(1, Math.round(width * dpr))
      canvas.height = Math.max(1, Math.round(height * dpr))
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resize) : null
    if (ro !== null) ro.observe(wrap)

    const project = (p: P3): { sx: number; sy: number; scale: number; z: number } => {
      const cam = camRef.current
      const cy = Math.cos(cam.yaw); const sy = Math.sin(cam.yaw)
      const cp = Math.cos(cam.pitch); const sp = Math.sin(cam.pitch)
      const x1 = p.x * cy - p.z * sy
      const z1 = p.x * sy + p.z * cy
      const y2 = p.y * cp - z1 * sp
      const z2 = p.y * sp + z1 * cp
      const zc = z2 + cam.dist
      const f = 520 / Math.max(80, zc)
      return { sx: width / 2 + x1 * f, sy: height / 2 + 30 + y2 * f, scale: f, z: zc }
    }

    const frame = () => {
      const cam = camRef.current
      if (performance.now() - cam.autoAt > 4000) cam.yaw += 0.0028

      ctx.clearRect(0, 0, width, height)
      const { points, links } = dataRef.current
      const ids = new Map(points.map((p) => [p.id, p]))
      const projd = new Map<string, ReturnType<typeof project>>()
      for (const p of points) projd.set(p.id, project(p))

      const sortedLinks = [...links].sort((a, b) =>
        ((projd.get(b[0])?.z ?? 0) + (projd.get(b[1])?.z ?? 0)) - ((projd.get(a[0])?.z ?? 0) + (projd.get(a[1])?.z ?? 0)))
      const LINK_STYLE: Record<string, { line: string; dot: string }> = {
        spawns: { line: '#6aa2ff88', dot: '#6aa2ff' },
        yields: { line: '#5b87c777', dot: '#5b87c7' },
        proves: { line: '#e05c5c99', dot: '#ff8a8a' },
        depends_on: { line: '#e0975b88', dot: '#e0975b' },
        derived_from: { line: '#8a7fc755', dot: '#8a7fc7' },
        targets: { line: '#7fb06655', dot: '#7fb069' },
        parent: { line: '#4f7a5566', dot: '#4f7a55' },
      }
      for (const [from, to, rel] of sortedLinks) {
        const a = projd.get(from)
        const b = projd.get(to)
        if (a === undefined || b === undefined) continue
        const st = LINK_STYLE[rel] ?? { line: '#46505c66', dot: '#46505c' }
        ctx.strokeStyle = st.line
        ctx.lineWidth = rel === 'proves' ? 1.8 : 1.1
        ctx.beginPath()
        ctx.moveTo(a.sx, a.sy)
        ctx.lineTo(b.sx, b.sy)
        ctx.stroke()
        const t = (performance.now() / 700 + (a.sx + b.sy) / 260) % 1
        const px = a.sx + (b.sx - a.sx) * t
        const py = a.sy + (b.sy - a.sy) * t
        ctx.fillStyle = st.dot
        ctx.beginPath()
        ctx.arc(px, py, 1.8, 0, Math.PI * 2)
        ctx.fill()
      }

      const hover = hoverRef.current
      const drawOrder = [...points].sort((a, b) => (projd.get(b.id)?.z ?? 0) - (projd.get(a.id)?.z ?? 0))
      for (const p of drawOrder) {
        const s = projd.get(p.id)
        if (s === undefined) continue
        const base = p.kind === 'goal' ? 13 : p.kind === 'finding' ? 8 : p.kind === 'intent' ? 9 : 6
        const r = Math.max(2.4, base * s.scale * (cam.dist / 460))
        const color = p.kind === 'finding' ? (SEVERITY_COLOR[p.severity ?? 'info'] ?? KIND_COLOR.finding!) : KIND_COLOR[p.kind]!
        const dim = hover !== null && hover !== p.id
        ctx.globalAlpha = dim ? 0.25 : 1

        ctx.strokeStyle = color
        ctx.lineWidth = 1.2
        ctx.globalAlpha *= 0.45
        ctx.beginPath()
        ctx.moveTo(s.sx, s.sy)
        ctx.lineTo(s.sx, s.sy + 26 * s.scale * (cam.dist / 460))
        ctx.stroke()
        ctx.globalAlpha = dim ? 0.25 : 1

        if (p.kind === 'asset') {
          ctx.fillStyle = color
          ctx.beginPath()
          ctx.moveTo(s.sx, s.sy - r)
          ctx.lineTo(s.sx + r, s.sy)
          ctx.lineTo(s.sx, s.sy + r)
          ctx.lineTo(s.sx - r, s.sy)
          ctx.closePath()
          ctx.fill()
        } else {
          if (hover === p.id) {
            ctx.save()
            ctx.shadowColor = color
            ctx.shadowBlur = 16
            ctx.fillStyle = color
            ctx.beginPath()
            ctx.arc(s.sx, s.sy, r + 2, 0, Math.PI * 2)
            ctx.fill()
            ctx.restore()
          }
          const g = ctx.createRadialGradient(s.sx - r / 3, s.sy - r / 3, 1, s.sx, s.sy, r)
          g.addColorStop(0, '#ffffff')
          g.addColorStop(0.35, color)
          g.addColorStop(1, shade(color))
          ctx.fillStyle = g
          ctx.beginPath()
          ctx.arc(s.sx, s.sy, r, 0, Math.PI * 2)
          ctx.fill()
        }

        if (hover === p.id) {
          ctx.font = '600 12px system-ui, sans-serif'
          const text = truncate(p.label, 34)
          const wText = ctx.measureText(text).width
          ctx.fillStyle = '#000000cc'
          ctx.fillRect(s.sx + r + 6, s.sy - 15, wText + 12, 20)
          ctx.strokeStyle = color
          ctx.lineWidth = 1
          ctx.strokeRect(s.sx + r + 6, s.sy - 15, wText + 12, 20)
          ctx.fillStyle = '#dbe2ea'
          ctx.textAlign = 'left'
          ctx.textBaseline = 'middle'
          ctx.fillText(text, s.sx + r + 12, s.sy - 4)
        }
      }
      ctx.globalAlpha = 1

      ctx.fillStyle = '#8b95a1'
      ctx.font = '11px system-ui, sans-serif'
      ctx.textAlign = 'left'
      ctx.textBaseline = 'bottom'
      ctx.fillText(`立体攻击地形 · 拖拽旋转 / 滚轮推拉 · 节点 ${points.length}`, 10, height - 8)

      raf = requestAnimationFrame(frame)
    }
    raf = requestAnimationFrame(frame)

    let dragging = false
    let lx = 0
    let ly = 0
    let movedFar = false
    const down = (ev: PointerEvent) => {
      dragging = true
      movedFar = false
      lx = ev.clientX
      ly = ev.clientY
      canvas.setPointerCapture(ev.pointerId)
    }
    const move = (ev: PointerEvent) => {
      const cam = camRef.current
      if (dragging) {
        const dx = ev.clientX - lx
        const dy = ev.clientY - ly
        if (Math.abs(dx) + Math.abs(dy) > 3) { movedFar = true; cam.autoAt = performance.now() }
        cam.yaw += dx * 0.006
        cam.pitch = Math.max(-1.2, Math.min(1.2, cam.pitch + dy * 0.004))
        lx = ev.clientX
        ly = ev.clientY
        return
      }
      const rect = canvas.getBoundingClientRect()
      const mx = ev.clientX - rect.left
      const my = ev.clientY - rect.top
      let best: string | null = null
      let bestD = 18 * 18
      for (const p of dataRef.current.points) {
        const s = project(p)
        const d = (s.sx - mx) ** 2 + (s.sy - my) ** 2
        if (d < bestD) { bestD = d; best = p.id }
      }
      hoverRef.current = best
      canvas.style.cursor = best !== null ? 'pointer' : 'grab'
    }
    const up = () => { dragging = false }
    const wheel = (ev: WheelEvent) => {
      ev.preventDefault()
      const cam = camRef.current
      cam.dist = Math.max(180, Math.min(1100, cam.dist * (ev.deltaY < 0 ? 0.9 : 1.1)))
      cam.autoAt = performance.now()
    }
    canvas.addEventListener('pointerdown', down)
    canvas.addEventListener('pointermove', move)
    canvas.addEventListener('pointerup', up)
    canvas.addEventListener('wheel', wheel, { passive: false })

    return () => {
      cancelAnimationFrame(raf)
      if (ro !== null) ro.disconnect()
      canvas.removeEventListener('pointerdown', down)
      canvas.removeEventListener('pointermove', move)
      canvas.removeEventListener('pointerup', up)
      canvas.removeEventListener('wheel', wheel)
    }
  }, [])

  const empty = projection.nodes.length === 0
  return (
    <div>
      <div ref={wrapRef} className="rt-canvas-wrap">
        <canvas ref={canvasRef} className="rt-canvas" aria-label="立体攻击地形图" role="img" />
        {empty && <p className="rt-empty">暂无可视化数据。</p>}
      </div>
      <div className="rt-legend">
        {Object.entries(KIND_COLOR).map(([k, c]) => (
          <span key={k} className="rt-legend-item"><i style={{ background: c }} /> {KIND_ZH[k] ?? k}</span>
        ))}
      </div>
    </div>
  )
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** Darken a hex colour towards the sphere's shadow stop. */
function shade(hex: string): string {
  const n = parseInt(hex.slice(1), 16)
  const r = Math.round(((n >> 16) & 255) * 0.45)
  const g = Math.round(((n >> 8) & 255) * 0.45)
  const b = Math.round((n & 255) * 0.45)
  return `rgb(${r},${g},${b})`
}
