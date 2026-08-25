/**
 * CVSS v3.1 base-score computation (FIRST spec) and MITRE ATT&CK technique-id
 * validation — pure functions shared by the store (finding writes) and the
 * report renderer.
 */

const METRICS = {
  AV: { N: 0.85, A: 0.77, L: 0.55, P: 0.62 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const

/** Privileged-required weights differ when scope changes (FIRST 3.1 §8.2). */
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 } as const

export interface CvssBase {
  av: keyof typeof METRICS.AV
  ac: keyof typeof METRICS.AC
  pr: keyof typeof METRICS.PR
  ui: keyof typeof METRICS.UI
  s: 'U' | 'C'
  c: keyof typeof METRICS.CIA
  i: keyof typeof METRICS.CIA
  a: keyof typeof METRICS.CIA
}

/**
 * Parse a v3.x base vector (`CVSS:3.1/AV:…` or bare `AV:…`). Returns null on
 * any malformed, duplicate, or missing metric — callers treat null as "no
 * score", never as an error.
 */
export function parseCvssVector(vector: string): CvssBase | null {
  const parts = vector.trim().split('/').filter((p) => p !== '')
  if (parts[0] === 'CVSS:3.0' || parts[0] === 'CVSS:3.1') parts.shift()
  const seen = new Map<string, string>()
  for (const part of parts) {
    const [key, value] = part.split(':')
    // Metric keys are 1–2 chars (C/I/A/S vs AV/AC/PR/UI); values always 1.
    if (key === undefined || value === undefined || key.length < 1 || key.length > 2 || value.length !== 1) {
      return null
    }
    if (seen.has(key)) return null
    seen.set(key, value)
  }
  const pick = <K extends string>(metric: string, table: Record<string, unknown>): K => {
    const value = seen.get(metric)
    return value !== undefined && value in table ? (value as K) : (undefined as never)
  }
  const parsed: CvssBase | null = {
    av: pick('AV', METRICS.AV),
    ac: pick('AC', METRICS.AC),
    pr: pick('PR', METRICS.PR),
    ui: pick('UI', METRICS.UI),
    s: seen.get('S') === 'C' ? 'C' : seen.get('S') === 'U' ? 'U' : (undefined as never),
    c: pick('C', METRICS.CIA),
    i: pick('I', METRICS.CIA),
    a: pick('A', METRICS.CIA),
  }
  return Object.values(parsed).every((v) => v !== undefined) ? parsed : null
}

/** Official FIRST roundup: guard against IEEE-754 drift before ceiling. */
function roundup(value: number): number {
  const intInput = Math.round(value * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

/** Base score per FIRST CVSS v3.1 specification §8, rounded per Appendix A. */
export function cvssBaseScore(base: CvssBase): number {
  const changed = base.s === 'C'
  const iscBase = Math.min(
    1 - (1 - METRICS.CIA[base.c]) * (1 - METRICS.CIA[base.i]) * (1 - METRICS.CIA[base.a]),
    0.915,
  )
  const impact = changed
    ? 7.52 * (iscBase - 0.029) - 3.25 * (iscBase - 0.02) ** 15
    : 6.42 * iscBase
  const exploitability =
    8.22 * METRICS.AV[base.av] * METRICS.AC[base.ac]
    * (changed ? PR_CHANGED[base.pr] : METRICS.PR[base.pr])
    * METRICS.UI[base.ui]
  if (impact <= 0) return 0
  return changed
    ? roundup(Math.min(1.08 * (impact + exploitability), 10))
    : roundup(Math.min(impact + exploitability, 10))
}

/** Vector → score, or null when the vector does not parse. */
export function scoreVector(vector: string): number | null {
  const base = parseCvssVector(vector)
  return base === null ? null : cvssBaseScore(base)
}

/** MITRE ATT&CK technique id (`T1110`) or sub-technique (`T1110.003`). */
export const ATTACK_TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/

/** OWASP Top 10 category id for the 2017 or 2021 edition (`A01:2021`). */
export const OWASP_CATEGORY_RE = /^A\d{2}:(2017|2021)$/

export function validTechniqueIds(ids: readonly string[]): boolean {
  return ids.every((id) => ATTACK_TECHNIQUE_RE.test(id))
}

export function validOwaspIds(ids: readonly string[]): boolean {
  return ids.every((id) => OWASP_CATEGORY_RE.test(id))
}
