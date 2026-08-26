/**
 * CVSS v4.0 base-score engine, ported line-for-line from the official
 * RedHatProductSecurity/cvss implementation (cvss/cvss4.py) so scores match
 * FIRST validation vectors exactly. Lookup tables live in cvss4-data.ts.
 */

import {
  CVSS_LOOKUP_GLOBAL,
  EPSILON,
  MAX_COMPOSED,
  MAX_SEVERITY,
  METRICS_MANDATORY,
  METRICS_VALUE_NAMES,
} from './cvss4-data.js'

export type Cvss4Metrics = Record<string, string>

export class Cvss4Error extends Error {}

/** Round half away from zero to one decimal, with the official epsilon guard. */
function finalRounding(x: number): number {
  return Math.round((x + EPSILON) * 10) / 10
}

export interface Cvss4Result {
  vector: string
  metrics: Cvss4Metrics
  /** Canonical spec-ordered vector without X-valued optionals. */
  cleaned: string
  macroVector: string
  baseScore: number
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical'
}

const SPEC_ORDER = [
  'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA',
  'E', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC',
  'MVI', 'MVA', 'MSC', 'MSI', 'MSA', 'S', 'AU', 'R', 'V', 'RE', 'U',
]

export function parseCvss4(vector: string): Cvss4Result {
  if (vector === '') throw new Cvss4Error('Malformed CVSS4 vector, vector is empty')
  if (vector.endsWith('/')) throw new Cvss4Error(`Malformed CVSS4 vector, trailing "/"`)
  if (!vector.startsWith('CVSS:4.0/')) {
    throw new Cvss4Error(`Malformed CVSS4 vector "${vector}" is missing mandatory prefix or uses unsupported CVSS version`)
  }

  const metrics: Cvss4Metrics = {}
  for (const field of vector.split('/').slice(1)) {
    if (field === '') throw new Cvss4Error(`Empty field in CVSS4 vector "${vector}"`)
    const sep = field.indexOf(':')
    if (sep === -1) throw new Cvss4Error(`Malformed CVSS4 field "${field}"`)
    const metric = field.slice(0, sep)
    const value = field.slice(sep + 1)
    if (metric in metrics) throw new Cvss4Error(`Duplicate metric "${metric}"`)
    const valid = METRICS_VALUE_NAMES[metric]
    if (valid === undefined) throw new Cvss4Error(`Invalid metric key in CVSS4 vector "${field}"`)
    if (!(value in valid)) throw new Cvss4Error(`Invalid metric value in CVSS4 vector "${field}"`)
    metrics[metric] = value
  }

  const missing = METRICS_MANDATORY.filter((m) => !(m in metrics))
  if (missing.length > 0) {
    throw new Cvss4Error(`Missing mandatory metrics "${missing.join(', ')}"`)
  }

  for (const m of ['MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA']) {
    if (!(m in metrics) || metrics[m] === 'X') metrics[m] = metrics[m.slice(1)]!
  }
  for (const m of ['S', 'AU', 'R', 'V', 'RE', 'U', 'CR', 'IR', 'AR', 'E']) {
    if (!(m in metrics)) metrics[m] = 'X'
  }

  const original = Object.fromEntries(
    SPEC_ORDER.filter((k) => k in metrics && metrics[k] !== 'X').map((k) => [k, metrics[k]!]),
  )
  const cleaned = `CVSS:4.0/${SPEC_ORDER.filter((k) => k in original).map((k) => `${k}:${original[k]}`).join('/')}`

  const accessor = (metric: string): string => {
    const selected = metrics[metric]
    if (metric === 'E' && selected === 'X') return 'A'
    if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && selected === 'X') return 'H'
    const modified = metrics[`M${metric}`]
    if (modified !== undefined && modified !== 'X') return modified
    return selected!
  }

  const macroVector = computeMacroVector(accessor)
  const baseScore = computeBaseScore(accessor, macroVector)
  return {
    vector,
    metrics,
    cleaned,
    macroVector,
    baseScore,
    severity: severityOf(baseScore),
  }
}

function computeMacroVector(m: (metric: string) => string): string {
  let eq1 = ''
  let eq2 = ''
  let eq3 = ''
  let eq4 = ''
  let eq5 = ''
  let eq6 = ''

  if (m('AV') === 'N' && m('PR') === 'N' && m('UI') === 'N') eq1 = '0'
  else if (
    (m('AV') === 'N' || m('PR') === 'N' || m('UI') === 'N')
    && !(m('AV') === 'N' && m('PR') === 'N' && m('UI') === 'N')
    && m('AV') !== 'P'
  ) eq1 = '1'
  else if (m('AV') === 'P' || !(m('AV') === 'N' || m('PR') === 'N' || m('UI') === 'N')) eq1 = '2'

  eq2 = m('AC') === 'L' && m('AT') === 'N' ? '0' : '1'

  if (m('VC') === 'H' && m('VI') === 'H') eq3 = '0'
  else if (
    !(m('VC') === 'H' && m('VI') === 'H')
    && (m('VC') === 'H' || m('VI') === 'H' || m('VA') === 'H')
  ) eq3 = '1'
  else eq3 = '2'

  if (m('MSI') === 'S' || m('MSA') === 'S') eq4 = '0'
  else if (m('SC') === 'H' || m('SI') === 'H' || m('SA') === 'H') eq4 = '1'
  else eq4 = '2'

  if (m('E') === 'A') eq5 = '0'
  else if (m('E') === 'P') eq5 = '1'
  else eq5 = '2'

  eq6 = (m('CR') === 'H' && m('VC') === 'H')
    || (m('IR') === 'H' && m('VI') === 'H')
    || (m('AR') === 'H' && m('VA') === 'H')
    ? '0'
    : '1'

  return eq1 + eq2 + eq3 + eq4 + eq5 + eq6
}

function extractValueMetric(metric: string, vector: string): string {
  const start = vector.indexOf(metric) + metric.length + 1
  const rest = vector.slice(start)
  const slash = rest.indexOf('/')
  return slash === -1 ? rest : rest.slice(0, slash)
}

function getEqMaxes(macroVector: string, eq: number): any {
  return (MAX_COMPOSED as any)[`eq${eq}`][macroVector[eq - 1]!]
}

function computeBaseScore(m: (metric: string) => string, macroVector: string): number {
  const AV_levels: Record<string, number> = { N: 0.0, A: 0.1, L: 0.2, P: 0.3 }
  const PR_levels: Record<string, number> = { N: 0.0, L: 0.1, H: 0.2 }
  const UI_levels: Record<string, number> = { N: 0.0, P: 0.1, A: 0.2 }
  const AC_levels: Record<string, number> = { L: 0.0, H: 0.1 }
  const AT_levels: Record<string, number> = { N: 0.0, P: 0.1 }
  const VC_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 }
  const VI_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 }
  const VA_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 }
  const SC_levels: Record<string, number> = { H: 0.1, L: 0.2, N: 0.3 }
  const SI_levels: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 }
  const SA_levels: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 }
  const CR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 }
  const IR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 }
  const AR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 }

  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => m(k) === 'N')) return 0.0

  let value = CVSS_LOOKUP_GLOBAL[macroVector]
  if (value === undefined) throw new Cvss4Error(`No lookup entry for MacroVector "${macroVector}"`)

  const eq1_val = Number(macroVector[0])
  const eq2_val = Number(macroVector[1])
  const eq3_val = Number(macroVector[2])
  const eq4_val = Number(macroVector[3])
  const eq5_val = Number(macroVector[4])
  const eq6_val = Number(macroVector[5])

  const join = (...vals: number[]) => vals.join('')
  const scoreOf = (mv: string): number => {
    const v = CVSS_LOOKUP_GLOBAL[mv]
    return v === undefined ? Number.NaN : v
  }

  const score_eq1_next_lower_macro = scoreOf(join(eq1_val + 1, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val))
  const score_eq2_next_lower_macro = scoreOf(join(eq1_val, eq2_val + 1, eq3_val, eq4_val, eq5_val, eq6_val))

  let score_eq3eq6_next_lower_macro: number
  if (eq3_val === 0 && eq6_val === 0) {
    const left = scoreOf(join(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1))
    const right = scoreOf(join(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val))
    score_eq3eq6_next_lower_macro = Math.max(left, right)
  } else if (eq3_val === 1 && eq6_val === 1) {
    score_eq3eq6_next_lower_macro = scoreOf(join(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val))
  } else if (eq3_val === 0 && eq6_val === 1) {
    score_eq3eq6_next_lower_macro = scoreOf(join(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val))
  } else if (eq3_val === 1 && eq6_val === 0) {
    score_eq3eq6_next_lower_macro = scoreOf(join(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1))
  } else {
    score_eq3eq6_next_lower_macro = scoreOf(join(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val + 1))
  }

  const score_eq4_next_lower_macro = scoreOf(join(eq1_val, eq2_val, eq3_val, eq4_val + 1, eq5_val, eq6_val))
  const score_eq5_next_lower_macro = scoreOf(join(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val + 1, eq6_val))

  const eq1_maxes: string[] = getEqMaxes(macroVector, 1)
  const eq2_maxes: string[] = getEqMaxes(macroVector, 2)
  const eq3_eq6_maxes: string[] = (getEqMaxes(macroVector, 3) as Record<string, string[]>)[macroVector[5]!]!
  const eq4_maxes: string[] = getEqMaxes(macroVector, 4)
  const eq5_maxes: string[] = getEqMaxes(macroVector, 5)

  let severity_distance_AV = 0
  let severity_distance_PR = 0
  let severity_distance_UI = 0
  let severity_distance_AC = 0
  let severity_distance_AT = 0
  let severity_distance_VC = 0
  let severity_distance_VI = 0
  let severity_distance_VA = 0
  let severity_distance_SC = 0
  let severity_distance_SI = 0
  let severity_distance_SA = 0
  let severity_distance_CR = 0
  let severity_distance_IR = 0
  let severity_distance_AR = 0

  for (const max1 of eq1_maxes) {
    for (const max2 of eq2_maxes) {
      for (const max36 of eq3_eq6_maxes) {
        for (const max4 of eq4_maxes) {
          for (const max5 of eq5_maxes) {
            const maxVector = `${max1}${max2}${max36}${max4}${max5}`
            severity_distance_AV = AV_levels[m('AV')]! - AV_levels[extractValueMetric('AV', maxVector)]!
            severity_distance_PR = PR_levels[m('PR')]! - PR_levels[extractValueMetric('PR', maxVector)]!
            severity_distance_UI = UI_levels[m('UI')]! - UI_levels[extractValueMetric('UI', maxVector)]!
            severity_distance_AC = AC_levels[m('AC')]! - AC_levels[extractValueMetric('AC', maxVector)]!
            severity_distance_AT = AT_levels[m('AT')]! - AT_levels[extractValueMetric('AT', maxVector)]!
            severity_distance_VC = VC_levels[m('VC')]! - VC_levels[extractValueMetric('VC', maxVector)]!
            severity_distance_VI = VI_levels[m('VI')]! - VI_levels[extractValueMetric('VI', maxVector)]!
            severity_distance_VA = VA_levels[m('VA')]! - VA_levels[extractValueMetric('VA', maxVector)]!
            severity_distance_SC = SC_levels[m('SC')]! - SC_levels[extractValueMetric('SC', maxVector)]!
            severity_distance_SI = SI_levels[m('SI')]! - SI_levels[extractValueMetric('SI', maxVector)]!
            severity_distance_SA = SA_levels[m('SA')]! - SA_levels[extractValueMetric('SA', maxVector)]!
            severity_distance_CR = CR_levels[m('CR')]! - CR_levels[extractValueMetric('CR', maxVector)]!
            severity_distance_IR = IR_levels[m('IR')]! - IR_levels[extractValueMetric('IR', maxVector)]!
            severity_distance_AR = AR_levels[m('AR')]! - AR_levels[extractValueMetric('AR', maxVector)]!

            const distances = [
              severity_distance_AV, severity_distance_PR, severity_distance_UI,
              severity_distance_AC, severity_distance_AT, severity_distance_VC,
              severity_distance_VI, severity_distance_VA, severity_distance_SC,
              severity_distance_SI, severity_distance_SA, severity_distance_CR,
              severity_distance_IR, severity_distance_AR,
            ]
            if (!distances.some((d) => d < 0)) {
              // Found the governing max-severity depth vector.
              const current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI
              const current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
              const current_severity_distance_eq3eq6 =
                severity_distance_VC + severity_distance_VI + severity_distance_VA
                + severity_distance_CR + severity_distance_IR + severity_distance_AR
              const current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA

              const step = 0.1
              const available_distance_eq1 = value - score_eq1_next_lower_macro
              const available_distance_eq2 = value - score_eq2_next_lower_macro
              const available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
              const available_distance_eq4 = value - score_eq4_next_lower_macro
              const available_distance_eq5 = value - score_eq5_next_lower_macro

              const maxSeverityOf = (path: string): number => {
                const node = path.split('.').reduce<any>((acc, key) => acc?.[key], MAX_SEVERITY as any)
                return typeof node === 'number' ? node : Number(node)
              }
              const max_severity_eq1 = maxSeverityOf(`eq1.${eq1_val}`) * step
              const max_severity_eq2 = maxSeverityOf(`eq2.${eq2_val}`) * step
              const max_severity_eq3eq6 = maxSeverityOf(`eq3eq6.${eq3_val}.${eq6_val}`) * step
              const max_severity_eq4 = maxSeverityOf(`eq4.${eq4_val}`) * step

              let n_existing_lower = 0
              let normalized_sum = 0

              if (Number.isFinite(available_distance_eq1) && available_distance_eq1 >= 0) {
                n_existing_lower += 1
                normalized_sum += available_distance_eq1 * (current_severity_distance_eq1 / max_severity_eq1)
              }
              if (Number.isFinite(available_distance_eq2) && available_distance_eq2 >= 0) {
                n_existing_lower += 1
                normalized_sum += available_distance_eq2 * (current_severity_distance_eq2 / max_severity_eq2)
              }
              if (Number.isFinite(available_distance_eq3eq6) && available_distance_eq3eq6 >= 0) {
                n_existing_lower += 1
                normalized_sum += available_distance_eq3eq6 * (current_severity_distance_eq3eq6 / max_severity_eq3eq6)
              }
              if (Number.isFinite(available_distance_eq4) && available_distance_eq4 >= 0) {
                n_existing_lower += 1
                normalized_sum += available_distance_eq4 * (current_severity_distance_eq4 / max_severity_eq4)
              }
              if (Number.isFinite(available_distance_eq5) && available_distance_eq5 >= 0) {
                n_existing_lower += 1
                // percent_to_next_eq5_severity is 0 by definition.
              }

              const mean_distance = n_existing_lower === 0 ? 0 : normalized_sum / n_existing_lower
              value -= mean_distance
              value = Math.max(0.0, value)
              value = Math.min(10.0, value)
              return finalRounding(value)
            }
          }
        }
      }
    }
  }
  throw new Cvss4Error(`No governing max-severity vector found for MacroVector "${macroVector}"`)
}

export function severityOf(baseScore: number): Cvss4Result['severity'] {
  if (baseScore === 0.0) return 'None'
  if (baseScore <= 3.9) return 'Low'
  if (baseScore <= 6.9) return 'Medium'
  if (baseScore <= 8.9) return 'High'
  return 'Critical'
}
