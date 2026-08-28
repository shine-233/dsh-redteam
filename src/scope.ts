/**
 * Shared scope-matching rules used by the store, the session projection and
 * the report renderers so a target can never be judged compliant in one
 * surface and violating in another. Matching is intentionally coarse:
 * exact hit, dot-boundary domain match, or containment (entry ≥ 4 chars).
 */

import type { ScopeEntryRecord, ScopeIssue } from './types.js'

export function scopeMatches(value: string, entryValue: string): boolean {
  const v = value.toLowerCase()
  const e = entryValue.toLowerCase().trim()
  if (e === '') return false
  if (v === e) return true
  if (v.endsWith(`.${e}`) || e.endsWith(`.${v}`)) return true
  if (e.length >= 4 && (v.includes(e) || e.includes(v))) return true
  return false
}

/** IPv4 literal, optionally with a :port suffix. Scanner imports are
 * IP-shaped; an address cannot be judged against a hostname scope's in-list,
 * so it never raises an unscoped violation (explicit out-entries still hit). */
function isIpShaped(value: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(value)
}

export interface ScopeCheckInput {
  assets: readonly { id: string; value: string }[]
  /** Findings are checked via their affected asset's value when registered. */
  findings: readonly { id: string; assetValue: string | null }[]
  iocs: readonly { id: string; value: string }[]
}

export function scopeCheck(
  entries: readonly Pick<ScopeEntryRecord, 'kind' | 'value'>[],
  input: ScopeCheckInput,
): ScopeIssue[] {
  if (entries.length === 0) return []
  const out = entries.filter((e) => e.kind === 'out')
  const hasIn = entries.some((e) => e.kind === 'in')
  const issues: ScopeIssue[] = []
  const judge = (recordId: string, recordKind: ScopeIssue['recordKind'], value: string): void => {
    const hitOut = out.find((e) => scopeMatches(value, e.value))
    if (hitOut !== undefined) {
      issues.push({ recordId, recordKind, value, reason: 'out-of-scope', matched: hitOut.value })
      return
    }
    if (hasIn && !isIpShaped(value) && !entries.some((e) => e.kind === 'in' && scopeMatches(value, e.value))) {
      issues.push({ recordId, recordKind, value, reason: 'unscoped', matched: '' })
    }
  }
  for (const a of input.assets) judge(a.id, 'asset', a.value)
  for (const f of input.findings) {
    if (f.assetValue !== null) judge(f.id, 'finding', f.assetValue)
  }
  // IOCs are observed attacker infrastructure: they sit outside the client's
  // authorized scope by definition, so they never raise an unscoped issue —
  // only an explicit out-entry hit (C2 inside a forbidden range) is a signal.
  for (const i of input.iocs) {
    const hitOut = out.find((e) => scopeMatches(i.value, e.value))
    if (hitOut !== undefined) {
      issues.push({ recordId: i.id, recordKind: 'ioc', value: i.value, reason: 'out-of-scope', matched: hitOut.value })
    }
  }
  return issues
}
