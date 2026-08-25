/**
 * CVSS v3.1 base scoring against FIRST reference vectors, plus ATT&CK id
 * validation.
 */

import { describe, expect, it } from 'vitest'
import { ATTACK_TECHNIQUE_RE, cvssBaseScore, parseCvssVector, scoreVector } from '../src/cvss.js'

const V = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

describe('parseCvssVector', () => {
  it('parses a full prefixed vector', () => {
    const base = parseCvssVector(V)
    expect(base).toEqual({ av: 'N', ac: 'L', pr: 'N', ui: 'N', s: 'U', c: 'H', i: 'H', a: 'H' })
  })

  it('accepts bare vectors without the CVSS:3.1 prefix', () => {
    expect(parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N')).not.toBeNull()
  })

  it('rejects missing metrics, bad values, and duplicates', () => {
    expect(parseCvssVector('AV:N')).toBeNull()
    expect(parseCvssVector('AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull()
    expect(parseCvssVector(`${V}/AV:A`)).toBeNull() // duplicate metric key
    expect(parseCvssVector('')).toBeNull()
  })

  it('ignores temporal/supplemental metrics but rejects unknown keys', () => {
    const withTemporal = `${V}/E:H/RL:O/RC:C`
    expect(parseCvssVector(withTemporal)).not.toBeNull()
    expect(scoreVector(withTemporal)).toBe(scoreVector(V)) // base score unaffected
    expect(parseCvssVector(`${V}/ZZ:Z`)).toBeNull()
    // An explicit v4 prefix is a different key system — refuse to half-read it.
    expect(parseCvssVector(V.replace('CVSS:3.1', 'CVSS:4.0'))).toBeNull()
  })
})

describe('cvssBaseScore (FIRST reference scores)', () => {
  function score(vector: string): number {
    const base = parseCvssVector(vector)
    if (base === null) throw new Error(`unparsed: ${vector}`)
    return cvssBaseScore(base)
  }

  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', 3.7],
    // No confidentiality/integrity/availability impact → 0.
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s → %s', (vector, expected) => {
    expect(score(vector)).toBe(expected)
  })

  it('scoreVector returns null for unparseable input instead of throwing', () => {
    expect(scoreVector('not-a-vector')).toBeNull()
  })
})

describe('ATT&CK technique ids', () => {
  it.each(['T1110', 'T1110.003', 'T1059.007'])('accepts %s', (id) => {
    expect(ATTACK_TECHNIQUE_RE.test(id)).toBe(true)
  })
  it.each(['1110', 'T11', 'TX110', 'T1110.3', 't1110'])('rejects %s', (id) => {
    expect(ATTACK_TECHNIQUE_RE.test(id)).toBe(false)
  })
})
