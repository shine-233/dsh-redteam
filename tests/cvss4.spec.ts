/**
 * CVSS v4.0 engine against FIRST validation vectors (from the official
 * RedHatProductSecurity/cvss test set) plus grammar rejection cases.
 */

import { describe, expect, it } from 'vitest'
import { parseCvss4, Cvss4Error } from '../src/cvss4.js'
import { scoreAnyVector } from '../src/cvss.js'

describe('cvss v4.0', () => {
  it('scores FIRST reference vectors exactly', () => {
    const cases: [string, number][] = [
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L', 6.9],
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N', 8.7],
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/AR:L', 7.9],
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:H', 7.7],
      ['CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0],
      // Zero-impact shortcut.
      ['CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0],
    ]
    for (const [vector, expected] of cases) {
      expect(parseCvss4(vector).baseScore, vector).toBe(expected)
    }
  })

  it('maps scores to severity bands', () => {
    expect(parseCvss4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H').severity).toBe('Critical')
    expect(parseCvss4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L').severity).toBe('Medium')
  })

  it('rejects malformed vectors like the official parser', () => {
    expect(() => parseCvss4('CVSS:4.0')).toThrow(Cvss4Error)
    expect(() => parseCvss4('CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')).toThrow(/prefix/)
    expect(() => parseCvss4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/JJ:X')).toThrow(/Invalid metric key/)
    expect(() => parseCvss4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:J')).toThrow(/Invalid metric value/)
    expect(() => parseCvss4('CVSS:4.0/AV:N/AV:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')).toThrow(/Duplicate metric/)
    expect(() => parseCvss4('CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')).toThrow(/Missing mandatory/)
  })

  it('dispatches scoring by version prefix', () => {
    expect(scoreAnyVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8)
    expect(scoreAnyVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N')).toBe(8.7)
    expect(scoreAnyVector('CVSS:4.0/not-a-vector')).toBeNull()
    expect(scoreAnyVector('garbage')).toBeNull()
  })
})
