/**
 * Bundle manifest contract: the patch file parses, every row resolves to a
 * declared subpath export, and the preset directory is complete.
 */

import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'

const root = fileURLToPath(new URL('..', import.meta.url))

/** Neutralize !!js expressions — they evaluate only inside a live host. */
function readYaml(path: string): unknown {
  const raw = readFileSync(`${root}${path}`, 'utf8').replace(/!!js\s+\S.*$/gm, '"__js_expr__"')
  return yaml.load(raw)
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(`${root}${path}`, 'utf8'))
}

describe('bundle manifest', () => {
  it('declares bundle patch, client surface, and all referenced exports', () => {
    const pkg = readJson('package.json')
    expect(pkg.dsh.bundle.patch).toBe('./cordis.patch.yml')
    expect(pkg.dsh.client.platform).toBe('web')
    for (const required of [
      '.', './redteam', './storage-sqlite', './preset-root', './ui', './client',
      './invariant', './cordis.patch.yml', './package.json',
    ]) {
      expect(pkg.exports, `missing export ${required}`).toHaveProperty(required)
    }
    expect(pkg.license).toBe('MIT')
  })

  it('patch rows resolve to package subpaths and route only redteam to sqlite', () => {
    const pkg = readJson('package.json')
    const doc = readYaml('cordis.patch.yml') as any[]
    expect(Array.isArray(doc)).toBe(true)

    const names: string[] = []
    for (const row of doc) {
      if (row.insert !== undefined) {
        for (const inserted of row.insert as any[]) names.push(inserted.name)
      }
    }
    for (const name of names) {
      if (name === undefined) continue
      if (name.startsWith('@deepseek-ai/')) continue
      const [pkgName, subpath = '.'] = name.split('/')
      void pkgName
      const key = subpath === '' || subpath === '.' ? '.' : `./${subpath}`
      expect(pkg.exports, `row name ${name} has no export`).toHaveProperty(key)
    }
    const storageRoute = doc.find((row: any) => row.id === 'storage-domain')
    expect(storageRoute.config.routes).toEqual({ redteam: 'sqlite' })
    expect(storageRoute.config.backend).toBe('json')
  })

  it('ships a complete redteam preset directory', () => {
    const preset = readFileSync(`${root}preset/redteam/preset.yml`, 'utf8')
    expect(preset).toContain('name:')
    const composition = readFileSync(`${root}preset/redteam/agent.cordis.yml`, 'utf8')
    expect(composition).toContain("'dsh-redteam/redteam'")
    expect(composition).toContain('redteam_submit')
    // Children must not write outside submit.
    expect(composition.match(/- redteam_add_goal/g)?.length).toBeGreaterThanOrEqual(2)
    // The fence covers the full write surface, not just the add_* tools.
    for (const fenced of [
      'redteam_add_credential',
      'redteam_add_artifact',
      'redteam_add_hint',
      'redteam_update_intent',
      'redteam_retest_finding',
      'redteam_update_credential',
      'redteam_close_goal',
    ]) {
      expect(composition.match(new RegExp(`- ${fenced}$`, 'gm'))?.length).toBeGreaterThanOrEqual(2)
    }
  })

  it('pins node engines and ships MIT', () => {
    const pkg = readJson('package.json')
    expect(pkg.engines.node).toBe('^22.19.0 || >=24.0.0')
    expect(readFileSync(`${root}LICENSE`, 'utf8')).toContain('MIT License')
  })
})
