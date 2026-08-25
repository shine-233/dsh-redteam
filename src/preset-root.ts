/**
 * Registers this package's read-only preset root on the agent-presets roster.
 *
 * DSH rc-line replaces configured preset roots with its bundled root while it
 * boots a profile, and the roster resolves roots once at construction — so an
 * installed bundle cannot contribute a preset through its patch config alone.
 * This plugin runs after `agentPresets` exists and prepends the package-owned
 * directory (`preset/`) as a system-trust root; early roots win duplicate-id
 * races against later user roots, and nothing is copied into DSH_HOME.
 */

import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'

export const inject = ['agentPresets'] as const

interface PresetRoots {
  resolvedRoots: { path: string; trust: 'system' | 'user' }[]
}

export function apply(ctx: Context): void {
  const presets = ctx.get<PresetRoots>('agentPresets')
  if (presets === undefined) throw new Error('agentPresets service unavailable')
  const root = fileURLToPath(new URL('../preset/', import.meta.url))
  if (!presets.resolvedRoots.some((entry) => entry.path === root)) {
    presets.resolvedRoots.unshift({ path: root, trust: 'system' })
  }
}
