/**
 * Host plugin `dsh-redteam/redteam`: opens the redteam domain over the routed
 * backend, registers the eleven model-facing tools, injects the
 * `redteam:protocol` prompt section, and declares the session projection unit
 * the Web tab reads. Publishes no service — preset-scoped composition only.
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { ToolsRegistry } from '@deepseek-ai/dsh-tools'
import type { StorageDomainFacility } from '@deepseek-ai/dsh-storage-domain'
import type { SessionProjectionRegistry } from '@deepseek-ai/dsh-session-projection'
import { redteamDomainSpec } from './spec.js'
import { EngagementStore } from './store.js'
import { redteamTools } from './tools.js'
import { PROTOCOL_ORDER, PROTOCOL_SECTION, protocolText } from './instructions.js'
import { redteamProjectionDefinition } from './projection.js'

export const name = 'redteam'

export const inject = ['tools', 'storageDomain', 'systemPrompt', 'sessionProjections'] as const

export interface Config {
  language: 'zh' | 'en'
}

/** Schemastery configuration for the redteam host plugin. */
export const Config: z<Config> = z.object({
  language: z.union(['zh', 'en'] as const).default('zh'),
})

interface PromptSectionHost {
  section(section: {
    name: string
    order: number
    text: string | ((context: never) => string)
  }): () => void
}

/**
 * Plugin body. The domain opens asynchronously; tools resolve the store
 * through one shared promise so the first call may wait for open.
 */
export function apply(ctx: Context, config: Config): void {
  let storePromise: Promise<EngagementStore> | undefined

  ctx.inject(['storageDomain'], (domainCtx) => {
    const facility = domainCtx.get<StorageDomainFacility>('storageDomain')
    if (facility === undefined) throw new Error('storageDomain facility unavailable')
    storePromise ??= facility.open(redteamDomainSpec).then(
      (domain) => new EngagementStore(domain),
    )
    // Open failures surface to every caller; nothing swallows them here.
    void storePromise.catch(() => {})
  })

  const store = async (): Promise<EngagementStore> => {
    if (storePromise === undefined) throw new Error('redteam storage not opened yet')
    return storePromise
  }

  ctx.inject(['tools'], (toolsCtx) => {
    const registry = toolsCtx.get<ToolsRegistry>('tools')
    if (registry === undefined) throw new Error('tools registry unavailable')
    const disposers = redteamTools({ store }).map((tool) => registry.register(tool))
    ctx.effect(() => () => disposers.forEach((dispose) => dispose()), 'redteam.tools')
  })

  ctx.inject(['systemPrompt'], (promptCtx) => {
    const systemPrompt = promptCtx.get<PromptSectionHost>('systemPrompt')
    if (systemPrompt === undefined) return
    const dispose = systemPrompt.section({
      name: PROTOCOL_SECTION,
      order: PROTOCOL_ORDER,
      text: protocolText(config.language),
    })
    ctx.effect(() => dispose, 'redteam.protocolSection')
  })

  ctx.inject(['sessionProjections'], (projectionCtx) => {
    const projections = projectionCtx.get<SessionProjectionRegistry>('sessionProjections')
    if (projections === undefined) throw new Error('sessionProjections registry unavailable')
    const dispose = projections.register(redteamProjectionDefinition as never)
    ctx.effect(() => dispose, 'redteam.projection')
  })
}
