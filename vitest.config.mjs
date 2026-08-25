import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

// Unit plane: the host contracts are exercised through faithful fakes under
// tests/fakes/, so the suite runs standalone without a dsh checkout.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: '@deepseek-ai/dsh-tools',
        replacement: fileURLToPath(new URL('./tests/fakes/tools.ts', import.meta.url)),
      },
      {
        find: '@deepseek-ai/dsh-storage-domain',
        replacement: fileURLToPath(new URL('./tests/fakes/storage-domain.ts', import.meta.url)),
      },
      {
        find: '@deepseek-ai/dsh-session-projection',
        replacement: fileURLToPath(new URL('./tests/fakes/session-projection.ts', import.meta.url)),
      },
      {
        find: '@deepseek-ai/schemastery',
        replacement: fileURLToPath(new URL('./tests/fakes/schemastery.ts', import.meta.url)),
      },
      {
        find: '@deepseek-ai/cordis',
        replacement: fileURLToPath(new URL('./tests/fakes/cordis.ts', import.meta.url)),
      },
    ],
  },
  test: {
    include: ['tests/**/*.spec.ts', 'tests/**/*.spec.tsx'],
    environment: 'node',
  },
})
