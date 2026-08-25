import { defineConfig } from 'tsdown'

const HOST_EXTERNALS = [/^@deepseek-ai\//, /^node:/, 'zod']

export default [
  {
    // Host face: one bundle per manifest subpath export.
    entry: {
      index: 'src/index.ts',
      redteam: 'src/plugin.ts',
      invariant: 'src/invariant.ts',
      'preset-root': 'src/preset-root.ts',
      ui: 'src/ui.ts',
      'storage-sqlite/index': 'src/storage-sqlite/index.ts',
    },
    outDir: 'lib',
    format: 'esm',
    platform: 'node',
    target: 'es2024',
    dts: false,
    external: HOST_EXTERNALS,
    clean: true,
  },
  {
    // Client face: the browser half wrapped into the harness ModuleLoader
    // factory contract. Platform modules (React, runtime) arrive through the
    // host's shared module table and stay external as `require(...)` calls.
    entry: { client: 'src/client/index.ts' },
    outDir: 'lib',
    format: 'cjs',
    platform: 'browser',
    target: 'es2022',
    dts: false,
    external: [
      'react',
      'react/jsx-runtime',
      'react-dom',
      'react-dom/client',
      /^@deepseek-ai\//,
    ],
    banner: {
      js: 'window.__ModuleLoader__.load({ id: "dsh-redteam", factory: function(require){ const module = { exports: {} }; (function(module, exports){',
    },
    footer: {
      js: '})(module, module.exports); return module.exports; } });',
    },
    outputOptions: {
      inlineDynamicImports: true,
      // Manifest exports declare ./lib/client.js — keep the cjs face on that
      // exact name instead of the default .cjs suffix.
      entryFileNames: '[name].js',
    },
  },
] satisfies unknown[]
