import { readFileSync } from 'node:fs'
import { defineConfig } from 'vitest/config'

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  name: string
  version: string
}

const define = {
  __PLUGIN_VERSION__: JSON.stringify(pkg.version),
  __PLUGIN_NAME__: JSON.stringify(pkg.name),
}

export default defineConfig({
  define,
  test: {
    projects: [
      {
        define,
        test: {
          name: 'host',
          environment: 'node',
          include: ['tests/host/**/*.test.ts', 'tests/shared/**/*.test.ts'],
          testTimeout: 30_000,
        },
      },
      {
        define,
        esbuild: { jsx: 'automatic' },
        test: {
          name: 'client',
          environment: 'happy-dom',
          include: ['tests/client/**/*.test.{ts,tsx}'],
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      reporter: ['text-summary', 'html'],
    },
  },
})
