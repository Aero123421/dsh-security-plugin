import { afterEach, describe, expect, it } from 'vitest'
import type { AstGrepHandle } from '../../../src/host/analysis/astgrep.ts'
import { createHandlers } from '../../../src/host/service.ts'
import { copyFixture, createHarness, noNetwork, registryOf, type Harness } from './helpers.ts'
import { analyzeWorkspace } from '../../../src/host/scan/analysis.ts'

let h: Harness | undefined

afterEach(async () => {
  await h?.controller.dispose()
  h?.store.close()
})

describe('Python AST status', () => {
  it.each([true, false])('reports Python support=%s independently of JS AST availability', async supportsPython => {
    const engine: AstGrepHandle = {
      Lang: { JavaScript: 'javascript', TypeScript: 'typescript', Tsx: 'tsx' },
      supportsPython,
      parse: () => {
        throw new Error('parser not used in bootstrap')
      },
    }
    h = createHarness({ astGrep: async () => engine })
    const rpc = createHandlers({
      ...h,
      llm: () => undefined,
      workspaces: () => registryOf([]),
      astGrep: async () => engine,
      toolkit: undefined,
      pluginVersion: 'test',
      now: () => new Date(),
    })
    const bootstrap = await rpc.getBootstrap(
      {},
      { request: new Request('http://localhost/'), loopback: true, signal: new AbortController().signal },
    )
    const expected = {
      available: true,
      reason: supportsPython ? 'Python AST available' : 'Python AST unavailable; Python uses the built-in parser',
    }
    expect(bootstrap.capabilities.analyzers.find(a => a.id === 'ast-grep')).toMatchObject(expected)
    const fixture = await copyFixture('flask-secure')
    try {
      const analysis = await analyzeWorkspace({
        root: fixture.root,
        settings: h.settings.get().settings,
        config: h.config,
        toolkit: undefined,
        astGrep: engine,
        fetch: noNetwork,
        signal: new AbortController().signal,
      })
      expect(analysis.analyzers.find(a => a.id === 'ast-grep')).toMatchObject(expected)
    } finally {
      await fixture.cleanup()
    }
  })
})
