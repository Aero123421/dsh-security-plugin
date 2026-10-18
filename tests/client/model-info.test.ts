import { describe, expect, it } from 'vitest'
import { createController } from '../../src/client/controller.ts'
import type { ModelOption, RpcResult } from '../../src/shared/contracts.ts'
import { fakeApi, ok } from './helpers.tsx'

const providers = [{ id: 'p', name: 'Provider', models: [{ id: 'm', name: 'Model' }] }]
describe('model details', () => {
  it('coalesces detail requests, enriches the selected model and caches until a refresh', async () => {
    const api = fakeApi({
      listModels: () => ok(providers),
      getModelInfo: () => ok({ id: 'm', name: 'Model', reasoningEfforts: [{ id: 'high', name: 'High' }] }),
    })
    const c = createController({ api, storage: null })
    try {
      await c.loadModels()
      await Promise.all([c.loadModelInfo('p', 'm'), c.loadModelInfo('p', 'm')])
      expect(api.callsOf('getModelInfo')).toHaveLength(1)
      expect(c.store.getState().models.value?.[0]?.models[0]?.reasoningEfforts).toHaveLength(1)
      await c.loadModelInfo('p', 'm')
      expect(api.callsOf('getModelInfo')).toHaveLength(1)
      await c.loadModels(true)
      await c.loadModelInfo('p', 'm')
      expect(api.callsOf('getModelInfo')).toHaveLength(2)
    } finally {
      c.dispose()
    }
  })

  it('starts a new detail request while a refreshed catalog still has an old request in flight', async () => {
    const pending: ((value: RpcResult<ModelOption>) => void)[] = []
    const api = fakeApi({
      listModels: () => ok(providers),
      getModelInfo: () => new Promise(resolve => pending.push(resolve)),
    })
    const c = createController({ api, storage: null })
    try {
      await c.loadModels()
      const old = c.loadModelInfo('p', 'm')
      await c.loadModels(true)
      const fresh = c.loadModelInfo('p', 'm')
      expect(pending).toHaveLength(2)
      pending[1]!(ok({ id: 'm', name: 'Fresh' }))
      expect((await fresh).ok).toBe(true)
      pending[0]!(ok({ id: 'm', name: 'Stale' }))
      expect((await old).ok).toBe(false)
      expect(c.store.getState().models.value?.[0]?.models[0]?.name).toBe('Fresh')
    } finally {
      c.dispose()
    }
  })

  it('discards old detail responses after list refresh or disposal', async () => {
    let finish: (value: RpcResult<ModelOption>) => void = () => {}
    const api = fakeApi({
      listModels: () => ok(providers),
      getModelInfo: () =>
        new Promise(resolve => {
          finish = resolve
        }),
    })
    const c = createController({ api, storage: null })
    try {
      await c.loadModels()
      const old = c.loadModelInfo('p', 'm')
      await c.loadModels(true)
      finish(ok({ id: 'm', name: 'stale' }))
      expect((await old).ok).toBe(false)
      expect(c.store.getState().models.value?.[0]?.models[0]?.name).toBe('Model')
      const latest = c.loadModelInfo('p', 'm')
      c.dispose()
      finish(ok({ id: 'm', name: 'disposed' }))
      expect((await latest).ok).toBe(false)
      expect(api.callsOf('getModelInfo')).toHaveLength(2)
      expect((await c.loadModelInfo('p', 'm')).ok).toBe(false)
      expect(api.callsOf('getModelInfo')).toHaveLength(2)
    } finally {
      c.dispose()
    }
  })
})
