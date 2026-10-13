/**
 * Bootstrap/settings races, driven by barriers: each `getBootstrap` call
 * returns a deferred promise the test resolves in a chosen order, so an old
 * response can be made to arrive after a newer one (no sleeps).
 */

import { describe, expect, it } from 'vitest'
import { createController } from '../../src/client/controller.ts'
import type { Bootstrap, RpcResult } from '../../src/shared/contracts.ts'
import type { UiLanguage } from '../../src/shared/settings.ts'
import { fail, fakeApi, makeBootstrap, makeSettings, ok } from './helpers.tsx'

interface Deferred<T> {
  readonly promise: Promise<T>
  resolve(value: T): void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => {
    resolve = r
  })
  return { promise, resolve }
}

/** Let every queued continuation run (no timers involved). */
async function flush() {
  for (let i = 0; i < 10; i++) await Promise.resolve()
}

function bootstrapAt(revision: number, language: UiLanguage): RpcResult<Bootstrap> {
  return ok(makeBootstrap({ settingsRevision: revision, settings: makeSettings({ ui: { language } }) }))
}

/** A fake API whose `getBootstrap` calls each wait on their own barrier. */
function barrierApi() {
  const pending: Deferred<RpcResult<Bootstrap>>[] = []
  const api = fakeApi({
    getBootstrap: () => {
      const gate = deferred<RpcResult<Bootstrap>>()
      pending.push(gate)
      return gate.promise
    },
    listWorkspaces: () => ok([]),
  })
  return { api, pending }
}

function settingsOf(controller: ReturnType<typeof createController>) {
  const state = controller.store.getState()
  return {
    revision: state.bootstrap.value?.settingsRevision,
    language: state.bootstrap.value?.settings.ui.language,
    formRevision: state.form?.revision,
    formLanguage: state.form?.base.ui.language,
    status: state.bootstrap.status,
  }
}

describe('controller bootstrap generations', () => {
  it('a forced reload starts a new request instead of joining the in-flight one', async () => {
    const { api, pending } = barrierApi()
    const controller = createController({ api, storage: null })
    const first = controller.reloadBootstrap()
    const joined = controller.reloadBootstrap()
    expect(pending).toHaveLength(1)
    const forced = controller.reloadBootstrap({ force: true })
    expect(pending).toHaveLength(2)

    // The newer request answers first, then the older one arrives with older settings.
    pending[1]!.resolve(bootstrapAt(3, 'ja'))
    await forced
    pending[0]!.resolve(bootstrapAt(2, 'zh'))
    const [a, b] = await Promise.all([first, joined])

    expect(settingsOf(controller)).toEqual({
      revision: 3,
      language: 'ja',
      formRevision: 3,
      formLanguage: 'ja',
      status: 'ready',
    })
    // Callers of the superseded request get the newer outcome, not the stale one.
    expect(a.ok && a.value.settingsRevision).toBe(3)
    expect(b.ok && b.value.settingsRevision).toBe(3)
    controller.dispose()
  })

  it('discards an older generation even when it answers with a higher revision', async () => {
    const { api, pending } = barrierApi()
    const controller = createController({ api, storage: null })
    void controller.reloadBootstrap()
    // A reconnect: the new connection may reach a different (restarted) Host.
    const reloaded = controller.reload()
    pending[1]!.resolve(bootstrapAt(1, 'ja'))
    await reloaded
    pending[0]!.resolve(bootstrapAt(9, 'zh'))
    await flush()
    expect(settingsOf(controller)).toMatchObject({ revision: 1, language: 'ja' })
    controller.dispose()
  })

  it('an older generation failing after a newer success leaves no error behind', async () => {
    const { api, pending } = barrierApi()
    const controller = createController({ api, storage: null })
    const first = controller.reloadBootstrap()
    const forced = controller.reloadBootstrap({ force: true })
    pending[1]!.resolve(bootstrapAt(2, 'ja'))
    await forced
    pending[0]!.resolve(fail('security/transport'))
    const result = await first
    expect(result.ok).toBe(true)
    expect(controller.store.getState().bootstrap).toMatchObject({ status: 'ready' })
    expect(controller.store.getState().bootstrap.error).toBeUndefined()
    controller.dispose()
  })

  it('never applies a bootstrap whose settings revision is older than a completed save', async () => {
    const { api, pending } = barrierApi()
    api.handlers.updateSettings = () => ok({ settings: makeSettings({ ui: { language: 'zh' } }), revision: 5 })
    const controller = createController({ api, storage: null })
    const initial = controller.reloadBootstrap()
    pending[0]!.resolve(bootstrapAt(4, 'auto'))
    await initial

    // A revalidation read starts, the user saves, and the save finishes first.
    const stale = controller.reloadBootstrap()
    controller.updateDraft(d => ({ ...d, ui: { language: 'zh' } }))
    await controller.saveSettings()
    expect(settingsOf(controller)).toMatchObject({ revision: 5, language: 'zh', formRevision: 5 })

    pending[1]!.resolve(
      ok(
        makeBootstrap({
          settingsRevision: 4,
          settings: makeSettings({ ui: { language: 'auto' } }),
          canEditHighRiskSettings: false,
        }),
      ),
    )
    const result = await stale
    expect(settingsOf(controller)).toEqual({
      revision: 5,
      language: 'zh',
      formRevision: 5,
      formLanguage: 'zh',
      status: 'ready',
    })
    expect(controller.store.getState().form?.draft.ui.language).toBe('zh')
    expect(controller.store.getState().language).toBe('zh')
    // The non-settings fields of that response are still current and are kept.
    expect(controller.store.getState().bootstrap.value?.canEditHighRiskSettings).toBe(false)
    expect(result.ok && result.value.settingsRevision).toBe(5)
    controller.dispose()
  })

  it('a save conflict forces a fresh read instead of joining an older in-flight one', async () => {
    const { api, pending } = barrierApi()
    api.handlers.updateSettings = () => ({
      ok: false,
      error: { code: 'security/conflict', message: 'conflict', details: { revision: 2 } },
    })
    const controller = createController({ api, storage: null })
    const initial = controller.reloadBootstrap()
    pending[0]!.resolve(bootstrapAt(1, 'auto'))
    await initial

    const older = controller.reloadBootstrap() // started before the other tab's change landed
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '30' } }))
    const saving = controller.saveSettings()
    await flush()
    expect(pending).toHaveLength(3)
    pending[2]!.resolve(bootstrapAt(2, 'ja'))
    await saving
    pending[1]!.resolve(bootstrapAt(1, 'auto'))
    await older

    expect(settingsOf(controller)).toMatchObject({ revision: 2, language: 'ja', formRevision: 2 })
    const form = controller.store.getState().form
    expect(form?.draft.storage.retentionDays).toBe('30')
    expect(form?.result).toEqual({ tone: 'warn', key: 'settings.conflict' })
    controller.dispose()
  })

  it('accepts a lower revision after a conflict shows the Host store was reset', async () => {
    let served = bootstrapAt(7, 'ja')
    const api = fakeApi({
      getBootstrap: () => served,
      updateSettings: () => ({
        ok: false,
        error: { code: 'security/conflict', message: 'conflict', details: { revision: 0 } },
      }),
    })
    const controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    served = bootstrapAt(0, 'auto')
    // Without evidence of a reset, the lower revision is treated as stale.
    await controller.reloadBootstrap({ force: true })
    expect(settingsOf(controller)).toMatchObject({ revision: 7, language: 'ja' })

    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '30' } }))
    await controller.saveSettings()
    expect(settingsOf(controller)).toMatchObject({ revision: 0, language: 'auto', formRevision: 0 })
    controller.dispose()
  })

  it('ignores a bootstrap that arrives after dispose', async () => {
    const { api, pending } = barrierApi()
    const controller = createController({ api, storage: null })
    const request = controller.reloadBootstrap()
    controller.dispose()
    pending[0]!.resolve(bootstrapAt(3, 'ja'))
    const result = await request
    expect(result.ok).toBe(false)
    expect(controller.store.getState().bootstrap.value).toBeUndefined()
  })
})
