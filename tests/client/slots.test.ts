import { describe, expect, it } from 'vitest'
import { apply } from '../../src/client/index.ts'
import type { DshClientContext } from '../../src/client/dsh.ts'

describe('language slot registration', () => {
  it('re-registers the same ids when the plugin language changes and disposes them on unload', () => {
    const registrations: { name: string; id?: string }[] = []
    const live = new Map<string, number>()
    let localeListener: (() => void) | undefined
    let locale = 'en'
    const disposers: (() => void)[] = []
    const ctx = {
      slots: {
        inject(key: string, callback: () => (() => unknown) | undefined) {
          if (key === 'sidebar.panellist' || key === 'settings.section' || key === 'main') {
            const dispose = callback()
            if (dispose) disposers.push(() => dispose())
          }
        },
        register(options: { name: string; id?: string }) {
          registrations.push({ name: options.name, id: options.id })
          live.set(options.name, (live.get(options.name) ?? 0) + 1)
          let disposed = false
          return () => {
            if (disposed) return
            disposed = true
            live.set(options.name, (live.get(options.name) ?? 1) - 1)
          }
        },
      },
      locale: {
        getLocale: () => ({ active: locale }),
        subscribe(listener: () => void) {
          localeListener = listener
          return () => {
            if (localeListener === listener) localeListener = undefined
          }
        },
      },
      connection: {
        rpc: { call: async () => ({ ok: false, error: { code: 'unused', message: 'unused' } }) },
        isLoopback: true,
      },
      get: () => undefined,
      on: () => () => undefined,
      effect(execute: () => (() => unknown) | undefined) {
        const dispose = execute()
        if (dispose) disposers.push(() => dispose())
      },
    } as unknown as DshClientContext

    apply(ctx)
    const sidebar = () => registrations.filter(entry => entry.name === 'sidebar.panellist')
    const settings = () => registrations.filter(entry => entry.name === 'settings.section')
    expect(sidebar()).toEqual([{ name: 'sidebar.panellist', id: 'dsh-security' }])
    expect(settings()).toEqual([{ name: 'settings.section', id: 'dsh-security' }])
    expect(live.get('sidebar.panellist')).toBe(1)
    expect(live.get('settings.section')).toBe(1)

    locale = 'zh'
    localeListener?.()
    expect(sidebar()).toHaveLength(2)
    expect(settings()).toHaveLength(2)
    expect(sidebar().every(entry => entry.id === 'dsh-security')).toBe(true)
    expect(settings().every(entry => entry.id === 'dsh-security')).toBe(true)
    expect(live.get('sidebar.panellist')).toBe(1)
    expect(live.get('settings.section')).toBe(1)

    for (const dispose of disposers) dispose()
    expect(live.get('sidebar.panellist')).toBe(0)
    expect(live.get('settings.section')).toBe(0)
    locale = 'zh'
    localeListener?.()
    expect(sidebar()).toHaveLength(2)
    expect(settings()).toHaveLength(2)
  })
})
