import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DshClientContext } from '../../src/client/dsh.ts'
import { apply, inject } from '../../src/client/index.ts'

afterEach(() => {
  document.head.innerHTML = ''
})

function fakeCtx() {
  const effects: { label: string | undefined; dispose: () => unknown }[] = []
  const registrations: { options: Record<string, unknown>; component: unknown }[] = []
  const injected: string[] = []
  const listeners: Record<string, () => void> = {}
  let localeListener: (() => void) | undefined
  let active = 'ja-JP'
  const ctx: DshClientContext = {
    slots: {
      inject(key, callback) {
        injected.push(key)
        callback()
      },
      register(options, component) {
        registrations.push({ options, component })
        return () => {}
      },
    },
    locale: {
      getLocale: () => ({ active }),
      subscribe(listener) {
        localeListener = listener
        return () => {
          localeListener = undefined
        }
      },
    },
    connection: {
      isLoopback: true,
      rpc: { call: vi.fn(async () => ({ ok: false as const, error: { code: 'security/not-found', message: '' } })) },
    },
    get: () => undefined,
    on(event, listener) {
      listeners[event] = listener
      return () => {
        delete listeners[event]
      }
    },
    effect(execute, label) {
      effects.push({ label, dispose: execute() })
    },
  }
  return {
    ctx,
    effects,
    registrations,
    injected,
    listeners,
    setLocale(next: string) {
      active = next
      localeListener?.()
    },
  }
}

describe('plugin entry', () => {
  it('declares the required services', () => {
    expect(inject).toEqual(['slots', 'locale', 'connection'])
  })

  it('registers sidebar, main and settings slots and one style tag', () => {
    const { ctx, registrations, injected, effects } = fakeCtx()
    apply(ctx)
    expect(injected).toEqual(['sidebar.panellist', 'main', 'settings.section'])
    const byName = Object.fromEntries(registrations.map(r => [r.options.name, r.options]))
    expect(byName['sidebar.panellist']).toMatchObject({ id: 'security', order: 20 })
    expect(byName.main).toMatchObject({ key: 'security' })
    expect(byName['settings.section']).toMatchObject({ id: 'security', order: 40 })
    const label = byName['sidebar.panellist']?.label as () => string
    expect(label()).toBe('セキュリティ')
    const props = (byName.main!.inject as () => { controller: unknown })()
    expect(props.controller).toBeDefined()

    const styles = document.head.querySelectorAll('style[data-plugin="dsh-security-plugin"]')
    expect(styles).toHaveLength(1)
    expect(styles[0]?.textContent).toContain('.dshsec-page')
    for (const e of effects) e.dispose()
    expect(document.head.querySelectorAll('style[data-plugin="dsh-security-plugin"]')).toHaveLength(0)
  })

  it('re-labels when the DSH locale changes and refetches on connection reset', async () => {
    const { ctx, registrations, listeners, setLocale, effects } = fakeCtx()
    apply(ctx)
    const label = registrations[0]?.options.label as () => string
    setLocale('zh-CN')
    expect(label()).toBe('安全')
    const rpc = ctx.connection.rpc.call as ReturnType<typeof vi.fn>
    const before = rpc.mock.calls.length
    listeners['connection/reset']?.()
    await Promise.resolve()
    const endpoints = rpc.mock.calls.slice(before).map(call => call[1])
    expect(endpoints).toContain('dsh-security/getBootstrap')
    expect(endpoints).toContain('dsh-security/listWorkspaces')
    for (const e of effects) e.dispose()
  })
})
