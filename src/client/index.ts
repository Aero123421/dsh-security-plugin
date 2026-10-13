/**
 * Browser plugin entry. DSH loads `lib/client.js`, injects the Cordis
 * services named in `inject`, and calls `apply(ctx)`. Everything the plugin
 * owns (style tag, controller timers, subscriptions, slot registrations) is
 * tied to `ctx` so unloading the plugin removes it.
 */

import { createApi } from './api.ts'
import { createController } from './controller.ts'
import { asLayout, asUiWorkspace, type DshClientContext } from './dsh.ts'
import { getTranslator } from './i18n.ts'
import { SecurityPanelIcon } from './icons.tsx'
import { STYLE_ATTRIBUTE, STYLES } from './styles.ts'
import { SecurityPage } from './views/SecurityPage.tsx'
import { SettingsSection } from './views/Settings.tsx'

export const inject = ['slots', 'locale', 'connection']

export function apply(ctx: DshClientContext): void {
  const controller = createController({
    api: createApi(ctx.connection.rpc),
    dshLocale: safeLocale(ctx),
    host: {
      layout: () => asLayout(ctx.get('layout')),
      uiWorkspace: () => asUiWorkspace(ctx.get('uiWorkspace')),
      isLoopback: ctx.connection.isLoopback === true,
    },
  })
  const label = () => getTranslator(controller.store.getState().language).t('nav.security')

  ctx.effect(() => {
    const style = document.createElement('style')
    style.setAttribute('data-plugin', STYLE_ATTRIBUTE)
    style.textContent = STYLES
    document.head.append(style)
    return () => style.remove()
  }, 'dsh-security:styles')

  ctx.effect(() => () => controller.dispose(), 'dsh-security:controller')

  ctx.effect(() => ctx.locale.subscribe(() => controller.setDshLocale(safeLocale(ctx))), 'dsh-security:locale')

  ctx.effect(
    () =>
      ctx.on('connection/reset', () => {
        void controller.reload()
      }),
    'dsh-security:reconnect',
  )

  ctx.slots.inject('sidebar.panellist', () =>
    ctx.slots.register({ name: 'sidebar.panellist', id: 'security', order: 20, label }, SecurityPanelIcon),
  )

  ctx.slots.inject('main', () =>
    ctx.slots.register({ name: 'main', key: 'security', inject: () => ({ controller }) }, SecurityPage),
  )

  ctx.slots.inject('settings.section', () =>
    ctx.slots.register(
      { name: 'settings.section', id: 'security', order: 40, label, inject: () => ({ controller }) },
      SettingsSection,
    ),
  )
}

function safeLocale(ctx: DshClientContext): string {
  try {
    const active = ctx.locale.getLocale()?.active
    return typeof active === 'string' ? active : 'en'
  } catch {
    return 'en'
  }
}
