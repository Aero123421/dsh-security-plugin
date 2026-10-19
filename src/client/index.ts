/**
 * Browser plugin entry. DSH loads `lib/client.js`, injects the Cordis
 * services named in `inject`, and calls `apply(ctx)`. Everything the plugin
 * owns (style tag, controller timers, subscriptions, slot registrations) is
 * tied to `ctx` so unloading the plugin removes it.
 */

import { createApi } from './api.ts'
import { createController } from './controller.ts'
import { asLayout, asUiWorkspace, asWorkspaces, type DshClientContext, SECURITY_SLOT_ID } from './dsh.ts'
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
      workspaces: () => asWorkspaces(ctx.get('workspaces')),
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
        // A new connection may reach a restarted Host: start a new request generation.
        void controller.reload()
      }),
    'dsh-security:reconnect',
  )

  ctx.slots.inject('sidebar.panellist', () =>
    bindLanguageSlot(controller.store, () =>
      ctx.slots.register({ name: 'sidebar.panellist', id: SECURITY_SLOT_ID, order: 20, label }, SecurityPanelIcon),
    ),
  )

  ctx.slots.inject('main', () =>
    ctx.slots.register({ name: 'main', key: SECURITY_SLOT_ID, inject: () => ({ controller }) }, SecurityPage),
  )

  ctx.slots.inject('settings.section', () =>
    bindLanguageSlot(controller.store, () =>
      ctx.slots.register(
        { name: 'settings.section', id: SECURITY_SLOT_ID, order: 40, label, inject: () => ({ controller }) },
        SettingsSection,
      ),
    ),
  )
}

/**
 * Re-register one slot when the plugin language changes. DSH resolves `label`
 * only when the slot ledger or the DSH locale changes, so a language that
 * arrives after bootstrap would otherwise stay on the first English label.
 * The previous registration is removed before the next one is added.
 */
function bindLanguageSlot(
  store: { getState(): { readonly language: string }; subscribe(listener: () => void): () => void },
  register: () => () => unknown,
): () => void {
  let dispose = register()
  let language = store.getState().language
  const unsubscribe = store.subscribe(() => {
    const next = store.getState().language
    if (next === language) return
    language = next
    const previous = dispose
    previous()
    dispose = register()
  })
  return () => {
    unsubscribe()
    dispose()
  }
}

function safeLocale(ctx: DshClientContext): string {
  try {
    const active = ctx.locale.getLocale()?.active
    return typeof active === 'string' ? active : 'en'
  } catch {
    return 'en'
  }
}
