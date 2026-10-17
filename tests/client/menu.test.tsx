import { act } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MenuButton, type MenuItem } from '../../src/client/components/Menu.tsx'
import { click, flush, type Mounted, mount } from './helpers.tsx'

let mounted: Mounted | undefined

afterEach(() => {
  mounted?.unmount()
  mounted = undefined
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const items = (onSelect = vi.fn()): MenuItem[] =>
  ['Markdown', 'JSON', 'SARIF'].map(label => ({ id: label, label, onSelect: () => onSelect(label) }))

function renderMenu(options: { disabled?: boolean; busy?: boolean; items?: MenuItem[]; dialog?: boolean } = {}) {
  const onSelect = vi.fn()
  const entries = options.items ?? items(onSelect)
  const content = (overrides = {}) => (
    <div className="dshsec-root" lang="ja" style={{ color: 'rgb(1, 2, 3)' }}>
      <div {...(options.dialog ? { role: 'dialog' } : {})}>
        <button type="button">Before</button>
        <div className="dshsec-table-wrap" style={{ overflowX: 'auto' }}>
          <MenuButton label="書き出し" items={entries} {...options} {...overrides} />
        </div>
        <button type="button">After</button>
      </div>
    </div>
  )
  mounted = mount(content())
  const trigger = mounted.container.querySelector<HTMLButtonElement>('[aria-haspopup="menu"]')!
  const panel = () => mounted?.container.querySelector<HTMLElement>('[role="menu"]') ?? null
  const entriesInMenu = () => [...(panel()?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])]
  return { trigger, panel, entriesInMenu, onSelect, content, container: mounted.container }
}

async function key(el: Element, value: string, shiftKey = false) {
  const event = new KeyboardEvent('keydown', { key: value, shiftKey, bubbles: true, cancelable: true })
  await act(async () => {
    el.dispatchEvent(event)
  })
  return event
}

function geometry(options: { trigger?: DOMRect; origin?: DOMRect; width?: number; height?: number } = {}) {
  let trigger = options.trigger ?? new DOMRect(560, 340, 70, 30)
  const origin = options.origin ?? new DOMRect()
  vi.stubGlobal('innerWidth', 640)
  vi.stubGlobal('innerHeight', 400)
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    if (this.getAttribute('aria-haspopup') === 'menu') return trigger
    if (this.classList.contains('dshsec-menu-layer')) return origin
    if (this.getAttribute('role') === 'menu') return new DOMRect(0, 0, options.width ?? 180, options.height ?? 100)
    return new DOMRect()
  })
  vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockImplementation(function (this: HTMLElement) {
    return this.getAttribute('role') === 'menu' ? (options.height ?? 100) : 0
  })
  return { move: (rect: DOMRect) => (trigger = rect) }
}

describe('MenuButton portal', () => {
  it('places the popup outside the clipping table but inside the theme/language root', async () => {
    geometry()
    const menu = renderMenu()
    await click(menu.trigger)
    const panel = menu.panel()!
    expect(panel.closest('.dshsec-table-wrap')).toBeNull()
    expect(panel.closest('.dshsec-root')?.getAttribute('lang')).toBe('ja')
    expect(panel.parentElement?.className).toBe('dshsec-menu-layer')
    expect(panel.getAttribute('aria-labelledby')).toBe(menu.trigger.id)
    expect(panel.id).toBe(menu.trigger.getAttribute('aria-controls'))
    expect(menu.trigger.getAttribute('aria-expanded')).toBe('true')
    expect(document.activeElement).toBe(menu.entriesInMenu()[0])
    expect(panel.style.top).toBe('236px')
    expect(panel.style.left).toBe('450px')
    expect(panel.style.right).toBe('auto')
  })

  it('keeps a dialog popup inside its focus scope rather than moving it to body', async () => {
    geometry()
    const menu = renderMenu({ dialog: true })
    await click(menu.trigger)
    expect(menu.panel()?.parentElement?.parentElement?.getAttribute('role')).toBe('dialog')
  })

  it('clamps both axes, chooses the larger side, and compensates for the layer origin', async () => {
    const geo = geometry({
      trigger: new DOMRect(3, 1, 40, 24),
      origin: new DOMRect(20, 30, 640, 400),
      width: 180,
      height: 900,
    })
    const menu = renderMenu()
    await click(menu.trigger)
    expect(menu.panel()?.style.left).toBe('-12px')
    expect(menu.panel()?.style.top).toBe('-1px')
    expect(menu.panel()?.style.maxHeight).toBe('363px')
    geo.move(new DOMRect(800, 500, 40, 24))
    await act(async () => document.dispatchEvent(new Event('scroll')))
    expect(menu.panel()?.style.left).toBe('432px')
    expect(menu.panel()?.style.top).toBe('-22px')
    expect(menu.panel()?.style.maxHeight).toBe('384px')
  })

  it('tracks resize and ancestor scrolling without closing or resetting the focused item', async () => {
    const geo = geometry()
    const menu = renderMenu()
    await click(menu.trigger)
    await key(document.activeElement!, 'ArrowDown')
    const focused = document.activeElement
    geo.move(new DOMRect(30, 100, 70, 30))
    await act(async () => window.dispatchEvent(new Event('resize')))
    expect(menu.panel()?.style.left).toBe('8px')
    expect(menu.panel()?.style.top).toBe('134px')
    await act(async () => menu.container.querySelector('.dshsec-table-wrap')!.dispatchEvent(new Event('scroll')))
    expect(menu.panel()).not.toBeNull()
    expect(document.activeElement).toBe(focused)
  })

  it('bounds long Japanese or unbroken labels to the viewport without truncating their text', async () => {
    geometry()
    const label = '非常に長い日本語の形式名とファイル名'.repeat(20)
    const menu = renderMenu({ items: [{ id: 'long', label, onSelect: vi.fn() }] })
    await click(menu.trigger)
    expect(menu.entriesInMenu()[0]?.textContent).toBe(label)
    expect(menu.panel()?.style.width).toBe('max-content')
    expect(menu.panel()?.style.maxWidth).toBe('max(0px, calc(100vw - 16px))')
    expect(menu.panel()?.classList.contains('dshsec-menu-panel')).toBe(true)
  })

  it('supports arrows, Home, End, Escape and selection with trigger focus restored', async () => {
    geometry()
    const menu = renderMenu()
    await key(menu.trigger, 'ArrowUp')
    expect(document.activeElement).toBe(menu.entriesInMenu()[2])
    await key(document.activeElement!, 'ArrowDown')
    expect(document.activeElement).toBe(menu.entriesInMenu()[0])
    await key(document.activeElement!, 'End')
    expect(document.activeElement).toBe(menu.entriesInMenu()[2])
    await key(document.activeElement!, 'Home')
    expect(document.activeElement).toBe(menu.entriesInMenu()[0])
    await key(document.activeElement!, 'Escape')
    expect(menu.panel()).toBeNull()
    expect(document.activeElement).toBe(menu.trigger)
    await click(menu.trigger)
    await click(menu.entriesInMenu()[1])
    expect(menu.onSelect).toHaveBeenCalledExactlyOnceWith('JSON')
    expect(menu.panel()).toBeNull()
    expect(document.activeElement).toBe(menu.trigger)
  })

  it.each([false, true])(
    'closes on Tab (shift=%s) and moves to the trigger neighbour, not the portal neighbour',
    async shift => {
      geometry()
      const menu = renderMenu()
      await click(menu.trigger)
      const event = await key(document.activeElement!, 'Tab', shift)
      expect(event.defaultPrevented).toBe(true)
      expect(menu.panel()).toBeNull()
      expect(document.activeElement?.textContent).toBe(shift ? 'Before' : 'After')
    },
  )

  it('keeps Tab navigation inside a containing dialog and skips hidden or disabled controls', async () => {
    geometry()
    const menu = renderMenu({ dialog: true })
    const after = [...menu.container.querySelectorAll('button')].find(button => button.textContent === 'After')!
    const hidden = document.createElement('button')
    hidden.textContent = 'Hidden'
    hidden.hidden = true
    after.before(hidden)
    const disabled = document.createElement('button')
    disabled.textContent = 'Disabled'
    disabled.disabled = true
    after.before(disabled)
    await click(menu.trigger)
    await key(document.activeElement!, 'Tab')
    expect(document.activeElement).toBe(after)
    after.remove()
    await click(menu.trigger)
    await key(document.activeElement!, 'Tab')
    expect(document.activeElement?.textContent).toBe('Before')
  })

  it('treats portal clicks as inside and outside clicks/focus as close without stealing focus', async () => {
    geometry()
    const menu = renderMenu()
    await click(menu.trigger)
    await act(async () => menu.entriesInMenu()[1]!.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })))
    expect(menu.panel()).not.toBeNull()
    const after = [...menu.container.querySelectorAll('button')].find(button => button.textContent === 'After')!
    await act(async () => {
      after.focus()
      after.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    })
    expect(menu.panel()).toBeNull()
    expect(document.activeElement).toBe(after)
  })

  it.each([{ disabled: true }, { busy: true }, { items: [] }])('closes when no longer available: %j', async change => {
    geometry()
    const menu = renderMenu()
    await click(menu.trigger)
    mounted!.rerender(menu.content(change))
    expect(menu.panel()).toBeNull()
    expect(menu.trigger.disabled).toBe(true)
    mounted!.rerender(menu.content())
    expect(menu.panel()).toBeNull()
  })

  it('removes the portal when its trigger disappears and cleans up resize/scroll listeners on unmount', async () => {
    geometry()
    const docRemove = vi.spyOn(document, 'removeEventListener')
    const winRemove = vi.spyOn(window, 'removeEventListener')
    const menu = renderMenu()
    await click(menu.trigger)
    // Simulate an external owner removing the trigger while its component is alive.
    const wrap = menu.trigger.parentElement!
    const comment = document.createComment('trigger owner')
    wrap.replaceChild(comment, menu.trigger)
    await flush()
    expect(menu.panel()).toBeNull()
    wrap.replaceChild(menu.trigger, comment)
    await click(menu.trigger)
    mounted!.unmount()
    mounted = undefined
    expect(document.querySelector('.dshsec-menu-layer')).toBeNull()
    expect(docRemove.mock.calls.some(([type, , capture]) => type === 'scroll' && capture === true)).toBe(true)
    expect(docRemove.mock.calls.some(([type]) => type === 'mousedown')).toBe(true)
    expect(docRemove.mock.calls.some(([type]) => type === 'focusin')).toBe(true)
    expect(winRemove.mock.calls.some(([type]) => type === 'resize')).toBe(true)
  })
})
