import { act } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Field } from '../../src/client/components/Field.tsx'
import { ProjectSelect } from '../../src/client/components/ProjectSelect.tsx'
import type { WorkspaceSummary } from '../../src/shared/contracts.ts'
import { click, type Mounted, mount } from './helpers.tsx'

let mounted: Mounted | undefined

afterEach(() => {
  mounted?.unmount()
  mounted = undefined
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const WORKSPACES = [
  { id: 'alpha', title: 'Alpha', displayPath: '~/code/alpha' },
  { id: 'beta', title: 'Beta', displayPath: '~/code/beta' },
  { id: 'bravo', title: 'Bravo', displayPath: '~/code/bravo' },
]

function renderPicker(variant: 'quiet' | 'field' = 'quiet', workspaces: readonly WorkspaceSummary[] = WORKSPACES) {
  const onChange = vi.fn()
  mounted = mount(
    <div className="dshsec-root">
      <ProjectSelect workspaces={workspaces} value="beta" onChange={onChange} variant={variant} ariaLabel="Project" />
      <button type="button">After picker</button>
    </div>,
  )
  const trigger = mounted.container.querySelector<HTMLButtonElement>('button[aria-haspopup="listbox"]')
  const list = () => mounted?.container.querySelector<HTMLElement>('[role="listbox"]') ?? null
  const options = () => [...(list()?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? [])]
  return { trigger, list, options, onChange, container: mounted.container }
}

async function key(el: Element, value: string) {
  await act(async () => {
    el.dispatchEvent(new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true }))
  })
}

describe('ProjectSelect', () => {
  it.each(['quiet', 'field'] as const)(
    'opens the %s listbox on click with selected focus and a fixed check gutter',
    async variant => {
      const picker = renderPicker(variant)
      expect(picker.trigger?.type).toBe('button')
      expect(picker.trigger?.getAttribute('aria-label')).toBe('Project: Beta')
      expect(picker.trigger?.getAttribute('aria-expanded')).toBe('false')
      await click(picker.trigger)
      expect(picker.list()?.id).toBe(picker.trigger?.getAttribute('aria-controls'))
      expect(picker.trigger?.getAttribute('aria-expanded')).toBe('true')
      expect(picker.options().map(o => o.getAttribute('aria-selected'))).toEqual(['false', 'true', 'false'])
      expect(document.activeElement).toBe(picker.options()[1])
      expect(picker.options()[1]?.querySelector('.dshsec-projsel-check svg')).not.toBeNull()
      expect(picker.options()[0]?.querySelector('.dshsec-projsel-check svg')).toBeNull()
      expect(picker.options().every(o => o.querySelector('.dshsec-projsel-check'))).toBe(true)
      await click(picker.options()[0])
      expect(picker.onChange).toHaveBeenCalledExactlyOnceWith('alpha')
      expect(picker.list()).toBeNull()
      expect(document.activeElement).toBe(picker.trigger)
    },
  )

  it.each(['Enter', ' ', 'ArrowDown', 'ArrowUp'])(
    'opens with %s on the selected option, not the first',
    async value => {
      const picker = renderPicker()
      await key(picker.trigger!, value)
      expect(document.activeElement).toBe(picker.options()[1])
    },
  )

  it('moves with ArrowDown and selects with Enter, reporting the workspace id', async () => {
    const picker = renderPicker()
    await key(picker.trigger!, 'ArrowDown')
    await key(document.activeElement!, 'ArrowDown')
    expect(document.activeElement).toBe(picker.options()[2])
    await key(document.activeElement!, 'Enter')
    expect(picker.onChange).toHaveBeenCalledExactlyOnceWith('bravo')
    expect(picker.list()).toBeNull()
    expect(document.activeElement).toBe(picker.trigger)
  })

  it('wraps arrows, supports Home/End and selects with Space', async () => {
    const picker = renderPicker()
    await click(picker.trigger)
    await key(document.activeElement!, 'End')
    await key(document.activeElement!, 'ArrowDown')
    expect(document.activeElement).toBe(picker.options()[0])
    await key(document.activeElement!, 'ArrowUp')
    expect(document.activeElement).toBe(picker.options()[2])
    await key(document.activeElement!, 'Home')
    expect(document.activeElement).toBe(picker.options()[0])
    await key(document.activeElement!, ' ')
    expect(picker.onChange).toHaveBeenCalledExactlyOnceWith('alpha')
  })

  it('closes on Escape, refocuses the trigger and does not change selection', async () => {
    const picker = renderPicker()
    await click(picker.trigger)
    await key(document.activeElement!, 'Escape')
    expect(picker.list()).toBeNull()
    expect(document.activeElement).toBe(picker.trigger)
    expect(picker.onChange).not.toHaveBeenCalled()
  })

  it('closes on Tab without preventing normal navigation', async () => {
    const picker = renderPicker()
    await click(picker.trigger)
    const event = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })
    await act(async () => {
      document.activeElement?.dispatchEvent(event)
    })
    expect(event.defaultPrevented).toBe(false)
    expect(picker.list()).toBeNull()
    expect(document.activeElement).toBe(picker.trigger)
  })

  it('closes on outside mousedown without stealing focus', async () => {
    const picker = renderPicker()
    await click(picker.trigger)
    const after = picker.container.querySelector<HTMLButtonElement>('.dshsec-root > button')!
    await act(async () => {
      after.focus()
      after.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    })
    expect(picker.list()).toBeNull()
    expect(document.activeElement).toBe(after)
  })

  it('cycles repeated letters, matches prefixes and resets typeahead after 600ms', async () => {
    const picker = renderPicker()
    let now = 1000
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    await click(picker.trigger)
    await key(document.activeElement!, 'b')
    expect(document.activeElement).toBe(picker.options()[2])
    await key(document.activeElement!, 'b')
    expect(document.activeElement).toBe(picker.options()[1])
    await key(document.activeElement!, 'r')
    expect(document.activeElement).toBe(picker.options()[2])
    now += 601
    await key(document.activeElement!, 'a')
    expect(document.activeElement).toBe(picker.options()[0])
  })

  it.each(['quiet', 'field'] as const)(
    'positions the %s panel outside scroll bodies and caps it on narrow viewports',
    async variant => {
      vi.stubGlobal('innerWidth', 1024)
      vi.stubGlobal('innerHeight', 768)
      vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
        if (this.classList.contains('dshsec-projsel-trigger')) return new DOMRect(30, 100, 600, 34)
        if (this.classList.contains('dshsec-projsel-layer')) return new DOMRect(10, 20, 1024, 768)
        return new DOMRect()
      })
      const picker = renderPicker(variant)
      await click(picker.trigger)
      const panel = picker.list()!
      expect(panel.style.width).toBe(variant === 'quiet' ? '440px' : '600px')
      expect(panel.style.left).toBe('20px')
      expect(panel.style.top).toBe('118px')
      expect(panel.style.maxHeight).toBe('320px')
      vi.stubGlobal('innerWidth', 360)
      await act(async () => {
        window.dispatchEvent(new Event('resize'))
      })
      expect(panel.style.width).toBe('328px')
      expect(panel.style.left).toBe('6px')
    },
  )

  it('renders long Japanese titles and full paths as separate ellipsis-ready lines', async () => {
    const long = {
      id: 'long',
      title: '日本語の長いプロジェクト名'.repeat(8),
      displayPath: `~/very/${'long/'.repeat(30)}unique-tail`,
    }
    const picker = renderPicker('quiet', [...WORKSPACES, long])
    await click(picker.trigger)
    const option = picker.options().at(-1)!
    expect(option.querySelector('.dshsec-projsel-title')?.textContent).toBe(long.title)
    expect(option.querySelector('.dshsec-projsel-path')?.textContent).toBe(long.displayPath)
    expect(option.title).toBe(long.displayPath)
  })

  it('falls back to path/id and omits the secondary line when there is no title or path', async () => {
    const picker = renderPicker('quiet', [
      { id: 'path', title: '', displayPath: '~/path-only' },
      { id: 'id-only', title: '', displayPath: '' },
      { id: 'title', title: 'Title only', displayPath: '' },
    ])
    await click(picker.trigger)
    expect(picker.options().map(o => o.querySelector('.dshsec-projsel-title')?.textContent)).toEqual([
      '~/path-only',
      'id-only',
      'Title only',
    ])
    expect(picker.list()?.querySelector('.dshsec-projsel-path')).toBeNull()
  })

  it.each(['quiet', 'field'] as const)('never opens a popup for one workspace in the %s variant', async variant => {
    const picker = renderPicker(variant, [WORKSPACES[0]!])
    expect(picker.trigger).toBeNull()
    if (variant === 'quiet') expect(picker.container.querySelector('.dshsec-project')?.tagName).toBe('DIV')
    else expect(picker.container.querySelector<HTMLButtonElement>('.dshsec-projsel-trigger')?.disabled).toBe(true)
    await click(picker.container.querySelector('.dshsec-project-title'))
    expect(picker.list()).toBeNull()
    expect(picker.onChange).not.toHaveBeenCalled()
  })

  it('wires field label, description, validation and disabled state to the real trigger', async () => {
    const onChange = vi.fn()
    const field = (disabled: boolean) => (
      <div className="dshsec-root">
        <Field label="Project" hint="Managed by DSH" error="Choose a project">
          {({ id, describedBy, invalid }) => (
            <ProjectSelect
              workspaces={WORKSPACES}
              value="beta"
              onChange={onChange}
              variant="field"
              ariaLabel="Project"
              id={id}
              describedBy={describedBy}
              invalid={invalid}
              disabled={disabled}
            />
          )}
        </Field>
      </div>
    )
    mounted = mount(field(false))
    const label = mounted.container.querySelector('label')!
    const trigger = document.getElementById(label.htmlFor) as HTMLButtonElement
    expect(trigger.tagName).toBe('BUTTON')
    expect(trigger.getAttribute('aria-invalid')).toBe('true')
    expect(
      trigger
        .getAttribute('aria-describedby')
        ?.split(' ')
        .map(id => document.getElementById(id)?.textContent),
    ).toEqual(['Managed by DSH', 'Choose a project'])
    await click(trigger)
    expect(mounted.container.querySelector('[role="listbox"]')).not.toBeNull()
    mounted.rerender(field(true))
    expect(trigger.disabled).toBe(true)
    expect(mounted.container.querySelector('[role="listbox"]')).toBeNull()
    await click(trigger)
    expect(mounted.container.querySelector('[role="listbox"]')).toBeNull()
    mounted.rerender(field(false))
    expect(mounted.container.querySelector('[role="listbox"]')).toBeNull()
  })
})
