import { act, useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Modal } from '../../src/client/components/Modal.tsx'
import { ControllerProvider } from '../../src/client/context.tsx'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { click, fakeApi, flush, type Mounted, mount } from './helpers.tsx'

let mounted: Mounted | undefined
let controller: SecurityController | undefined
afterEach(() => {
  mounted?.unmount()
  mounted = undefined
  controller?.dispose()
  controller = undefined
  document.body.innerHTML = ''
})

function render(ui: React.ReactNode) {
  controller = createController({ api: fakeApi(), storage: null })
  mounted = mount(<ControllerProvider controller={controller}>{ui}</ControllerProvider>)
  return mounted.container
}

async function press(target: EventTarget, key: string) {
  await act(async () => {
    target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }))
  })
}

/**
 * Two dialogs: the follow-up opens first, then the first closes once its
 * awaited work settles (Add folder registering a path, then New scan).
 */
function Handover(props: { readonly onSecondClosed?: () => void }) {
  const [first, setFirst] = useState(false)
  const [second, setSecond] = useState(false)
  return (
    <>
      <button type="button" onClick={() => setFirst(true)}>
        Opener
      </button>
      {first ? (
        <Modal title="First" onClose={() => setFirst(false)}>
          <button
            type="button"
            onClick={async () => {
              setSecond(true)
              await Promise.resolve()
              setFirst(false)
            }}
          >
            Continue
          </button>
        </Modal>
      ) : null}
      {second ? (
        <Modal
          title="Second"
          onClose={() => {
            setSecond(false)
            props.onSecondClosed?.()
          }}
        >
          <input aria-label="Second field" />
        </Modal>
      ) : null}
    </>
  )
}

describe('modal focus', () => {
  it('returns focus to the opener when the dialog closes', async () => {
    const container = render(<Handover />)
    const opener = [...container.querySelectorAll('button')].find(b => b.textContent === 'Opener')!
    opener.focus()
    await click(opener)
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!
    expect(dialog.contains(document.activeElement)).toBe(true)
    await press(document.activeElement!, 'Escape')
    expect(document.querySelector('[role="dialog"]')).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  it('leaves focus in a dialog that opened while the previous one closed', async () => {
    const container = render(<Handover />)
    const opener = [...container.querySelectorAll('button')].find(b => b.textContent === 'Opener')!
    opener.focus()
    await click(opener)
    const next = [...document.querySelectorAll<HTMLButtonElement>('[role="dialog"] button')].find(
      b => b.textContent === 'Continue',
    )!
    next.focus()
    await click(next)
    await flush()
    const dialogs = document.querySelectorAll<HTMLElement>('[role="dialog"]')
    expect(dialogs).toHaveLength(1)
    expect(dialogs[0]!.textContent).toContain('Second')
    expect(document.activeElement?.getAttribute('aria-label')).toBe('Second field')
  })

  it('closes the topmost dialog on Escape even when focus left every dialog', async () => {
    const closed = vi.fn()
    const container = render(<Handover onSecondClosed={closed} />)
    const opener = [...container.querySelectorAll('button')].find(b => b.textContent === 'Opener')!
    await click(opener)
    await click([...document.querySelectorAll('[role="dialog"] button')].find(b => b.textContent === 'Continue'))
    ;(document.activeElement as HTMLElement | null)?.blur()
    expect(document.activeElement).toBe(document.body)
    await press(document.body, 'Escape')
    expect(closed).toHaveBeenCalledTimes(1)
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })
})
