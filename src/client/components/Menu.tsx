import { type KeyboardEvent, type ReactNode, useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { IconChevronDown } from '../icons.tsx'

export interface MenuItem {
  readonly id: string
  readonly label: string
  readonly onSelect: () => void
}

const VIEWPORT_GUTTER = 8
const TRIGGER_GAP = 4

/** Find the trigger's neighbour, not the portalled menu's DOM neighbour. */
function tabNeighbour(trigger: HTMLButtonElement, backwards: boolean): HTMLElement | undefined {
  const doc = trigger.ownerDocument
  const scope = trigger.closest<HTMLElement>('[role="dialog"], [role="alertdialog"]') ?? doc
  const candidates = [
    ...scope.querySelectorAll<HTMLElement>(
      'a[href], area[href], button, input, select, textarea, [tabindex], [contenteditable="true"]',
    ),
  ].filter(element => {
    if (element.tabIndex < 0 || element.matches(':disabled') || element.closest('[hidden], [inert]')) return false
    for (let ancestor: HTMLElement | null = element; ancestor; ancestor = ancestor.parentElement) {
      const style = doc.defaultView?.getComputedStyle(ancestor)
      if (style?.display === 'none' || style?.visibility === 'hidden') return false
    }
    return true
  })
  // Positive tabindex precedes ordinary DOM-order navigation.
  candidates.sort((a, b) => (a.tabIndex || Number.MAX_SAFE_INTEGER) - (b.tabIndex || Number.MAX_SAFE_INTEGER))
  const index = candidates.indexOf(trigger)
  if (index < 0) return undefined
  const next = index + (backwards ? -1 : 1)
  if (next >= 0 && next < candidates.length) return candidates[next]
  // Dialogs retain focus; outside a dialog leave the viewport boundary to the browser.
  if (scope !== doc) return backwards ? candidates.at(-1) : candidates[0]
  return undefined
}

/** Menu button with a viewport-bounded popup outside scrolling content. */
export function MenuButton(props: {
  readonly label: ReactNode
  readonly ariaLabel?: string
  readonly items: readonly MenuItem[]
  readonly icon?: ReactNode
  readonly size?: 'sm' | 'md'
  readonly disabled?: boolean
  readonly busy?: boolean
  readonly align?: 'start' | 'end'
}) {
  const [expanded, setExpanded] = useState(false)
  const unavailable = props.disabled || props.busy || props.items.length === 0
  const open = expanded && !unavailable
  const menuId = useId()
  const triggerId = useId()
  const buttonRef = useRef<HTMLButtonElement>(null)
  const layerRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([])
  const focusLast = useRef(false)
  const [position, setPosition] = useState({ left: 0, top: 0, maxHeight: 0, ready: false })
  const doc = buttonRef.current?.ownerDocument ?? (typeof document !== 'undefined' ? document : undefined)
  // Preserve the plugin theme, language, and a containing dialog's focus scope.
  const host =
    buttonRef.current?.closest<HTMLElement>('[role="dialog"], [role="alertdialog"], .dshsec-root') ?? doc?.body

  useEffect(() => {
    if (unavailable) setExpanded(false)
  }, [unavailable])

  useLayoutEffect(() => {
    const win = doc?.defaultView
    if (!open || !doc || !win) return
    const place = () => {
      const button = buttonRef.current
      const layer = layerRef.current
      const menu = menuRef.current
      if (!button?.isConnected || !host?.isConnected || button.disabled) {
        setExpanded(false)
        return
      }
      if (!layer || !menu) return
      const trigger = button.getBoundingClientRect()
      // A container or an animating dialog may establish the fixed layer's
      // containing block. Convert viewport coordinates to that layer's origin.
      const origin = layer.getBoundingClientRect()
      const width = menu.getBoundingClientRect().width
      const naturalHeight = menu.scrollHeight + menu.offsetHeight - menu.clientHeight
      const below = Math.max(0, win.innerHeight - VIEWPORT_GUTTER - trigger.bottom - TRIGGER_GAP)
      const above = Math.max(0, trigger.top - VIEWPORT_GUTTER - TRIGGER_GAP)
      const up = naturalHeight > below && above > below
      const maxHeight = Math.min(Math.max(0, win.innerHeight - VIEWPORT_GUTTER * 2), up ? above : below)
      const height = Math.min(naturalHeight, maxHeight)
      const desiredLeft = props.align === 'start' ? trigger.left : trigger.right - width
      const left = Math.max(VIEWPORT_GUTTER, Math.min(desiredLeft, win.innerWidth - VIEWPORT_GUTTER - width))
      const desiredTop = up ? trigger.top - TRIGGER_GAP - height : trigger.bottom + TRIGGER_GAP
      const top = Math.max(VIEWPORT_GUTTER, Math.min(desiredTop, win.innerHeight - VIEWPORT_GUTTER - height))
      const next = { left: left - origin.left, top: top - origin.top, maxHeight, ready: true }
      setPosition(previous =>
        previous.left === next.left &&
        previous.top === next.top &&
        previous.maxHeight === next.maxHeight &&
        previous.ready
          ? previous
          : next,
      )
    }
    place()
    win.addEventListener('resize', place)
    doc.addEventListener('scroll', place, true)
    host?.addEventListener('animationend', place)
    const resize = typeof win.ResizeObserver === 'function' ? new win.ResizeObserver(place) : undefined
    if (buttonRef.current) resize?.observe(buttonRef.current)
    if (menuRef.current) resize?.observe(menuRef.current)
    // A trigger removed by its owner must not leave an orphaned portal behind.
    const mutation = new win.MutationObserver(() => {
      if (
        !buttonRef.current?.isConnected ||
        !host?.isConnected ||
        buttonRef.current.disabled ||
        buttonRef.current.closest('[hidden], [inert]')
      )
        setExpanded(false)
    })
    mutation.observe(doc.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['disabled', 'hidden', 'inert'],
    })
    return () => {
      win.removeEventListener('resize', place)
      doc.removeEventListener('scroll', place, true)
      host?.removeEventListener('animationend', place)
      resize?.disconnect()
      mutation.disconnect()
    }
  }, [open, doc, host, props.align])

  useEffect(() => {
    // Browsers cannot focus an item while the first positioning pass keeps
    // the popup hidden. Focus only after that pass has made it visible.
    if (!open || !doc || !position.ready) return
    const items = itemRefs.current.slice(0, props.items.length)
    ;(focusLast.current ? items.at(-1) : items[0])?.focus()
    const outside = (event: Event) => {
      const target = event.target as Node
      if (!buttonRef.current?.contains(target) && !layerRef.current?.contains(target)) setExpanded(false)
    }
    doc.addEventListener('mousedown', outside)
    doc.addEventListener('focusin', outside)
    return () => {
      doc.removeEventListener('mousedown', outside)
      doc.removeEventListener('focusin', outside)
    }
  }, [open, doc, props.items.length, position.ready])

  const close = (refocus: boolean) => {
    setExpanded(false)
    if (refocus && buttonRef.current?.isConnected && !buttonRef.current.disabled) buttonRef.current.focus()
  }

  const onMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const items = itemRefs.current.slice(0, props.items.length).filter((el): el is HTMLButtonElement => el !== null)
    const index = items.indexOf(doc?.activeElement as HTMLButtonElement)
    let next = -1
    if (event.key === 'ArrowDown') next = (index + 1) % items.length
    else if (event.key === 'ArrowUp') next = (index - 1 + items.length) % items.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = items.length - 1
    else if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      close(true)
      return
    } else if (event.key === 'Tab') {
      // Native navigation starts from the portal's DOM location even if the
      // trigger is focused during keydown. Move explicitly in trigger order.
      const target = buttonRef.current ? tabNeighbour(buttonRef.current, event.shiftKey) : undefined
      if (target) {
        event.preventDefault()
        event.stopPropagation()
        close(false)
        target.focus()
      } else close(true)
      return
    }
    if (next >= 0) {
      event.preventDefault()
      items[next]?.focus()
      items[next]?.scrollIntoView?.({ block: 'nearest' })
    }
  }

  return (
    <div className="dshsec-menu-wrap">
      <button
        ref={buttonRef}
        id={triggerId}
        type="button"
        className={`dshsec-btn dshsec-btn--secondary ${props.size === 'sm' ? 'dshsec-btn--sm' : ''}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={props.ariaLabel}
        aria-busy={props.busy || undefined}
        disabled={unavailable}
        onClick={() => {
          focusLast.current = false
          setExpanded(v => !v)
        }}
        onKeyDown={event => {
          if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && !open) {
            event.preventDefault()
            focusLast.current = event.key === 'ArrowUp'
            setExpanded(true)
          }
        }}
      >
        {props.icon ? <span className="dshsec-btn-icon">{props.icon}</span> : null}
        {props.label}
        <IconChevronDown size={14} />
      </button>
      {open && host
        ? createPortal(
            <div className={`dshsec-menu-layer${host === doc?.body ? ' dshsec-root' : ''}`} ref={layerRef}>
              <div
                ref={menuRef}
                id={menuId}
                role="menu"
                aria-labelledby={triggerId}
                className={`dshsec-menu dshsec-menu-panel dshsec-menu--${props.align ?? 'end'}`}
                style={{
                  left: position.left,
                  top: position.top,
                  right: 'auto',
                  width: 'max-content',
                  minWidth: `min(160px, calc(100vw - ${VIEWPORT_GUTTER * 2}px))`,
                  maxWidth: `max(0px, calc(100vw - ${VIEWPORT_GUTTER * 2}px))`,
                  maxHeight: position.maxHeight,
                  visibility: position.ready ? 'visible' : 'hidden',
                }}
                onKeyDown={onMenuKey}
              >
                {props.items.map((item, i) => (
                  <button
                    key={item.id}
                    ref={el => {
                      itemRefs.current[i] = el
                    }}
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    className="dshsec-menu-item"
                    onClick={() => {
                      close(true)
                      item.onSelect()
                    }}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>,
            host,
          )
        : null}
    </div>
  )
}
