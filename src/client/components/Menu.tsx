import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef, useState } from 'react'
import { IconChevronDown } from '../icons.tsx'

export interface MenuItem {
  readonly id: string
  readonly label: string
  readonly onSelect: () => void
}

/** Menu button (`aria-haspopup="menu"`) with arrow-key navigation and Esc/outside-click close. */
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
  const [open, setOpen] = useState(false)
  const menuId = useId()
  const wrapRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([])

  useEffect(() => {
    if (!open) return
    itemRefs.current[0]?.focus()
    const onDown = (event: MouseEvent) => {
      if (!wrapRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const close = (refocus: boolean) => {
    setOpen(false)
    if (refocus) buttonRef.current?.focus()
  }

  const onMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const items = itemRefs.current.filter((el): el is HTMLButtonElement => el !== null)
    const index = items.indexOf(document.activeElement as HTMLButtonElement)
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
      setOpen(false)
      return
    }
    if (next >= 0) {
      event.preventDefault()
      items[next]?.focus()
    }
  }

  return (
    <div className="dshsec-menu-wrap" ref={wrapRef}>
      <button
        ref={buttonRef}
        type="button"
        className={`dshsec-btn dshsec-btn--secondary ${props.size === 'sm' ? 'dshsec-btn--sm' : ''}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={props.ariaLabel}
        aria-busy={props.busy || undefined}
        disabled={props.disabled || props.busy}
        onClick={() => setOpen(v => !v)}
        onKeyDown={event => {
          if (event.key === 'ArrowDown' && !open) {
            event.preventDefault()
            setOpen(true)
          }
        }}
      >
        {props.icon ? <span className="dshsec-btn-icon">{props.icon}</span> : null}
        {props.label}
        <IconChevronDown size={14} />
      </button>
      {open ? (
        <div
          id={menuId}
          role="menu"
          className={`dshsec-menu dshsec-menu--${props.align ?? 'end'}`}
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
      ) : null}
    </div>
  )
}
