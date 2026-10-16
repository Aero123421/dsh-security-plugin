import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useT } from '../context.tsx'
import { IconClose } from '../icons.tsx'

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function focusableWithin(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
    el => !el.hasAttribute('disabled') && el.getAttribute('aria-hidden') !== 'true',
  )
}

/**
 * Modal dialog: rendered in a portal, traps Tab focus, closes on Esc and on
 * backdrop click, and restores focus to the opener when it unmounts.
 */
export function Modal(props: {
  readonly title: ReactNode
  readonly onClose: () => void
  readonly children: ReactNode
  readonly footer?: ReactNode
  readonly size?: 'sm' | 'md' | 'lg'
  readonly role?: 'dialog' | 'alertdialog'
  /** Element to focus first; defaults to the first focusable inside the body. */
  readonly initialFocusRef?: { readonly current: HTMLElement | null }
  readonly describedBy?: string
}) {
  const tr = useT()
  const titleId = useId()
  const dialogRef = useRef<HTMLDivElement>(null)
  const onCloseRef = useRef(props.onClose)
  onCloseRef.current = props.onClose
  const initialFocusRef = props.initialFocusRef

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const dialog = dialogRef.current
    const target =
      initialFocusRef?.current ??
      (dialog?.querySelector<HTMLElement>('[data-autofocus]') ||
        (dialog ? focusableWithin(dialog).find(el => !el.classList.contains('dshsec-modal-x')) : undefined) ||
        dialog)
    target?.focus()
    if (!dialog) return

    let lastFocused = target
    let parked: HTMLElement | undefined
    const onFocus = (event: FocusEvent) => {
      if (event.target instanceof HTMLElement && dialog.contains(event.target) && event.target !== dialog) {
        lastFocused = event.target
        parked = undefined
      }
    }
    dialog.addEventListener('focusin', onFocus)
    // Browsers can blur a newly disabled button to body without a focus event.
    // Remember the control before that happens, and park focus on the dialog so
    // Tab/Escape still reach its handlers while an RPC is pending.
    const observer = new MutationObserver(() => {
      const active = document.activeElement
      if (lastFocused?.matches(':disabled') && (active === lastFocused || !dialog.contains(active))) {
        parked = lastFocused
        dialog.focus()
      } else if (parked && active === dialog && (!dialog.contains(parked) || !parked.matches(':disabled'))) {
        const restore = dialog.contains(parked)
          ? parked
          : focusableWithin(dialog).find(el => !el.classList.contains('dshsec-modal-x'))
        parked = undefined
        restore?.focus()
      }
    })
    observer.observe(dialog, { subtree: true, childList: true, attributes: true, attributeFilter: ['disabled'] })
    return () => {
      observer.disconnect()
      dialog.removeEventListener('focusin', onFocus)
      if (opener?.isConnected) opener.focus()
    }
  }, [initialFocusRef])

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.stopPropagation()
      event.preventDefault()
      onCloseRef.current()
      return
    }
    if (event.key !== 'Tab' || !dialogRef.current) return
    const items = focusableWithin(dialogRef.current)
    if (!items.length) {
      event.preventDefault()
      return
    }
    const first = items[0]!
    const last = items[items.length - 1]!
    const active = document.activeElement
    if (event.shiftKey && (active === first || active === dialogRef.current || !dialogRef.current.contains(active))) {
      event.preventDefault()
      last.focus()
    } else if (
      !event.shiftKey &&
      (active === last || active === dialogRef.current || !dialogRef.current.contains(active))
    ) {
      event.preventDefault()
      first.focus()
    }
  }

  const content = (
    // biome-ignore lint/a11y/noStaticElementInteractions: backdrop click is a pointer convenience; Esc and the close button are the accessible paths
    <div
      className="dshsec-root dshsec-modal-backdrop"
      lang={tr.lang}
      onMouseDown={event => {
        if (event.target === event.currentTarget) onCloseRef.current()
      }}
    >
      {/* biome-ignore lint/a11y/noStaticElementInteractions: the dialog element traps Tab and handles Esc */}
      {/* biome-ignore lint/a11y/useAriaPropsSupportedByRole: role is dialog or alertdialog, both support aria-modal */}
      <div
        ref={dialogRef}
        className={`dshsec-modal dshsec-modal--${props.size ?? 'md'}`}
        role={props.role ?? 'dialog'}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={props.describedBy}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        <header className="dshsec-modal-head">
          <h2 id={titleId} className="dshsec-modal-title">
            {props.title}
          </h2>
          <button
            type="button"
            className="dshsec-iconbtn dshsec-modal-x"
            onClick={() => onCloseRef.current()}
            aria-label={tr.t('common.closeDialog')}
          >
            <IconClose size={18} />
          </button>
        </header>
        <div className="dshsec-modal-body">{props.children}</div>
        {props.footer ? <footer className="dshsec-modal-foot">{props.footer}</footer> : null}
      </div>
    </div>
  )
  return typeof document !== 'undefined' ? createPortal(content, document.body) : content
}
