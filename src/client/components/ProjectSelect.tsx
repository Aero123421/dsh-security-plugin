import { type KeyboardEvent, useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { WorkspaceSummary } from '../../shared/contracts.ts'
import { IconCheck, IconChevronDown, IconFolder } from '../icons.tsx'

function projectTitle(workspace: WorkspaceSummary | undefined): string {
  return workspace?.title || workspace?.displayPath || workspace?.id || ''
}

/** Project identity and a themed listbox; a single project never opens a popup. */
export function ProjectSelect(props: {
  readonly workspaces: readonly WorkspaceSummary[]
  readonly value: string | undefined
  readonly onChange: (id: string) => void
  readonly variant: 'quiet' | 'field'
  readonly id?: string
  readonly describedBy?: string | undefined
  readonly invalid?: boolean
  readonly disabled?: boolean
  readonly ariaLabel: string
}) {
  const { workspaces, variant } = props
  const current = workspaces.find(w => w.id === props.value) ?? workspaces[0]
  const title = projectTitle(current)
  const path = current?.title && current.displayPath ? current.displayPath : ''
  const many = workspaces.length > 1
  const [expanded, setExpanded] = useState(false)
  const open = expanded && many && !props.disabled
  const listId = useId()
  const buttonRef = useRef<HTMLButtonElement>(null)
  const layerRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const optionRefs = useRef<(HTMLButtonElement | null)[]>([])
  const search = useRef({ text: '', time: 0 })
  const [position, setPosition] = useState({ left: 0, top: 0, width: 0, maxHeight: 320 })

  // Keep the popup outside scrolling bodies, but inside the dialog's focus scope and theme root.
  const host = buttonRef.current?.closest<HTMLElement>('[role="dialog"], .dshsec-root')
  useEffect(() => {
    if (props.disabled || !many) setExpanded(false)
  }, [props.disabled, many])

  useLayoutEffect(() => {
    if (!open) return
    const place = () => {
      const trigger = buttonRef.current?.getBoundingClientRect()
      const origin = layerRef.current?.getBoundingClientRect()
      if (!trigger || !origin) return
      const cap = Math.max(0, window.innerWidth - 32)
      const minWidth = Math.min(440, cap)
      const width = variant === 'field' ? Math.min(cap, Math.max(trigger.width, minWidth)) : minWidth
      const left = Math.max(16, Math.min(trigger.left, window.innerWidth - width - 16))
      const below = window.innerHeight - trigger.bottom - 20
      const above = trigger.top - 20
      const up = below < 160 && above > below
      const maxHeight = Math.max(0, Math.min(320, up ? above : below))
      const height = Math.min(listRef.current?.scrollHeight ?? 0, maxHeight)
      const top = up ? trigger.top - 4 - height : trigger.bottom + 4
      setPosition({ left: left - origin.left, top: top - origin.top, width, maxHeight })
    }
    place()
    window.addEventListener('resize', place)
    document.addEventListener('scroll', place, true)
    host?.addEventListener('animationend', place)
    return () => {
      window.removeEventListener('resize', place)
      document.removeEventListener('scroll', place, true)
      host?.removeEventListener('animationend', place)
    }
  }, [open, variant, host])

  useEffect(() => {
    if (!open) return
    search.current = { text: '', time: 0 }
    optionRefs.current[workspaces.findIndex(w => w.id === current?.id)]?.focus()
    const onDown = (event: MouseEvent) => {
      const target = event.target as Node
      if (!buttonRef.current?.contains(target) && !layerRef.current?.contains(target)) setExpanded(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open, current?.id, workspaces])

  const close = (refocus: boolean) => {
    setExpanded(false)
    if (refocus) buttonRef.current?.focus()
  }

  const onListKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = optionRefs.current.indexOf(document.activeElement as HTMLButtonElement)
    let next = -1
    if (event.key === 'ArrowDown') next = (index + 1) % workspaces.length
    else if (event.key === 'ArrowUp') next = (index - 1 + workspaces.length) % workspaces.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = workspaces.length - 1
    else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      const workspace = workspaces[index]
      if (workspace) {
        close(true)
        props.onChange(workspace.id)
      }
    } else if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      close(true)
    } else if (event.key === 'Tab') {
      // Let the browser continue from the trigger, rather than from a removed portal option.
      close(true)
    } else if (event.key.length === 1 && event.key !== ' ' && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const now = Date.now()
      const letter = event.key.toLocaleLowerCase()
      const previous = now - search.current.time < 600 ? search.current.text : ''
      const text = previous === letter ? letter : previous + letter
      search.current = { text, time: now }
      for (let step = 1; step <= workspaces.length; step++) {
        const candidate = (index + step) % workspaces.length
        if (projectTitle(workspaces[candidate]).toLocaleLowerCase().startsWith(text)) {
          next = candidate
          break
        }
      }
      event.preventDefault()
    }
    if (next >= 0) {
      event.preventDefault()
      optionRefs.current[next]?.focus()
      optionRefs.current[next]?.scrollIntoView?.({ block: 'nearest' })
    }
  }

  const identity = (
    <>
      <IconFolder size={16} />
      <span className="dshsec-project-title">{title}</span>
      {path ? <span className="dshsec-project-path">{path}</span> : null}
    </>
  )
  const triggerClass = `dshsec-projsel-trigger ${variant === 'quiet' ? 'dshsec-project' : 'dshsec-input'}${many ? ' is-picker' : ''}`

  if (!many && variant === 'quiet') {
    return (
      <div className="dshsec-project" title={path || title}>
        {identity}
        <span className="dshsec-visually-hidden">{props.ariaLabel}</span>
      </div>
    )
  }

  return (
    <div className={`dshsec-projsel dshsec-projsel--${variant}`}>
      <button
        ref={buttonRef}
        type="button"
        id={props.id}
        className={triggerClass}
        title={current?.displayPath || title}
        disabled={props.disabled || !many}
        aria-label={`${props.ariaLabel}: ${title}`}
        aria-describedby={props.describedBy}
        aria-invalid={props.invalid || undefined}
        aria-haspopup={many ? 'listbox' : undefined}
        aria-expanded={many ? open : undefined}
        aria-controls={open ? listId : undefined}
        onClick={() => setExpanded(v => !v)}
        onKeyDown={event => {
          if (['Enter', ' ', 'ArrowDown', 'ArrowUp'].includes(event.key)) {
            event.preventDefault()
            setExpanded(true)
          }
        }}
      >
        {identity}
        {many ? <IconChevronDown size={14} /> : null}
      </button>
      {open && host
        ? createPortal(
            <div className="dshsec-projsel-layer" ref={layerRef}>
              <div
                ref={listRef}
                id={listId}
                role="listbox"
                aria-label={props.ariaLabel}
                className={`dshsec-menu dshsec-projsel-panel dshsec-projsel-panel--${variant}`}
                style={position}
                onKeyDown={onListKey}
              >
                {workspaces.map((workspace, index) => (
                  <button
                    key={workspace.id}
                    ref={el => {
                      optionRefs.current[index] = el
                    }}
                    type="button"
                    role="option"
                    aria-selected={workspace.id === current?.id}
                    tabIndex={-1}
                    className="dshsec-menu-item dshsec-projsel-option"
                    title={workspace.displayPath || projectTitle(workspace)}
                    onClick={() => {
                      close(true)
                      props.onChange(workspace.id)
                    }}
                  >
                    <span className="dshsec-projsel-check">
                      {workspace.id === current?.id ? <IconCheck size={16} /> : null}
                    </span>
                    <span className="dshsec-projsel-text">
                      <span className="dshsec-projsel-title">{projectTitle(workspace)}</span>
                      {workspace.title && workspace.displayPath ? (
                        <span className="dshsec-projsel-path">{workspace.displayPath}</span>
                      ) : null}
                    </span>
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
