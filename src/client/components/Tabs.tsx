import { type KeyboardEvent, type ReactNode, useRef } from 'react'

export interface TabItem<K extends string> {
  readonly id: K
  readonly label: ReactNode
}

/**
 * WAI-ARIA tabs with automatic activation: Left/Right (and Home/End) move
 * focus and selection together. Panels are rendered by the caller with
 * `tabPanelProps`.
 */
export function Tabs<K extends string>(props: {
  readonly idPrefix: string
  readonly label: string
  readonly items: readonly TabItem<K>[]
  readonly value: K
  readonly onChange: (value: K) => void
}) {
  const refs = useRef(new Map<K, HTMLButtonElement>())
  const { items, value, onChange, idPrefix } = props

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const index = items.findIndex(item => item.id === value)
    let next = -1
    if (event.key === 'ArrowRight') next = (index + 1) % items.length
    else if (event.key === 'ArrowLeft') next = (index - 1 + items.length) % items.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = items.length - 1
    if (next < 0) return
    event.preventDefault()
    const target = items[next]
    if (!target) return
    onChange(target.id)
    refs.current.get(target.id)?.focus()
  }

  return (
    <div className="dshsec-tabs" role="tablist" aria-label={props.label}>
      {items.map(item => {
        const selected = item.id === value
        return (
          <button
            key={item.id}
            ref={el => {
              if (el) refs.current.set(item.id, el)
              else refs.current.delete(item.id)
            }}
            type="button"
            role="tab"
            id={`${idPrefix}-tab-${item.id}`}
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${item.id}`}
            tabIndex={selected ? 0 : -1}
            className="dshsec-tab"
            onClick={() => onChange(item.id)}
            onKeyDown={onKeyDown}
          >
            {item.label}
          </button>
        )
      })}
    </div>
  )
}

export function tabPanelProps(idPrefix: string, id: string) {
  return {
    role: 'tabpanel' as const,
    id: `${idPrefix}-panel-${id}`,
    'aria-labelledby': `${idPrefix}-tab-${id}`,
    tabIndex: 0,
  }
}
