import type { ReactNode } from 'react'

export interface ChoiceOption<V extends string> {
  readonly value: V
  readonly label: ReactNode
  readonly description?: ReactNode
  /** Small accent label next to the name ("Recommended"). */
  readonly tag?: ReactNode
  readonly disabled?: boolean
}

/**
 * Radio cards. Native radios inside labels, so arrow keys, form semantics and
 * screen readers work without extra code; the visible dot mirrors the state.
 */
export function ChoiceCards<V extends string>(props: {
  readonly name: string
  readonly value: V
  readonly options: readonly ChoiceOption<V>[]
  readonly onChange: (value: V) => void
}) {
  return (
    <div className="dshsec-choices">
      {props.options.map(option => {
        const selected = option.value === props.value
        return (
          <label
            key={option.value}
            className={`dshsec-choice${selected ? ' is-selected' : ''}${option.disabled ? ' is-disabled' : ''}`}
          >
            <input
              type="radio"
              name={props.name}
              value={option.value}
              checked={selected}
              disabled={option.disabled}
              onChange={() => props.onChange(option.value)}
            />
            <span className="dshsec-choice-dot" aria-hidden="true" />
            <span className="dshsec-choice-name">
              {option.label}
              {option.tag ? <span className="dshsec-choice-tag">{option.tag}</span> : null}
            </span>
            {option.description ? <span className="dshsec-choice-desc">{option.description}</span> : null}
          </label>
        )
      })}
    </div>
  )
}
