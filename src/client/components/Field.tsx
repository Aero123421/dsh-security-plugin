import { type ReactNode, useId } from 'react'

export interface SelectOption<V extends string> {
  readonly value: V
  readonly label: string
  readonly disabled?: boolean
}

/** Label + control + hint + inline error, wired with ids for assistive tech. */
export function Field(props: {
  readonly label: ReactNode
  readonly hint?: ReactNode
  readonly error?: string
  readonly children: (ids: { id: string; describedBy: string | undefined; invalid: boolean }) => ReactNode
  readonly className?: string
}) {
  const id = useId()
  const hintId = `${id}-hint`
  const errorId = `${id}-error`
  const describedBy = [props.hint ? hintId : '', props.error ? errorId : ''].filter(Boolean).join(' ') || undefined
  return (
    <div className={`dshsec-field ${props.className ?? ''}`}>
      <label className="dshsec-label" htmlFor={id}>
        {props.label}
      </label>
      {props.children({ id, describedBy, invalid: Boolean(props.error) })}
      {props.hint ? (
        <div className="dshsec-hint" id={hintId}>
          {props.hint}
        </div>
      ) : null}
      {props.error ? (
        <div className="dshsec-field-error" id={errorId}>
          {props.error}
        </div>
      ) : null}
    </div>
  )
}

export function Select<V extends string>(props: {
  readonly id?: string
  readonly value: V
  readonly options: readonly SelectOption<V>[]
  readonly onChange: (value: V) => void
  readonly disabled?: boolean
  readonly describedBy?: string | undefined
  readonly invalid?: boolean
  readonly ariaLabel?: string
  readonly className?: string
}) {
  return (
    <span className={`dshsec-select ${props.className ?? ''}`}>
      <select
        id={props.id}
        value={props.value}
        disabled={props.disabled}
        aria-describedby={props.describedBy}
        aria-invalid={props.invalid || undefined}
        aria-label={props.ariaLabel}
        onChange={event => props.onChange(event.target.value as V)}
      >
        {props.options.map(option => (
          <option key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </option>
        ))}
      </select>
    </span>
  )
}

/** A labelled switch (`role="switch"`) with an optional hint. */
export function Toggle(props: {
  readonly label: ReactNode
  readonly hint?: ReactNode
  readonly checked: boolean
  readonly onChange: (checked: boolean) => void
  readonly disabled?: boolean
  readonly note?: ReactNode
}) {
  const id = useId()
  const hintId = `${id}-hint`
  const noteId = `${id}-note`
  const describedBy = [props.hint ? hintId : '', props.note ? noteId : ''].filter(Boolean).join(' ') || undefined
  return (
    <div className={`dshsec-toggle-row ${props.disabled ? 'is-disabled' : ''}`}>
      <div className="dshsec-toggle-text">
        <label className="dshsec-label" htmlFor={id}>
          {props.label}
        </label>
        {props.hint ? (
          <div className="dshsec-hint" id={hintId}>
            {props.hint}
          </div>
        ) : null}
        {props.note ? (
          <div className="dshsec-toggle-note" id={noteId}>
            {props.note}
          </div>
        ) : null}
      </div>
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={props.checked}
        aria-describedby={describedBy}
        disabled={props.disabled}
        className="dshsec-switch"
        onClick={() => props.onChange(!props.checked)}
      >
        <span className="dshsec-switch-thumb" />
      </button>
    </div>
  )
}
