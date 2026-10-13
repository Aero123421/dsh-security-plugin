import { type ButtonHTMLAttributes, forwardRef, type ReactNode } from 'react'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'link'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: ButtonVariant
  readonly size?: 'sm' | 'md'
  readonly icon?: ReactNode
  readonly busy?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(props, ref) {
  const { variant = 'secondary', size = 'md', icon, busy, className, children, type, disabled, ...rest } = props
  const classes = ['dshsec-btn', `dshsec-btn--${variant}`, size === 'sm' ? 'dshsec-btn--sm' : '', className ?? '']
    .filter(Boolean)
    .join(' ')
  return (
    <button
      ref={ref}
      type={type ?? 'button'}
      className={classes}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {icon ? <span className="dshsec-btn-icon">{icon}</span> : null}
      {children}
    </button>
  )
})
