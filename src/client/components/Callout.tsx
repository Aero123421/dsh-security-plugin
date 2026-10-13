import type { ReactNode } from 'react'
import { IconCheck, IconInfo, IconWarn } from '../icons.tsx'

export type CalloutTone = 'info' | 'success' | 'warn' | 'error'

/** Inline message block. Errors are announced (`role="alert"`), others politely. */
export function Callout(props: {
  readonly tone?: CalloutTone
  readonly title?: ReactNode
  readonly children?: ReactNode
  readonly action?: ReactNode
  readonly live?: boolean
  readonly className?: string
}) {
  const tone = props.tone ?? 'info'
  const icon =
    tone === 'success' ? <IconCheck size={16} /> : tone === 'info' ? <IconInfo size={16} /> : <IconWarn size={16} />
  const role = props.live === false ? undefined : tone === 'error' ? 'alert' : 'status'
  return (
    <div className={`dshsec-callout dshsec-callout--${tone} ${props.className ?? ''}`} role={role}>
      <span className="dshsec-callout-icon">{icon}</span>
      <div className="dshsec-callout-main">
        {props.title ? <div className="dshsec-callout-title">{props.title}</div> : null}
        {props.children ? <div className="dshsec-callout-body">{props.children}</div> : null}
      </div>
      {props.action ? <div className="dshsec-callout-action">{props.action}</div> : null}
    </div>
  )
}
