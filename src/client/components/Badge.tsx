import type { ReactNode } from 'react'
import type { QuoteCheck, ScanStatus, Severity, TriageState, Verification } from '../../shared/domain.ts'
import { useT } from '../context.tsx'
import { IconCheck, IconWarn } from '../icons.tsx'

export type BadgeTone = 'neutral' | 'quiet' | 'brand' | 'success' | 'warn' | 'error' | 'error-strong'

/** Small text tag ("New", a triage decision). Kept quiet so severity stays the only color in a row. */
export function Badge(props: {
  readonly tone?: BadgeTone
  readonly title?: string
  readonly className?: string
  readonly children: ReactNode
}) {
  return (
    <span
      className={`dshsec-badge dshsec-badge--${props.tone ?? 'neutral'}${props.className ? ` ${props.className}` : ''}`}
      title={props.title}
    >
      {props.children}
    </span>
  )
}

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  critical: 'error-strong',
  high: 'error',
  medium: 'warn',
  low: 'neutral',
  info: 'quiet',
}

export function severityTone(severity: Severity): BadgeTone {
  return SEVERITY_TONE[severity] ?? 'neutral'
}

/** Severity as a colored dot and its name. */
export function SeverityLabel(props: { readonly severity: Severity }) {
  const tr = useT()
  const label = tr.lookup(`severity.${props.severity}`) ?? String(props.severity ?? '—')
  return (
    <span className={`dshsec-sev dshsec-sev--${props.severity}`}>
      <span className="dshsec-sev-dot" aria-hidden="true" />
      {label}
    </span>
  )
}

/** How firmly a finding is established, as plain text; the explanation is its tooltip. */
export function VerificationLabel(props: { readonly verification: Verification; readonly withTitle?: boolean }) {
  const tr = useT()
  const label = tr.lookup(`verification.${props.verification}`) ?? String(props.verification ?? '—')
  const explain = tr.lookup(`verification.${props.verification}.explain`)
  return (
    <span
      className={`dshsec-verif dshsec-verif--${props.verification}`}
      title={props.withTitle === false ? undefined : explain}
    >
      {label}
    </span>
  )
}

/** Whether the host found a cited quote in the source. Only a failed check draws attention. */
export function QuoteCheckLabel(props: { readonly check: QuoteCheck }) {
  const tr = useT()
  const label = tr.lookup(`quote.${props.check}`) ?? String(props.check ?? '—')
  const ok = props.check === 'match' || props.check === 'relocated'
  return (
    <span className={`dshsec-quote dshsec-quote--${props.check}`} title={tr.lookup(`quote.${props.check}.explain`)}>
      {ok ? <IconCheck size={13} /> : props.check === 'mismatch' ? <IconWarn size={13} /> : null}
      {label}
    </span>
  )
}

/** Scan status as a dot and a word, like DSH's own status rows. */
export function StatusLabel(props: { readonly status: ScanStatus }) {
  const tr = useT()
  return (
    <span className={`dshsec-status dshsec-status--${props.status}`}>
      <span className="dshsec-status-dot" aria-hidden="true" />
      {tr.lookup(`status.${props.status}`) ?? String(props.status ?? '—')}
    </span>
  )
}

export function TriageBadge(props: { readonly triage: TriageState }) {
  const tr = useT()
  if (props.triage === 'open') return null
  return <Badge tone="quiet">{tr.lookup(`triage.${props.triage}`) ?? String(props.triage)}</Badge>
}
