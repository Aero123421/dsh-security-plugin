import type { ReactNode } from 'react'
import type { QuoteCheck, ScanStatus, Severity, TriageState, Verification } from '../../shared/domain.ts'
import { useT } from '../context.tsx'

export type BadgeTone = 'neutral' | 'quiet' | 'brand' | 'success' | 'warn' | 'error' | 'error-strong'

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

export function SeverityBadge(props: { readonly severity: Severity }) {
  const tr = useT()
  const label = tr.lookup(`severity.${props.severity}`) ?? String(props.severity ?? '—')
  return (
    <Badge tone={severityTone(props.severity)} className="dshsec-sev">
      {label}
    </Badge>
  )
}

/** Number of filled bars in the certainty glyph. */
const CERTAINTY_LEVEL: Record<Verification, number> = {
  refuted: 0,
  inconclusive: 1,
  potential: 1,
  strong_static_evidence: 2,
  proven_dynamic: 3,
}

/**
 * The certainty glyph: three ascending bars, filled up to how firmly a
 * finding is established. Ruled-out findings show empty bars.
 */
export function CertaintyGlyph(props: { readonly verification: Verification }) {
  const level = CERTAINTY_LEVEL[props.verification] ?? 0
  return (
    <span className={`dshsec-certainty dshsec-certainty--${level}`} aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  )
}

export function VerificationBadge(props: { readonly verification: Verification; readonly withTitle?: boolean }) {
  const tr = useT()
  const label = tr.lookup(`verification.${props.verification}`) ?? String(props.verification ?? '—')
  const explain = tr.lookup(`verification.${props.verification}.explain`)
  return (
    <span
      className={`dshsec-verif dshsec-verif--${props.verification}`}
      title={props.withTitle === false ? undefined : explain}
    >
      <CertaintyGlyph verification={props.verification} />
      <span>{label}</span>
    </span>
  )
}

const QUOTE_TONE: Record<QuoteCheck, BadgeTone> = {
  match: 'success',
  relocated: 'success',
  mismatch: 'warn',
  stale: 'neutral',
  unchecked: 'quiet',
}

export function QuoteBadge(props: { readonly check: QuoteCheck }) {
  const tr = useT()
  return (
    <Badge tone={QUOTE_TONE[props.check] ?? 'neutral'} title={tr.lookup(`quote.${props.check}.explain`)}>
      {tr.lookup(`quote.${props.check}`) ?? String(props.check ?? '—')}
    </Badge>
  )
}

const STATUS_TONE: Record<ScanStatus, BadgeTone> = {
  queued: 'neutral',
  running: 'brand',
  paused: 'neutral',
  completed: 'success',
  failed: 'error',
  cancelled: 'quiet',
  interrupted: 'warn',
}

export function StatusBadge(props: { readonly status: ScanStatus }) {
  const tr = useT()
  return (
    <Badge tone={STATUS_TONE[props.status] ?? 'neutral'}>
      {tr.lookup(`status.${props.status}`) ?? String(props.status ?? '—')}
    </Badge>
  )
}

export function TriageBadge(props: { readonly triage: TriageState }) {
  const tr = useT()
  if (props.triage === 'open') return null
  return <Badge tone="quiet">{tr.lookup(`triage.${props.triage}`) ?? String(props.triage)}</Badge>
}
