import { type ReactNode, type RefObject, useEffect, useId, useRef, useState } from 'react'
import type { AttackStepView, EvidenceView, FindingDetail, ScanSummary } from '../../shared/contracts.ts'
import { TRIAGE_STATES, type TriageState } from '../../shared/domain.ts'
import { Badge, QuoteBadge, SeverityBadge, VerificationBadge } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { CodeBlock, formatLocation, Paragraphs } from '../components/Text.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import { findingKey, type Loadable } from '../controller.ts'
import { asArray, text } from '../format.ts'
import { errorText } from '../i18n.ts'
import { attackStepText, findingImpact, findingRecommendation, findingSummary, findingTitle } from '../localized.ts'
import { IconChat, IconCopy, IconRefresh } from '../icons.tsx'
import { LoadError, Loading } from './shared.tsx'

const IDLE: Loadable<FindingDetail> = { status: 'idle' }

/** Ordered detail sections; tests assert this order. */
export const DETAIL_SECTIONS = ['problem', 'sure', 'evidence', 'fix', 'recheck'] as const

export function FindingDetailView(props: {
  readonly scan: ScanSummary
  readonly findingId: string
  /** Truthy: focus the heading once loaded. A new value (or finding) focuses again. */
  readonly focusOnOpen?: boolean | number
}) {
  const controller = useController()
  const { scan, findingId } = props
  const entry = useSecurity(s => s.findingDetails[findingKey(scan.id, findingId)] ?? IDLE)
  const headingRef = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    void controller.loadFinding(scan.id, findingId)
  }, [controller, scan.id, findingId])

  const detail = entry.value
  const ready = Boolean(detail)
  useEffect(() => {
    if (ready && props.focusOnOpen && findingId) headingRef.current?.focus()
  }, [ready, props.focusOnOpen, findingId])

  if (!detail && entry.status === 'error' && entry.error) {
    return <LoadError error={entry.error} onRetry={() => void controller.loadFinding(scan.id, findingId, true)} />
  }
  if (!detail) return <Loading />
  return <DetailBody detail={detail} scan={scan} headingRef={headingRef} />
}

function DetailBody(props: {
  readonly detail: FindingDetail
  readonly scan: ScanSummary
  readonly headingRef: RefObject<HTMLHeadingElement>
}) {
  const tr = useT()
  const { detail, scan } = props
  const preconditions = asArray(detail.preconditions).filter(p => typeof p === 'string' && p.trim())
  return (
    <article className="dshsec-detail" aria-labelledby={`dshsec-detail-${detail.id}`}>
      <header className="dshsec-detail-head">
        <div className="dshsec-detail-tags">
          <SeverityBadge severity={detail.severity} />
          {detail.isNew ? <Badge tone="brand">{tr.t('findings.new')}</Badge> : null}
        </div>
        <h2 className="dshsec-detail-title" id={`dshsec-detail-${detail.id}`} ref={props.headingRef} tabIndex={-1}>
          {findingTitle(tr, detail)}
        </h2>
        <p className="dshsec-detail-loc">{formatLocation(detail.location)}</p>
      </header>

      <DetailSection id="problem" title={tr.t('detail.problem')}>
        <Paragraphs text={findingSummary(tr, detail)} />
        {detail.impact ? (
          <div className="dshsec-stack-sm">
            <h4 className="dshsec-h4">{tr.t('detail.impact')}</h4>
            <Paragraphs text={findingImpact(tr, detail)} />
          </div>
        ) : null}
        {preconditions.length ? (
          <div className="dshsec-stack-sm">
            <h4 className="dshsec-h4">{tr.t('detail.preconditions')}</h4>
            <ul className="dshsec-list">
              {preconditions.map(p => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </DetailSection>

      <DetailSection id="sure" title={tr.t('detail.sure')}>
        <div className="dshsec-sure">
          <VerificationBadge verification={detail.verification} withTitle={false} />
          <p>{tr.lookup(`verification.${detail.verification}.explain`) ?? '—'}</p>
        </div>
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('detail.review')}</h4>
          {detail.review ? (
            <div className="dshsec-review">
              <p className="dshsec-review-verdict">
                <strong>{tr.lookup(`review.${detail.review.verdict}`) ?? text(detail.review.verdict)}</strong>
                {detail.review.model ? (
                  <span className="dshsec-muted"> — {tr.t('detail.reviewBy', { model: detail.review.model })}</span>
                ) : null}
              </p>
              <Paragraphs text={detail.review.reasoning} />
            </div>
          ) : (
            <p className="dshsec-muted">{tr.t('detail.noReview')}</p>
          )}
        </div>
      </DetailSection>

      <EvidenceSection detail={detail} />

      <FixSection detail={detail} scan={scan} />

      <RecheckSection scan={scan} />

      <TriageControl key={detail.id} detail={detail} scanId={scan.id} />

      <ReferenceSection detail={detail} />
    </article>
  )
}

function DetailSection(props: {
  readonly id: (typeof DETAIL_SECTIONS)[number]
  readonly title: string
  readonly children: ReactNode
}) {
  const headingId = useId()
  return (
    <section className="dshsec-dsec" data-section={props.id} aria-labelledby={headingId}>
      <h3 className="dshsec-dsec-title" id={headingId}>
        {props.title}
      </h3>
      <div className="dshsec-dsec-body">{props.children}</div>
    </section>
  )
}

function EvidenceSection(props: { readonly detail: FindingDetail }) {
  const tr = useT()
  const steps = [...asArray(props.detail.attackPath)].sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
  const evidence = asArray(props.detail.evidence)
  const counter = asArray(props.detail.counterevidence)
  const limitations = asArray(props.detail.limitations).filter(l => typeof l === 'string' && l.trim())
  const empty = !steps.length && !evidence.length && !counter.length && !limitations.length
  return (
    <DetailSection id="evidence" title={tr.t('detail.evidence')}>
      {empty ? <p className="dshsec-muted">{tr.t('detail.noEvidence')}</p> : null}
      {steps.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('detail.attackPath')}</h4>
          <ol className="dshsec-path">
            {steps.map((step, i) => (
              <AttackStep
                // biome-ignore lint/suspicious/noArrayIndexKey: steps are positional; order may repeat
                key={`${step.order}-${i}`}
                step={step}
                index={i}
                description={attackStepText(tr, props.detail, step.description)}
              />
            ))}
          </ol>
        </div>
      ) : null}
      {evidence.length ? <EvidenceList title={tr.t('detail.supporting')} items={evidence} /> : null}
      {counter.length ? <EvidenceList title={tr.t('detail.counter')} items={counter} /> : null}
      {limitations.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('detail.limitations')}</h4>
          <ul className="dshsec-list">
            {limitations.map(l => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </DetailSection>
  )
}

function AttackStep(props: { readonly step: AttackStepView; readonly index: number; readonly description: string }) {
  const tr = useT()
  const { step } = props
  return (
    <li className={`dshsec-path-step ${step.quoteCheck === 'mismatch' ? 'is-unverified' : ''}`}>
      <div className="dshsec-path-head">
        <span className="dshsec-path-n">{tr.t('detail.step', { n: props.index + 1 })}</span>
        <QuoteBadge check={step.quoteCheck} />
      </div>
      <Paragraphs text={props.description} />
      {typeof step.snippet === 'string' && step.snippet ? (
        <CodeBlock snippet={step.snippet} location={step.location} />
      ) : step.location ? (
        <p className="dshsec-detail-loc">{formatLocation(step.location)}</p>
      ) : null}
    </li>
  )
}

function EvidenceList(props: { readonly title: string; readonly items: readonly EvidenceView[] }) {
  const tr = useT()
  return (
    <div className="dshsec-stack-sm">
      <h4 className="dshsec-h4">{props.title}</h4>
      <ul className="dshsec-evidence">
        {props.items.map(item => (
          <li key={item.id} className={item.quoteCheck === 'mismatch' ? 'is-unverified' : ''}>
            <div className="dshsec-path-head">
              <Badge tone="quiet">{tr.lookup(`trust.${item.trust}`) ?? text(item.trust)}</Badge>
              <QuoteBadge check={item.quoteCheck} />
            </div>
            <Paragraphs text={item.claim} />
            {typeof item.snippet === 'string' && item.snippet ? (
              <CodeBlock snippet={item.snippet} location={item.location} />
            ) : item.location ? (
              <p className="dshsec-detail-loc">{formatLocation(item.location)}</p>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  )
}

type ActionNote = { readonly tone: 'success' | 'error'; readonly text: string } | undefined

function FixSection(props: { readonly detail: FindingDetail; readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const { detail, scan } = props
  const [busy, setBusy] = useState<'chat' | 'copy' | undefined>()
  const [note, setNote] = useState<ActionNote>()
  const canChat = controller.canFixInChat()

  const openChat = async () => {
    setBusy('chat')
    setNote(undefined)
    const result = await controller.fixInChat({ workspaceId: scan.workspaceId, scanId: scan.id, findingId: detail.id })
    setBusy(undefined)
    setNote(
      result.ok
        ? { tone: 'success', text: tr.t('detail.chatRequested') }
        : { tone: 'error', text: errorText(tr, result.error) },
    )
  }

  const copy = async () => {
    setBusy('copy')
    setNote(undefined)
    const result = await controller.copyFixPrompt(scan.id, detail.id)
    setBusy(undefined)
    setNote(
      result.ok
        ? { tone: 'success', text: tr.t('common.copied') }
        : {
            tone: 'error',
            text: result.error.code === 'security/clipboard' ? tr.t('detail.copyFailed') : errorText(tr, result.error),
          },
    )
  }

  return (
    <DetailSection id="fix" title={tr.t('detail.fix')}>
      {findingRecommendation(tr, detail).trim() ? (
        <Paragraphs text={findingRecommendation(tr, detail)} />
      ) : (
        <p className="dshsec-muted">{tr.t('detail.noRecommendation')}</p>
      )}
      <div className="dshsec-actions">
        {canChat ? (
          <Button
            variant="primary"
            icon={<IconChat size={16} />}
            busy={busy === 'chat'}
            onClick={() => void openChat()}
          >
            {tr.t('detail.fixInChat')}
          </Button>
        ) : null}
        <Button icon={<IconCopy size={16} />} busy={busy === 'copy'} onClick={() => void copy()}>
          {tr.t('detail.copyPrompt')}
        </Button>
      </div>
      {note ? <Callout tone={note.tone}>{note.text}</Callout> : null}
    </DetailSection>
  )
}

function RecheckSection(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    await controller.quickRescan(props.scan.workspaceId, props.scan.subpath, props.scan.mode)
    setBusy(false)
  }
  return (
    <DetailSection id="recheck" title={tr.t('detail.recheck')}>
      <p>{tr.t('detail.recheckBody')}</p>
      <div className="dshsec-actions">
        <Button icon={<IconRefresh size={16} />} busy={busy} onClick={() => void run()}>
          {tr.t('detail.runRecheck', { mode: tr.t(`mode.${props.scan.mode}`) })}
        </Button>
      </div>
    </DetailSection>
  )
}

function TriageControl(props: { readonly detail: FindingDetail; readonly scanId: string }) {
  const controller = useController()
  const tr = useT()
  const { detail } = props
  const [triage, setTriage] = useState<TriageState>(detail.triage)
  const [noteText, setNoteText] = useState(detail.triageNote ?? '')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ActionNote>()
  const noteId = useId()
  const helpId = useId()
  const draftRef = useRef({ triage, note: noteText })
  const savedRef = useRef({ triage: detail.triage, note: detail.triageNote ?? '' })

  useEffect(() => {
    const next = { triage: detail.triage, note: detail.triageNote ?? '' }
    // Server refreshes may update a clean draft, never newer unsaved input.
    if (sameDecision(draftRef.current, savedRef.current)) {
      draftRef.current = next
      setTriage(next.triage)
      setNoteText(next.note)
      setResult(undefined)
    }
    savedRef.current = next
  }, [detail.triage, detail.triageNote])

  const dirty = triage !== detail.triage || noteText.trim() !== (detail.triageNote ?? '').trim()

  const save = async () => {
    setBusy(true)
    setResult(undefined)
    const submitted = { ...draftRef.current }
    const outcome = await controller.setTriage({ scanId: props.scanId, findingId: detail.id, ...submitted })
    setBusy(false)
    setResult(
      outcome.ok
        ? {
            tone: 'success',
            text: tr.t(
              sameDecision(draftRef.current, submitted) ? 'detail.decisionSaved' : 'detail.decisionSavedDraft',
            ),
          }
        : { tone: 'error', text: errorText(tr, outcome.error) },
    )
  }

  return (
    <section className="dshsec-triage" aria-labelledby={`${helpId}-title`}>
      <fieldset className="dshsec-fieldset">
        <legend className="dshsec-h3" id={`${helpId}-title`}>
          {tr.t('detail.decision')}
        </legend>
        <p className="dshsec-hint" id={helpId}>
          {tr.t('detail.decisionHelp')}
        </p>
        <div className="dshsec-segmented">
          {TRIAGE_STATES.map(state => (
            <label key={state} className={`dshsec-seg ${triage === state ? 'is-selected' : ''}`}>
              <input
                type="radio"
                name={`dshsec-triage-${detail.id}`}
                value={state}
                checked={triage === state}
                onChange={() => {
                  draftRef.current = { ...draftRef.current, triage: state }
                  setTriage(state)
                  setResult(undefined)
                }}
              />
              <span>{tr.t(`triage.${state}`)}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <div className="dshsec-field">
        <label className="dshsec-label" htmlFor={noteId}>
          {tr.t('detail.note')}
        </label>
        <textarea
          id={noteId}
          className="dshsec-textarea"
          rows={2}
          value={noteText}
          maxLength={2000}
          onChange={event => {
            draftRef.current = { ...draftRef.current, note: event.target.value }
            setNoteText(event.target.value)
            setResult(undefined)
          }}
        />
      </div>
      <div className="dshsec-actions">
        <Button busy={busy} disabled={!dirty} onClick={() => void save()}>
          {tr.t('detail.saveDecision')}
        </Button>
      </div>
      {dirty && !busy ? <p className="dshsec-hint">{tr.t('settings.unsaved')}</p> : null}
      {result ? <Callout tone={result.tone}>{result.text}</Callout> : null}
    </section>
  )
}

function sameDecision(a: { triage: TriageState; note: string }, b: { triage: TriageState; note: string }): boolean {
  return a.triage === b.triage && a.note.trim() === b.note.trim()
}

/**
 * Reference hosts rendered as links. References can be written by a model that
 * read untrusted code, so anything else is shown as plain text the user can
 * copy, never as a clickable link.
 */
const LINKED_REFERENCE_HOSTS = [
  'cwe.mitre.org',
  'cve.mitre.org',
  'www.cve.org',
  'nvd.nist.gov',
  'osv.dev',
  'owasp.org',
  'cheatsheetseries.owasp.org',
  'github.com',
  'developer.mozilla.org',
  'rustsec.org',
  'pkg.go.dev',
  'security.snyk.io',
]

/** Exported for tests. */
export function isLinkableReference(value: string): boolean {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.port !== '') return false
  const host = url.hostname.toLowerCase()
  if (!LINKED_REFERENCE_HOSTS.includes(host)) return false
  // Only GitHub's advisory database, not arbitrary repositories or gists.
  return host !== 'github.com' || url.pathname.startsWith('/advisories/')
}

function ReferenceSection(props: { readonly detail: FindingDetail }) {
  const tr = useT()
  const { detail } = props
  const references = asArray(detail.references).filter(r => typeof r === 'string' && r.trim())
  const createdBy = detail.createdBy
  const foundBy = createdBy
    ? [
        tr.lookup(`role.${createdBy.role}`) ??
          (createdBy.role === 'analyzer' ? tr.t('source.sast') : text(createdBy.role)),
        createdBy.analyzer,
        createdBy.model,
      ]
        .filter(Boolean)
        .join(' · ')
    : undefined
  return (
    <footer className="dshsec-refs">
      <h3 className="dshsec-h4">{tr.t('detail.reference')}</h3>
      <dl className="dshsec-kv dshsec-kv--compact">
        <div className="dshsec-kv-row">
          <dt>{tr.t('detail.cwe')}</dt>
          <dd>{text(detail.cwe)}</dd>
        </div>
        {detail.ruleId ? (
          <div className="dshsec-kv-row">
            <dt>{tr.t('detail.rule')}</dt>
            <dd className="dshsec-cell-mono">{detail.ruleId}</dd>
          </div>
        ) : null}
        <div className="dshsec-kv-row">
          <dt>{tr.t('detail.foundBy')}</dt>
          <dd>
            {tr.lookup(`source.${detail.source}`) ?? text(detail.source)}
            {foundBy ? <span className="dshsec-muted"> — {foundBy}</span> : null}
          </dd>
        </div>
      </dl>
      {references.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('detail.references')}</h4>
          <ul className="dshsec-list dshsec-refs-list">
            {references.map(ref => (
              <li key={ref}>
                {isLinkableReference(ref) ? (
                  <a href={ref} target="_blank" rel="noopener noreferrer" className="dshsec-link">
                    {ref}
                  </a>
                ) : (
                  ref
                )}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </footer>
  )
}
