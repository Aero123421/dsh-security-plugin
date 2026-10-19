import { type ReactNode, type RefObject, useEffect, useId, useRef, useState } from 'react'
import type { AttackStepView, EvidenceView, FindingDetail, ScanSummary } from '../../shared/contracts.ts'
import { type CodeRef, type QuoteCheck, TRIAGE_STATES, type TriageState } from '../../shared/domain.ts'
import { Badge, QuoteCheckLabel, SeverityLabel, TriageBadge, VerificationLabel } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { CodeBlock, formatLocation, Paragraphs } from '../components/Text.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import { findingKey, type Loadable } from '../controller.ts'
import { asArray, text } from '../format.ts'
import { errorText } from '../i18n.ts'
import { IconChat, IconCopy, IconRefresh } from '../icons.tsx'
import { LoadError, Loading } from './shared.tsx'

const IDLE: Loadable<FindingDetail> = { status: 'idle' }

/** Ordered detail sections; tests assert this order. */
export const DETAIL_SECTIONS = ['problem', 'evidence', 'review', 'fix'] as const

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
  const impact = typeof detail.impact === 'string' && detail.impact.trim() ? detail.impact : undefined
  return (
    <article className="dshsec-detail" aria-labelledby={`dshsec-detail-${detail.id}`}>
      <header className="dshsec-detail-head">
        <p className="dshsec-detail-tags">
          <SeverityLabel severity={detail.severity} />
          <VerificationLabel verification={detail.verification} />
          {detail.isNew ? <Badge tone="brand">{tr.t('findings.new')}</Badge> : null}
          <TriageBadge triage={detail.triage} />
        </p>
        <h2 className="dshsec-detail-title" id={`dshsec-detail-${detail.id}`} ref={props.headingRef} tabIndex={-1}>
          {text(detail.title)}
        </h2>
        <p className="dshsec-detail-loc">{formatLocation(detail.location)}</p>
        <FixActions detail={detail} scan={scan} />
      </header>

      <DetailSection id="problem" title={tr.t('detail.problem')}>
        <Paragraphs text={detail.summary} />
        {impact || preconditions.length ? (
          <dl className="dshsec-kv dshsec-kv--detail">
            {impact ? (
              <div className="dshsec-kv-row">
                <dt>{tr.t('detail.impact')}</dt>
                <dd>
                  <Paragraphs text={impact} />
                </dd>
              </div>
            ) : null}
            {preconditions.length ? (
              <div className="dshsec-kv-row">
                <dt>{tr.t('detail.preconditions')}</dt>
                <dd>
                  <ul className="dshsec-plain-list">
                    {preconditions.map(p => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                </dd>
              </div>
            ) : null}
          </dl>
        ) : null}
      </DetailSection>

      <EvidenceSection detail={detail} />

      <DetailSection id="review" title={tr.t('detail.review')}>
        {detail.review ? (
          <div className="dshsec-review">
            <p className="dshsec-review-verdict">
              <strong>{tr.lookup(`review.${detail.review.verdict}`) ?? text(detail.review.verdict)}</strong>
              {detail.review.model ? (
                <span className="dshsec-muted"> · {tr.t('detail.reviewBy', { model: detail.review.model })}</span>
              ) : null}
            </p>
            <Paragraphs text={detail.review.reasoning} />
          </div>
        ) : (
          <p className="dshsec-muted">{tr.t('detail.noReview')}</p>
        )}
        <p className="dshsec-hint">{tr.lookup(`verification.${detail.verification}.explain`) ?? ''}</p>
      </DetailSection>

      <DetailSection id="fix" title={tr.t('detail.fix')}>
        {typeof detail.recommendation === 'string' && detail.recommendation.trim() ? (
          <Paragraphs text={detail.recommendation} />
        ) : (
          <p className="dshsec-muted">{tr.t('detail.noRecommendation')}</p>
        )}
        <Recheck scan={scan} />
      </DetailSection>

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

/** Identity of a cited excerpt; the same code quoted twice is shown once. */
function excerptKey(location: CodeRef | undefined, snippet: unknown): string {
  return `${formatLocation(location)}\u0000${typeof snippet === 'string' ? snippet.trim() : ''}`
}

function EvidenceSection(props: { readonly detail: FindingDetail }) {
  const tr = useT()
  const steps = [...asArray(props.detail.attackPath)].sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
  const shown = new Set(steps.map(step => excerptKey(step.location, step.snippet)))
  const evidence = asArray(props.detail.evidence).filter(item => {
    const key = excerptKey(item.location, item.snippet)
    if (shown.has(key)) return false
    shown.add(key)
    return true
  })
  const counter = asArray(props.detail.counterevidence)
  const limitations = asArray(props.detail.limitations).filter(l => typeof l === 'string' && l.trim())
  const empty = !steps.length && !evidence.length && !counter.length && !limitations.length
  return (
    <DetailSection id="evidence" title={tr.t('detail.evidence')}>
      {empty ? <p className="dshsec-muted">{tr.t('detail.noEvidence')}</p> : null}
      {steps.length ? (
        <ol className="dshsec-path" aria-label={tr.t('detail.attackPath')}>
          {steps.map((step, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: steps are positional; order may repeat
            <AttackStep key={`${step.order}-${i}`} step={step} index={i} total={steps.length} />
          ))}
        </ol>
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

/** A cited excerpt with its location and the host's quote check in the caption. */
function Excerpt(props: {
  readonly snippet: unknown
  readonly location: CodeRef | undefined
  readonly check: QuoteCheck
}) {
  const { snippet, location, check } = props
  if (typeof snippet === 'string' && snippet) {
    return <CodeBlock snippet={snippet} location={location} aside={<QuoteCheckLabel check={check} />} />
  }
  if (!location) return check === 'unchecked' ? null : <QuoteCheckLabel check={check} />
  return (
    <p className="dshsec-detail-loc">
      {formatLocation(location)} <QuoteCheckLabel check={check} />
    </p>
  )
}

function AttackStep(props: { readonly step: AttackStepView; readonly index: number; readonly total: number }) {
  const tr = useT()
  const { step } = props
  return (
    <li className={`dshsec-path-step${step.quoteCheck === 'mismatch' ? ' is-unverified' : ''}`}>
      <div className="dshsec-path-text">
        {props.total > 1 ? (
          <span className="dshsec-path-n">
            <span aria-hidden="true">{props.index + 1}</span>
            <span className="dshsec-visually-hidden">{tr.t('detail.step', { n: props.index + 1 })}</span>
          </span>
        ) : null}
        <Paragraphs text={step.description} />
      </div>
      <Excerpt snippet={step.snippet} location={step.location} check={step.quoteCheck} />
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
            <div className="dshsec-evidence-claim">
              <Paragraphs text={item.claim} />
              <span className="dshsec-muted dshsec-evidence-source">
                {tr.lookup(`trust.${item.trust}`) ?? text(item.trust)}
              </span>
            </div>
            <Excerpt snippet={item.snippet} location={item.location} check={item.quoteCheck} />
          </li>
        ))}
      </ul>
    </div>
  )
}

type ActionNote = { readonly tone: 'success' | 'error'; readonly text: string } | undefined

/** Hand the fix to DSH's coding agent, or copy the prompt. The plugin itself never edits code. */
function FixActions(props: { readonly detail: FindingDetail; readonly scan: ScanSummary }) {
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
    <div className="dshsec-stack-sm">
      <div className="dshsec-actions">
        {canChat ? (
          <Button
            variant="primary"
            size="sm"
            icon={<IconChat size={15} />}
            busy={busy === 'chat'}
            onClick={() => void openChat()}
          >
            {tr.t('detail.fixInChat')}
          </Button>
        ) : null}
        <Button size="sm" icon={<IconCopy size={15} />} busy={busy === 'copy'} onClick={() => void copy()}>
          {tr.t('detail.copyPrompt')}
        </Button>
      </div>
      {note ? <Callout tone={note.tone}>{note.text}</Callout> : null}
    </div>
  )
}

function Recheck(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    await controller.quickRescan(props.scan.workspaceId, props.scan.subpath, props.scan.mode)
    setBusy(false)
  }
  return (
    <div className="dshsec-recheck">
      <p className="dshsec-hint">{tr.t('detail.recheckBody')}</p>
      <Button size="sm" icon={<IconRefresh size={14} />} busy={busy} onClick={() => void run()}>
        {tr.t('detail.runRecheck', { mode: tr.t(`mode.${props.scan.mode}`) })}
      </Button>
    </div>
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
    <section className="dshsec-dsec dshsec-triage" aria-labelledby={`${helpId}-title`}>
      <fieldset className="dshsec-fieldset">
        <legend className="dshsec-dsec-title" id={`${helpId}-title`}>
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
        <Button size="sm" busy={busy} disabled={!dirty} onClick={() => void save()}>
          {tr.t('detail.saveDecision')}
        </Button>
        {dirty && !busy ? <span className="dshsec-hint">{tr.t('settings.unsaved')}</span> : null}
      </div>
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
            {foundBy ? <span className="dshsec-muted"> · {foundBy}</span> : null}
          </dd>
        </div>
        {references.length ? (
          <div className="dshsec-kv-row">
            <dt>{tr.t('detail.references')}</dt>
            <dd>
              <ul className="dshsec-plain-list dshsec-refs-list">
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
            </dd>
          </div>
        ) : null}
      </dl>
    </footer>
  )
}
