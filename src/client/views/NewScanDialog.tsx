import { useEffect, useId, useMemo, useState } from 'react'
import type { ProviderOption, RpcFailure, ScanEstimate, WorkspaceSummary } from '../../shared/contracts.ts'
import { SCAN_MODES, type ScanMode } from '../../shared/domain.ts'
import { DEFAULT_SETTINGS } from '../../shared/settings.ts'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { Field, Select } from '../components/Field.tsx'
import { Modal } from '../components/Modal.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import type { NewScanRequest } from '../controller.ts'
import { DASH, formatCompact, formatNumber } from '../format.ts'
import { errorText } from '../i18n.ts'
import { describeRoute, hunterModel, recipients, resolveRoleModels } from '../models.ts'

const EMPTY_WORKSPACES: readonly WorkspaceSummary[] = []
const EMPTY_PROVIDERS: readonly ProviderOption[] = []

type EstimateState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly value: ScanEstimate }
  | { readonly status: 'error' }

export function NewScanDialog(props: { readonly request: NewScanRequest }) {
  const controller = useController()
  const tr = useT()
  const workspaces = useSecurity(s => s.workspaces.value ?? EMPTY_WORKSPACES)
  const currentWorkspace = useSecurity(s => s.workspaceId)
  const settings = useSecurity(s => s.bootstrap.value?.settings) ?? DEFAULT_SETTINGS
  const canEditHighRisk = useSecurity(s => s.bootstrap.value?.canEditHighRiskSettings === true)
  const providers = useSecurity(s => s.models.value ?? EMPTY_PROVIDERS)

  const [workspaceId, setWorkspaceId] = useState(
    () => props.request.workspaceId ?? currentWorkspace ?? workspaces[0]?.id ?? '',
  )
  const [mode, setMode] = useState<ScanMode>(() => props.request.mode ?? settings.scan?.defaultMode ?? 'deep')
  const [estimate, setEstimate] = useState<EstimateState>({ status: 'loading' })
  const [agreed, setAgreed] = useState(false)
  const [forceConsent, setForceConsent] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<RpcFailure | undefined>()
  const [showConsentHint, setShowConsentHint] = useState(false)
  const consentId = useId()

  useEffect(() => {
    void controller.loadModels()
  }, [controller])

  useEffect(() => {
    if (!workspaceId) return
    const abort = new AbortController()
    setEstimate({ status: 'loading' })
    void controller.estimate(workspaceId, mode, abort.signal).then(result => {
      if (abort.signal.aborted) return
      setEstimate(result.ok ? { status: 'ready', value: result.value } : { status: 'error' })
    })
    return () => abort.abort()
  }, [controller, workspaceId, mode])

  const roles = useMemo(() => resolveRoleModels(settings.models), [settings.models])
  const hunter = hunterModel(settings.models)
  const needsConsent = settings.privacy?.sendCodeToModel !== true || forceConsent
  const sendTo = useMemo(() => recipients(providers, roles), [providers, roles])
  const withheld = Array.isArray(settings.privacy?.withheldGlobs) ? settings.privacy.withheldGlobs : []
  const budget = settings.budgets?.[mode]?.maxTokens

  const goToModels = () => {
    controller.closeNewScan()
    controller.setTab('settings')
  }

  const submit = async () => {
    if (!workspaceId || submitting) return
    if (needsConsent && !agreed) {
      setShowConsentHint(true)
      document.getElementById(consentId)?.focus()
      return
    }
    setSubmitting(true)
    setError(undefined)
    const result = await controller.startScan({ workspaceId, mode, consent: needsConsent })
    setSubmitting(false)
    if (result.ok) {
      controller.closeNewScan()
      controller.setTab('overview')
      return
    }
    if (result.error.code === 'security/consent-required') {
      setForceConsent(true)
      setAgreed(false)
    }
    if (result.error.code === 'security/busy') {
      controller.closeNewScan()
      controller.setTab('overview')
      controller.flash({ tone: 'info', error: result.error })
      return
    }
    setError(result.error)
  }

  const workspaceOptions = workspaces.map(w => ({ value: w.id, label: w.title || w.displayPath || w.id }))

  return (
    <Modal
      title={tr.t('newScan.title')}
      onClose={controller.closeNewScan}
      size="lg"
      footer={
        <>
          <Button onClick={controller.closeNewScan}>{tr.t('common.cancel')}</Button>
          <Button variant="primary" busy={submitting} disabled={!workspaceId} onClick={() => void submit()}>
            {submitting ? tr.t('newScan.starting') : tr.t('newScan.start')}
          </Button>
        </>
      }
    >
      <form
        className="dshsec-stack"
        onSubmit={event => {
          event.preventDefault()
          void submit()
        }}
      >
        <Field label={tr.t('newScan.project')}>
          {({ id }) => <Select id={id} value={workspaceId} options={workspaceOptions} onChange={setWorkspaceId} />}
        </Field>

        <fieldset className="dshsec-fieldset">
          <legend className="dshsec-label">{tr.t('newScan.mode')}</legend>
          <ModeCards value={mode} onChange={setMode} name="dshsec-newscan-mode" />
        </fieldset>

        <EstimatePanel estimate={estimate} budget={budget} />

        <section className="dshsec-subsection" aria-labelledby={`${consentId}-models`}>
          <h3 className="dshsec-h3" id={`${consentId}-models`}>
            {tr.t('newScan.modelsTitle')}
          </h3>
          <dl className="dshsec-kv">
            {roles.map(r => (
              <div key={r.role} className="dshsec-kv-row">
                <dt>{tr.t(`role.${r.role}`)}</dt>
                <dd>
                  {r.ref ? (
                    describeRoute(providers, r.ref)
                  ) : (
                    <span className="dshsec-muted">{tr.t('common.notSet')}</span>
                  )}
                  {r.inherited ? <span className="dshsec-muted"> {tr.t('newScan.inherited')}</span> : null}
                </dd>
              </div>
            ))}
          </dl>
          {!hunter ? (
            <Callout
              tone="warn"
              action={
                <Button size="sm" variant="link" onClick={goToModels}>
                  {tr.t('newScan.configureModels')}
                </Button>
              }
            >
              {tr.t('newScan.noModel')}
            </Callout>
          ) : null}
        </section>

        {needsConsent ? (
          <section className="dshsec-consent" aria-labelledby={`${consentId}-title`}>
            <h3 className="dshsec-h3" id={`${consentId}-title`}>
              {tr.t('consent.title')}
            </h3>
            <p>{tr.t('consent.body')}</p>
            <ul className="dshsec-list">
              {sendTo.length ? (
                sendTo.map(r => (
                  <li key={r.provider}>
                    <strong>{r.provider}</strong> — {r.models.join(', ')}
                  </li>
                ))
              ) : (
                <li>{tr.t('consent.noProviders')}</li>
              )}
            </ul>
            <p className="dshsec-muted">{tr.t('consent.withheld')}</p>
            {withheld.length ? (
              <p className="dshsec-muted">{tr.t('consent.withheldExtra', { globs: withheld.join(', ') })}</p>
            ) : null}
            {!canEditHighRisk ? <p className="dshsec-muted">{tr.t('consent.remote')}</p> : null}
            <label className="dshsec-check">
              <input
                id={consentId}
                type="checkbox"
                checked={agreed}
                required
                aria-invalid={showConsentHint && !agreed ? true : undefined}
                onChange={event => {
                  setAgreed(event.target.checked)
                  setShowConsentHint(false)
                }}
              />
              <span>{tr.t('consent.checkbox')}</span>
            </label>
            {showConsentHint && !agreed ? <div className="dshsec-field-error">{tr.t('consent.required')}</div> : null}
          </section>
        ) : null}

        {error ? (
          <Callout
            tone={error.code === 'security/busy' ? 'info' : 'error'}
            action={
              error.code === 'security/no-model' ? (
                <Button size="sm" variant="link" onClick={goToModels}>
                  {tr.t('newScan.configureModels')}
                </Button>
              ) : undefined
            }
          >
            {errorText(tr, error)}
          </Callout>
        ) : null}
        <button type="submit" hidden tabIndex={-1} aria-hidden="true" />
      </form>
    </Modal>
  )
}

/** Mode choice as radio cards (native radios: arrow keys work out of the box). */
export function ModeCards(props: {
  readonly value: ScanMode
  readonly onChange: (mode: ScanMode) => void
  readonly name: string
}) {
  const tr = useT()
  return (
    <div className="dshsec-modes">
      {SCAN_MODES.map(mode => (
        <label key={mode} className={`dshsec-mode ${props.value === mode ? 'is-selected' : ''}`}>
          <input
            type="radio"
            name={props.name}
            value={mode}
            checked={props.value === mode}
            onChange={() => props.onChange(mode)}
          />
          <span className="dshsec-mode-name">
            {tr.t(`mode.${mode}`)}
            {mode === 'deep' ? <span className="dshsec-mode-rec">{tr.t('mode.recommended')}</span> : null}
          </span>
          <span className="dshsec-mode-desc">{tr.t(`mode.${mode}.desc`)}</span>
        </label>
      ))}
    </div>
  )
}

function EstimatePanel(props: { readonly estimate: EstimateState; readonly budget: number | undefined }) {
  const tr = useT()
  const locale = tr.intlLocale
  const { estimate } = props
  return (
    <section className="dshsec-subsection" aria-busy={estimate.status === 'loading'}>
      <h3 className="dshsec-h3">{tr.t('newScan.estimateTitle')}</h3>
      {estimate.status === 'loading' ? <p className="dshsec-muted">{tr.t('newScan.estimating')}</p> : null}
      {estimate.status === 'error' ? <p className="dshsec-muted">{tr.t('newScan.estimateFailed')}</p> : null}
      {estimate.status === 'ready' ? (
        <>
          <dl className="dshsec-estimate">
            <div>
              <dt>{tr.t('newScan.files')}</dt>
              <dd>{formatNumber(estimate.value.files, locale)}</dd>
            </div>
            <div>
              <dt>{tr.t('newScan.endpoints')}</dt>
              <dd>{formatNumber(estimate.value.endpoints, locale)}</dd>
            </div>
            <div>
              <dt>{tr.t('newScan.tasks')}</dt>
              <dd>{formatNumber(estimate.value.plannedTasks, locale)}</dd>
            </div>
            <div>
              <dt>{tr.t('newScan.tokens')}</dt>
              <dd>
                {tr.t('newScan.tokensRange', {
                  min: formatCompact(estimate.value.tokens?.min, locale),
                  max: formatCompact(estimate.value.tokens?.max, locale),
                })}
              </dd>
            </div>
          </dl>
          <dl className="dshsec-kv">
            <div className="dshsec-kv-row">
              <dt>{tr.t('newScan.languages')}</dt>
              <dd>
                {Array.isArray(estimate.value.languages) && estimate.value.languages.length
                  ? estimate.value.languages.map(l => `${l.language} (${formatNumber(l.files, locale)})`).join(', ')
                  : DASH}
              </dd>
            </div>
            <div className="dshsec-kv-row">
              <dt>{tr.t('newScan.frameworks')}</dt>
              <dd>
                {Array.isArray(estimate.value.frameworks) && estimate.value.frameworks.length
                  ? estimate.value.frameworks.join(', ')
                  : DASH}
              </dd>
            </div>
          </dl>
          {estimate.value.excluded > 0 ? (
            <p className="dshsec-muted">
              {tr.t('newScan.excluded', { count: formatNumber(estimate.value.excluded, locale) })}
            </p>
          ) : null}
          {estimate.value.truncated ? <Callout tone="warn">{tr.t('newScan.truncated')}</Callout> : null}
          <p className="dshsec-hint">{tr.t('newScan.estimateNote', { budget: formatCompact(props.budget, locale) })}</p>
        </>
      ) : null}
    </section>
  )
}
