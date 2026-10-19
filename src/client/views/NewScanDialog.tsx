import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react'
import type { ModelOption, ProviderOption, RpcFailure, ScanEstimate, WorkspaceSummary } from '../../shared/contracts.ts'
import { type RoleName, SCAN_MODES, type ScanMode } from '../../shared/domain.ts'
import { DEFAULT_SETTINGS, type ModelRef } from '../../shared/settings.ts'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { Field, Select, type SelectOption } from '../components/Field.tsx'
import { Modal } from '../components/Modal.tsx'
import { ProjectSelect } from '../components/ProjectSelect.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import type { NewScanRequest } from '../controller.ts'
import { formatCompact, formatNumber } from '../format.ts'
import { errorText } from '../i18n.ts'
import {
  describeRoute,
  hunterModel,
  recipients,
  type ResolvedRole,
  resolveRoleModels,
  rolesForMode,
} from '../models.ts'
import { AddProjectFolder } from './AddProjectFolder.tsx'

const EMPTY_WORKSPACES: readonly WorkspaceSummary[] = []
const EMPTY_PROVIDERS: readonly ProviderOption[] = []

type EstimateState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly value: ScanEstimate }
  | { readonly status: 'error' }

/** What the review choice can be: the built-in checks alone, or AI review at a depth. */
export type ReviewChoice = 'builtin' | ScanMode
const REVIEW_CHOICES: readonly ReviewChoice[] = ['builtin', ...SCAN_MODES]

/** Mode sent for a built-in-only scan; depth only shapes the AI phases. */
const BUILTIN_MODE: ScanMode = 'quick'

export function NewScanDialog(props: { readonly request: NewScanRequest }) {
  const controller = useController()
  const tr = useT()
  const workspaces = useSecurity(s => s.workspaces.value ?? EMPTY_WORKSPACES)
  const currentWorkspace = useSecurity(s => s.workspaceId)
  const addingProject = useSecurity(s => s.addingProject)
  const settings = useSecurity(s => s.bootstrap.value?.settings) ?? DEFAULT_SETTINGS
  const canEditHighRisk = useSecurity(s => s.bootstrap.value?.canEditHighRiskSettings === true)
  const llmAvailable = useSecurity(s => s.bootstrap.value?.capabilities?.llm !== false)
  const models = useSecurity(s => s.models)
  const providers = models.value ?? EMPTY_PROVIDERS

  const [workspaceId, setWorkspaceId] = useState(
    () => props.request.workspaceId ?? currentWorkspace ?? workspaces[0]?.id ?? '',
  )
  const [subpath, setSubpath] = useState(props.request.subpath ?? '')
  const [showSubpath, setShowSubpath] = useState(Boolean(props.request.subpath))
  const [choice, setChoice] = useState<ReviewChoice>(() =>
    llmAvailable ? (props.request.mode ?? settings.scan?.defaultMode ?? 'deep') : 'builtin',
  )
  const [picked, setPicked] = useState<{ provider: string; model: string }>({ provider: '', model: '' })
  const [estimate, setEstimate] = useState<EstimateState>({ status: 'loading' })
  const [agreed, setAgreed] = useState(false)
  const [forceConsent, setForceConsent] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<RpcFailure | undefined>()
  const [showConsentHint, setShowConsentHint] = useState(false)
  const [showModelHint, setShowModelHint] = useState(false)
  const consentId = useId()
  const projectId = useId()
  const subpathId = useId()
  const pickerRef = useRef<HTMLDivElement>(null)

  const ai = choice !== 'builtin'
  const mode: ScanMode = ai ? choice : (settings.scan?.defaultMode ?? 'deep')
  const scanMode = ai ? choice : BUILTIN_MODE

  useEffect(() => {
    void controller.loadModels()
  }, [controller])

  useEffect(() => {
    if (!workspaceId) return
    const abort = new AbortController()
    setEstimate({ status: 'loading' })
    void controller.estimate(workspaceId, scanMode, abort.signal, subpath).then(result => {
      if (abort.signal.aborted) return
      setEstimate(result.ok ? { status: 'ready', value: result.value } : { status: 'error' })
    })
    return () => abort.abort()
  }, [controller, workspaceId, scanMode, subpath])

  const configured = hunterModel(settings.models)
  const pickedRef: ModelRef | undefined =
    !configured && picked.provider && picked.model ? { provider: picked.provider, model: picked.model } : undefined
  const roles = useMemo(() => {
    const effective = pickedRef ? { ...settings.models, default: pickedRef } : settings.models
    const used = new Set<RoleName>(rolesForMode(mode))
    return resolveRoleModels(effective).filter(r => used.has(r.role))
  }, [settings.models, pickedRef, mode])
  const needsConsent = ai && (settings.privacy?.sendCodeToModel !== true || forceConsent)
  const sendTo = useMemo(() => recipients(providers, roles), [providers, roles])
  const withheld = Array.isArray(settings.privacy?.withheldGlobs) ? settings.privacy.withheldGlobs : []
  const budget = settings.budgets?.[mode]?.maxTokens
  const noProviders = models.status === 'ready' && !providers.some(p => Array.isArray(p.models) && p.models.length)

  const goToSettings = () => {
    controller.closeNewScan()
    controller.setTab('settings')
  }

  const chooseBuiltin = () => {
    setChoice('builtin')
    setError(undefined)
  }

  const submit = async () => {
    if (!workspaceId || submitting || addingProject) return
    if (ai && !configured && !pickedRef) {
      setShowModelHint(true)
      pickerRef.current?.querySelector<HTMLElement>('select:not([disabled])')?.focus()
      return
    }
    if (needsConsent && !agreed) {
      setShowConsentHint(true)
      document.getElementById(consentId)?.focus()
      return
    }
    setSubmitting(true)
    setError(undefined)
    // The dialog cannot be dismissed while submitting, so the busy state
    // must clear even if startScan throws instead of returning a result.
    const result = await controller
      .startScan({
        workspaceId,
        ...(subpath ? { subpath } : {}),
        mode: scanMode,
        aiReview: ai,
        ...(ai && needsConsent ? { consent: true } : {}),
        ...(ai && pickedRef ? { model: pickedRef } : {}),
      })
      .catch(
        () =>
          ({
            ok: false,
            error: { code: 'security/result-unknown', message: '', details: {} },
          }) as const,
      )
      .finally(() => setSubmitting(false))
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

  return (
    <Modal
      title={tr.t('newScan.title')}
      onClose={controller.closeNewScan}
      dismissible={!submitting}
      size="lg"
      footer={
        <>
          <Button disabled={submitting} onClick={controller.closeNewScan}>
            {tr.t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            busy={submitting}
            disabled={!workspaceId || addingProject}
            onClick={() => void submit()}
          >
            {submitting ? tr.t('newScan.starting') : ai ? tr.t('newScan.start') : tr.t('newScan.startBuiltin')}
          </Button>
        </>
      }
    >
      {submitting ? <Callout>{tr.t('newScan.startingHint')}</Callout> : null}
      <form
        aria-busy={submitting}
        onSubmit={event => {
          event.preventDefault()
          void submit()
        }}
      >
        <fieldset className="dshsec-fieldset dshsec-form" disabled={submitting}>
          <FormRow label={tr.t('newScan.project')} htmlFor={projectId}>
            <div className="dshsec-form-inline">
              <ProjectSelect
                id={projectId}
                variant="field"
                ariaLabel={tr.t('newScan.project')}
                value={workspaceId}
                workspaces={workspaces}
                disabled={addingProject || submitting}
                onChange={value => {
                  setWorkspaceId(value)
                  setSubpath('')
                }}
              />
              <AddProjectFolder
                variant="icon"
                disabled={submitting}
                onAdded={value => {
                  setWorkspaceId(value)
                  setSubpath('')
                }}
              />
            </div>
            {showSubpath ? (
              <div className="dshsec-field">
                <label className="dshsec-label dshsec-label--sub" htmlFor={subpathId}>
                  {tr.t('newScan.subpath')}
                </label>
                <input
                  id={subpathId}
                  className="dshsec-input"
                  type="text"
                  value={subpath}
                  placeholder="packages/app"
                  maxLength={1024}
                  onChange={event => setSubpath(event.target.value)}
                />
              </div>
            ) : (
              <Button size="sm" variant="link" className="dshsec-form-extra" onClick={() => setShowSubpath(true)}>
                {tr.t('newScan.subpathShow')}
              </Button>
            )}
          </FormRow>

          <fieldset className="dshsec-fieldset dshsec-form-row">
            <legend className="dshsec-form-label">{tr.t('newScan.how')}</legend>
            <div className="dshsec-form-control">
              <ReviewChoices
                value={choice}
                onChange={next => {
                  setChoice(next)
                  setError(undefined)
                }}
                name="dshsec-newscan-review"
              />
              <p className="dshsec-hint">
                {tr.t(choice === 'builtin' ? 'newScan.builtin.desc' : `mode.${choice}.desc`)}
              </p>
            </div>
          </fieldset>

          <FormRow label={tr.t('newScan.estimateTitle')}>
            <EstimateLine estimate={estimate} budget={budget} ai={ai} />
          </FormRow>

          {ai ? (
            <FormRow label={tr.t('newScan.modelsTitle')}>
              {models.status === 'error' && models.error ? (
                <Callout
                  tone="error"
                  action={
                    <Button size="sm" onClick={() => void controller.loadModels(true)}>
                      {tr.t('common.retry')}
                    </Button>
                  }
                >
                  {tr.t(models.value ? 'settings.modelsStale' : 'settings.modelsLoadFailed')}
                </Callout>
              ) : null}
              {configured ? (
                <div className="dshsec-form-inline">
                  <RouteList roles={roles} providers={providers} />
                  <Button size="sm" variant="link" onClick={goToSettings}>
                    {tr.t('newScan.changeModels')}
                  </Button>
                </div>
              ) : noProviders ? (
                <Callout
                  tone="warn"
                  action={
                    <Button size="sm" onClick={chooseBuiltin}>
                      {tr.t('newScan.useBuiltin')}
                    </Button>
                  }
                >
                  {tr.t('newScan.noProviders')}
                </Callout>
              ) : (
                <div ref={pickerRef} className="dshsec-stack-sm">
                  <ModelPicker
                    providers={providers}
                    loading={!models.value && models.status !== 'error'}
                    value={picked}
                    invalid={showModelHint && !pickedRef}
                    onChange={next => {
                      setPicked(next)
                      setShowModelHint(false)
                    }}
                  />
                  {showModelHint && !pickedRef ? (
                    <div className="dshsec-field-error" role="alert">
                      {tr.t('newScan.modelRequired')}
                    </div>
                  ) : (
                    <p className="dshsec-hint">{tr.t('newScan.chooseModelHint')}</p>
                  )}
                </div>
              )}
            </FormRow>
          ) : null}

          {needsConsent ? (
            <section
              className={`dshsec-consent${showConsentHint && !agreed ? ' is-invalid' : ''}`}
              aria-labelledby={`${consentId}-title`}
            >
              <h3 className="dshsec-h3" id={`${consentId}-title`}>
                {tr.t('consent.title')}
              </h3>
              <p>
                {tr.t('consent.body')}{' '}
                {sendTo.length
                  ? sendTo.map((r, i) => (
                      <span key={r.provider}>
                        {i > 0 ? ', ' : null}
                        <strong>{r.provider}</strong> ({r.models.join(', ')})
                      </span>
                    ))
                  : tr.t('consent.noProviders')}
              </p>
              <p className="dshsec-hint">{tr.t('consent.withheld')}</p>
              {withheld.length ? (
                <p className="dshsec-hint">{tr.t('consent.withheldExtra', { globs: withheld.join(', ') })}</p>
              ) : null}
              {!canEditHighRisk ? <p className="dshsec-hint">{tr.t('consent.remote')}</p> : null}
              <label className="dshsec-check">
                <input
                  id={consentId}
                  type="checkbox"
                  checked={agreed}
                  aria-invalid={showConsentHint && !agreed ? true : undefined}
                  aria-describedby={showConsentHint && !agreed ? `${consentId}-error` : undefined}
                  onChange={event => {
                    setAgreed(event.target.checked)
                    setShowConsentHint(false)
                  }}
                />
                <span>{tr.t('consent.checkbox')}</span>
              </label>
              {showConsentHint && !agreed ? (
                <div className="dshsec-field-error" id={`${consentId}-error`} role="alert">
                  {tr.t('consent.required')}
                </div>
              ) : null}
            </section>
          ) : null}

          {settings.privacy?.allowDependencyLookup !== true &&
          (estimate.status !== 'ready' || estimate.value.dependencyManifests !== 0) ? (
            <p className="dshsec-hint dshsec-form-note">
              {tr.t('newScan.dependencyLookupOff')}{' '}
              <Button size="sm" variant="link" onClick={goToSettings}>
                {tr.t('newScan.dependencySettings')}
              </Button>
            </p>
          ) : null}

          {error ? (
            <Callout
              tone={error.code === 'security/busy' ? 'info' : 'error'}
              action={
                error.code === 'security/no-model' ? (
                  <Button size="sm" variant="link" onClick={goToSettings}>
                    {tr.t('newScan.configureModels')}
                  </Button>
                ) : ai && (error.code === 'security/forbidden-remote' || error.code === 'security/consent-required') ? (
                  <Button size="sm" onClick={chooseBuiltin}>
                    {tr.t('newScan.useBuiltin')}
                  </Button>
                ) : undefined
              }
            >
              {errorText(tr, error)}
            </Callout>
          ) : null}
          <button type="submit" hidden tabIndex={-1} aria-hidden="true" />
        </fieldset>
      </form>
    </Modal>
  )
}

/** Label column + control, like DSH's settings rows. */
function FormRow(props: { readonly label: string; readonly htmlFor?: string; readonly children: ReactNode }) {
  return (
    <div className="dshsec-form-row">
      {props.htmlFor ? (
        <label className="dshsec-form-label" htmlFor={props.htmlFor}>
          {props.label}
        </label>
      ) : (
        <span className="dshsec-form-label">{props.label}</span>
      )}
      <div className="dshsec-form-control">{props.children}</div>
    </div>
  )
}

/** Built-in only / Quick / Deep / Research as one segmented radio group (arrow keys move the choice). */
export function ReviewChoices(props: {
  readonly value: ReviewChoice
  readonly onChange: (value: ReviewChoice) => void
  readonly name: string
}) {
  const tr = useT()
  return (
    <div className="dshsec-modes">
      {REVIEW_CHOICES.map(choice => (
        <label key={choice} className={`dshsec-mode${props.value === choice ? ' is-selected' : ''}`}>
          <input
            type="radio"
            name={props.name}
            value={choice}
            checked={props.value === choice}
            onChange={() => props.onChange(choice)}
          />
          <span>{choice === 'builtin' ? tr.t('newScan.builtin') : tr.t(`mode.${choice}`)}</span>
        </label>
      ))}
    </div>
  )
}

/** Which model each role will use; one line when they all share a route. */
function RouteList(props: { readonly roles: readonly ResolvedRole[]; readonly providers: readonly ProviderOption[] }) {
  const tr = useT()
  const { roles, providers } = props
  const first = roles[0]?.ref
  const shared =
    first !== undefined &&
    roles.every(
      r =>
        r.ref?.provider === first.provider &&
        r.ref?.model === first.model &&
        (r.ref?.reasoningEffort ?? '') === (first.reasoningEffort ?? ''),
    )
  if (shared) return <span className="dshsec-route-model">{describeRoute(providers, first)}</span>
  return (
    <ul className="dshsec-routes">
      {roles.map(r => (
        <li key={r.role}>
          <span className="dshsec-route-role">{tr.t(`role.${r.role}`)}</span>
          <span className="dshsec-route-model">
            {r.ref ? (
              describeRoute(providers, r.ref)
            ) : (
              <span className="dshsec-muted">{tr.t('newScan.roleSkipped')}</span>
            )}
          </span>
        </li>
      ))}
    </ul>
  )
}

function modelsOf(provider: ProviderOption | undefined): readonly ModelOption[] {
  return Array.isArray(provider?.models) ? provider.models : []
}

/** Provider → model selects, fed by `listModels`. */
function ModelPicker(props: {
  readonly providers: readonly ProviderOption[]
  readonly loading: boolean
  readonly value: { provider: string; model: string }
  readonly invalid: boolean
  readonly onChange: (value: { provider: string; model: string }) => void
}) {
  const tr = useT()
  const { providers, value } = props
  const usable = providers.filter(p => modelsOf(p).length > 0)
  const provider = providers.find(p => p.id === value.provider)

  // A single usable provider needs no choice; preselect it (the model stays explicit when there are several).
  const only = usable.length === 1 ? usable[0] : undefined
  useEffect(() => {
    if (only && !value.provider) {
      const models = modelsOf(only)
      props.onChange({ provider: only.id, model: models.length === 1 ? (models[0]?.id ?? '') : '' })
    }
  }, [only, value.provider, props.onChange])

  const providerOptions: SelectOption<string>[] = [
    { value: '', label: props.loading ? tr.t('common.loading') : tr.t('settings.chooseProvider'), disabled: true },
    ...providers.map(p => ({
      value: p.id,
      label: modelsOf(p).length ? p.name || p.id : tr.t('settings.unavailableModel', { name: p.name || p.id }),
      disabled: modelsOf(p).length === 0,
    })),
  ]
  const modelOptions: SelectOption<string>[] = [
    { value: '', label: tr.t('settings.chooseModel'), disabled: true },
    ...modelsOf(provider).map(m => ({ value: m.id, label: m.name || m.id })),
  ]

  return (
    <div className="dshsec-grid-2">
      <Field label={tr.t('settings.provider')}>
        {({ id }) => (
          <Select
            id={id}
            value={value.provider}
            options={providerOptions}
            disabled={props.loading}
            invalid={props.invalid && !value.provider}
            onChange={providerId => {
              const models = modelsOf(providers.find(p => p.id === providerId))
              props.onChange({ provider: providerId, model: models.length === 1 ? (models[0]?.id ?? '') : '' })
            }}
          />
        )}
      </Field>
      <Field label={tr.t('settings.model')}>
        {({ id }) => (
          <Select
            id={id}
            value={value.model}
            options={modelOptions}
            disabled={!value.provider}
            invalid={props.invalid && Boolean(value.provider) && !value.model}
            onChange={model => props.onChange({ provider: value.provider, model })}
          />
        )}
      </Field>
    </div>
  )
}

/** The scan's size in one line: files and endpoints, and for AI review the tasks and token range. */
function EstimateLine(props: {
  readonly estimate: EstimateState
  readonly budget: number | undefined
  readonly ai: boolean
}) {
  const tr = useT()
  const locale = tr.intlLocale
  const { estimate, ai } = props
  if (estimate.status === 'loading') {
    return (
      <p className="dshsec-muted" aria-busy="true">
        {tr.t('newScan.estimating')}
      </p>
    )
  }
  if (estimate.status === 'error') return <p className="dshsec-muted">{tr.t('newScan.estimateFailed')}</p>
  const value = estimate.value
  const languages = Array.isArray(value.languages)
    ? value.languages.map(l => `${l.language} (${formatNumber(l.files, locale)})`).join(', ')
    : ''
  const frameworks = Array.isArray(value.frameworks) ? value.frameworks.join(', ') : ''
  return (
    <div className="dshsec-stack-xs">
      <p className="dshsec-num">
        {tr.t('newScan.scopeFiles', {
          files: formatNumber(value.files, locale),
          endpoints: formatNumber(value.endpoints, locale),
        })}
        {ai
          ? ` · ${tr.t('newScan.scopeAi', {
              tasks: formatNumber(value.plannedTasks, locale),
              min: formatCompact(value.tokens?.min, locale),
              max: formatCompact(value.tokens?.max, locale),
              budget: formatCompact(props.budget, locale),
            })}`
          : null}
      </p>
      {languages || frameworks ? (
        <p className="dshsec-hint">{[languages, frameworks].filter(Boolean).join(' · ')}</p>
      ) : null}
      {value.excluded > 0 ? (
        <p className="dshsec-hint">{tr.t('newScan.excluded', { count: formatNumber(value.excluded, locale) })}</p>
      ) : null}
      {value.truncated ? <Callout tone="warn">{tr.t('newScan.truncated')}</Callout> : null}
    </div>
  )
}
