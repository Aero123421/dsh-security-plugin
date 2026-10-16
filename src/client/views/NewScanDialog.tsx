import { useEffect, useId, useMemo, useRef, useState } from 'react'
import type { ModelOption, ProviderOption, RpcFailure, ScanEstimate, WorkspaceSummary } from '../../shared/contracts.ts'
import { type RoleName, SCAN_MODES, type ScanMode } from '../../shared/domain.ts'
import { DEFAULT_SETTINGS, type ModelRef } from '../../shared/settings.ts'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { ChoiceCards } from '../components/Choice.tsx'
import { Field, Select, type SelectOption } from '../components/Field.tsx'
import { Modal } from '../components/Modal.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import type { NewScanRequest } from '../controller.ts'
import { DASH, formatCompact, formatNumber } from '../format.ts'
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

type Approach = 'ai' | 'builtin'

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
  const [approach, setApproach] = useState<Approach>(() => (llmAvailable ? 'ai' : 'builtin'))
  const [mode, setMode] = useState<ScanMode>(() => props.request.mode ?? settings.scan?.defaultMode ?? 'deep')
  const [picked, setPicked] = useState<{ provider: string; model: string }>({ provider: '', model: '' })
  const [estimate, setEstimate] = useState<EstimateState>({ status: 'loading' })
  const [agreed, setAgreed] = useState(false)
  const [forceConsent, setForceConsent] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<RpcFailure | undefined>()
  const [showConsentHint, setShowConsentHint] = useState(false)
  const [showModelHint, setShowModelHint] = useState(false)
  const consentId = useId()
  const pickerRef = useRef<HTMLDivElement>(null)

  const ai = approach === 'ai'
  const scanMode = ai ? mode : BUILTIN_MODE

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

  const goToModels = () => {
    controller.closeNewScan()
    controller.setTab('settings')
  }

  const chooseBuiltin = () => {
    setApproach('builtin')
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
    const result = await controller.startScan({
      workspaceId,
      ...(subpath ? { subpath } : {}),
      mode: scanMode,
      aiReview: ai,
      ...(ai && needsConsent ? { consent: true } : {}),
      ...(ai && pickedRef ? { model: pickedRef } : {}),
    })
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

  const workspaceOptions = workspaces.map(w => ({
    value: w.id,
    label: w.title && w.displayPath ? `${w.title} — ${w.displayPath}` : w.title || w.displayPath || w.id,
  }))

  return (
    <Modal
      title={tr.t('newScan.title')}
      onClose={controller.closeNewScan}
      size="lg"
      footer={
        <>
          <Button onClick={controller.closeNewScan}>{tr.t('common.cancel')}</Button>
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
      <form
        className="dshsec-stack"
        onSubmit={event => {
          event.preventDefault()
          void submit()
        }}
      >
        <Field label={tr.t('newScan.project')} hint={tr.t('project.managedHint')}>
          {({ id, describedBy }) => (
            <>
              <Select
                id={id}
                value={workspaceId}
                options={workspaceOptions}
                disabled={workspaceOptions.length <= 1 || addingProject || submitting}
                describedBy={describedBy}
                onChange={value => {
                  setWorkspaceId(value)
                  setSubpath('')
                }}
              />
              <AddProjectFolder
                disabled={submitting}
                onAdded={value => {
                  setWorkspaceId(value)
                  setSubpath('')
                }}
              />
            </>
          )}
        </Field>

        <Field label={tr.t('newScan.subpath')} hint={tr.t('newScan.subpathHint')}>
          {({ id, describedBy }) => (
            <input
              id={id}
              className="dshsec-input"
              type="text"
              value={subpath}
              placeholder="packages/app"
              maxLength={1024}
              aria-describedby={describedBy}
              onChange={event => setSubpath(event.target.value)}
            />
          )}
        </Field>

        <fieldset className="dshsec-fieldset">
          <legend className="dshsec-label">{tr.t('newScan.how')}</legend>
          <ChoiceCards<Approach>
            name="dshsec-newscan-approach"
            value={approach}
            onChange={value => {
              setApproach(value)
              setError(undefined)
            }}
            options={[
              { value: 'ai', label: tr.t('newScan.ai'), description: tr.t('newScan.ai.desc') },
              { value: 'builtin', label: tr.t('newScan.builtin'), description: tr.t('newScan.builtin.desc') },
            ]}
          />
        </fieldset>

        {ai ? (
          <fieldset className="dshsec-fieldset">
            <legend className="dshsec-label">{tr.t('newScan.mode')}</legend>
            <ModeCards value={mode} onChange={setMode} name="dshsec-newscan-mode" />
          </fieldset>
        ) : null}

        <EstimatePanel estimate={estimate} budget={budget} ai={ai} />

        {ai ? (
          <section className="dshsec-subsection" aria-labelledby={`${consentId}-models`}>
            <div className="dshsec-subhead">
              <h3 className="dshsec-h3" id={`${consentId}-models`}>
                {configured ? tr.t('newScan.modelsTitle') : tr.t('newScan.chooseModel')}
              </h3>
              {configured ? (
                <Button size="sm" variant="link" onClick={goToModels}>
                  {tr.t('newScan.changeModels')}
                </Button>
              ) : null}
            </div>
            {configured ? (
              <RouteList roles={roles} providers={providers} />
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
                {!models.value && models.status === 'error' && models.error ? (
                  <Callout
                    tone="error"
                    action={
                      <Button size="sm" onClick={() => void controller.loadModels(true)}>
                        {tr.t('common.retry')}
                      </Button>
                    }
                  >
                    {tr.t('settings.modelsLoadFailed')}
                  </Callout>
                ) : null}
                {showModelHint && !pickedRef ? (
                  <div className="dshsec-field-error" role="alert">
                    {tr.t('newScan.modelRequired')}
                  </div>
                ) : (
                  <p className="dshsec-hint">{tr.t('newScan.chooseModelHint')}</p>
                )}
              </div>
            )}
          </section>
        ) : null}

        {needsConsent ? (
          <section
            className={`dshsec-consent${showConsentHint && !agreed ? ' is-invalid' : ''}`}
            aria-labelledby={`${consentId}-title`}
          >
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

        {error ? (
          <Callout
            tone={error.code === 'security/busy' ? 'info' : 'error'}
            action={
              error.code === 'security/no-model' ? (
                <Button size="sm" variant="link" onClick={goToModels}>
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
      </form>
    </Modal>
  )
}

/** Scan depth as radio cards. */
export function ModeCards(props: {
  readonly value: ScanMode
  readonly onChange: (mode: ScanMode) => void
  readonly name: string
}) {
  const tr = useT()
  return (
    <ChoiceCards<ScanMode>
      name={props.name}
      value={props.value}
      onChange={props.onChange}
      options={SCAN_MODES.map(mode => ({
        value: mode,
        label: tr.t(`mode.${mode}`),
        description: tr.t(`mode.${mode}.desc`),
        ...(mode === 'deep' ? { tag: tr.t('mode.recommended') } : {}),
      }))}
    />
  )
}

/** Which model each role will use; collapsed to one line when they all share a route. */
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
  if (shared && roles.length > 1) {
    return (
      <ul className="dshsec-routes">
        <li>
          <span className="dshsec-route-role">{tr.t('newScan.allRoles')}</span>
          <span className="dshsec-route-model">{describeRoute(providers, first)}</span>
        </li>
      </ul>
    )
  }
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

function EstimatePanel(props: {
  readonly estimate: EstimateState
  readonly budget: number | undefined
  readonly ai: boolean
}) {
  const tr = useT()
  const locale = tr.intlLocale
  const { estimate, ai } = props
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
            {ai ? (
              <>
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
              </>
            ) : null}
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
            <p className="dshsec-hint">
              {tr.t('newScan.excluded', { count: formatNumber(estimate.value.excluded, locale) })}
            </p>
          ) : null}
          {estimate.value.truncated ? <Callout tone="warn">{tr.t('newScan.truncated')}</Callout> : null}
          {ai ? (
            <p className="dshsec-hint">
              {tr.t('newScan.estimateNote', { budget: formatCompact(props.budget, locale) })}
            </p>
          ) : null}
        </>
      ) : null}
    </section>
  )
}
