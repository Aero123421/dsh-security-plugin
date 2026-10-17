import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react'
import type {
  AnalyzerStatus,
  ModelOption,
  OperatorLimits,
  ProviderOption,
  ToolkitEntry,
} from '../../shared/contracts.ts'
import { SCAN_MODES, SEVERITIES } from '../../shared/domain.ts'
import { Badge } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { ErrorBoundary } from '../components/ErrorBoundary.tsx'
import { Field, Select, type SelectGroup, type SelectOption, Toggle } from '../components/Field.tsx'
import { ControllerProvider, useController, useSecurity, useT } from '../context.tsx'
import type { SecurityController } from '../controller.ts'
import { copyText } from '../download.ts'
import { formatNumber, text } from '../format.ts'
import { analyzerReasonText, errorText, LANGUAGE_NAMES, type Translator } from '../i18n.ts'
import { IconExternal } from '../icons.tsx'
import { modelName } from '../models.ts'
import {
  BUDGET_FIELDS,
  budgetRange,
  type HighRiskPath,
  isDraftDirty,
  isHighRiskLocked,
  MODEL_SLOTS,
  modelRefOf,
  type ModelDraft,
  type ModelSlot,
  parallelRange,
  type SettingsDraft,
  UI_LANGUAGES,
  validateDraft,
} from '../settingsForm.ts'
import { LoadError, Loading, RenderFailure } from './shared.tsx'

/** Where releases are published. The page links here; it never fetches it. */
export const RELEASES_URL = 'https://github.com/Aero123421/dsh-security-plugin/releases'
/** DSH versions this plugin build supports (keep in step with package.json `peerDependencies`). */
export const SUPPORTED_DSH_RANGE = '0.2.1-alpha.2 – 0.2.x'
/** What to paste into DSH's plugin screen; X.Y.Z is the release tag the user picks. */
export const MANUAL_UPDATE_SPEC = 'github:Aero123421/dsh-security-plugin#vX.Y.Z'
export const MANUAL_UPDATE_CLI = `dsh plugin --profile web add -w ${MANUAL_UPDATE_SPEC}`
const COPIED_MS = 2000

const NO_PROVIDERS: readonly ProviderOption[] = []
const NO_ANALYZERS: readonly AnalyzerStatus[] = []

/** Section registered in DSH Settings → Security. */
export function SettingsSection(props: { readonly controller: SecurityController; readonly close?: () => void }) {
  return (
    <ControllerProvider controller={props.controller}>
      <SettingsSectionFrame {...(props.close ? { close: props.close } : {})} />
    </ControllerProvider>
  )
}

function SettingsSectionFrame(props: { readonly close?: () => void }) {
  const controller = useController()
  const tr = useT()
  const language = useSecurity(s => s.language)
  useEffect(() => {
    controller.ensureLoaded()
  }, [controller])
  return (
    <div className="dshsec-root dshsec-settings-host" lang={language}>
      <div className="dshsec-settings-intro">
        <p className="dshsec-muted">{tr.t('settings.intro')}</p>
        {controller.canOpenPage() ? (
          <Button icon={<IconExternal size={14} />} onClick={() => controller.openSecurityPage(props.close)}>
            {tr.t('settings.openPage')}
          </Button>
        ) : null}
      </div>
      <ErrorBoundary fallback={reset => <RenderFailure onRetry={reset} />}>
        <SettingsPanel />
      </ErrorBoundary>
    </div>
  )
}

/** The settings form, used by the Settings tab and the DSH Settings section. */
export function SettingsPanel() {
  const controller = useController()
  const bootstrap = useSecurity(s => s.bootstrap)
  const form = useSecurity(s => s.form)

  useEffect(() => {
    void controller.loadModels()
    void controller.loadToolkit()
  }, [controller])

  if (!form && bootstrap.status === 'error' && bootstrap.error) {
    return <LoadError error={bootstrap.error} onRetry={() => void controller.reloadBootstrap({ force: true })} />
  }
  if (!form || !bootstrap.value) return <Loading />
  return <SettingsForm />
}

function SettingsForm() {
  const controller = useController()
  const tr = useT()
  const form = useSecurity(s => s.form)!
  const limits = useSecurity(s => s.bootstrap.value?.limits)
  const canEditHighRisk = useSecurity(s => s.bootstrap.value?.canEditHighRiskSettings === true)
  const { base, draft, saving, result } = form
  const dirty = isDraftDirty(base, draft)
  const errors = useMemo(() => validateDraft(draft, base, limits), [draft, base, limits])
  const errorFor = (path: string) => {
    const e = errors[path]
    return e ? tr.t(e.key, e.params) : undefined
  }
  const update = controller.updateDraft
  const formRef = useRef<HTMLFormElement>(null)

  return (
    <form
      ref={formRef}
      className="dshsec-settings"
      onSubmit={event => {
        event.preventDefault()
        if (Object.keys(errors).length) {
          // Take the user to the first field that needs fixing.
          formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus()
        }
        void controller.saveSettings()
      }}
      noValidate
    >
      <ModelsSection draft={draft} errorFor={errorFor} />

      <SettingsGroup title={tr.t('settings.scan')}>
        <Field label={tr.t('settings.defaultMode')}>
          {({ id }) => (
            <Select
              id={id}
              value={draft.scan.defaultMode}
              options={SCAN_MODES.map(mode => ({ value: mode, label: tr.t(`mode.${mode}`) }))}
              onChange={defaultMode => update(d => ({ ...d, scan: { ...d.scan, defaultMode } }))}
            />
          )}
        </Field>
        <Field label={tr.t('settings.exclude')} hint={tr.t('settings.excludeHint')}>
          {({ id, describedBy }) => (
            <textarea
              id={id}
              className="dshsec-textarea dshsec-mono"
              rows={4}
              spellCheck={false}
              aria-describedby={describedBy}
              value={draft.scan.excludeGlobs}
              onChange={event => {
                const value = event.target.value
                update(d => ({ ...d, scan: { ...d.scan, excludeGlobs: value } }))
              }}
            />
          )}
        </Field>
        <Toggle
          label={tr.t('settings.includeTests')}
          hint={tr.t('settings.includeTestsHint')}
          checked={draft.scan.includeTests}
          onChange={includeTests => update(d => ({ ...d, scan: { ...d.scan, includeTests } }))}
        />
        <div className="dshsec-grid-2">
          <NumberField
            label={tr.t('settings.parallel')}
            hint={tr.t('settings.parallelHint', { max: parallelRange(limits).max })}
            value={draft.scan.parallelWorkers}
            range={parallelRange(limits)}
            error={errorFor('scan.parallelWorkers')}
            onChange={parallelWorkers => update(d => ({ ...d, scan: { ...d.scan, parallelWorkers } }))}
          />
          <Field label={tr.t('settings.threshold')} hint={tr.t('settings.thresholdHint')}>
            {({ id, describedBy }) => (
              <Select
                id={id}
                describedBy={describedBy}
                value={draft.scan.reviewThreshold}
                options={SEVERITIES.map(sev => ({ value: sev, label: tr.t(`severity.${sev}`) }))}
                onChange={reviewThreshold => update(d => ({ ...d, scan: { ...d.scan, reviewThreshold } }))}
              />
            )}
          </Field>
        </div>
      </SettingsGroup>

      <BudgetsSection draft={draft} limits={limits} errorFor={errorFor} />

      <SettingsGroup title={tr.t('settings.privacy')}>
        <HighRiskToggle
          path="privacy.sendCodeToModel"
          label={tr.t('settings.sendCode')}
          hint={tr.t('settings.sendCodeHint')}
          checked={draft.privacy.sendCodeToModel}
          locked={isHighRiskLocked('privacy.sendCodeToModel', base, draft, canEditHighRisk)}
          canEdit={canEditHighRisk}
          onChange={sendCodeToModel => update(d => ({ ...d, privacy: { ...d.privacy, sendCodeToModel } }))}
        />
        <Field label={tr.t('settings.withheld')} hint={tr.t('settings.withheldHint')}>
          {({ id, describedBy }) => (
            <textarea
              id={id}
              className="dshsec-textarea dshsec-mono"
              rows={3}
              spellCheck={false}
              aria-describedby={describedBy}
              value={draft.privacy.withheldGlobs}
              onChange={event => {
                const value = event.target.value
                update(d => ({ ...d, privacy: { ...d.privacy, withheldGlobs: value } }))
              }}
            />
          )}
        </Field>
        <HighRiskToggle
          path="privacy.allowDependencyLookup"
          label={tr.t('settings.osv')}
          hint={tr.t('settings.osvHint')}
          checked={draft.privacy.allowDependencyLookup}
          locked={isHighRiskLocked('privacy.allowDependencyLookup', base, draft, canEditHighRisk)}
          canEdit={canEditHighRisk}
          onChange={allowDependencyLookup => update(d => ({ ...d, privacy: { ...d.privacy, allowDependencyLookup } }))}
        />
        <HighRiskToggle
          path="privacy.useExternalAnalyzers"
          label={tr.t('settings.external')}
          hint={tr.t('settings.externalHint')}
          checked={draft.privacy.useExternalAnalyzers}
          locked={isHighRiskLocked('privacy.useExternalAnalyzers', base, draft, canEditHighRisk)}
          canEdit={canEditHighRisk}
          onChange={useExternalAnalyzers => update(d => ({ ...d, privacy: { ...d.privacy, useExternalAnalyzers } }))}
        />
      </SettingsGroup>

      <SettingsGroup title={tr.t('settings.storage')}>
        <NumberField
          label={tr.t('settings.retention')}
          hint={tr.t('settings.retentionHint')}
          value={draft.storage.retentionDays}
          range={{ min: 0, max: 3650 }}
          error={errorFor('storage.retentionDays')}
          onChange={retentionDays => update(d => ({ ...d, storage: { ...d.storage, retentionDays } }))}
        />
        <Toggle
          label={tr.t('settings.transcripts')}
          hint={tr.t('settings.transcriptsHint')}
          checked={draft.storage.keepTranscripts}
          onChange={keepTranscripts => update(d => ({ ...d, storage: { ...d.storage, keepTranscripts } }))}
        />
        <Field label={tr.t('settings.language')}>
          {({ id }) => (
            <Select
              id={id}
              value={draft.ui.language}
              options={UI_LANGUAGES.map(lang => ({
                value: lang,
                label: lang === 'auto' ? tr.t('settings.languageAuto') : LANGUAGE_NAMES[lang],
              }))}
              onChange={language => update(d => ({ ...d, ui: { language } }))}
            />
          )}
        </Field>
      </SettingsGroup>

      <ToolkitSection />

      <VersionSection />

      {result && !dirty ? (
        <Callout tone={result.tone}>{'key' in result ? tr.t(result.key) : errorText(tr, result.error)}</Callout>
      ) : null}

      {dirty ? (
        <section className="dshsec-savebar" aria-label={tr.t('settings.unsaved')}>
          <span
            className={`dshsec-savebar-text${result?.tone === 'error' ? ' is-error' : ''}`}
            role="status"
            aria-live="polite"
          >
            {result ? ('key' in result ? tr.t(result.key) : errorText(tr, result.error)) : tr.t('settings.unsaved')}
          </span>
          <div className="dshsec-savebar-actions">
            <Button variant="ghost" onClick={controller.discardDraft} disabled={saving}>
              {tr.t('settings.discard')}
            </Button>
            <Button type="submit" variant="primary" busy={saving}>
              {saving ? tr.t('settings.saving') : tr.t('settings.save')}
            </Button>
          </div>
        </section>
      ) : null}
    </form>
  )
}

function SettingsGroup(props: { readonly title: string; readonly description?: string; readonly children: ReactNode }) {
  const id = useId()
  return (
    <section className="dshsec-sgroup" aria-labelledby={id}>
      <div className="dshsec-sgroup-head">
        <h2 className="dshsec-sgroup-title" id={id}>
          {props.title}
        </h2>
        {props.description ? <p className="dshsec-muted">{props.description}</p> : null}
      </div>
      <div className="dshsec-sgroup-body">{props.children}</div>
    </section>
  )
}

function NumberField(props: {
  readonly label: string
  readonly hint?: string
  readonly value: string
  readonly range: { min: number; max: number }
  readonly error: string | undefined
  readonly placeholder?: string
  readonly onChange: (value: string) => void
}) {
  return (
    <Field
      label={props.label}
      {...(props.hint ? { hint: props.hint } : {})}
      {...(props.error ? { error: props.error } : {})}
    >
      {({ id, describedBy, invalid }) => (
        <input
          id={id}
          className="dshsec-input dshsec-input--num"
          type="number"
          inputMode="numeric"
          min={props.range.min}
          max={props.range.max}
          step={1}
          placeholder={props.placeholder}
          value={props.value}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          onChange={event => props.onChange(event.target.value)}
        />
      )}
    </Field>
  )
}

function HighRiskToggle(props: {
  readonly path: HighRiskPath
  readonly label: string
  readonly hint: string
  readonly checked: boolean
  readonly locked: boolean
  readonly canEdit: boolean
  readonly onChange: (value: boolean) => void
}) {
  const tr = useT()
  return (
    <Toggle
      label={props.label}
      hint={props.hint}
      checked={props.checked}
      disabled={props.locked}
      onChange={value => {
        if (value && props.locked) return
        props.onChange(value)
      }}
      {...(!props.canEdit ? { note: tr.t('settings.highRiskLocked') } : {})}
    />
  )
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

function ModelsSection(props: {
  readonly draft: SettingsDraft
  readonly errorFor: (path: string) => string | undefined
}) {
  const controller = useController()
  const tr = useT()
  const models = useSecurity(s => s.models)
  const providers = models.value ?? NO_PROVIDERS
  const fallback = modelRefOf(props.draft.models.default)

  return (
    <SettingsGroup title={tr.t('settings.models')} description={tr.t('settings.modelsDesc')}>
      {models.status === 'error' && models.error ? (
        <LoadError
          title={tr.t(models.value ? 'settings.modelsStale' : 'settings.modelsLoadFailed')}
          error={models.error}
          onRetry={() => void controller.loadModels(true)}
        />
      ) : null}
      {models.status === 'ready' && !providers.length ? (
        <Callout tone="warn">{tr.t('settings.noProviders')}</Callout>
      ) : null}
      {providers
        .filter(p => p.error)
        .map(p => (
          <Callout key={p.id} tone="warn" live={false}>
            {tr.t('settings.providerError', { provider: p.name || p.id, error: p.error ?? '' })}
          </Callout>
        ))}
      <div className="dshsec-roles">
        {MODEL_SLOTS.map(slot => (
          <ModelRoute
            key={slot}
            slot={slot}
            value={props.draft.models[slot]}
            providers={providers}
            fallbackLabel={fallback ? modelName(providers, fallback) : undefined}
            errorFor={props.errorFor}
          />
        ))}
      </div>
    </SettingsGroup>
  )
}

/** Option value for "inherit / not set" in the combined route select. */
const INHERIT = ''
const ROUTE_SEP = '\u0000'

function routeKey(provider: string, model: string): string {
  return provider ? `${provider}${ROUTE_SEP}${model}` : INHERIT
}

/**
 * One role: name and a one-line explanation on the left, a single model
 * select on the right (models grouped by provider). Unset roles say which
 * model they will use instead. Effort and output cap live under "Advanced".
 */
function ModelRoute(props: {
  readonly slot: ModelSlot
  readonly value: ModelDraft
  readonly providers: readonly ProviderOption[]
  readonly fallbackLabel: string | undefined
  readonly errorFor: (path: string) => string | undefined
}) {
  const controller = useController()
  const tr = useT()
  const { slot, value, providers } = props
  const selectId = useId()
  const descId = `${selectId}-desc`
  const provider = providers.find(p => p.id === value.provider)
  const model = asModels(provider).find(m => m.id === value.model)
  const efforts = Array.isArray(model?.reasoningEfforts) ? model.reasoningEfforts : []
  const set = (next: ModelDraft) => controller.updateDraft(d => ({ ...d, models: { ...d.models, [slot]: next } }))
  const isDefault = slot === 'default'
  const inherited = !isDefault && !value.provider
  const modelError = props.errorFor(`models.${slot}.model`)
  const outputError = props.errorFor(`models.${slot}.maxOutputTokens`)

  const groups: SelectGroup<string>[] = providers
    .filter(p => asModels(p).length)
    .map(p => ({
      label: p.name || p.id,
      options: asModels(p).map(m => ({ value: routeKey(p.id, m.id), label: m.name || m.id })),
    }))
  const current = routeKey(value.provider, value.model)
  const known = groups.some(g => g.options.some(o => o.value === current))
  if (value.provider && !known) {
    const name = value.model ? `${provider?.name || value.provider} · ${value.model}` : provider?.name || value.provider
    groups.push({
      label: tr.t('settings.unavailableGroup'),
      options: [{ value: current, label: tr.t('settings.unavailableModel', { name }) }],
    })
  }
  const first: SelectOption<string> = isDefault
    ? { value: INHERIT, label: tr.t('settings.noDefault') }
    : {
        value: INHERIT,
        label: props.fallbackLabel
          ? tr.t('settings.usesDefaultNamed', { model: props.fallbackLabel })
          : tr.t('settings.usesDefault'),
      }

  return (
    <div
      className={`dshsec-role${isDefault ? ' dshsec-role--default' : ''}${inherited ? ' is-inherited' : ''}`}
      data-slot={slot}
    >
      <div className="dshsec-role-text">
        <label className="dshsec-label" htmlFor={selectId}>
          {tr.t(`role.${slot}`)}
        </label>
        <p className="dshsec-hint" id={descId}>
          {tr.t(`role.${slot}.desc`)}
        </p>
      </div>
      <div className="dshsec-role-control">
        <Select
          id={selectId}
          value={current}
          options={[first]}
          groups={groups}
          describedBy={modelError ? `${descId} ${selectId}-error` : descId}
          invalid={Boolean(modelError)}
          onChange={key => {
            if (key === INHERIT) {
              set({ provider: '', model: '', reasoningEffort: '', maxOutputTokens: '' })
              return
            }
            const [providerId = '', modelId = ''] = key.split(ROUTE_SEP)
            set({
              provider: providerId,
              model: modelId,
              reasoningEffort: modelId === value.model && providerId === value.provider ? value.reasoningEffort : '',
              maxOutputTokens: value.maxOutputTokens,
            })
          }}
        />
        {modelError ? (
          <div className="dshsec-field-error" id={`${selectId}-error`}>
            {modelError}
          </div>
        ) : null}
        {value.provider ? (
          <details className="dshsec-advanced" open={Boolean(outputError) || undefined}>
            <summary>{tr.t('settings.advanced')}</summary>
            <div className="dshsec-advanced-body">
              {efforts.length ? (
                <Field label={tr.t('settings.effort')}>
                  {({ id }) => (
                    <Select
                      id={id}
                      value={value.reasoningEffort}
                      options={[
                        { value: '', label: tr.t('settings.effortDefault') },
                        ...efforts.map(e => ({ value: e.id, label: e.name || e.id })),
                      ]}
                      onChange={reasoningEffort => set({ ...value, reasoningEffort })}
                    />
                  )}
                </Field>
              ) : null}
              <NumberField
                label={tr.t('settings.maxOutput')}
                hint={tr.t('settings.maxOutputHint')}
                value={value.maxOutputTokens}
                range={{ min: 1, max: 1_000_000 }}
                error={outputError}
                onChange={maxOutputTokens => set({ ...value, maxOutputTokens })}
              />
            </div>
          </details>
        ) : null}
      </div>
    </div>
  )
}

function asModels(provider: ProviderOption | undefined): readonly ModelOption[] {
  return Array.isArray(provider?.models) ? provider.models : []
}

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

function BudgetsSection(props: {
  readonly draft: SettingsDraft
  readonly limits: OperatorLimits | undefined
  readonly errorFor: (path: string) => string | undefined
}) {
  const controller = useController()
  const tr = useT()
  return (
    <SettingsGroup title={tr.t('settings.budgets')} description={tr.t('settings.budgetsDesc')}>
      <div className="dshsec-budgets">
        {SCAN_MODES.map(mode => (
          <fieldset key={mode} className="dshsec-budget">
            <legend className="dshsec-role-name">{tr.t(`mode.${mode}`)}</legend>
            {BUDGET_FIELDS.map(field => (
              <NumberField
                key={field}
                label={tr.t(`budget.${field}`)}
                value={props.draft.budgets[mode][field]}
                range={budgetRange(field, props.limits)}
                error={props.errorFor(`budgets.${mode}.${field}`)}
                onChange={value =>
                  controller.updateDraft(d => ({
                    ...d,
                    budgets: { ...d.budgets, [mode]: { ...d.budgets[mode], [field]: value } },
                  }))
                }
              />
            ))}
          </fieldset>
        ))}
      </div>
    </SettingsGroup>
  )
}

// ---------------------------------------------------------------------------
// Toolkit
// ---------------------------------------------------------------------------

function sourceLabel(tr: Translator, status: AnalyzerStatus | undefined): string {
  return status ? (tr.lookup(`source.${status.source}`) ?? text(status.source)) : '—'
}

function ToolkitSection() {
  const controller = useController()
  const tr = useT()
  const toolkit = useSecurity(s => s.toolkit)
  const analyzers = useSecurity(s => s.bootstrap.value?.capabilities?.analyzers ?? NO_ANALYZERS)
  const builtins = analyzers.filter(
    a => a?.source === 'builtin' || ['secrets', 'sast', 'routes', 'dependencies', 'osv', 'ast-grep'].includes(a?.id),
  )
  const tools = toolkit.value ?? []

  return (
    <SettingsGroup title={tr.t('settings.toolkit')} description={tr.t('settings.toolkitDesc')}>
      {builtins.length ? (
        <div className="dshsec-stack-sm">
          <h3 className="dshsec-h4">{tr.t('settings.builtin')}</h3>
          <ul className="dshsec-analyzers">
            {builtins.map(a => (
              <li key={a.id}>
                <span className={`dshsec-dot ${a.available ? 'is-on' : 'is-off'}`} aria-hidden="true" />
                <span className="dshsec-analyzer-name">{tr.lookup(`analyzer.${a.id}`) ?? text(a.id)}</span>
                <div className="dshsec-muted">
                  {a.available ? tr.t('analyzer.available') : tr.t('analyzer.unavailable')}
                  {a.version ? ` · ${a.version}` : ''}
                  {!a.available ? ` — ${analyzerReasonText(tr, a)}` : ''}
                  {!a.available && a.reason ? (
                    <details>
                      <summary>{tr.t('diagnostic.details')}</summary>
                      <p>{a.reason}</p>
                    </details>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="dshsec-stack-sm">
        <h3 className="dshsec-h4">{tr.t('settings.external.tools')}</h3>
        {!toolkit.value && toolkit.status === 'error' && toolkit.error ? (
          <LoadError
            title={tr.t('settings.toolkitLoadFailed')}
            error={toolkit.error}
            onRetry={() => void controller.loadToolkit(true)}
          />
        ) : !toolkit.value ? (
          <Loading />
        ) : tools.length ? (
          <ul className="dshsec-tools">
            {tools.map(tool => (
              <ToolRow key={tool.id} tool={tool} />
            ))}
          </ul>
        ) : (
          <p className="dshsec-muted">{tr.t('toolkit.empty')}</p>
        )}
      </div>
    </SettingsGroup>
  )
}

/**
 * Running version and how to update by hand. Deliberately offline: no update
 * check, no request to GitHub; the user picks a release and installs it.
 */
function VersionSection() {
  const tr = useT()
  const version = useSecurity(s => s.bootstrap.value?.pluginVersion)
  return (
    <SettingsGroup title={tr.t('settings.version')} description={tr.t('settings.versionDesc')}>
      <dl className="dshsec-facts">
        <div>
          <dt>{tr.t('version.running')}</dt>
          <dd className="dshsec-mono" data-testid="dshsec-plugin-version">
            {text(version)}
          </dd>
        </div>
        <div>
          <dt>{tr.t('version.supported')}</dt>
          <dd className="dshsec-num">{SUPPORTED_DSH_RANGE}</dd>
        </div>
      </dl>
      <p>
        <a className="dshsec-link dshsec-link-icon" href={RELEASES_URL} target="_blank" rel="noopener noreferrer">
          {tr.t('version.releases')}
          <IconExternal size={12} />
        </a>
      </p>
      <div className="dshsec-stack-sm">
        <h3 className="dshsec-h4">{tr.t('version.manual')}</h3>
        <CopyLine label={tr.t('version.ui')} value={MANUAL_UPDATE_SPEC} />
        <CopyLine label={tr.t('version.cli')} value={MANUAL_UPDATE_CLI} />
        <p className="dshsec-hint">{tr.t('version.replace')}</p>
      </div>
    </SettingsGroup>
  )
}

function CopyLine(props: { readonly label: string; readonly value: string }) {
  const tr = useT()
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  useEffect(() => {
    if (state !== 'copied') return
    const timer = setTimeout(() => setState('idle'), COPIED_MS)
    return () => clearTimeout(timer)
  }, [state])
  const copy = async () => {
    setState((await copyText(props.value)) ? 'copied' : 'failed')
  }
  return (
    <div className="dshsec-copyline">
      <span className="dshsec-copyline-label">{props.label}</span>
      <div className="dshsec-copyline-row">
        <code className="dshsec-copyline-code dshsec-mono">{props.value}</code>
        <Button
          size="sm"
          variant="ghost"
          aria-label={tr.t('version.copyLabel', { what: props.value })}
          onClick={() => void copy()}
        >
          {state === 'copied' ? tr.t('common.copied') : tr.t('version.copy')}
        </Button>
      </div>
      <span className="dshsec-visually-hidden" role="status" aria-live="polite">
        {state === 'copied' ? tr.t('common.copied') : ''}
      </span>
      {state === 'failed' ? <p className="dshsec-hint">{tr.t('version.copyFailed')}</p> : null}
    </div>
  )
}

function ToolRow(props: { readonly tool: ToolkitEntry }) {
  const controller = useController()
  const tr = useT()
  const { tool } = props
  const [accepted, setAccepted] = useState(false)
  const [busy, setBusy] = useState(false)
  const [outcome, setOutcome] = useState<{ tone: 'success' | 'error'; text: string } | undefined>()
  const acceptId = useId()
  const status = tool.status
  const available = status?.available === true
  const version = tool.installed?.version ?? status?.version
  const installable = Boolean(tool.managed) && !tool.installed

  const install = async () => {
    setBusy(true)
    setOutcome(undefined)
    const result = await controller.installTool(tool.id)
    setBusy(false)
    setOutcome(
      result.ok
        ? { tone: 'success', text: tr.t('toolkit.installed') }
        : { tone: 'error', text: errorText(tr, result.error) },
    )
  }

  return (
    <li className="dshsec-tool">
      <div className="dshsec-tool-head">
        <span className={`dshsec-dot ${available ? 'is-on' : 'is-off'}`} aria-hidden="true" />
        <span className="dshsec-analyzer-name">
          {isSafeUrl(tool.homepage) ? (
            <a className="dshsec-link" href={tool.homepage} target="_blank" rel="noopener noreferrer">
              {text(tool.name)}
            </a>
          ) : (
            text(tool.name)
          )}
        </span>
        <Badge tone={available ? 'success' : 'quiet'}>
          {available ? tr.t('analyzer.available') : tr.t('analyzer.unavailable')}
        </Badge>
      </div>
      <div className="dshsec-tool-meta dshsec-muted">
        <span>{tr.t('toolkit.license', { license: text(tool.license) })}</span>
        {status && status.source !== 'disabled' ? <span>{sourceLabel(tr, status)}</span> : null}
        {version ? <span>{tr.t('toolkit.version', { version })}</span> : null}
      </div>
      {!available && status ? (
        <div className="dshsec-hint">
          <p>{analyzerReasonText(tr, status)}</p>
          {status.reason ? (
            <details>
              <summary>{tr.t('diagnostic.details')}</summary>
              <p>{status.reason}</p>
            </details>
          ) : null}
        </div>
      ) : null}
      {installable && tool.managed ? (
        <div className="dshsec-tool-install">
          <p className="dshsec-hint">
            {tr.t('toolkit.download')}: {tool.managed.version}
            {typeof tool.managed.sizeBytes === 'number'
              ? ` · ${formatNumber(Math.round(tool.managed.sizeBytes / 1024 / 1024), tr.intlLocale)} MB`
              : ''}
          </p>
          <label className="dshsec-check" htmlFor={acceptId}>
            <input id={acceptId} type="checkbox" checked={accepted} onChange={e => setAccepted(e.target.checked)} />
            <span>{tr.t('toolkit.accept', { name: text(tool.name), license: text(tool.license) })}</span>
          </label>
          <div>
            <Button size="sm" busy={busy} disabled={!accepted} onClick={() => void install()}>
              {busy ? tr.t('toolkit.installing') : tr.t('toolkit.install')}
            </Button>
          </div>
        </div>
      ) : !available && tool.installHint ? (
        <p className="dshsec-hint dshsec-install-hint">{tool.installHint}</p>
      ) : null}
      {outcome ? <Callout tone={outcome.tone}>{outcome.text}</Callout> : null}
    </li>
  )
}

function isSafeUrl(value: unknown): value is string {
  if (typeof value !== 'string') return false
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:'
  } catch {
    return false
  }
}
