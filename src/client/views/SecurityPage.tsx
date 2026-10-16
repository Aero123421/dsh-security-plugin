import { useEffect, useMemo } from 'react'
import type { WorkspaceSummary } from '../../shared/contracts.ts'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { ErrorBoundary } from '../components/ErrorBoundary.tsx'
import { ProjectSelect } from '../components/ProjectSelect.tsx'
import { Tabs, tabPanelProps } from '../components/Tabs.tsx'
import { ControllerProvider, PageWidthContext, useController, useSecurity, useT } from '../context.tsx'
import { TAB_IDS, type SecurityController, type TabId } from '../controller.ts'
import { useElementWidth } from '../hooks.ts'
import { errorText } from '../i18n.ts'
import { IconPlus, IconRefresh } from '../icons.tsx'
import { AddProjectFolder } from './AddProjectFolder.tsx'
import { FindingsView, SPLIT_MIN_WIDTH } from './Findings.tsx'
import { HistoryView } from './History.tsx'
import { NewScanDialog } from './NewScanDialog.tsx'
import { OverviewView } from './Overview.tsx'
import { SettingsPanel } from './Settings.tsx'
import { RenderFailure } from './shared.tsx'

const ID_PREFIX = 'dshsec-main'
const EMPTY_WORKSPACES: readonly WorkspaceSummary[] = []

/** Main-area panel registered in DSH's `main` slot. */
export function SecurityPage(props: { readonly controller: SecurityController }) {
  return (
    <ControllerProvider controller={props.controller}>
      <PageFrame />
    </ControllerProvider>
  )
}

function PageFrame() {
  const controller = useController()
  const tr = useT()
  const tab = useSecurity(s => s.tab)
  const language = useSecurity(s => s.language)
  const newScan = useSecurity(s => s.newScan)
  const [pageRef, width] = useElementWidth<HTMLDivElement>()
  const split = tab === 'findings' && width >= SPLIT_MIN_WIDTH

  useEffect(() => {
    // DSH unmounts the panel when another one is shown; pick up scans started elsewhere.
    controller.revalidate()
  }, [controller])

  const tabs = useMemo(() => TAB_IDS.map(id => ({ id, label: tr.t(`tab.${id}`) })), [tr])

  return (
    <PageWidthContext.Provider value={width}>
      <div className={`dshsec-root dshsec-page${split ? ' dshsec-page--split' : ''}`} lang={language} ref={pageRef}>
        <div className="dshsec-scroll">
          <div className="dshsec-column">
            <ErrorBoundary fallback={reset => <RenderFailure onRetry={reset} />}>
              <PageHeader />
              <GlobalBanners />
            </ErrorBoundary>
            <Tabs<TabId>
              idPrefix={ID_PREFIX}
              label={tr.t('page.sections')}
              items={tabs}
              value={tab}
              onChange={controller.setTab}
            />
            <div className="dshsec-tabpanel" {...tabPanelProps(ID_PREFIX, tab)}>
              <ErrorBoundary resetKey={tab} fallback={reset => <RenderFailure onRetry={reset} />}>
                <TabBody tab={tab} />
              </ErrorBoundary>
            </div>
          </div>
        </div>
        {newScan ? (
          <ErrorBoundary
            fallback={() => <RenderFailure onRetry={controller.closeNewScan} retryLabel={tr.t('common.close')} />}
          >
            <NewScanDialog request={newScan} />
          </ErrorBoundary>
        ) : null}
      </div>
    </PageWidthContext.Provider>
  )
}

function TabBody(props: { readonly tab: TabId }) {
  switch (props.tab) {
    case 'overview':
      return <OverviewView />
    case 'findings':
      return <FindingsView />
    case 'history':
      return <HistoryView />
    case 'settings':
      return <SettingsPanel />
  }
}

function PageHeader() {
  const controller = useController()
  const tr = useT()
  const workspaces = useSecurity(s => s.workspaces.value ?? EMPTY_WORKSPACES)
  const workspaceId = useSecurity(s => s.workspaceId)
  const canScan = useSecurity(s => s.bootstrap.value?.capabilities?.workspaces !== false)

  return (
    <header className="dshsec-head">
      <h1 className="dshsec-title">{tr.t('page.title')}</h1>
      <Button
        variant="primary"
        icon={<IconPlus size={16} />}
        disabled={!canScan || !workspaces.length}
        onClick={() => controller.openNewScan({ ...(workspaceId ? { workspaceId } : {}) })}
      >
        {tr.t('page.newScan')}
      </Button>
      <div className="dshsec-head-project">
        {workspaces.length ? (
          <ProjectPicker workspaces={workspaces} value={workspaceId} onChange={controller.selectWorkspace} />
        ) : null}
        <AddProjectFolder onAdded={id => controller.openNewScan({ workspaceId: id })} showHint />
      </div>
    </header>
  )
}

/** The current project as a quiet line, with a themed listbox when there is a choice. */
export function ProjectPicker(props: {
  readonly workspaces: readonly WorkspaceSummary[]
  readonly value: string | undefined
  readonly onChange: (workspaceId: string) => void
}) {
  const tr = useT()
  return <ProjectSelect {...props} variant="quiet" ariaLabel={tr.t('page.workspace')} />
}

function GlobalBanners() {
  const controller = useController()
  const tr = useT()
  const bootstrap = useSecurity(s => s.bootstrap)
  const workspaces = useSecurity(s => s.workspaces)
  const flash = useSecurity(s => s.flash)
  const mismatch = useSecurity(() => controller.contractMismatch())

  const loadError =
    (bootstrap.status === 'error' && bootstrap.error) ||
    (workspaces.status === 'error' && workspaces.error) ||
    undefined

  return (
    <div className="dshsec-banners">
      {mismatch ? (
        <Callout
          tone="warn"
          action={
            <Button size="sm" onClick={() => window.location.reload()}>
              {tr.t('banner.reload')}
            </Button>
          }
        >
          {tr.t('banner.contract')}
        </Callout>
      ) : null}
      {loadError ? (
        <Callout
          tone="error"
          title={tr.t('state.loadFailed')}
          action={
            <Button size="sm" icon={<IconRefresh size={14} />} onClick={() => void controller.reload()}>
              {tr.t('common.retry')}
            </Button>
          }
        >
          {errorText(tr, loadError)}
        </Callout>
      ) : null}
      {flash ? (
        <Callout
          tone={flash.tone}
          action={
            <Button size="sm" variant="ghost" onClick={controller.dismissFlash}>
              {tr.t('common.dismiss')}
            </Button>
          }
        >
          {'key' in flash ? tr.t(flash.key) : errorText(tr, flash.error)}
        </Callout>
      ) : null}
    </div>
  )
}
