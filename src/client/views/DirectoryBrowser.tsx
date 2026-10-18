import { useEffect, useRef, useState } from 'react'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { Field, Toggle } from '../components/Field.tsx'
import { Modal } from '../components/Modal.tsx'
import { useController, useT } from '../context.tsx'
import type { DshDirectoryListing } from '../dsh.ts'
import type { MessageKey } from '../i18n.ts'

/** Uses DSH's public Host-directory API; paths are never joined in the browser. */
export function DirectoryBrowser(props: {
  readonly busy: boolean
  readonly error?: MessageKey
  readonly onClose: () => void
  readonly onPick: (path: string) => void
  readonly onNative: () => void
}) {
  const controller = useController()
  const tr = useT()
  const [request, setRequest] = useState<{ path?: string; seq: number }>({ seq: 0 })
  const [listing, setListing] = useState<DshDirectoryListing>()
  const [path, setPath] = useState('')
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [hidden, setHidden] = useState(false)
  const [limit, setLimit] = useState(200)
  const native = useRef(props.onNative)
  native.current = props.onNative
  useEffect(() => {
    const abort = new AbortController()
    setLoading(true)
    setFailed(false)
    void controller.listProjectFolders(request.path, abort.signal).then(
      result => {
        if (abort.signal.aborted) return
        setListing(result)
        setPath(result.path)
        setLimit(200)
        setLoading(false)
      },
      error => {
        if (abort.signal.aborted) return
        const capability = (error as { rpcError?: { details?: { capability?: string } } })?.rpcError?.details
          ?.capability
        if (capability === 'native' && controller.host.uiWorkspace()?.pickDirectory) {
          native.current()
          return
        }
        setLoading(false)
        setFailed(true)
      },
    )
    return () => abort.abort()
  }, [controller, request])
  const navigate = (next?: string) => setRequest(r => ({ path: next, seq: r.seq + 1 }))
  const entries = listing?.entries.filter(entry => hidden || !entry.hidden) ?? []
  return (
    <Modal
      title={tr.t('project.chooseFolder')}
      size="md"
      onClose={props.onClose}
      dismissible={!props.busy}
      footer={
        <>
          <Button disabled={props.busy} onClick={props.onClose}>
            {tr.t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            busy={props.busy}
            disabled={loading || failed || !listing}
            onClick={() => {
              if (listing) props.onPick(listing.path)
            }}
          >
            {tr.t('project.useFolder')}
          </Button>
        </>
      }
    >
      <div className="dshsec-stack">
        <p className="dshsec-hint">{tr.t('project.hostFolder')}</p>
        <form
          className="dshsec-stack-sm"
          onSubmit={event => {
            event.preventDefault()
            if (!props.busy) navigate(path || undefined)
          }}
        >
          <Field label={tr.t('project.folderPath')}>
            {({ id }) => (
              <input
                className="dshsec-input"
                id={id}
                value={path}
                disabled={props.busy}
                onChange={event => setPath(event.target.value)}
              />
            )}
          </Field>
          <div>
            <Button type="submit" disabled={props.busy} busy={loading}>
              {tr.t('project.openFolder')}
            </Button>
          </div>
        </form>
        {failed ? <Callout tone="error">{tr.t('project.browseFailed')}</Callout> : null}
        {props.error ? <Callout tone="error">{tr.t(props.error)}</Callout> : null}
        {listing && !failed ? (
          <>
            <nav className="dshsec-actions dshsec-directory-crumbs" aria-label={tr.t('project.folderPath')}>
              {listing.crumbs.map(crumb => (
                <Button
                  key={crumb.path}
                  size="sm"
                  variant="link"
                  disabled={props.busy || loading}
                  onClick={() => navigate(crumb.path)}
                >
                  {crumb.name}
                </Button>
              ))}
            </nav>
            <Toggle label={tr.t('project.showHidden')} checked={hidden} onChange={setHidden} disabled={props.busy} />
            <ul className="dshsec-directory-list" aria-busy={loading} aria-label={tr.t('project.folders')}>
              {entries.slice(0, limit).map(entry => (
                <li key={entry.path}>
                  <Button variant="ghost" disabled={props.busy || loading} onClick={() => navigate(entry.path)}>
                    {entry.name}
                  </Button>
                </li>
              ))}
            </ul>
            {entries.length > limit ? (
              <Button size="sm" onClick={() => setLimit(n => n + 200)}>
                {tr.t('project.moreFolders')}
              </Button>
            ) : null}
            {listing.truncated ? <p className="dshsec-hint">{tr.t('project.foldersTruncated')}</p> : null}
          </>
        ) : null}
      </div>
    </Modal>
  )
}
