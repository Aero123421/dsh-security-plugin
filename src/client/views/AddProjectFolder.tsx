import { useEffect, useRef, useState } from 'react'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import type { MessageKey } from '../i18n.ts'
import { IconFolderPlus } from '../icons.tsx'
import { DirectoryBrowser } from './DirectoryBrowser.tsx'

/**
 * Optional DSH folder-registration front door: an icon button next to the
 * page's project picker, or a text button in forms and empty states.
 */
export function AddProjectFolder(props: {
  readonly onAdded: (workspaceId: string) => void
  readonly disabled?: boolean
  readonly variant?: 'icon' | 'link' | 'button'
}) {
  const controller = useController()
  const tr = useT()
  const adding = useSecurity(s => s.addingProject)
  const connectionGeneration = useSecurity(s => s.connectionGeneration)
  const [error, setError] = useState<MessageKey>()
  const [browsing, setBrowsing] = useState(false)
  const button = useRef<HTMLButtonElement>(null)
  const pending = useRef<AbortController>()

  useEffect(() => () => pending.current?.abort(), [])
  useEffect(() => {
    void connectionGeneration
    pending.current?.abort()
    pending.current = undefined
    setBrowsing(false)
    setError(undefined)
  }, [connectionGeneration])

  if (!controller.canAddProject()) return null

  const add = async (path?: string) => {
    if (adding || props.disabled || pending.current) return
    // Keep the opener focused across the native picker; Modal restores it on close.
    button.current?.focus()
    const abort = new AbortController()
    pending.current = abort
    setError(undefined)
    const result = await controller.addProjectFolder(abort.signal, path)
    if (abort.signal.aborted) return
    pending.current = undefined
    if (result && 'error' in result) setError(result.error)
    else if (result) {
      setBrowsing(false)
      props.onAdded(result.workspaceId)
    }
  }

  const open = () => {
    setError(undefined)
    if (controller.canBrowseProjectFolders()) setBrowsing(true)
    else void add()
  }
  const variant = props.variant ?? 'link'

  return (
    <div className={`dshsec-add-project dshsec-add-project--${variant}`}>
      {variant === 'icon' ? (
        <button
          ref={button}
          type="button"
          className="dshsec-iconbtn"
          disabled={props.disabled}
          aria-disabled={adding || undefined}
          aria-busy={adding || undefined}
          aria-label={tr.t('project.add')}
          title={tr.t('project.add')}
          onClick={open}
        >
          <IconFolderPlus size={18} />
        </button>
      ) : (
        <Button
          ref={button}
          size="sm"
          variant={variant === 'button' ? 'secondary' : 'link'}
          icon={variant === 'button' ? <IconFolderPlus size={16} /> : undefined}
          disabled={props.disabled}
          aria-disabled={adding || undefined}
          aria-busy={adding || undefined}
          onClick={open}
        >
          {tr.t('project.add')}
        </Button>
      )}
      {error ? <Callout tone="error">{tr.t(error)}</Callout> : null}
      {browsing ? (
        <DirectoryBrowser
          busy={adding}
          error={error}
          onClose={() => {
            if (!adding) setBrowsing(false)
          }}
          onPick={path => void add(path)}
          onNative={() => {
            setBrowsing(false)
            void add()
          }}
        />
      ) : null}
    </div>
  )
}
