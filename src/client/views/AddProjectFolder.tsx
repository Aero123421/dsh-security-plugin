import { useEffect, useId, useRef, useState } from 'react'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import type { MessageKey } from '../i18n.ts'

/** Optional DSH folder-registration front door, shared by the header and scan form. */
export function AddProjectFolder(props: {
  readonly onAdded: (workspaceId: string) => void
  readonly disabled?: boolean
  readonly showHint?: boolean
}) {
  const controller = useController()
  const tr = useT()
  const adding = useSecurity(s => s.addingProject)
  const [error, setError] = useState<MessageKey>()
  const button = useRef<HTMLButtonElement>(null)
  const pending = useRef<AbortController>()
  const hintId = useId()

  useEffect(() => () => pending.current?.abort(), [])

  if (!controller.canAddProject()) return null

  const add = async () => {
    if (adding || props.disabled) return
    // Keep the opener focused across the native picker; Modal restores it on close.
    button.current?.focus()
    const abort = new AbortController()
    pending.current = abort
    setError(undefined)
    const result = await controller.addProjectFolder(abort.signal)
    if (abort.signal.aborted) return
    pending.current = undefined
    button.current?.focus()
    if (result && 'error' in result) setError(result.error)
    else if (result) props.onAdded(result.workspaceId)
  }

  return (
    <div className="dshsec-add-project">
      <Button
        ref={button}
        size="sm"
        variant="link"
        disabled={props.disabled}
        aria-disabled={adding || undefined}
        aria-busy={adding || undefined}
        aria-describedby={props.showHint ? hintId : undefined}
        title={tr.t('project.addHint')}
        onClick={() => void add()}
      >
        {tr.t('project.add')}
      </Button>
      {props.showHint ? (
        <p className="dshsec-hint" id={hintId}>
          {tr.t('project.addHint')}
        </p>
      ) : null}
      {error ? <Callout tone="error">{tr.t(error)}</Callout> : null}
    </div>
  )
}
