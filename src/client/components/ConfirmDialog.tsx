import { useId, useRef, useState } from 'react'
import type { RpcResult } from '../../shared/contracts.ts'
import { useT } from '../context.tsx'
import { errorText } from '../i18n.ts'
import { Button } from './Button.tsx'
import { Callout } from './Callout.tsx'
import { Modal } from './Modal.tsx'

/** Confirmation for destructive actions. Focus starts on the safe choice. */
export function ConfirmDialog(props: {
  readonly title: string
  readonly body: string
  readonly confirmLabel: string
  readonly cancelLabel?: string
  readonly onConfirm: () => Promise<RpcResult<unknown>>
  readonly onClose: () => void
}) {
  const tr = useT()
  const bodyId = useId()
  const cancelRef = useRef<HTMLButtonElement>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ code: string; message: string } | undefined>()

  const confirm = async () => {
    setBusy(true)
    setError(undefined)
    const result = await props.onConfirm()
    setBusy(false)
    if (result.ok) props.onClose()
    else setError(result.error)
  }

  return (
    <Modal
      title={props.title}
      onClose={props.onClose}
      dismissible={!busy}
      size="sm"
      role="alertdialog"
      describedBy={bodyId}
      initialFocusRef={cancelRef}
      footer={
        <>
          <Button ref={cancelRef} disabled={busy} onClick={props.onClose}>
            {props.cancelLabel ?? tr.t('common.cancel')}
          </Button>
          <Button variant="danger" busy={busy} onClick={() => void confirm()}>
            {props.confirmLabel}
          </Button>
        </>
      }
    >
      <p id={bodyId} className="dshsec-muted">
        {props.body}
      </p>
      {error ? <Callout tone="error">{errorText(tr, error)}</Callout> : null}
    </Modal>
  )
}
