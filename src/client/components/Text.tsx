import type { ReactNode } from 'react'
import type { CodeRef } from '../../shared/domain.ts'
import { DASH } from '../format.ts'

/**
 * Render untrusted multi-line text safely: blank lines split paragraphs,
 * single newlines become `<br>`. Never interprets HTML or Markdown.
 */
export function Paragraphs(props: { readonly text: unknown; readonly className?: string }) {
  const value = typeof props.text === 'string' ? props.text.trim() : ''
  if (!value) return <p className={props.className}>{DASH}</p>
  const paragraphs = value.split(/\n\s*\n/)
  return (
    <>
      {paragraphs.map((paragraph, i) => {
        const lines = paragraph.split('\n')
        return (
          // biome-ignore lint/suspicious/noArrayIndexKey: static text split; order never changes
          <p key={i} className={props.className}>
            {lines.map((line, j) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: static text split; order never changes
              <span key={j}>
                {j > 0 ? <br /> : null}
                {line}
              </span>
            ))}
          </p>
        )
      })}
    </>
  )
}

export function formatLocation(ref: CodeRef | undefined): string {
  if (!ref || typeof ref.path !== 'string') return DASH
  const start = Number.isFinite(ref.startLine) ? ref.startLine : undefined
  const end = Number.isFinite(ref.endLine) ? ref.endLine : start
  if (start === undefined) return ref.path
  return start === end || end === undefined ? `${ref.path}:${start}` : `${ref.path}:${start}-${end}`
}

/**
 * Source excerpt with line numbers taken from the cited location. Long lines
 * wrap under their own text (the line number column stays put), so nothing
 * is hidden past the right edge of a narrow pane.
 */
export function CodeBlock(props: {
  readonly snippet: string
  readonly location?: CodeRef | undefined
  readonly label?: string
  /** Shown at the end of the caption, e.g. the host's quote check. */
  readonly aside?: ReactNode
}) {
  const lines = props.snippet.replace(/\n$/, '').split('\n')
  const start = props.location && Number.isFinite(props.location.startLine) ? Math.max(1, props.location.startLine) : 1
  const width = String(start + lines.length - 1).length
  return (
    <figure className="dshsec-code">
      {props.location || props.aside ? (
        <figcaption className="dshsec-code-path">
          <span>{props.location ? formatLocation(props.location) : null}</span>
          {props.aside}
        </figcaption>
      ) : null}
      <pre title={props.label}>
        <code>
          {lines.map((line, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: lines are positional
            <span className="dshsec-code-line" key={i}>
              <span className="dshsec-code-ln" aria-hidden="true">
                {String(start + i).padStart(width, ' ')}
              </span>
              <span className="dshsec-code-src">{line || ' '}</span>
            </span>
          ))}
        </code>
      </pre>
    </figure>
  )
}
