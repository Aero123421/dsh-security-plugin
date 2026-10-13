// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { marked } from 'marked'

interface Props {
  /** Markdown written by any project member in the project settings form. */
  description: string
}

export function ProjectDescription({ description }: Props) {
  const html = marked.parse(description, { async: false }) as string
  return <section className="prose max-w-none" dangerouslySetInnerHTML={{ __html: html }} />
}
