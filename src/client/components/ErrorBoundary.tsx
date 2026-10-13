import { Component, type ReactNode } from 'react'

/**
 * Last line of defense against unexpected Host data: a render error inside
 * one tab shows a recoverable message instead of blanking DSH's main area.
 */
export class ErrorBoundary extends Component<
  { readonly fallback: (reset: () => void) => ReactNode; readonly resetKey?: unknown; readonly children: ReactNode },
  { readonly failed: boolean; readonly key: unknown }
> {
  override state = { failed: false, key: this.props.resetKey }

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true }
  }

  static getDerivedStateFromProps(
    props: { readonly resetKey?: unknown },
    state: { readonly failed: boolean; readonly key: unknown },
  ): { failed: boolean; key: unknown } | null {
    return Object.is(props.resetKey, state.key) ? null : { failed: false, key: props.resetKey }
  }

  override componentDidCatch(error: unknown): void {
    console.error('[dsh-security] view failed to render', error)
  }

  override render(): ReactNode {
    if (this.state.failed) return this.props.fallback(() => this.setState({ failed: false }))
    return this.props.children
  }
}
