import { useEffect, useMemo, useState } from 'react'
import type { ScanSummary } from '../shared/contracts.ts'
import { useController, useSecurity } from './context.tsx'
import type { Loadable } from './controller.ts'

const EMPTY_SCANS: readonly ScanSummary[] = []
const IDLE: Loadable<readonly ScanSummary[]> = { status: 'idle' }

/** Scan list of the selected workspace (stable reference between unrelated updates). */
export function useWorkspaceScans(): {
  readonly entry: Loadable<readonly ScanSummary[]>
  readonly scans: readonly ScanSummary[]
} {
  const entry = useSecurity(s => (s.workspaceId ? (s.scans[s.workspaceId] ?? IDLE) : IDLE))
  return useMemo(() => ({ entry, scans: entry.value ?? EMPTY_SCANS }), [entry])
}

/** Whether the page can scan at all, and why not. */
export function useScanAvailability(): 'loading' | 'unsupported' | 'no-workspaces' | 'ready' {
  const capability = useSecurity(s => s.bootstrap.value?.capabilities?.workspaces)
  const workspaces = useSecurity(s => s.workspaces)
  if (capability === false) return 'unsupported'
  if (workspaces.status === 'ready' && !(workspaces.value?.length ?? 0)) return 'no-workspaces'
  if (!workspaces.value) return 'loading'
  return 'ready'
}

/** Keep a scan's detail polled while the component is mounted. */
export function useWatchScan(scanId: string | undefined, enabled: boolean): void {
  const controller = useController()
  useEffect(() => {
    if (!scanId || !enabled) return
    return controller.watchScan(scanId)
  }, [controller, scanId, enabled])
}

/** Re-render every `ms` so relative times stay fresh. */
export function useNow(ms = 30_000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(timer)
  }, [ms])
  return now
}

/**
 * Track an element's content width with ResizeObserver (falls back to the
 * window width where ResizeObserver is missing). Returns a callback ref.
 */
export function useElementWidth<E extends HTMLElement>(): [(el: E | null) => void, number] {
  const [el, setEl] = useState<E | null>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    if (!el) return
    const measure = () => setWidth(el.getBoundingClientRect().width || 0)
    measure()
    if (typeof ResizeObserver === 'function') {
      const observer = new ResizeObserver(measure)
      observer.observe(el)
      return () => observer.disconnect()
    }
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [el])
  return [setEl, width]
}
