import { act, type ReactElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import type {
  Bootstrap,
  FindingDetail,
  FindingSummary,
  RpcMethodName,
  RpcRequest,
  RpcResponse,
  RpcResult,
  ScanDetail,
  ScanSummary,
} from '../../src/shared/contracts.ts'
import { CONTRACT_VERSION } from '../../src/shared/contracts.ts'
import { DEFAULT_SETTINGS, type SecuritySettings } from '../../src/shared/settings.ts'
import type { SecurityApi } from '../../src/client/api.ts'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

type Handler<M extends RpcMethodName> = (
  payload: RpcRequest<M>,
) => RpcResult<RpcResponse<M>> | Promise<RpcResult<RpcResponse<M>>>

export type Handlers = { [M in RpcMethodName]?: Handler<M> }

export interface FakeApi extends SecurityApi {
  readonly calls: { method: RpcMethodName; payload: unknown }[]
  handlers: Handlers
  callsOf(method: RpcMethodName): unknown[]
}

export function ok<T>(value: T): RpcResult<T> {
  return { ok: true, value }
}

export function fail(code: string, message = code): RpcResult<never> {
  return { ok: false, error: { code, message, details: {} } }
}

/** Fake API: records every call; unhandled methods fail with `security/not-found`. */
export function fakeApi(handlers: Handlers = {}): FakeApi {
  const api: FakeApi = {
    calls: [],
    handlers,
    callsOf(method) {
      return api.calls.filter(c => c.method === method).map(c => c.payload)
    },
    async call(method, payload) {
      api.calls.push({ method, payload })
      const handler = api.handlers[method] as Handler<typeof method> | undefined
      if (!handler) return fail('security/not-found', `no handler for ${method}`) as never
      return (await handler(payload)) as never
    },
  }
  return api
}

export function makeSettings(overrides: Partial<SecuritySettings> = {}): SecuritySettings {
  return { ...DEFAULT_SETTINGS, ...overrides }
}

export function makeBootstrap(overrides: Partial<Bootstrap> = {}): Bootstrap {
  return {
    pluginVersion: '0.1.0',
    contractVersion: CONTRACT_VERSION,
    settings: makeSettings(),
    settingsRevision: 1,
    loopback: true,
    canEditHighRiskSettings: true,
    capabilities: { llm: true, workspaces: true, analyzers: [] },
    limits: {
      maxParallelWorkers: 4,
      maxConcurrentScans: 1,
      maxFiles: 10_000,
      maxFileBytes: 1_000_000,
      maxTotalBytes: 100_000_000,
      maxTokensPerScan: 20_000_000,
      maxLlmCallsPerScan: 2000,
    },
    ...overrides,
  }
}

export function makeScan(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    id: 'scan-1',
    workspaceId: 'ws-1',
    workspaceTitle: 'Demo',
    mode: 'deep',
    status: 'completed',
    phase: 'done',
    createdAt: '2026-10-01T10:00:00.000Z',
    startedAt: '2026-10-01T10:00:01.000Z',
    finishedAt: '2026-10-01T10:20:00.000Z',
    counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    confirmed: 1,
    ...overrides,
  }
}

export function makeDetail(summary: Partial<ScanSummary> = {}, overrides: Partial<ScanDetail> = {}): ScanDetail {
  return {
    summary: makeScan(summary),
    phases: [],
    usage: { llmCalls: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0, elapsedMs: 0 },
    budget: { maxLlmCalls: 300, maxTokens: 3_000_000, maxMinutes: 60 },
    workers: [],
    notices: [],
    models: {},
    ...overrides,
  }
}

export function makeFinding(overrides: Partial<FindingSummary> = {}): FindingSummary {
  return {
    id: 'f-1',
    scanId: 'scan-1',
    fingerprint: 'fp-1',
    title: 'SQL injection in /users',
    category: 'injection',
    severity: 'high',
    verification: 'strong_static_evidence',
    closure: 'confirmed',
    source: 'ai',
    location: { path: 'src/users.ts', startLine: 10, endLine: 12 },
    summary: 'User input reaches a SQL query.',
    triage: 'open',
    isNew: false,
    ...overrides,
  }
}

export function makeFindingDetail(overrides: Partial<FindingDetail> = {}): FindingDetail {
  return {
    ...makeFinding(),
    cwe: 'CWE-89',
    impact: 'An attacker can read the database.',
    preconditions: ['The endpoint is public'],
    attackPath: [
      {
        order: 1,
        description: 'Request reaches the handler.',
        location: { path: 'src/users.ts', startLine: 10, endLine: 11 },
        snippet: ['const q = req.query.id', 'db.query("SELECT * FROM u WHERE id=" + q)'].join('\n'),
        quoteCheck: 'match',
      },
      {
        order: 2,
        description: 'Query runs.',
        quoteCheck: 'mismatch',
        snippet: 'run()',
        location: { path: 'src/db.ts', startLine: 3, endLine: 3 },
      },
    ],
    recommendation: 'Use parameters.\n\nSee the docs.',
    evidence: [],
    counterevidence: [],
    review: { verdict: 'confirmed', reasoning: 'No sanitizer.', model: 'deepseek-chat' },
    limitations: ['Deployment unknown'],
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
    createdBy: { role: 'hunter', model: 'deepseek-chat' },
    ...overrides,
  }
}

export interface Mounted {
  readonly container: HTMLElement
  readonly root: Root
  rerender(element: ReactElement): void
  unmount(): void
}

export function mount(element: ReactElement): Mounted {
  const container = document.createElement('div')
  document.body.append(container)
  const root = createRoot(container)
  act(() => root.render(element))
  return {
    container,
    root,
    rerender(next) {
      act(() => root.render(next))
    },
    unmount() {
      act(() => root.unmount())
      container.remove()
    },
  }
}

/** Let pending promises (and the React updates they cause) settle. */
export async function flush(times = 5): Promise<void> {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await Promise.resolve()
    })
  }
}

export async function click(el: Element | null | undefined): Promise<void> {
  if (!el) throw new Error('click: element not found')
  await act(async () => {
    ;(el as HTMLElement).click()
  })
  await flush()
}

export function byText<E extends Element = HTMLElement>(root: ParentNode, selector: string, text: string | RegExp): E {
  const match = [...root.querySelectorAll<E>(selector)].find(el =>
    typeof text === 'string' ? el.textContent?.includes(text) : text.test(el.textContent ?? ''),
  )
  if (!match) throw new Error(`no ${selector} with text ${String(text)}`)
  return match
}
