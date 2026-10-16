/**
 * Structural views of the DSH Host services this plugin uses. They mirror the
 * published DSH types (`@deepseek-ai/dsh-llm`, `@deepseek-ai/dsh-client-connection`,
 * `@deepseek-ai/dsh-workspace`) closely enough that the real services are
 * assignable to them; `tests/host/dsh-conformance.test.ts` checks that against
 * the DSH version pinned in devDependencies. Depending on these small views
 * instead of the full DSH type graph keeps the plugin buildable on its own and
 * lets tests substitute fakes.
 */

// ---------------------------------------------------------------------------
// LLM registry (`ctx.llm`)
// ---------------------------------------------------------------------------

export interface LlmTextBlock {
  type: 'text'
  text: string
}
export interface LlmReasoningBlock {
  type: 'reasoning'
  text: string
}
export interface LlmToolCallBlock {
  type: 'tool-call'
  id: string
  name: string
  /** Raw JSON string as produced by the model. */
  arguments: string
}
/** Content blocks this plugin produces or reads. Unknown block types are preserved opaquely. */
export type LlmContentBlock = LlmTextBlock | LlmReasoningBlock | LlmToolCallBlock | { type: string }

export interface LlmFailure {
  readonly message: string
  readonly code: string
  readonly status?: number
  readonly providerRetryAfterMs?: number
}

export interface LlmTokenUsage {
  inputTokens: number
  outputTokens: number
  totalTokens?: number
  cacheReadTokens?: number
  cacheWriteTokens?: number
  reasoningTokens?: number
}

export type LlmFinishReason =
  | { kind: 'stop' }
  | { kind: 'tool-calls' }
  | { kind: 'max-tokens' }
  | { kind: 'aborted'; failure: LlmFailure }
  | { kind: 'error'; failure: LlmFailure }
  | { kind: string; failure?: LlmFailure }

export type LlmStreamChunk =
  | { type: 'block-start'; index: number; blockType: string }
  | { type: 'text-delta'; index: number; text: string }
  | { type: 'reasoning-delta'; index: number; text: string }
  | { type: 'tool-call-delta'; index: number; id: string; name?: string; argumentsDelta: string }
  | { type: 'block-end'; index: number; block: LlmContentBlock }
  | { type: 'usage'; usage: LlmTokenUsage }
  | { type: 'finish'; reason: LlmFinishReason; replayState?: unknown }

export interface LlmToolSchema {
  name: string
  description: string
  /** JSON Schema object for the arguments. */
  parameters: Record<string, unknown>
}

/** Messages accepted by `GenerateOptions.messages` (durable shapes, built by hand). */
export interface LlmUserInput {
  readonly role: 'user'
  readonly content: readonly LlmContentBlock[]
}
export interface LlmAssistantMessage {
  readonly id: string
  readonly role: 'assistant'
  readonly content: readonly LlmContentBlock[]
  readonly source: {
    readonly kind: 'model'
    readonly provider: string
    readonly model: string
    readonly replayState?: unknown
  }
}
export interface LlmToolResultMessage {
  readonly id: string
  readonly role: 'tool'
  readonly content: readonly LlmContentBlock[]
  readonly source: { readonly kind: 'tool'; readonly callId: string }
  readonly toolCallId: string
  readonly isError?: boolean
}
export type LlmRequestMessage = LlmUserInput | LlmAssistantMessage | LlmToolResultMessage

export interface LlmGenerateOptions {
  provider: string
  model: string
  /** Per-conversation identity for request routing / transport metadata; required by some providers (e.g. OpenCode). */
  sessionId?: string
  reasoningEffort?: string
  messages: LlmRequestMessage[]
  system?: string
  tools?: LlmToolSchema[]
  temperature?: number
  maxTokens?: number
  signal?: AbortSignal
}

export interface LlmProviderInfo {
  id: string
  name: string
}

export interface LlmModelInfo {
  provider: string
  id: string
  name: string
  description?: string
}

export interface LlmResolvedModelInfo extends LlmModelInfo {
  context?: { contextWindow: number }
  defaultMaxTokens?: number
  reasoning?: {
    efforts: readonly { id: string; name: string; description?: string }[]
    defaultEffort?: string
  }
}

/** The subset of DSH `LlmRuntime` this plugin calls. */
export interface LlmPort {
  listProviders(): LlmProviderInfo[]
  listModels(provider: string): Promise<LlmModelInfo[]>
  resolveModelInfo(provider: string, model: string, signal?: AbortSignal): Promise<LlmResolvedModelInfo>
  stream(options: LlmGenerateOptions): AsyncIterable<LlmStreamChunk>
}

// ---------------------------------------------------------------------------
// Connection exact Fetch routes (`ctx.connection.fetch`)
// ---------------------------------------------------------------------------

export interface ConnectionFetchRoute {
  /** Absolute path below `/api`. */
  readonly path: string
  readonly methods: readonly ('GET' | 'HEAD' | 'POST')[]
  readonly requestBody: 'buffered' | 'streaming'
  readonly fetch: (request: Request) => Promise<Response>
}

export interface ConnectionPort {
  readonly fetch: { register(route: ConnectionFetchRoute): () => Promise<void> }
}

// ---------------------------------------------------------------------------
// Workspace registry (`ctx.workspaceRegistry`)
// ---------------------------------------------------------------------------

export interface WorkspaceEntity {
  readonly id: string
  readonly path: string
  readonly title: string
}

export interface WorkspaceRegistryPort {
  list(): readonly WorkspaceEntity[]
  get(id: string): WorkspaceEntity | undefined
}

// ---------------------------------------------------------------------------
// Logger (`ctx.logger`)
// ---------------------------------------------------------------------------

export interface LoggerPort {
  debug(...args: unknown[]): void
  info(...args: unknown[]): void
  warn(...args: unknown[]): void
  error(...args: unknown[]): void
}
