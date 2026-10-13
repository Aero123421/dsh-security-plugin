/**
 * Compile-time conformance of the structural DSH ports in
 * `src/host/dsh/ports.ts` against the real DSH types pinned in
 * devDependencies (`@deepseek-ai/dsh-llm`, `@deepseek-ai/dsh-client-connection`,
 * `@deepseek-ai/dsh-workspace` 0.2.1-alpha.2, `@deepseek-ai/cordis` 4.0.5-alpha.1).
 *
 * The assertions are types: they are enforced by
 * `pnpm exec tsc -p tsconfig.test.json --noEmit` (part of `pnpm typecheck`),
 * not by the vitest run, which only executes the few runtime checks below.
 *
 * Intentional widenings (documented, and asserted so the notes cannot go stale):
 *
 * 1. Branded ids. DSH brands `ReasoningEffortId`, `ToolCallId`, `MessageId`
 *    and `WorkspaceId` at compile time (`string & { [BRAND]: … }`); the ports
 *    use plain `string` so the plugin builds without the DSH type graph. The
 *    brands have no runtime representation (the brand constructors return
 *    their input), so requests the plugin builds are checked against DSH's
 *    `GenerateOptions` with brands erased. Consequence: the whole
 *    `LlmRuntime` class is NOT assignable to `LlmPort` (its `stream`
 *    parameter is branded), so `LlmPort` is checked method by method, and
 *    `src/host/dsh/adapters.ts` (`asLlm`) adapts `ctx.llm` through `unknown`
 *    after a runtime method check.
 * 2. Opaque content blocks. `LlmContentBlock` includes `{ type: string }` so
 *    blocks DSH streams back (images, tool additions, future kinds) survive a
 *    round trip. DSH's `ContentBlock` union is closed at compile time, so an
 *    arbitrary `{ type: string }` cannot be assigned to it; the request check
 *    therefore covers the block kinds the plugin itself creates (text,
 *    reasoning, tool-call). Anything else the plugin sends was produced by DSH.
 * 3. `WorkspaceRegistryPort.get(id: string)` vs DSH `get(id: WorkspaceId)`:
 *    the registry is assignable only through method-parameter bivariance;
 *    the plugin passes ids it read from `list()`/the browser as plain strings.
 */

import type { Context } from '@deepseek-ai/cordis'
import type {
  HostConnectionFetch,
  ConnectionFetchRoute as DshConnectionFetchRoute,
  HostConnectionHandle,
} from '@deepseek-ai/dsh-client-connection'
import {
  type AssistantMessage,
  type ContentBlock,
  type LlmFailure as DshLlmFailure,
  type LlmModelInfo as DshLlmModelInfo,
  type LlmProviderInfo as DshLlmProviderInfo,
  type LlmResolvedModelInfo as DshLlmResolvedModelInfo,
  type FinishReason,
  type GenerateOptions,
  type LlmRuntime,
  MessageId,
  ReasoningEffortId,
  type ReasoningBlock,
  type RequestMessage,
  type RequestUserInput,
  type StreamChunk,
  type TextBlock,
  type TokenUsage,
  type ToolCallBlock,
  ToolCallId,
  type ToolResultMessage,
  type ToolSchema,
} from '@deepseek-ai/dsh-llm'
import type { Workspace, WorkspaceId, WorkspaceRegistry } from '@deepseek-ai/dsh-workspace'
import { describe, expect, expectTypeOf, it } from 'vitest'
import type {
  ConnectionFetchRoute,
  ConnectionPort,
  LlmAssistantMessage,
  LlmContentBlock,
  LlmFailure,
  LlmFinishReason,
  LlmGenerateOptions,
  LlmModelInfo,
  LlmPort,
  LlmProviderInfo,
  LlmReasoningBlock,
  LlmRequestMessage,
  LlmResolvedModelInfo,
  LlmStreamChunk,
  LlmTextBlock,
  LlmTokenUsage,
  LlmToolCallBlock,
  LlmToolResultMessage,
  LlmToolSchema,
  LlmUserInput,
  WorkspaceEntity,
  WorkspaceRegistryPort,
} from '../../src/host/dsh/ports.ts'
import type { HostContext } from '../../src/host/index.ts'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Whether `T` is a branded string (a string with extra, symbol-keyed members). */
type IsBranded<T> = Exclude<keyof T, keyof string> extends never ? false : true

/** `T` with every DSH brand replaced by its underlying primitive (brands are compile-time only). */
type Unbranded<T> = T extends string
  ? IsBranded<T> extends true
    ? string
    : T
  : T extends AbortSignal
    ? T
    : T extends (...args: never[]) => unknown
      ? T
      : T extends readonly (infer U)[]
        ? T extends unknown[]
          ? Unbranded<U>[]
          : readonly Unbranded<U>[]
        : T extends object
          ? { [K in keyof T]: Unbranded<T[K]> }
          : T

/** Content blocks the plugin itself creates. */
type BuiltBlock = LlmTextBlock | LlmReasoningBlock | LlmToolCallBlock
/** A request message as the plugin builds it: only {@link BuiltBlock} content. */
type Built<M> = M extends { readonly content: readonly LlmContentBlock[] }
  ? Omit<M, 'content'> & { readonly content: readonly BuiltBlock[] }
  : never
/** Generate options as the worker builds them. */
type BuiltGenerateOptions = Omit<LlmGenerateOptions, 'messages'> & { messages: Built<LlmRequestMessage>[] }

type LlmMethod<K extends keyof LlmPort> = LlmPort[K]

// ---------------------------------------------------------------------------
// LLM registry (`ctx.llm`)
// ---------------------------------------------------------------------------

describe('LlmPort ⟵ @deepseek-ai/dsh-llm LlmRuntime', () => {
  it('accepts every LlmRuntime method the plugin calls', () => {
    expectTypeOf<LlmRuntime['listProviders']>().toExtend<LlmMethod<'listProviders'>>()
    expectTypeOf<LlmRuntime['listModels']>().toExtend<LlmMethod<'listModels'>>()
    expectTypeOf<LlmRuntime['resolveModelInfo']>().toExtend<LlmMethod<'resolveModelInfo'>>()
    // `stream`: DSH's return type is assignable to ours; the parameter is checked below with brands erased.
    expectTypeOf<ReturnType<LlmRuntime['stream']>>().toExtend<ReturnType<LlmMethod<'stream'>>>()
    expectTypeOf<Pick<LlmRuntime, 'listProviders' | 'listModels' | 'resolveModelInfo'>>().toExtend<
      Omit<LlmPort, 'stream'>
    >()
  })

  it('documents that the whole class is not assignable because of branded request ids', () => {
    expectTypeOf<LlmRuntime>().not.toExtend<LlmPort>()
    expectTypeOf<LlmGenerateOptions['reasoningEffort']>().not.toExtend<GenerateOptions['reasoningEffort']>()
    expectTypeOf<LlmToolCallBlock>().not.toExtend<ToolCallBlock>()
  })

  it('reads every metadata shape LlmRuntime returns', () => {
    expectTypeOf<DshLlmProviderInfo>().toExtend<LlmProviderInfo>()
    expectTypeOf<DshLlmModelInfo>().toExtend<LlmModelInfo>()
    expectTypeOf<DshLlmResolvedModelInfo>().toExtend<LlmResolvedModelInfo>()
  })

  it('reads every StreamChunk DSH emits', () => {
    expectTypeOf<StreamChunk>().toExtend<LlmStreamChunk>()
    expectTypeOf<ContentBlock>().toExtend<LlmContentBlock>()
    expectTypeOf<FinishReason>().toExtend<LlmFinishReason>()
    expectTypeOf<TokenUsage>().toExtend<LlmTokenUsage>()
    expectTypeOf<DshLlmFailure>().toExtend<LlmFailure>()
    expectTypeOf<TextBlock>().toExtend<LlmTextBlock>()
    expectTypeOf<ReasoningBlock>().toExtend<LlmReasoningBlock>()
    expectTypeOf<ToolCallBlock>().toExtend<LlmToolCallBlock>()
  })

  it('builds requests DSH GenerateOptions accepts (brands erased, plugin-created blocks)', () => {
    expectTypeOf<BuiltGenerateOptions>().toExtend<Unbranded<GenerateOptions>>()
    expectTypeOf<Built<LlmUserInput>>().toExtend<Unbranded<RequestUserInput>>()
    expectTypeOf<Built<LlmAssistantMessage>>().toExtend<Unbranded<AssistantMessage>>()
    expectTypeOf<Built<LlmToolResultMessage>>().toExtend<Unbranded<ToolResultMessage>>()
    expectTypeOf<Built<LlmRequestMessage>>().toExtend<Unbranded<RequestMessage>>()
    expectTypeOf<LlmToolSchema>().toExtend<ToolSchema>()
    expectTypeOf<BuiltBlock>().toExtend<Unbranded<ContentBlock>>()
  })

  it('relies on brands that are compile-time only', () => {
    expect(ReasoningEffortId('high')).toBe('high')
    expect(ToolCallId('call_1')).toBe('call_1')
    expect(MessageId('m_1')).toBe('m_1')
  })
})

// ---------------------------------------------------------------------------
// Connection exact Fetch routes (`ctx.connection.fetch`)
// ---------------------------------------------------------------------------

describe('ConnectionPort ⟷ @deepseek-ai/dsh-client-connection', () => {
  it('accepts HostConnectionHandle.fetch as ConnectionPort.fetch', () => {
    expectTypeOf<HostConnectionHandle['fetch']>().toExtend<ConnectionPort['fetch']>()
    expectTypeOf<HostConnectionFetch>().toExtend<ConnectionPort['fetch']>()
    expectTypeOf<HostConnectionHandle>().toExtend<ConnectionPort>()
  })

  it('registers routes DSH accepts', () => {
    expectTypeOf<ConnectionFetchRoute>().toExtend<DshConnectionFetchRoute>()
    expectTypeOf<DshConnectionFetchRoute>().toExtend<ConnectionFetchRoute>()
    expectTypeOf<Parameters<HostConnectionFetch['register']>[0]>().toExtend<ConnectionFetchRoute>()
  })
})

// ---------------------------------------------------------------------------
// Workspace registry (`ctx.workspaceRegistry`)
// ---------------------------------------------------------------------------

describe('WorkspaceRegistryPort ⟵ @deepseek-ai/dsh-workspace', () => {
  it('accepts WorkspaceRegistry and Workspace', () => {
    expectTypeOf<WorkspaceRegistry>().toExtend<WorkspaceRegistryPort>()
    expectTypeOf<Workspace>().toExtend<WorkspaceEntity>()
    expectTypeOf<ReturnType<WorkspaceRegistry['list']>>().toExtend<ReturnType<WorkspaceRegistryPort['list']>>()
    expectTypeOf<ReturnType<WorkspaceRegistry['get']>>().toExtend<ReturnType<WorkspaceRegistryPort['get']>>()
  })

  it('documents that get() is only bivariantly compatible (WorkspaceId is branded)', () => {
    expectTypeOf<WorkspaceId>().toExtend<string>()
    expectTypeOf<string>().not.toExtend<WorkspaceId>()
  })
})

// ---------------------------------------------------------------------------
// Cordis context handed to `apply(ctx)`
// ---------------------------------------------------------------------------

describe('HostContext ⟵ @deepseek-ai/cordis Context', () => {
  it('accepts the real Cordis context', () => {
    expectTypeOf<Context>().toExtend<HostContext>()
  })

  it('resolves the DSH services the plugin reads to its ports', () => {
    expectTypeOf<Context['llm']>().toExtend<Pick<LlmPort, 'listProviders' | 'listModels' | 'resolveModelInfo'>>()
    expectTypeOf<Context['connection']>().toExtend<ConnectionPort>()
    expectTypeOf<Context['workspaceRegistry']>().toExtend<WorkspaceRegistryPort>()
  })
})
