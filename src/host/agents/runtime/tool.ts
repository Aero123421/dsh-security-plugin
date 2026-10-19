/**
 * Tool definitions for runtime workers. A tool pairs a zod input schema (the
 * model-facing JSON Schema is derived from it) with either an `execute`
 * function or a `terminal` descriptor. Terminal tools end the worker: their
 * validated arguments become the worker's output.
 */

import { z } from 'zod'
import type { LlmToolSchema } from '../../dsh/ports.ts'
import { coerceArgs } from './lenient.ts'

/** Tool names the model sees: lower snake case, 2–41 characters. */
export const TOOL_NAME_PATTERN = /^[a-z][a-z0-9_]{1,40}$/

/** Per-call context handed to `execute`. */
export interface ToolContext {
  /** The worker's cancellation signal; long-running tools must honor it. */
  readonly signal: AbortSignal
  readonly workerId: string
  /** 1-based model turn whose response requested this call. */
  readonly turn: number
}

/** What a tool returns to the model. */
export interface ToolResult {
  readonly text: string
  readonly isError?: boolean
}

/** What a terminal tool knows about the run when the model submits. */
export interface TerminalContext {
  /**
   * This is the worker's last request (its final or grace turn, or a budget
   * wrap-up). A submission sent back now is lost, so `validate` should accept
   * what it can verify and let `toOutput` drop the rest.
   */
  readonly final: boolean
  /** Non-terminal tool calls the worker has run so far (failed calls included). */
  readonly toolCalls: number
}

/**
 * Marks a tool as terminal. `validate` may return an error message that is sent
 * back to the model as an error result (the worker continues); `toOutput` maps
 * accepted arguments to the worker's output.
 *
 * Declared with method syntax so a `WorkerTool<A, T>` with concrete `A` fits a
 * `WorkerTool<unknown, T>[]` list.
 */
export interface TerminalSpec<A, T> {
  validate?(args: A, context: TerminalContext): string | undefined
  toOutput(args: A, context: TerminalContext): T
}

/**
 * A tool a worker can call. Non-terminal tools need `execute`; terminal tools
 * need `terminal`. Arguments are validated against `input` before either runs.
 */
export interface WorkerTool<A = unknown, T = unknown> {
  /** Matches {@link TOOL_NAME_PATTERN}. */
  readonly name: string
  readonly description: string
  /** Validated before execute; the JSON Schema sent to the model is derived from it. */
  readonly input: z.ZodType<A>
  /**
   * Repairs decoded arguments before `input` validates them. Defaults to
   * {@link coerceArgs} over `input` (see `lenient.ts`); a tool sets its own to
   * add field-specific repairs. Must not throw for any JSON value.
   */
  coerce?(args: unknown): unknown
  /** Terminal tools end the worker; their parsed value is the worker's output. */
  readonly terminal?: TerminalSpec<A, T>
  /** Required for non-terminal tools. Thrown errors become `Tool failed: <message>` results. */
  execute?(args: A, ctx: ToolContext): Promise<ToolResult>
}

const schemaCache = new WeakMap<WorkerTool<unknown, unknown>, LlmToolSchema>()

/**
 * Validate a tool definition and return it unchanged (typed).
 * @throws TypeError when the name is invalid, the input is not an object schema,
 *   or a non-terminal tool lacks `execute`.
 */
export function defineTool<A, T = never>(tool: WorkerTool<A, T>): WorkerTool<A, T> {
  assertValidTool(tool)
  return tool
}

/**
 * Decoded arguments after the tool's repairs ({@link WorkerTool.coerce}, else
 * {@link coerceArgs} over its input schema). A repair that throws leaves the
 * arguments as they were, for the schema to report.
 */
export function coerceToolArgs<A, T>(tool: WorkerTool<A, T>, args: unknown): unknown {
  try {
    return tool.coerce ? tool.coerce(args) : coerceArgs(tool.input, args)
  } catch {
    return args
  }
}

/** Throws a TypeError describing the first problem with `tool`, if any. */
export function assertValidTool<A, T>(tool: WorkerTool<A, T>): void {
  if (typeof tool.name !== 'string' || !TOOL_NAME_PATTERN.test(tool.name)) {
    throw new TypeError(`Invalid tool name ${JSON.stringify(tool.name)}: must match ${TOOL_NAME_PATTERN}`)
  }
  if (typeof tool.description !== 'string' || tool.description.trim() === '') {
    throw new TypeError(`Tool ${tool.name} needs a description`)
  }
  if (!tool.terminal && typeof tool.execute !== 'function') {
    throw new TypeError(`Tool ${tool.name} is not terminal and has no execute function`)
  }
  if (tool.terminal && typeof tool.terminal.toOutput !== 'function') {
    throw new TypeError(`Terminal tool ${tool.name} has no toOutput function`)
  }
  toolSchema(tool)
}

/**
 * The model-facing schema of a tool. Parameters are the JSON Schema of the
 * zod input (input side, so defaulted fields are optional) without `$schema`
 * and without the ±2^53 bounds zod adds to every integer (they say nothing and
 * cost tokens on every request). Results are cached per tool object.
 * @throws TypeError when the input does not describe a JSON object.
 */
export function toolSchema<A, T>(tool: WorkerTool<A, T>): LlmToolSchema {
  const key = tool as WorkerTool<unknown, unknown>
  const cached = schemaCache.get(key)
  if (cached) return cached
  const { $schema: _ignored, ...parameters } = z.toJSONSchema(tool.input, {
    io: 'input',
    unrepresentable: 'any',
  }) as Record<string, unknown>
  if (parameters.type !== 'object') {
    throw new TypeError(`Tool ${tool.name} input must be an object schema`)
  }
  dropSafeIntegerBounds(parameters)
  const schema: LlmToolSchema = { name: tool.name, description: tool.description, parameters }
  schemaCache.set(key, schema)
  return schema
}

/** Removes `minimum`/`maximum` values that only restate the safe-integer range, in place. */
function dropSafeIntegerBounds(node: unknown): void {
  if (Array.isArray(node)) {
    for (const item of node) dropSafeIntegerBounds(item)
    return
  }
  if (typeof node !== 'object' || node === null) return
  const record = node as Record<string, unknown>
  if (record.minimum === Number.MIN_SAFE_INTEGER) delete record.minimum
  if (record.maximum === Number.MAX_SAFE_INTEGER) delete record.maximum
  for (const value of Object.values(record)) dropSafeIntegerBounds(value)
}
