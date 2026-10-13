/**
 * Runtime guards for optional DSH services read through `ctx.get(name)`.
 * A service that does not have the expected methods is treated as absent,
 * so an incompatible DSH build degrades features instead of crashing.
 */

import type { ConnectionPort, LlmPort, WorkspaceRegistryPort } from './ports.ts'

function hasMethods(value: unknown, names: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return names.every(name => typeof record[name] === 'function')
}

export function asLlm(value: unknown): LlmPort | undefined {
  return hasMethods(value, ['listProviders', 'listModels', 'resolveModelInfo', 'stream'])
    ? (value as unknown as LlmPort)
    : undefined
}

export function asWorkspaceRegistry(value: unknown): WorkspaceRegistryPort | undefined {
  return hasMethods(value, ['list', 'get']) ? (value as unknown as WorkspaceRegistryPort) : undefined
}

export function asConnection(value: unknown): ConnectionPort | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const fetch = (value as { fetch?: unknown }).fetch
  return hasMethods(fetch, ['register']) ? (value as unknown as ConnectionPort) : undefined
}
