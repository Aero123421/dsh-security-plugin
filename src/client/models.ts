/** Model-route helpers shared by the New Scan dialog and Settings. */

import type { ProviderOption } from '../shared/contracts.ts'
import { ROLE_NAMES, type RoleName } from '../shared/domain.ts'
import type { ModelRef, RoleModels } from '../shared/settings.ts'

export interface ResolvedRole {
  readonly role: RoleName
  readonly ref: ModelRef | undefined
  /** True when the role has no own route and uses `default`. */
  readonly inherited: boolean
}

function validRef(ref: ModelRef | undefined | null): ModelRef | undefined {
  return ref && typeof ref.provider === 'string' && ref.provider && typeof ref.model === 'string' && ref.model
    ? ref
    : undefined
}

/** Each role's effective route: its own, else `default`, else none. */
export function resolveRoleModels(models: RoleModels | undefined): ResolvedRole[] {
  const fallback = validRef(models?.default)
  return ROLE_NAMES.map(role => {
    const own = validRef(models?.[role])
    return { role, ref: own ?? fallback, inherited: !own && Boolean(fallback) }
  })
}

export function hunterModel(models: RoleModels | undefined): ModelRef | undefined {
  return validRef(models?.hunter) ?? validRef(models?.default)
}

export function providerName(providers: readonly ProviderOption[] | undefined, id: string): string {
  return providers?.find(p => p.id === id)?.name || id
}

export function modelName(providers: readonly ProviderOption[] | undefined, ref: ModelRef): string {
  const provider = providers?.find(p => p.id === ref.provider)
  return provider?.models?.find(m => m.id === ref.model)?.name || ref.model
}

export function describeRoute(providers: readonly ProviderOption[] | undefined, ref: ModelRef): string {
  return `${providerName(providers, ref.provider)} · ${modelName(providers, ref)}`
}

/** Distinct providers (with their models) that will receive code. */
export function recipients(
  providers: readonly ProviderOption[] | undefined,
  roles: readonly ResolvedRole[],
): { readonly provider: string; readonly models: readonly string[] }[] {
  const byProvider = new Map<string, Set<string>>()
  for (const { ref } of roles) {
    if (!ref) continue
    const name = providerName(providers, ref.provider)
    const set = byProvider.get(name) ?? new Set<string>()
    set.add(modelName(providers, ref))
    byProvider.set(name, set)
  }
  return [...byProvider].map(([provider, models]) => ({ provider, models: [...models] }))
}
