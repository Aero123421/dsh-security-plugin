/**
 * Structural views of the DSH client services this plugin uses. Only the
 * members we call are described, so the real Cordis context is assignable and
 * tests can pass small fakes. Never import DSH packages for values here: the
 * browser bundle may only reach DSH through `ctx`.
 */

import type { ComponentType } from 'react'

/**
 * The id this plugin registers under in DSH's shared slots (sidebar panel,
 * main view key, settings section). Namespaced so it cannot collide with DSH
 * or another plugin; `layout.selectPanel()` must use the same value.
 */
export const SECURITY_SLOT_ID = 'dsh-security'

export type DshRpcOutcome =
  | { readonly ok: true; readonly value: unknown }
  | {
      readonly ok: false
      readonly error: { readonly code: string; readonly message: string; readonly details?: object }
    }

export interface DshRpc {
  call(channel: string, endpoint: string, payload: unknown, signal?: AbortSignal): Promise<DshRpcOutcome>
}

export interface DshConnection {
  readonly rpc: DshRpc
  readonly isLoopback: boolean
}

export interface DshLocale {
  getLocale(): { readonly active: string }
  subscribe(listener: () => void): () => void
}

export interface DshSlots {
  inject(key: string, callback: () => (() => unknown) | undefined): void
  register<P>(options: Record<string, unknown>, component: ComponentType<P>): () => unknown
}

/** `ctx.get('layout')` — optional. */
export interface DshLayout {
  selectPanel(id: string): unknown
}

/** `ctx.get('uiWorkspace')` — optional. */
export interface DshUiWorkspace {
  startSession?(workspaceId: string, options: { prompt: string; clearPreviousDraft?: boolean }): unknown
  /** Host-native picker; cancellation resolves to null. */
  pickDirectory?(): Promise<string | null>
  /** Browser-based directory access, when supplied by DSH. Paths come from the Host. */
  listDirectory?(path?: string, signal?: AbortSignal): Promise<DshDirectoryListing>
}

export interface DshDirectoryListing {
  readonly path: string
  readonly home: string
  readonly crumbs: readonly { readonly name: string; readonly path: string; readonly hidden: boolean }[]
  readonly entries: readonly { readonly name: string; readonly path: string; readonly hidden: boolean }[]
  readonly truncated: boolean
}

/** `ctx.get('workspaces')` — optional, React-free Workspace Controller. */
export interface DshWorkspaces {
  /** Returns the created or already-registered workspace (not a result wrapper). */
  create(input: { path: string }): Promise<{ readonly workspaceId: string }>
}

export interface DshClientContext {
  readonly slots: DshSlots
  readonly locale: DshLocale
  readonly connection: DshConnection
  get(name: string): unknown
  on(event: 'connection/reset', listener: () => void): () => unknown
  effect(execute: () => () => unknown, label?: string): unknown
}

export function asLayout(value: unknown): DshLayout | undefined {
  return isObject(value) && typeof value.selectPanel === 'function' ? (value as unknown as DshLayout) : undefined
}

export function asUiWorkspace(value: unknown): DshUiWorkspace | undefined {
  return isObject(value) &&
    (typeof value.startSession === 'function' ||
      typeof value.pickDirectory === 'function' ||
      typeof value.listDirectory === 'function')
    ? (value as unknown as DshUiWorkspace)
    : undefined
}

export function asWorkspaces(value: unknown): DshWorkspaces | undefined {
  return isObject(value) && typeof value.create === 'function' ? (value as unknown as DshWorkspaces) : undefined
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
