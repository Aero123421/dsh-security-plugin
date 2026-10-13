/**
 * Structural views of the DSH client services this plugin uses. Only the
 * members we call are described, so the real Cordis context is assignable and
 * tests can pass small fakes. Never import DSH packages for values here: the
 * browser bundle may only reach DSH through `ctx`.
 */

import type { ComponentType } from 'react'

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
  startSession(workspaceId: string, options: { prompt: string; clearPreviousDraft?: boolean }): unknown
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
  return isObject(value) && typeof value.startSession === 'function' ? (value as unknown as DshUiWorkspace) : undefined
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
