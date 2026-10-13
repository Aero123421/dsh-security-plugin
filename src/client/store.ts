/** Minimal external store for `useSyncExternalStore`. */

import { useSyncExternalStore } from 'react'

export interface Store<S> {
  getState(): S
  setState(update: S | ((prev: S) => S)): void
  subscribe(listener: () => void): () => void
}

export function createStore<S>(initial: S): Store<S> {
  let state = initial
  const listeners = new Set<() => void>()
  return {
    getState: () => state,
    setState(update) {
      const next = typeof update === 'function' ? (update as (prev: S) => S)(state) : update
      if (Object.is(next, state)) return
      state = next
      for (const listener of [...listeners]) {
        try {
          listener()
        } catch (error) {
          console.error('[dsh-security] store listener failed', error)
        }
      }
    },
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
  }
}

/**
 * Subscribe to a slice. `selector` must return an existing reference or a
 * primitive (never build a new object), so unrelated updates do not re-render.
 */
export function useStoreSelector<S, T>(store: Pick<Store<S>, 'getState' | 'subscribe'>, selector: (state: S) => T): T {
  return useSyncExternalStore(
    store.subscribe,
    () => selector(store.getState()),
    () => selector(store.getState()),
  )
}
