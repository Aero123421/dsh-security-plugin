/** React glue: the controller travels through context inside our own trees. */

import { createContext, type ReactNode, useContext } from 'react'
import type { SecurityController, SecurityState } from './controller.ts'
import { getTranslator, type Translator } from './i18n.ts'
import { useStoreSelector } from './store.ts'

const ControllerContext = createContext<SecurityController | null>(null)

export function ControllerProvider(props: { controller: SecurityController; children: ReactNode }) {
  return <ControllerContext.Provider value={props.controller}>{props.children}</ControllerContext.Provider>
}

export function useController(): SecurityController {
  const controller = useContext(ControllerContext)
  if (!controller) throw new Error('dsh-security: component rendered outside ControllerProvider')
  return controller
}

/** Select a stable slice of controller state (return existing references or primitives). */
export function useSecurity<T>(selector: (state: SecurityState) => T): T {
  return useStoreSelector(useController().store, selector)
}

export function useT(): Translator {
  return getTranslator(useSecurity(s => s.language))
}

/** Width of the main panel, measured by the page frame (0 when unknown). */
export const PageWidthContext = createContext(0)

export function usePageWidth(): number {
  return useContext(PageWidthContext)
}
