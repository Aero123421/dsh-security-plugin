/** Resolve browser-supplied scan scope inside a registered project. Never expose Host paths in failures. */
import { realpath, stat } from 'node:fs/promises'
import { isAbsolute, join, relative, sep, win32 } from 'node:path'
import type { WorkspaceEntity } from '../dsh/ports.ts'
import { RpcError } from '../rpc/errors.ts'

export async function resolveScanRoot(
  workspace: WorkspaceEntity,
  subpath?: string,
): Promise<{ workspaceRoot: string; root: string; subpath?: string }> {
  if (
    subpath !== undefined &&
    (subpath.length > 1024 ||
      /[\u0000-\u001f\u007f-\u009f\\]/.test(subpath) ||
      isAbsolute(subpath) ||
      win32.isAbsolute(subpath) ||
      (subpath !== '' && subpath.split('/').some(part => part === '' || part === '.' || part === '..')))
  ) {
    throw new RpcError(
      'security/bad-request',
      'Use a relative subfolder path without empty, ".", or ".." segments.',
      {},
    )
  }
  let workspaceRoot: string
  try {
    workspaceRoot = await realpath(workspace.path)
    if (!(await stat(workspaceRoot)).isDirectory()) throw new Error('not a directory')
  } catch {
    throw new RpcError('security/workspace-unavailable', 'The project folder cannot be read.', {
      workspaceId: workspace.id,
    })
  }
  if (!subpath) return { workspaceRoot, root: workspaceRoot }
  let root: string
  try {
    root = await realpath(join(workspaceRoot, subpath))
  } catch {
    throw new RpcError('security/not-found', 'The subfolder was not found in this project.', {})
  }
  const prefix = workspaceRoot.endsWith(sep) ? workspaceRoot : workspaceRoot + sep
  if (root === workspaceRoot || !root.startsWith(prefix)) {
    throw new RpcError('security/not-found', 'The subfolder was not found in this project.', {})
  }
  try {
    if (!(await stat(root)).isDirectory()) throw new Error('not a directory')
  } catch {
    throw new RpcError('security/not-found', 'The subfolder was not found in this project.', {})
  }
  return { workspaceRoot, root, subpath: relative(workspaceRoot, root).split(sep).join('/') }
}

/** Accept legacy path spellings, but never a different filesystem target. */
export async function sameScanRoot(stored: string, resolved: string): Promise<boolean> {
  if (stored === resolved) return true
  try {
    return (await realpath(stored)) === resolved
  } catch {
    return false
  }
}

/** Effective root for a validated, durable scan. Legacy records may not yet be canonical. */
export function scanRoot(scan: { readonly workspaceRoot: string; readonly subpath?: string }): string {
  return scan.subpath ? join(scan.workspaceRoot, scan.subpath) : scan.workspaceRoot
}
