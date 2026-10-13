import { readdir, readFile } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { AstGrepHandle } from '../../../src/host/analysis/astgrep.ts'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import type { Endpoint, Snapshot } from '../../../src/host/analysis/types.ts'
import { materializeFixtureText } from '../../../bench/fixtures.ts'
import { snapshotOf } from './helpers.ts'

const FIXTURES = fileURLToPath(new URL('../../fixtures/routes/', import.meta.url))
const APPS = fileURLToPath(new URL('../../fixtures/apps/', import.meta.url))

/**
 * Load one `tests/fixtures/routes/<name>` directory as a snapshot rooted at
 * that directory. `isTest` is cleared: inside the fixture the files are the
 * application under analysis.
 */
export async function routeFixture(name: string, extra: Record<string, string> = {}): Promise<Snapshot> {
  return dirSnapshot(join(FIXTURES, name), extra)
}

/** Load one `tests/fixtures/apps/<name>` application (the end-to-end fixtures) as a snapshot. */
export async function appFixture(name: string): Promise<Snapshot> {
  return dirSnapshot(join(APPS, name), {})
}

async function dirSnapshot(dir: string, extra: Record<string, string>): Promise<Snapshot> {
  const files: Record<string, string> = {}
  const walk = async (current: string): Promise<void> => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const abs = join(current, entry.name)
      if (entry.isDirectory()) await walk(abs)
      else if (entry.name !== 'biome.json')
        files[relative(dir, abs).split(sep).join('/')] = materializeFixtureText(await readFile(abs, 'utf8'))
    }
  }
  await walk(dir)
  const snapshot = snapshotOf({ ...files, ...extra }, dir)
  return { ...snapshot, files: new Map([...snapshot.files].map(([p, f]) => [p, { ...f, isTest: false }])) }
}

/** Extract endpoints from a fixture. */
export async function routesOf(
  name: string,
  handle: AstGrepHandle | undefined,
  extra: Record<string, string> = {},
): Promise<{ endpoints: Endpoint[]; warnings: string[] }> {
  return extractRoutes(await routeFixture(name, extra), { astGrep: handle })
}

/** `METHOD route` per endpoint, in output order. */
export function routeList(endpoints: readonly Endpoint[]): string[] {
  return endpoints.map(e => `${e.method} ${e.route}`)
}

/** The endpoint with this method and route (throws when absent, for readable failures). */
export function endpoint(endpoints: readonly Endpoint[], method: string, route: string): Endpoint {
  const found = endpoints.find(e => e.method === method && e.route === route)
  if (!found) throw new Error(`no endpoint ${method} ${route} in [${routeList(endpoints).join(', ')}]`)
  return found
}
