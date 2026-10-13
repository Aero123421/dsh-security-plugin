/**
 * Copy a fixture app to a directory you can register as a DSH workspace,
 * leaving out the answer keys (`expected.json`, `README.md`) so the model
 * under evaluation cannot read them, and joining the fake credentials that
 * the repository stores split (`FAKE_SECRET_SPLIT`).
 *
 *   node --experimental-strip-types bench/prepare.ts <app-name> <destination-dir>
 *
 * Prints the absolute path of the copy (`<destination-dir>/<app-name>`).
 */

import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { copyFixtureApp, loadFixtures } from './fixtures.ts'

const [app, dest] = process.argv.slice(2)
if (!app || !dest) {
  process.stderr.write('Usage: node --experimental-strip-types bench/prepare.ts <app-name> <destination-dir>\n')
  process.exit(2)
}
const manifests = await loadFixtures()
const manifest = manifests.find(m => m.app === app)
if (!manifest) {
  process.stderr.write(`Unknown fixture app "${app}". Fixture apps: ${manifests.map(m => m.app).join(', ')}\n`)
  process.exit(2)
}
if (existsSync(join(resolve(dest), app))) {
  process.stderr.write(`${join(resolve(dest), app)} already exists; choose an empty destination.\n`)
  process.exit(1)
}
process.stdout.write(`${await copyFixtureApp(manifest, dest)}\n`)
