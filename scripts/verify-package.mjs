#!/usr/bin/env node
/**
 * Verifies the npm tarball before it is packed or published: exactly the
 * expected files, a browser bundle in DSH's module-loader format, and the
 * `package.json` fields DSH reads to install the plugin.
 *
 * Usage: node scripts/verify-package.mjs   (after `pnpm build`)
 *
 * Runs `npm pack --dry-run --json --ignore-scripts`, so nothing is written
 * and the `prepack` hook (which calls this script) is not re-entered. Works
 * in this pnpm repository and on Windows. Exits non-zero with one line per
 * problem. Plain Node ESM, no dependencies.
 */

import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { isBuiltin } from 'node:module'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

/** Files that must be in the tarball. Anything else (except OPTIONAL) is an error. */
const REQUIRED = [
  'package.json',
  'lib/index.js',
  'lib/index.js.map',
  'lib/client.js',
  'lib/client.js.map',
  'cordis.patch.yml',
  'toolkit.lock.json',
  'README.md',
  'README.ja.md',
  'LICENSE',
  'THIRD_PARTY_NOTICES.md',
  'SECURITY.md',
  'CHANGELOG.md',
]
/** License files esbuild writes for `legalComments: 'linked'` when a bundled package has legal comments. */
const OPTIONAL = [/^lib\/[^/]+\.LEGAL\.txt$/]
/** Paths that must never ship; reported with a clearer message than "unexpected". */
const LEAKS = [
  /^src\//,
  /^tests\//,
  /^bench\//,
  /^scripts\//,
  /^docs\//,
  /^coverage\//,
  /^node_modules\//,
  /^\.github\//,
]

const CLIENT_PREFIX = 'window.__ModuleLoader__.load('
/**
 * Catches a second runtime copy (React, Cordis) or another large library slipping into the browser bundle, which
 * adds 100 KB or more. The bundle itself is mostly the three UI dictionaries (en/ja/zh) and the scoped CSS.
 */
const CLIENT_MAX_BYTES = 320 * 1024

const problems = []
const warnings = []
const fail = message => problems.push(message)

for (const file of ['lib/index.js', 'lib/client.js']) {
  if (!existsSync(join(root, file))) {
    console.error(`verify-package: ${file} does not exist. Run \`pnpm build\` first.`)
    process.exit(1)
  }
}

const pkg = readJson('package.json')
const pack = npmPackDryRun()
const packed = new Map(pack.files.map(file => [toPosix(file.path), file.size]))

// -- File list ----------------------------------------------------------------

for (const file of REQUIRED) {
  if (packed.has(file)) continue
  fail(
    existsSync(join(root, file))
      ? `${file} exists but is not in the tarball; add it to "files" in package.json`
      : `${file} is missing from the tarball and from the repository`,
  )
}
for (const file of packed.keys()) {
  if (REQUIRED.includes(file) || OPTIONAL.some(pattern => pattern.test(file))) continue
  fail(
    LEAKS.some(pattern => pattern.test(file))
      ? `${file} leaked into the tarball; development files must not ship`
      : `unexpected file in the tarball: ${file}`,
  )
}
for (const name of readdirSync(join(root, 'lib'))) {
  const file = `lib/${name}`
  if (/\.LEGAL\.txt$/.test(name) && !packed.has(file)) {
    fail(`${file} was emitted by the build but is not in the tarball; add "lib/*.LEGAL.txt" to "files" in package.json`)
  }
}

// -- Bundles ------------------------------------------------------------------

const client = readFileSync(join(root, 'lib/client.js'), 'utf8')
const clientBytes = statSync(join(root, 'lib/client.js')).size
if (!client.startsWith(CLIENT_PREFIX)) {
  fail(`lib/client.js must start with \`${CLIENT_PREFIX}\` (DSH's dynamic client-bundle format)`)
}
if (clientBytes >= CLIENT_MAX_BYTES) {
  fail(`lib/client.js is ${formatBytes(clientBytes)}; keep it under ${formatBytes(CLIENT_MAX_BYTES)}`)
}

const host = readFileSync(join(root, 'lib/index.js'), 'utf8')
if (host.trim() === '') fail('lib/index.js is empty')
else if (!/export\s*\{[^}]*\bapply\b[^}]*\}/.test(host)) fail('lib/index.js does not export `apply` (the plugin entry)')

// Check runtime specifiers, including ast-grep's constant-valued dynamic imports.
// Dev dependencies are bundled, not available to consumers of the tarball.
const declared = { ...pkg.dependencies, ...pkg.optionalDependencies, ...pkg.peerDependencies }
const code = host
  .split('\n')
  .filter(line => !/^\s*(?:\/\/|\*|\/\*)/.test(line))
  .join('\n')
const constants = new Map(
  [...code.matchAll(/\b(?:const|var|let)\s+(\w+)\s*=\s*["']([^"']+)["']/g)].map(m => [m[1], m[2]]),
)
const specifiers = new Set()
for (const match of code.matchAll(/(?<![\w.])(?:import|(?:__)?require)\(\s*([^\s?)][^\n)]*)\s*\)(?!\s*\{)/g)) {
  const expression = match[1].trim()
  const literal = /^["']([^"']+)["']$/.exec(expression)?.[1]
  const specifier = literal ?? constants.get(expression)
  if (specifier) specifiers.add(specifier)
  else fail(`lib/index.js: cannot verify dynamic module specifier ${expression}`)
}
for (const match of code.matchAll(/^import\s+(?:[^\n]*?\s+from\s+)?["']([^"']+)["']/gm)) specifiers.add(match[1])
for (const specifier of specifiers) {
  if (isBuiltin(specifier)) continue
  const name = specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]
  if (!Object.hasOwn(declared, name))
    fail(
      `lib/index.js: runtime module ${specifier} is not declared in package.json dependencies, optionalDependencies or peerDependencies`,
    )
}

// -- package.json -------------------------------------------------------------

const patch = pkg.dsh?.bundle?.patch
if (typeof patch !== 'string') fail('package.json: dsh.bundle.patch is missing')
else if (!packed.has(stripDot(patch)))
  fail(`package.json: dsh.bundle.patch points to ${patch}, which is not in the tarball`)

if (pkg.dsh?.client?.platform !== 'web') fail(`package.json: dsh.client.platform must be "web"`)

const clientExport = pkg.exports?.['./client']
if (typeof clientExport !== 'string') fail('package.json: exports["./client"] is missing')
else if (stripDot(clientExport) !== 'lib/client.js') fail(`package.json: exports["./client"] must be ./lib/client.js`)

const mainExport = pkg.exports?.['.']
if (typeof mainExport !== 'string' || !packed.has(stripDot(mainExport))) {
  fail('package.json: exports["."] must point to a file in the tarball')
}
if (typeof pkg.main === 'string' && !packed.has(stripDot(pkg.main))) {
  fail(`package.json: main points to ${pkg.main}, which is not in the tarball`)
}

const bundleName = /^\s*name:\s*['"]?([^'"\s#]+)/m.exec(readFileSync(join(root, 'cordis.patch.yml'), 'utf8'))?.[1]
if (bundleName !== pkg.name) {
  fail(`cordis.patch.yml inserts "${bundleName ?? '(none)'}" but the package is "${pkg.name}"`)
}

// -- Toolkit lock (warning only: an unpinned asset only disables managed installs) ----

const lock = readJson('toolkit.lock.json')
const unpinned = Object.entries(lock.tools ?? {}).flatMap(([id, tool]) =>
  Object.entries(tool.assets ?? {})
    .filter(([, asset]) => asset.sha256 === null)
    .map(([platform]) => `${id}/${platform}`),
)
if (unpinned.length > 0) {
  warnings.push(
    `toolkit.lock.json has ${unpinned.length} unpinned asset(s) (${unpinned.join(', ')}); ` +
      'managed installs of these refuse to run until `pnpm toolkit:pin` is committed',
  )
}

// -- Report -------------------------------------------------------------------

console.log(`${pack.id} → ${pack.filename}`)
console.log(`  ${packed.size} files, ${formatBytes(pack.size)} packed, ${formatBytes(pack.unpackedSize)} unpacked`)
for (const [file, size] of [...packed].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
  console.log(`  ${formatBytes(size).padStart(10)}  ${file}`)
}
console.log(`  lib/client.js: ${formatBytes(clientBytes)} of ${formatBytes(CLIENT_MAX_BYTES)} allowed`)
for (const warning of warnings) console.warn(`warning: ${warning}`)

if (problems.length > 0) {
  console.error(`\nverify-package: ${problems.length} problem(s):`)
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}
console.log('verify-package: OK')

// -- Helpers ------------------------------------------------------------------

function npmPackDryRun() {
  const args = ['pack', '--dry-run', '--json', '--ignore-scripts']
  const options = { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
  // `npm` is `npm.cmd` on Windows, which only runs through a shell. The command line is a fixed
  // string (no user input); passing it whole avoids Node's warning about shell + argument arrays.
  const result =
    process.platform === 'win32'
      ? spawnSync(`npm ${args.join(' ')}`, { ...options, shell: true })
      : spawnSync('npm', args, options)
  if (result.error || result.status !== 0) {
    console.error('verify-package: `npm pack --dry-run --json` failed')
    if (result.error) console.error(result.error.message)
    if (result.stderr) console.error(result.stderr.trim())
    process.exit(1)
  }
  // npm <= 11 prints an array with one entry; npm 12 prints an object keyed
  // by package name. Accept both. Slice from the first JSON opener in case
  // npm ever writes a preamble line to stdout.
  const openers = [result.stdout.indexOf('['), result.stdout.indexOf('{')].filter(index => index >= 0)
  const start = openers.length > 0 ? Math.min(...openers) : 0
  let parsed
  try {
    parsed = JSON.parse(result.stdout.slice(start))
  } catch (error) {
    console.error(`verify-package: could not parse npm pack output: ${error instanceof Error ? error.message : error}`)
    process.exit(1)
  }
  const entry = Array.isArray(parsed)
    ? parsed[0]
    : Array.isArray(parsed?.files)
      ? parsed
      : Object.values(parsed ?? {})[0]
  if (!entry || !Array.isArray(entry.files)) {
    console.error('verify-package: npm pack returned no file list')
    process.exit(1)
  }
  return entry
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(join(root, file), 'utf8'))
  } catch (error) {
    console.error(`verify-package: cannot read ${file}: ${error instanceof Error ? error.message : error}`)
    process.exit(1)
  }
}

function toPosix(path) {
  return path.replace(/\\/g, '/')
}

function stripDot(path) {
  return toPosix(path).replace(/^\.\//, '')
}

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}
