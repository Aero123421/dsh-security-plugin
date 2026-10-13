#!/usr/bin/env node
/**
 * Packs the release asset into `release/` and writes `release/SHA256SUMS`.
 *
 *   node scripts/release-pack.mjs [--tag vX.Y.Z]
 *
 * Expects a built, verified tree (`pnpm build`, `node scripts/verify-package.mjs`).
 * With `--tag`, fails unless the tag equals `v` + package.json version.
 * Prints the asset path. Only the tarball and the checksum file are written.
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
const tagIndex = process.argv.indexOf('--tag')
const tag = tagIndex >= 0 ? process.argv[tagIndex + 1] : undefined
if (tag !== undefined && tag !== `v${pkg.version}`) {
  console.error(`release-pack: tag ${tag} does not match package.json version ${pkg.version}`)
  process.exit(1)
}

const dir = 'release'
rmSync(dir, { recursive: true, force: true })
mkdirSync(dir)
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const out = execFileSync(npm, ['pack', '--json', '--pack-destination', dir], {
  encoding: 'utf8',
  shell: process.platform === 'win32',
})
const [packed] = JSON.parse(out)
const expected = `${pkg.name}-${pkg.version}.tgz`
if (packed?.filename !== expected) {
  console.error(`release-pack: expected ${expected}, npm produced ${packed?.filename}`)
  process.exit(1)
}
const asset = join(dir, expected)
const sha = createHash('sha256').update(readFileSync(asset)).digest('hex')
writeFileSync(join(dir, 'SHA256SUMS'), `${sha}  ${expected}\n`)
console.log(asset)
