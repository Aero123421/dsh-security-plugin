#!/usr/bin/env node
/**
 * Rebuilds `lib/` and fails if the result differs from what is committed.
 *
 * `lib/` is tracked in git so `github:Aero123421/dsh-security-plugin#vX.Y.Z`
 * installs without a build step; this keeps the committed output honest.
 */
import { execFileSync } from 'node:child_process'

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' })
execFileSync(process.execPath, ['scripts/build.mjs'], { stdio: 'inherit' })
const status = git('status', '--porcelain', '--', 'lib').trim()
if (status !== '') {
  console.error('check-lib: lib/ does not match a fresh build. Run `pnpm build` and commit lib/.')
  console.error(status)
  console.error(git('diff', '--stat', '--', 'lib'))
  process.exit(1)
}
console.log('check-lib: committed lib/ matches a fresh build')
