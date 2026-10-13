#!/usr/bin/env node
/**
 * Writes GitHub Release notes for a version to stdout: install instructions
 * for that exact tag, then the version's CHANGELOG section.
 *
 *   node scripts/release-notes.mjs 0.1.0 > notes.md
 */
import { readFileSync } from 'node:fs'

const version = process.argv[2]
if (!version) {
  console.error('usage: node scripts/release-notes.mjs <version>')
  process.exit(2)
}
const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
const repo = pkg.repository.url
  .replace(/^git\+/, '')
  .replace(/\.git$/, '')
  .replace('https://github.com/', '')
const changelog = readFileSync('CHANGELOG.md', 'utf8')
const heading = new RegExp(`^## \\[${version.replace(/\./g, '\\.')}\\][^\\n]*$`, 'm')
const start = changelog.search(heading)
if (start < 0) {
  console.error(`release-notes: CHANGELOG.md has no "## [${version}]" section`)
  process.exit(1)
}
const rest = changelog.slice(start).split('\n')
const end = rest.findIndex((line, index) => index > 0 && (/^## \[/.test(line) || /^\[[^\]]+\]: /.test(line)))
const section = rest
  .slice(1, end < 0 ? undefined : end)
  .join('\n')
  .trim()
const tag = `v${version}`
const asset = `${pkg.name}-${version}.tgz`
process.stdout.write(`## Install

Requires DSH \`${pkg.peerDependencies['@deepseek-ai/dsh']}\` and Node.js \`${pkg.engines.node}\`.

In DSH → **Plugins → Add plugin**, enter:

\`\`\`text
github:${repo}#${tag}
\`\`\`

or from a terminal:

\`\`\`sh
dsh plugin --profile web add -w github:${repo}#${tag}
\`\`\`

The release asset \`${asset}\` installs the same build:
\`dsh plugin --profile web add -w https://github.com/${repo}/releases/download/${tag}/${asset}\`
(check it against \`SHA256SUMS\`). Restart DSH if it asks.

${section}
`)
