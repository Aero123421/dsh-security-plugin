#!/usr/bin/env node
/**
 * Pins the managed toolkit: downloads every asset listed in toolkit.lock.json,
 * computes its SHA-256 and size, cross-checks the hash against the upstream
 * checksums file when the tool lists one, and writes the results back.
 *
 * Usage: node scripts/pin-toolkit.mjs [--tool <id>] [--check]
 *   --tool <id>  only pin one tool (repeatable)
 *   --check      verify the pinned hashes without rewriting the lock
 *
 * Maintainer-only. Plain Node ESM, no dependencies.
 */

import { createHash } from 'node:crypto'
import { readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const MAX_BYTES = 200 * 1024 * 1024
const TIMEOUT_MS = 10 * 60_000

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const lockPath = join(root, 'toolkit.lock.json')
const args = process.argv.slice(2)
const check = args.includes('--check')
const only = new Set(args.flatMap((arg, i) => (arg === '--tool' && args[i + 1] ? [args[i + 1]] : [])))

const lock = JSON.parse(await readFile(lockPath, 'utf8'))
if (lock.schemaVersion !== 1 || typeof lock.tools !== 'object' || lock.tools === null) {
  fail('toolkit.lock.json: unsupported schema')
}

let failures = 0
for (const [id, tool] of Object.entries(lock.tools)) {
  if (only.size > 0 && !only.has(id)) continue
  let upstream
  if (tool.checksumsUrl) {
    try {
      upstream = parseChecksums(await downloadText(tool.checksumsUrl))
    } catch (error) {
      console.warn(`warning: ${id}: upstream checksums unavailable (${error instanceof Error ? error.message : error})`)
    }
  }
  for (const [platform, asset] of Object.entries(tool.assets ?? {})) {
    const label = `${id} ${tool.version} ${platform}`
    try {
      if (!/^https:\/\//.test(asset.url)) throw new Error('asset URL must use https')
      const { sha256, size } = await hashDownload(asset.url)
      const fileName = decodeURIComponent(new URL(asset.url).pathname.split('/').pop() ?? '')
      const expected = upstream?.get(fileName)
      if (upstream && !expected) throw new Error(`${fileName} is missing from the upstream checksums file`)
      if (expected && expected !== sha256) throw new Error(`upstream checksum ${expected} != downloaded ${sha256}`)
      if (check) {
        if (asset.sha256 !== sha256) throw new Error(`pinned ${asset.sha256} != downloaded ${sha256}`)
        console.log(`ok      ${label}`)
      } else {
        asset.sha256 = sha256
        asset.size = size
        console.log(`pinned  ${label}  ${sha256}  ${size} bytes${expected ? '  (matches upstream)' : ''}`)
      }
    } catch (error) {
      failures++
      console.error(`FAILED  ${label}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

if (!check) {
  const tmp = `${lockPath}.tmp`
  await writeFile(tmp, `${JSON.stringify(lock, null, 2)}\n`)
  await rename(tmp, lockPath)
  console.log(`wrote ${lockPath}`)
}
if (failures > 0) fail(`${failures} asset(s) failed`)

async function hashDownload(url) {
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT_MS) })
  if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`)
  const hash = createHash('sha256')
  let size = 0
  for await (const chunk of response.body) {
    size += chunk.byteLength
    if (size > MAX_BYTES) throw new Error(`asset exceeds ${MAX_BYTES} bytes`)
    hash.update(chunk)
  }
  return { sha256: hash.digest('hex'), size }
}

async function downloadText(url) {
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(60_000) })
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`)
  return await response.text()
}

/** `sha256  filename` lines (sha256sum / goreleaser format). */
function parseChecksums(text) {
  const map = new Map()
  for (const line of text.split(/\r?\n/)) {
    const match = /^([0-9a-f]{64})\s+\*?(\S+)$/i.exec(line.trim())
    if (match) map.set(match[2], match[1].toLowerCase())
  }
  return map
}

function fail(message) {
  console.error(message)
  process.exit(1)
}
