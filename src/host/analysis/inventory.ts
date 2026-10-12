/**
 * Cheap, synchronous overview of a snapshot: languages, manifests, frameworks.
 * Used for scan estimates and to steer which analyzers and prompts apply.
 */

import type { Inventory, Language, Snapshot, SnapshotFile } from './types.ts'

const MANIFEST_NAMES: ReadonlySet<string> = new Set([
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'pipfile',
  'pipfile.lock',
  'pyproject.toml',
  'poetry.lock',
  'uv.lock',
  'setup.py',
  'setup.cfg',
  'go.mod',
  'go.sum',
  'cargo.toml',
  'cargo.lock',
  'gemfile',
  'gemfile.lock',
  'composer.json',
  'composer.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
])

const MANIFEST_PATTERNS: readonly RegExp[] = [
  /^requirements[^/]*\.(?:txt|in)$/i,
  /^dockerfile(?:\.[^/]*)?$/i,
  /\.dockerfile$/i,
  /^(?:docker-)?compose[^/]*\.ya?ml$/i,
  /\.tf$/i,
]

const K8S_MAX_BYTES = 200 * 1024

/** npm package name → framework label. */
const NPM_FRAMEWORKS: Readonly<Record<string, string>> = {
  express: 'express',
  fastify: 'fastify',
  koa: 'koa',
  '@koa/router': 'koa',
  'koa-router': 'koa',
  hono: 'hono',
  '@nestjs/core': 'nestjs',
  next: 'next',
  nuxt: 'nuxt',
  '@sveltejs/kit': 'sveltekit',
  'apollo-server': 'apollo-server',
  'apollo-server-express': 'apollo-server',
  '@apollo/server': 'apollo-server',
  'graphql-yoga': 'graphql-yoga',
  'socket.io': 'socket.io',
  prisma: 'prisma',
  '@prisma/client': 'prisma',
  sequelize: 'sequelize',
  typeorm: 'typeorm',
  mongoose: 'mongoose',
  knex: 'knex',
  'drizzle-orm': 'drizzle-orm',
  jsonwebtoken: 'jsonwebtoken',
  passport: 'passport',
  'next-auth': 'next-auth',
  '@auth/core': 'next-auth',
  'express-session': 'express-session',
  helmet: 'helmet',
  cors: 'cors',
}

/** Normalized (PEP 503) PyPI name → framework label. */
const PYTHON_FRAMEWORKS: Readonly<Record<string, string>> = {
  flask: 'flask',
  fastapi: 'fastapi',
  django: 'django',
  djangorestframework: 'django',
  starlette: 'starlette',
  aiohttp: 'aiohttp',
  tornado: 'tornado',
  sqlalchemy: 'sqlalchemy',
  pyjwt: 'pyjwt',
  jwt: 'pyjwt',
  'python-jose': 'python-jose',
  pydantic: 'pydantic',
  celery: 'celery',
}

/** Summarize languages, manifests, frameworks, and test files in a snapshot. */
export function buildInventory(snapshot: Snapshot): Inventory {
  const languages = new Map<Language, { files: number; bytes: number }>()
  const manifests: string[] = []
  const frameworks = new Set<string>()
  let testFiles = 0

  for (const file of snapshot.files.values()) {
    const entry = languages.get(file.language) ?? { files: 0, bytes: 0 }
    entry.files += 1
    entry.bytes += file.size
    languages.set(file.language, entry)
    if (file.isTest) testFiles += 1
    if (isManifest(file)) manifests.push(file.path)

    const name = baseName(file.path).toLowerCase()
    if (name === 'package.json') collectNpmFrameworks(file.content, frameworks)
    else if (/^requirements[^/]*\.(?:txt|in)$/.test(name)) collectRequirementsFrameworks(file.content, frameworks)
    else if (name === 'pyproject.toml' || name === 'pipfile') collectTomlFrameworks(file.content, frameworks)
  }

  return {
    languages: [...languages.entries()]
      .map(([language, stats]) => ({ language, files: stats.files, bytes: stats.bytes }))
      .sort((a, b) => b.files - a.files || b.bytes - a.bytes || compareStrings(a.language, b.language)),
    frameworks: [...frameworks].sort(compareStrings),
    manifests: manifests.sort(compareStrings),
    testFiles,
  }
}

function isManifest(file: SnapshotFile): boolean {
  const name = baseName(file.path)
  if (MANIFEST_NAMES.has(name.toLowerCase())) return true
  if (MANIFEST_PATTERNS.some(pattern => pattern.test(name))) return true
  if (file.language === 'yaml' && file.size <= K8S_MAX_BYTES) {
    return /^apiVersion:\s*\S/m.test(file.content) && /^kind:\s*\S/m.test(file.content)
  }
  return false
}

function collectNpmFrameworks(content: string, out: Set<string>): void {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch {
    return
  }
  if (!isRecord(parsed)) return
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = parsed[field]
    if (!isRecord(deps)) continue
    for (const name of Object.keys(deps)) {
      const label = NPM_FRAMEWORKS[name] ?? (name.startsWith('@remix-run/') ? 'remix' : undefined)
      if (label) out.add(label)
    }
  }
}

function collectRequirementsFrameworks(content: string, out: Set<string>): void {
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim()
    if (line === '' || line.startsWith('-')) continue
    const name = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line)?.[1]
    addPython(name, out)
  }
}

/**
 * Pick dependency names out of pyproject.toml / Pipfile without a TOML parser:
 * PEP 621 arrays (`"fastapi>=0.1"`), Poetry/Pipfile tables (`fastapi = "^0.1"`).
 */
function collectTomlFrameworks(content: string, out: Set<string>): void {
  const DEP_KEY = /dependencies|packages|requires/
  let section = ''
  let arrayDepth = 0
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$/, '').trim()
    if (arrayDepth > 0) {
      collectQuotedRequirements(line, out)
      arrayDepth += bracketDelta(line)
      continue
    }
    const header = /^\[\[?([^\]]+)\]\]?$/.exec(line)
    if (header) {
      section = header[1]!.trim().toLowerCase()
      continue
    }
    const kv = /^["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=\s*(.*)$/.exec(line)
    if (!kv) continue
    const key = kv[1]!
    const value = kv[2]!
    const depSection = DEP_KEY.test(section)
    if (depSection) addPython(key, out)
    if (value.startsWith('[') && (depSection || DEP_KEY.test(key.toLowerCase()))) {
      collectQuotedRequirements(value, out)
      arrayDepth = Math.max(0, bracketDelta(value))
    }
  }
}

/** PEP 508 strings inside a TOML array, e.g. `"fastapi[all]>=0.110"`. */
function collectQuotedRequirements(text: string, out: Set<string>): void {
  for (const match of text.matchAll(/["']\s*([A-Za-z0-9][A-Za-z0-9._-]*)/g)) addPython(match[1], out)
}

/** Net `[`/`]` count outside quoted strings. */
function bracketDelta(text: string): number {
  const bare = text.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, '')
  let delta = 0
  for (const ch of bare) {
    if (ch === '[') delta += 1
    else if (ch === ']') delta -= 1
  }
  return delta
}

function addPython(name: string | undefined, out: Set<string>): void {
  if (!name) return
  const label = PYTHON_FRAMEWORKS[name.toLowerCase().replace(/[-_.]+/g, '-')]
  if (label) out.add(label)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function baseName(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash < 0 ? path : path.slice(slash + 1)
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
