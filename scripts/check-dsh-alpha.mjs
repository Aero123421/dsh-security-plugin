#!/usr/bin/env node
/**
 * Checks this plugin against the newest published DSH alpha.
 *
 * DSH boots a plugin only when every `@deepseek-ai/dsh` and `@deepseek-ai/dsh-*`
 * peer range satisfies `semver.satisfies(runtime, range, { includePrerelease: true })`
 * (`evaluatePluginCompatibility` in `@deepseek-ai/dsh-app-boot`). A miss disables
 * the plugin before it loads.
 *
 *   node scripts/check-dsh-alpha.mjs [--skip-types] [--skip-boot]
 *
 * The command needs network, npm, and pnpm. It resolves the `alpha` dist-tag of
 * `@deepseek-ai/dsh`, checks that tag and the 0.2.x prerelease policy, typechecks
 * `tsconfig.test.json` against that release's SDK, and boots a scratch web profile
 * far enough to call `getBootstrap`. DevDependency pins stay on the minimum
 * supported release; the typecheck step restores `package.json` and `pnpm-lock.yaml`.
 */

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const skipTypes = process.argv.includes('--skip-types')
const skipBoot = process.argv.includes('--skip-boot')
const semverSpec = 'semver@^7.8.5'
/** Same option DSH passes to `semver.satisfies` when it admits a plugin. */
const includePrerelease = { includePrerelease: true }
const sdkPackages = ['@deepseek-ai/dsh-llm', '@deepseek-ai/dsh-client-connection', '@deepseek-ai/dsh-workspace']
/** Versions the `@deepseek-ai/dsh` peer range must keep admitting or rejecting. */
const mustAdmit = [
  '0.2.1-alpha.2',
  '0.2.1-alpha.3',
  '0.2.1-alpha.10',
  '0.2.2-0',
  '0.2.2-alpha.1',
  '0.2.9-rc.1',
  '0.2.10',
]
const mustReject = ['0.2.1-alpha.1', '0.2.0', '0.3.0-0', '0.3.0-alpha.1', '0.3.0']
const readyMs = 90_000
const installMs = 180_000

const workspaceProtocols = new Set(['workspace:^', 'workspace:~', 'workspace:*'])

let server
let serverOutput = { stdout: '', stderr: '' }

try {
  const alpha = npmAlpha()
  console.log(`@deepseek-ai/dsh alpha dist-tag: ${alpha}`)
  const semver = installSemver()
  checkPeerRange(semver, alpha)
  if (!skipTypes) typecheckAgainstAlpha(semver, alpha)
  else console.log('skipping SDK typecheck (--skip-types)')
  if (!skipBoot) await bootWebProfile(alpha)
  else console.log('skipping web boot (--skip-boot)')
  console.log('check-dsh-alpha: OK')
} catch (error) {
  console.error(error instanceof Error ? error.message : error)
  process.exitCode = 1
} finally {
  await stopServer()
}

function npmAlpha() {
  const value = npmJson(['@deepseek-ai/dsh', 'dist-tags.alpha'])
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`npm dist-tag alpha for @deepseek-ai/dsh was ${JSON.stringify(value)}`)
  }
  return value
}

function installSemver() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-semver-'))
  run('npm', ['init', '-y'], { cwd: dir })
  run('npm', ['install', '--silent', '--no-audit', '--no-fund', semverSpec], { cwd: dir, timeout: installMs })
  const installed = JSON.parse(readFileSync(join(dir, 'node_modules', 'semver', 'package.json'), 'utf8'))
  console.log(`semver ${installed.version} (DSH app-boot depends on ${semverSpec})`)
  return createRequire(join(dir, 'package.json'))('semver')
}

function checkPeerRange(semver, alpha) {
  if (semver.valid(alpha) === null) throw new Error(`alpha dist-tag ${alpha} is not a semantic version`)
  const peers = dshPeers(readPackage())
  if (!Object.hasOwn(peers, '@deepseek-ai/dsh')) {
    throw new Error('package.json is missing peerDependencies["@deepseek-ai/dsh"]')
  }
  for (const version of mustAdmit) {
    if (!satisfies(semver, version, peers['@deepseek-ai/dsh'])) {
      throw new Error(`peer range ${peers['@deepseek-ai/dsh']} does not admit ${version} with includePrerelease`)
    }
  }
  for (const version of mustReject) {
    if (satisfies(semver, version, peers['@deepseek-ai/dsh'])) {
      throw new Error(`peer range ${peers['@deepseek-ai/dsh']} admits ${version}; DSH would load this plugin there`)
    }
  }
  for (const [name, range] of Object.entries(peers)) {
    if (!satisfies(semver, alpha, range)) {
      throw new Error(
        `DSH ${alpha} would skip this plugin at boot: peerDependencies[${JSON.stringify(name)}] ${JSON.stringify(range)} does not match`,
      )
    }
    console.log(`peer ${name} ${range} admits ${alpha}`)
  }
}

function dshPeers(pkg) {
  const declared = pkg.peerDependencies
  if (typeof declared !== 'object' || declared === null || Array.isArray(declared)) {
    throw new Error('package.json peerDependencies must be an object')
  }
  const peers = {}
  for (const [name, range] of Object.entries(declared)) {
    if (name !== '@deepseek-ai/dsh' && !name.startsWith('@deepseek-ai/dsh-')) continue
    if (typeof range !== 'string') throw new Error(`peerDependencies[${JSON.stringify(name)}] must be a string`)
    peers[name] = range
  }
  return peers
}

function satisfies(semver, runtime, range) {
  const requirement = workspaceProtocols.has(range) ? runtime : range
  if (requirement.trim() === '') return false
  return semver.satisfies(runtime, requirement, includePrerelease)
}

function typecheckAgainstAlpha(semver, alpha) {
  for (const name of sdkPackages) {
    const published = npmJson([`${name}@${alpha}`, 'version'])
    if (published !== alpha) {
      throw new Error(`${name}@${alpha} resolved to ${JSON.stringify(published)}`)
    }
  }
  const cordisRange = npmJson([`@deepseek-ai/dsh@${alpha}`, 'dependencies.@deepseek-ai/cordis'])
  if (typeof cordisRange !== 'string') {
    throw new Error(`@deepseek-ai/dsh@${alpha} has no string @deepseek-ai/cordis dependency`)
  }
  const cordis = highestVersion(semver, npmJson([`@deepseek-ai/cordis@${cordisRange}`, 'version']))
  console.log(`typecheck SDK ${alpha}, @deepseek-ai/cordis@${cordis} (${cordisRange})`)

  const packagePath = join(root, 'package.json')
  const lockPath = join(root, 'pnpm-lock.yaml')
  const packageBackup = readFileSync(packagePath)
  const lockBackup = readFileSync(lockPath)
  let typecheckError
  try {
    run('pnpm', ['add', '-D', ...sdkPackages.map(name => `${name}@${alpha}`), `@deepseek-ai/cordis@${cordis}`], {
      cwd: root,
      timeout: installMs,
    })
    run('pnpm', ['exec', 'tsc', '-p', 'tsconfig.test.json', '--noEmit'], { cwd: root, timeout: installMs })
    console.log('tsconfig.test.json typechecks against the alpha SDK')
  } catch (error) {
    typecheckError = error
  } finally {
    writeFileSync(packagePath, packageBackup)
    writeFileSync(lockPath, lockBackup)
    try {
      run('pnpm', ['install', '--frozen-lockfile'], { cwd: root, timeout: installMs })
      console.log('restored devDependency pins')
    } catch (restoreError) {
      const detail = restoreError instanceof Error ? restoreError.message : String(restoreError)
      typecheckError = new Error(
        `${typecheckError instanceof Error ? typecheckError.message : 'typecheck failed'}\nrestoring the lockfile also failed: ${detail}`,
      )
    }
  }
  if (typecheckError) throw typecheckError
}

function highestVersion(semver, value) {
  const versions = (Array.isArray(value) ? value : [value]).filter(
    item => typeof item === 'string' && semver.valid(item),
  )
  const [best] = versions.sort(semver.rcompare)
  if (best === undefined) throw new Error(`npm returned no cordis version from ${JSON.stringify(value)}`)
  return best
}

async function bootWebProfile(alpha) {
  const home = mkdtempSync(join(tmpdir(), 'dsh-home-'))
  const installDir = mkdtempSync(join(tmpdir(), 'dsh-install-'))
  try {
    const env = { ...process.env, DSH_HOME: home }
    console.log(`installing @deepseek-ai/dsh@${alpha} into a scratch profile`)
    run('npm', ['init', '-y'], { cwd: installDir })
    run('npm', ['install', '--no-audit', '--no-fund', `@deepseek-ai/dsh@${alpha}`], {
      cwd: installDir,
      timeout: installMs,
    })
    run('npx', ['dsh', 'plugin', '--profile', 'web', 'add', '-w', root], { cwd: installDir, env, timeout: installMs })

    serverOutput = { stdout: '', stderr: '' }
    server = spawn('npx', ['dsh', '--profile', 'web', '--no-open', '--port', '0'], {
      cwd: installDir,
      env,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const url = await waitForWebUrl()
    const disabled = serverOutput.stderr
      .split('\n')
      .find(line => line.includes('disabling profile plugin') && line.includes('dsh-security'))
    if (disabled !== undefined) {
      throw new Error(`DSH disabled the plugin at boot: ${redact(disabled)}`)
    }
    const body = await callBootstrap(url)
    const version = readPackage().version
    const reported = body?.result?.ok === true ? body.result.value?.pluginVersion : undefined
    if (reported !== version) {
      throw new Error(`getBootstrap did not report plugin ${version}: ${redact(JSON.stringify(body)).slice(0, 500)}`)
    }
    const database = join(home, 'security', 'security.db')
    if (!existsSync(database)) throw new Error(`the plugin did not create ${database}`)
    console.log(`scratch web profile booted DSH ${alpha}; getBootstrap reports ${version}`)
  } finally {
    await stopServer()
    rmSync(home, { recursive: true, force: true })
    rmSync(installDir, { recursive: true, force: true })
  }
}

function waitForWebUrl() {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = callback => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      callback()
    }
    const timer = setTimeout(() => {
      finish(() =>
        reject(
          new Error(`web server did not become ready within ${readyMs}ms\n${redact(serverOutput.stderr).slice(-2000)}`),
        ),
      )
    }, readyMs)
    const onData = stream => chunk => {
      serverOutput[stream] += chunk.toString()
      const match = serverOutput.stdout.match(/dsh web: (https?:\/\/127\.0\.0\.1:\d+\/\?token=\S+)/)
      if (match?.[1]) finish(() => resolve(match[1]))
    }
    server.stdout.on('data', onData('stdout'))
    server.stderr.on('data', onData('stderr'))
    server.once('error', error => finish(() => reject(error)))
    server.once('exit', code => {
      finish(() =>
        reject(
          new Error(
            `dsh exited ${code} before it was ready\n${redact(serverOutput.stderr).slice(-2000)}\n${redact(serverOutput.stdout).slice(-500)}`,
          ),
        ),
      )
    })
  })
}

async function callBootstrap(url) {
  const index = await fetchLaunch(url)
  if (index.status !== 303) throw new Error(`launch URL returned HTTP ${index.status}; expected the cookie redirect`)
  const cookies = typeof index.headers.getSetCookie === 'function' ? index.headers.getSetCookie() : []
  const cookie = cookies.map(entry => entry.split(';')[0]).join('; ')
  if (cookie === '') throw new Error('launch URL did not set a session cookie')
  const origin = new URL(url).origin
  const payload = JSON.stringify({
    type: 'client-request',
    rpcId: 'dsh-alpha-check',
    method: 'dsh-security/getBootstrap',
    payload: {},
  })
  let response
  let text = ''
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    response = await fetch(`${origin}/api/dsh-security/getBootstrap`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin, cookie },
      body: payload,
    })
    text = await response.text()
    if (response.status !== 404) break
    await new Promise(resolve => setTimeout(resolve, 300))
  }
  if (response === undefined || response.status !== 200) {
    throw new Error(`getBootstrap returned HTTP ${response?.status ?? 'no response'}: ${redact(text).slice(0, 300)}`)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`getBootstrap returned non-JSON: ${redact(text).slice(0, 300)}`)
  }
}

async function fetchLaunch(url) {
  let last = 'the server did not accept the launch URL'
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    try {
      return await fetch(url, { redirect: 'manual' })
    } catch (error) {
      last = redact(error instanceof Error ? error.message : String(error))
      await new Promise(resolve => setTimeout(resolve, 300))
    }
  }
  throw new Error(`launch URL was not reachable: ${last}`)
}

async function stopServer() {
  const child = server
  server = undefined
  if (child === undefined || child.exitCode !== null || child.signalCode !== null) return
  signalGroup(child, 'SIGTERM')
  await new Promise(resolve => {
    const timer = setTimeout(() => {
      signalGroup(child, 'SIGKILL')
      resolve()
    }, 5_000)
    child.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

function signalGroup(child, signal) {
  try {
    process.kill(-child.pid, signal)
  } catch {
    try {
      child.kill(signal)
    } catch {
      // The process already exited.
    }
  }
}

function readPackage() {
  return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
}

function npmJson(viewArgs) {
  const stdout = capture('npm', ['view', ...viewArgs, '--json'])
  try {
    return JSON.parse(stdout)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`could not parse npm view ${viewArgs.join(' ')}: ${detail}\n${stdout.slice(0, 300)}`)
  }
}

function capture(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited ${result.status}\n${result.stderr ?? ''}`)
  }
  return result.stdout
}

function run(command, args, options) {
  const result = spawnSync(command, args, { stdio: 'inherit', ...options })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} exited ${result.status}`)
}

function redact(text) {
  return text.replace(/token=[^\s&]+/g, 'token=<redacted>').replace(/dsh-auth-[^=;\s]+=[^;\s]+/g, 'dsh-auth-<redacted>')
}
