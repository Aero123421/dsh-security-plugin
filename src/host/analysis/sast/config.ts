/**
 * Small line-based checks for container and deployment configuration:
 * Dockerfiles, docker-compose files and Kubernetes manifests.
 */

import type { SnapshotFile } from '../types.ts'
import { cweUrl, type FileContext, REF, type RuleMeta } from './rule.ts'

const DOCKER_REMOTE_ADD: RuleMeta = {
  id: 'docker.add-remote-url',
  title: 'Dockerfile ADD downloads from a URL',
  category: 'misconfiguration',
  cwe: 'CWE-829',
  severity: 'low',
  message:
    '`ADD <url>` downloads a file at build time without verifying its checksum, so a compromised or changed server can slip different content into your image.',
  recommendation:
    'Download with `curl -fsSL` and verify a pinned SHA-256 checksum (or use `ADD --checksum=sha256:...`), or `COPY` a vendored file.',
  references: [REF.integrity, cweUrl('CWE-829'), cweUrl('CWE-494')],
}

const DOCKER_PIPE_SHELL: RuleMeta = {
  id: 'docker.curl-pipe-shell',
  title: 'Remote script piped into a shell',
  category: 'misconfiguration',
  cwe: 'CWE-494',
  severity: 'low',
  message:
    'A script is downloaded and executed immediately (`curl ... | sh`). Whoever controls that URL, or anyone who can tamper with the download, runs code inside your build.',
  recommendation:
    'Download the script to a file, verify a pinned checksum or signature, then run it. Prefer distribution packages or pinned release artifacts.',
  references: [REF.integrity, cweUrl('CWE-494')],
}

const DOCKER_ENV_SECRET: RuleMeta = {
  id: 'docker.secret-in-env',
  title: 'Secret value baked into the image',
  category: 'secrets',
  cwe: 'CWE-798',
  severity: 'medium',
  message:
    'A password, token or key is set with `ENV`/`ARG` in the Dockerfile. It is stored in the image layers and visible to anyone who can pull the image (`docker history`, `docker inspect`).',
  recommendation:
    'Pass secrets at runtime (environment from your orchestrator, Docker/Kubernetes secrets) or use BuildKit `RUN --mount=type=secret` during the build.',
  references: [REF.misconfig, cweUrl('CWE-798'), cweUrl('CWE-538')],
}

const PRIVILEGED: RuleMeta = {
  id: 'container.privileged',
  title: 'Privileged container',
  category: 'misconfiguration',
  cwe: 'CWE-250',
  severity: 'medium',
  message:
    '`privileged: true` gives the container almost all host capabilities and device access. A compromise of the application inside it is effectively a compromise of the host.',
  recommendation:
    'Remove `privileged`. Grant only the specific capabilities the workload needs with `cap_add`/`capabilities.add`.',
  references: [REF.misconfig, cweUrl('CWE-250')],
}

const HOST_NETWORK: RuleMeta = {
  id: 'container.host-network',
  title: 'Container shares the host network',
  category: 'misconfiguration',
  cwe: 'CWE-668',
  severity: 'low',
  message:
    'The container uses the host’s network stack (`network_mode: host` / `hostNetwork: true`). It can reach services bound to localhost on the host and bypasses network isolation.',
  recommendation: 'Use the default bridge/pod network and publish only the ports you need.',
  references: [REF.misconfig, cweUrl('CWE-668')],
}

const PRIV_ESCALATION: RuleMeta = {
  id: 'k8s.allow-privilege-escalation',
  title: 'Privilege escalation allowed',
  category: 'misconfiguration',
  cwe: 'CWE-250',
  severity: 'low',
  message:
    '`allowPrivilegeEscalation: true` lets processes in the container gain more privileges than their parent (for example through setuid binaries).',
  recommendation:
    'Set `allowPrivilegeEscalation: false`, `runAsNonRoot: true` and drop all capabilities in the `securityContext`.',
  references: [REF.misconfig, cweUrl('CWE-250')],
}

/** Every rule of this rule set (several matchers may share one id). */
export const CONFIG_RULES: readonly RuleMeta[] = [
  DOCKER_REMOTE_ADD,
  DOCKER_PIPE_SHELL,
  DOCKER_ENV_SECRET,
  PRIVILEGED,
  HOST_NETWORK,
  PRIV_ESCALATION,
]

const SECRET_NAME = /(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)/i
const NOT_SECRET_NAME =
  /(?:_FILE|_PATH|_DIR|_URL|_HOST|_PORT|_USER(?:NAME)?|_NAME|_ID|_LENGTH|_TTL|_EXPIRY|_EXPIRES?)$/i
const PLACEHOLDER =
  /^(?:|changeme|change[-_]?me|replace[-_]?me|example|dummy|placeholder|secret|password|token|xxx+|\*+|none|null|true|false|<[^>]*>)$/i

/** Whether the file is handled by the config rules. */
export function isConfigFile(file: Pick<SnapshotFile, 'path' | 'language'>): boolean {
  return file.language === 'dockerfile' || file.language === 'yaml'
}

/** Run the config rules over one file. */
export function configRules(ctx: FileContext): void {
  const { file } = ctx
  if (file.language === 'dockerfile') dockerfile(ctx)
  else if (file.language === 'yaml') yaml(ctx)
}

function dockerfile(ctx: FileContext): void {
  const content = ctx.file.content
  for (const { text, start, end } of logicalLines(content, '\\')) {
    const instr = /^\s*([A-Za-z]+)\s+([\s\S]*)$/.exec(text)
    if (!instr) continue
    const op = instr[1]!.toUpperCase()
    const args = instr[2] ?? ''
    if (op === 'ADD') {
      if (/(?:^|\s)https?:\/\//i.test(args) && !/--checksum=/.test(args)) {
        ctx.report({ rule: DOCKER_REMOTE_ADD, kind: 'vulnerability', span: { start, end }, confidence: 'high' })
      }
    } else if (op === 'RUN') {
      if (
        /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:-E\s+)?(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)\b/.test(
          args,
        )
      ) {
        ctx.report({ rule: DOCKER_PIPE_SHELL, kind: 'vulnerability', span: { start, end }, confidence: 'high' })
      }
    } else if (op === 'ENV' || op === 'ARG') {
      for (const m of args.matchAll(
        /(?:^|\s)([A-Za-z_][\w.-]*)(?:=|\s+(?=[^=\s]+$))("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"']+)/g,
      )) {
        const name = m[1]!
        const raw = m[2]!
        const value = raw.replace(/^["']|["']$/g, '')
        if (!SECRET_NAME.test(name) || NOT_SECRET_NAME.test(name)) continue
        if (PLACEHOLDER.test(value) || /^\$\{?\w+\}?$/.test(value) || value.length < 4) continue
        const valueStart = start + text.indexOf(m[0]) + m[0].lastIndexOf(raw)
        ctx.report({
          rule: DOCKER_ENV_SECRET,
          kind: 'vulnerability',
          span: { start, end },
          confidence: op === 'ENV' ? 'high' : 'medium',
          mask: [{ start: valueStart, end: valueStart + raw.length }],
        })
      }
    }
  }
}

function yaml(ctx: FileContext): void {
  const { file } = ctx
  const content = file.content
  const lower = file.path.toLowerCase()
  const compose = /(?:^|\/)(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/.test(lower)
  const k8s = !compose && /^\s*apiVersion\s*:/m.test(content) && /^\s*kind\s*:/m.test(content)
  if (!compose && !k8s) return
  for (const m of content.matchAll(/^[ \t-]*privileged[ \t]*:[ \t]*(?:true|yes|"true"|'true')[ \t]*(?:#.*)?$/gim)) {
    ctx.report({ rule: PRIVILEGED, kind: 'vulnerability', span: lineSpan(m), confidence: 'high' })
  }
  const hostNet = compose
    ? /^[ \t-]*network_mode[ \t]*:[ \t]*["']?host["']?[ \t]*(?:#.*)?$/gim
    : /^[ \t-]*hostNetwork[ \t]*:[ \t]*(?:true|"true"|'true')[ \t]*(?:#.*)?$/gim
  for (const m of content.matchAll(hostNet))
    ctx.report({ rule: HOST_NETWORK, kind: 'vulnerability', span: lineSpan(m), confidence: 'high' })
  if (k8s) {
    for (const m of content.matchAll(
      /^[ \t-]*allowPrivilegeEscalation[ \t]*:[ \t]*(?:true|"true"|'true')[ \t]*(?:#.*)?$/gim,
    )) {
      ctx.report({ rule: PRIV_ESCALATION, kind: 'vulnerability', span: lineSpan(m), confidence: 'high' })
    }
  }
}

function lineSpan(m: RegExpMatchArray): { start: number; end: number } {
  const start = (m.index ?? 0) + (m[0].length - m[0].trimStart().length)
  return { start, end: (m.index ?? 0) + m[0].trimEnd().length }
}

/** Join lines ending with the continuation character; skip comments and blank lines. */
function logicalLines(content: string, continuation: string): { text: string; start: number; end: number }[] {
  const out: { text: string; start: number; end: number }[] = []
  let start = -1
  let text = ''
  let offset = 0
  for (const line of content.split('\n')) {
    const lineStart = offset
    offset += line.length + 1
    const trimmed = line.replace(/\r$/, '')
    if (start < 0) {
      if (/^\s*(?:#|$)/.test(trimmed)) continue
      start = lineStart
      text = ''
    } else if (/^\s*#/.test(trimmed)) continue
    if (trimmed.trimEnd().endsWith(continuation)) {
      text += `${trimmed.trimEnd().slice(0, -continuation.length)} `
      continue
    }
    text += trimmed
    out.push({ text, start, end: lineStart + trimmed.length })
    start = -1
  }
  if (start >= 0) out.push({ text, start, end: content.length })
  return out
}
