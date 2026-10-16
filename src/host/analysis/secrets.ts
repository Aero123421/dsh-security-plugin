/**
 * Built-in secret scanner and the redaction layer.
 *
 * Redaction is a hard boundary: every source excerpt that reaches a model, a
 * report, or the browser passes through `Redactor.redactFile` (snapshot
 * content with known match offsets) or `redactText` (arbitrary text). Secret
 * values are never stored: matches carry offsets, a hash, and a masked preview.
 */

import { createHash } from 'node:crypto'
import ignore from 'ignore'
import { type Severity, severityRank } from '../../shared/domain.ts'
import { isTestPath } from './snapshot.ts'
import { type Language, type Signal, type Snapshot, yieldToEventLoop } from './types.ts'

export type SecretConfidence = 'low' | 'medium' | 'high'

export interface SecretMatch {
  readonly ruleId: string
  readonly description: string
  readonly path: string
  /** 1-based line of the first secret character. */
  readonly line: number
  /** 1-based column of the first secret character. */
  readonly column: number
  readonly endLine: number
  /** 1-based column just past the last secret character (exclusive, as in SARIF). */
  readonly endColumn: number
  /** Character offset (UTF-16 index) of the secret in the file content. */
  readonly start: number
  /** Exclusive end offset. */
  readonly end: number
  readonly severity: Severity
  readonly confidence: SecretConfidence
  /** Hex SHA-256 of `ruleId`, `path`, and the secret value; never the value itself. */
  readonly fingerprint: string
  /** Masked value showing at most the first 4 characters. */
  readonly preview: string
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

interface RuleContext {
  readonly secret: string
  readonly groups: Readonly<Record<string, string | undefined>>
  /** Up to 48 characters preceding the whole match, for key-name context. */
  readonly before: string
}

interface SecretRule {
  readonly id: string
  readonly description: string
  /** Must carry the `g` and `d` flags; the `secret` group (or whole match) is the sensitive span. */
  readonly pattern: RegExp
  readonly severity: Severity
  readonly confidence: SecretConfidence
  /** Lower-case substrings; a file containing none of them is skipped for this rule. */
  readonly keywords: readonly string[]
  readonly minEntropy?: number
  /** Heuristic rules: excluded from `redactText` and reported with lower confidence. */
  readonly generic?: boolean
  readonly languages?: readonly Language[]
  /** Whole-text precondition (e.g. the file is a GCP service-account key). */
  readonly requires?: RegExp
  /** Structural check applied in both scan and redaction modes. */
  readonly validate?: (ctx: RuleContext) => boolean
  /** Scan-mode refinement: `false` drops the match, a value overrides confidence. */
  readonly refine?: (ctx: RuleContext) => SecretConfidence | false | undefined
}

const B = '(?<![A-Za-z0-9_-])'
const E = '(?![A-Za-z0-9_-])'

/** Ordered by priority: an earlier rule claims a span before later rules can overlap it. */
const RULES: readonly SecretRule[] = [
  {
    id: 'gcp-service-account',
    description: 'Google Cloud service-account private key',
    pattern: /"private_key"\s*:\s*"(?<secret>[^"]{64,16384})"/dg,
    requires: /"type"\s*:\s*"service_account"/,
    severity: 'critical',
    confidence: 'high',
    keywords: ['service_account'],
    validate: ({ secret }) => secret.includes('PRIVATE KEY'),
  },
  {
    id: 'private-key',
    description: 'Private key block',
    pattern:
      // The body may not cross another BEGIN marker, which keeps matching linear on hostile input.
      /-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----(?<secret>(?:(?!-----BEGIN )[\s\S]){16,32768}?)-----END (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----/dg,
    severity: 'critical',
    confidence: 'high',
    keywords: ['private key'],
    validate: ({ secret }) => looksLikeKeyMaterial(secret),
  },
  {
    id: 'aws-access-key-id',
    description: 'AWS access key ID',
    pattern: /(?<![A-Z0-9])(?<secret>(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})(?![A-Z0-9])/dg,
    severity: 'high',
    confidence: 'high',
    keywords: ['akia', 'asia', 'abia', 'acca', 'a3t'],
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS secret access key',
    pattern:
      /(?:aws[\w.-]{0,24}secret|secret[_.-]?access[_.-]?key)[\w.-]{0,24}["']?\s*(?::=|=>|:|=)\s*["']?(?<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/dgi,
    severity: 'critical',
    confidence: 'high',
    keywords: ['secret'],
    minEntropy: 3.5,
  },
  {
    id: 'github-token',
    description: 'GitHub token',
    pattern: new RegExp(`${B}(?<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'],
  },
  {
    id: 'github-fine-grained-token',
    description: 'GitHub fine-grained personal access token',
    pattern: new RegExp(`${B}(?<secret>github_pat_[A-Za-z0-9_]{60,251})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['github_pat_'],
  },
  {
    id: 'gitlab-token',
    description: 'GitLab personal access token',
    pattern: new RegExp(`${B}(?<secret>glpat-[A-Za-z0-9_-]{20,64})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['glpat-'],
  },
  {
    id: 'slack-token',
    description: 'Slack token',
    pattern: /(?<![A-Za-z0-9-])(?<secret>xox[abprse]-(?:[0-9]+-)?[A-Za-z0-9-]{10,250})(?![A-Za-z0-9-])/dg,
    severity: 'high',
    confidence: 'high',
    keywords: ['xoxb-', 'xoxa-', 'xoxp-', 'xoxr-', 'xoxs-', 'xoxe-'],
    validate: ({ secret }) => /\d/.test(secret),
  },
  {
    id: 'slack-webhook',
    description: 'Slack incoming webhook URL',
    pattern:
      /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/(?<secret>[A-Za-z0-9]{6,20}\/[A-Za-z0-9]{6,20}\/[A-Za-z0-9]{16,64})/dg,
    severity: 'medium',
    confidence: 'high',
    keywords: ['hooks.slack.com'],
    refine: ({ secret }) => (lowDiversity(secret.slice(secret.lastIndexOf('/') + 1)) ? false : undefined),
  },
  {
    id: 'stripe-secret-key',
    description: 'Stripe live secret key',
    pattern: new RegExp(`${B}(?<secret>sk_live_[A-Za-z0-9]{20,247})${E}`, 'dg'),
    severity: 'critical',
    confidence: 'high',
    keywords: ['sk_live_'],
  },
  {
    id: 'stripe-restricted-key',
    description: 'Stripe live restricted key',
    pattern: new RegExp(`${B}(?<secret>rk_live_[A-Za-z0-9]{20,247})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['rk_live_'],
  },
  {
    id: 'google-api-key',
    description: 'Google API key',
    pattern: new RegExp(`${B}(?<secret>AIza[0-9A-Za-z_-]{35})${E}`, 'dg'),
    severity: 'medium',
    confidence: 'medium',
    keywords: ['aiza'],
  },
  {
    id: 'anthropic-api-key',
    description: 'Anthropic API key',
    pattern: new RegExp(`${B}(?<secret>sk-ant-[A-Za-z0-9_-]{32,200})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['sk-ant-'],
  },
  {
    id: 'openai-api-key',
    description: 'OpenAI API key',
    pattern: new RegExp(
      `${B}(?<secret>sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,250}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|[A-Za-z0-9]{48})|sk-[A-Za-z0-9_-]{8,200}T3BlbkFJ[A-Za-z0-9_-]{8,200})${E}`,
      'dg',
    ),
    severity: 'high',
    confidence: 'high',
    keywords: ['sk-'],
  },
  {
    id: 'deepseek-api-key',
    description: 'DeepSeek API key',
    pattern: new RegExp(`${B}(?<secret>sk-[a-f0-9]{32})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['sk-'],
    minEntropy: 3,
  },
  {
    id: 'twilio-api-key',
    description: 'Twilio API key',
    pattern: /(?<![A-Za-z0-9])(?<secret>SK[0-9a-f]{32})(?![A-Za-z0-9])/dg,
    severity: 'high',
    confidence: 'medium',
    keywords: ['sk'],
    minEntropy: 3,
  },
  {
    id: 'twilio-auth-token',
    description: 'Twilio auth token',
    pattern:
      /twilio[\w.-]{0,30}(?:auth)?[_.-]?token["']?\s*(?::=|=>|:|=)\s*["']?(?<secret>[a-f0-9]{32})(?![A-Za-z0-9])/dgi,
    severity: 'high',
    confidence: 'high',
    keywords: ['twilio'],
    minEntropy: 3,
  },
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API key',
    pattern: new RegExp(`${B}(?<secret>SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['sg.'],
  },
  {
    id: 'npm-token',
    description: 'npm access token',
    pattern: new RegExp(`${B}(?<secret>npm_[A-Za-z0-9]{36})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['npm_'],
  },
  {
    id: 'pypi-token',
    description: 'PyPI upload token',
    pattern: new RegExp(`${B}(?<secret>pypi-AgE[A-Za-z0-9_-]{50,})${E}`, 'dg'),
    severity: 'high',
    confidence: 'high',
    keywords: ['pypi-age'],
  },
  {
    id: 'azure-storage-key',
    description: 'Azure storage or service-bus access key',
    pattern: /(?:AccountKey|SharedAccessKey)=(?<secret>[A-Za-z0-9+/]{30,120}={0,2})(?![A-Za-z0-9+/=])/dg,
    severity: 'critical',
    confidence: 'high',
    keywords: ['accountkey=', 'sharedaccesskey='],
    minEntropy: 3.5,
  },
  {
    id: 'jwt',
    description: 'JSON Web Token',
    pattern: new RegExp(
      `${B}(?<secret>eyJ[A-Za-z0-9_-]{5,4096}\\.eyJ[A-Za-z0-9_-]{5,8192}\\.[A-Za-z0-9_-]{16,1024})(?![A-Za-z0-9_.-])`,
      'dg',
    ),
    severity: 'medium',
    confidence: 'medium',
    keywords: ['eyj'],
    validate: ({ secret }) => isJwtHeader(secret.slice(0, secret.indexOf('.'))),
  },
  {
    id: 'database-url',
    description: 'Database or message-broker URL with an inline password',
    pattern:
      /(?<![A-Za-z0-9+])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/(?<user>[^:@/\s'"`]{0,128}):(?<secret>[^@/\s'"`]{1,256})@(?<host>[^\s/'"`:?#,]{1,255})/dg,
    severity: 'high',
    confidence: 'high',
    keywords: ['://'],
    validate: ({ secret }) => !isTemplateValue(secret),
    refine: ({ secret, groups }) => {
      const password = safeDecode(secret).toLowerCase()
      if (PLACEHOLDER_PASSWORDS.has(password) || /^[*x.]+$/.test(password) || /^%[sd]$/.test(password)) return false
      const host = (groups.host ?? '').toLowerCase()
      if (password === (groups.user ?? '').toLowerCase() || WEAK_DEFAULT_PASSWORDS.has(password)) return 'low'
      if (LOCAL_HOSTS.has(host)) return 'medium'
      return undefined
    },
  },
  {
    id: 'generic-secret',
    description: 'Hard-coded password, token, or API key',
    pattern:
      /(?<kw>pass(?:word|wd|phrase)|pwd|secret|api[_-]?key|token|private[_-]?key|credentials?)(?<suffix>[A-Za-z0-9_-]{0,40})["']?\s*(?::=|=>|===?|:|=)\s*(?<q>["'`])(?<secret>[^"'`\s\\]{12,256})\k<q>/dgi,
    severity: 'medium',
    confidence: 'low',
    keywords: ['pass', 'pwd', 'secret', 'api_key', 'apikey', 'api-key', 'token', 'private', 'credential'],
    minEntropy: 3.5,
    generic: true,
    refine: ({ secret, groups, before }) => {
      const prefix = /[A-Za-z0-9_.-]*$/.exec(before)?.[0] ?? ''
      return refineGeneric(secret, prefix + (groups.kw ?? '') + (groups.suffix ?? ''))
    },
  },
  {
    id: 'env-secret',
    description: 'Secret value in an environment file',
    pattern:
      /^[ \t]*(?:export[ \t]+)?(?<key>[A-Za-z0-9_.]{0,40}?(?:PASSWORD|PASSWD|PASS|SECRET|API_?KEY|TOKEN|PRIVATE_?KEY|CREDENTIALS?)[A-Za-z0-9_]{0,40})[ \t]*=[ \t]*["']?(?<secret>[^\s"'#]{8,256})/dgim,
    severity: 'medium',
    confidence: 'medium',
    keywords: ['pass', 'secret', 'key', 'token', 'credential'],
    minEntropy: 3,
    generic: true,
    languages: ['env'],
    refine: ({ secret, groups }) => {
      if (secret.startsWith('$') || secret.includes('://') || /^(?:true|false|null|none)$/i.test(secret)) return false
      if (KEY_NAME_EXCLUDE.test(groups.key ?? '')) return false
      return undefined
    },
  },
]

const PLACEHOLDER_PASSWORDS: ReadonlySet<string> = new Set([
  '',
  'password',
  'passwd',
  'pass',
  'pwd',
  'pw',
  'secret',
  'changeme',
  'mypassword',
  'yourpassword',
  'your_password',
  'your-password',
  'dbpassword',
  'db_password',
  'user:password',
])
const WEAK_DEFAULT_PASSWORDS: ReadonlySet<string> = new Set([
  'postgres',
  'root',
  'admin',
  'mysql',
  'redis',
  'guest',
  'mongo',
  'example',
])
const LOCAL_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '[::1]',
  'db',
  'database',
  'postgres',
  'postgresql',
  'mysql',
  'mariadb',
  'mongo',
  'mongodb',
  'redis',
  'rabbitmq',
  'host.docker.internal',
])

/** Values published in vendor documentation or emulators; never real credentials. */
const KNOWN_EXAMPLE_VALUES: ReadonlySet<string> = new Set([
  'AKIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  // Azurite / Azure Storage Emulator well-known key.
  'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==',
  // jwt.io sample token.
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
])

/** Markers that make any value a placeholder or a reference to a secret. */
const PLACEHOLDER_MARKERS =
  /^x{3}$|x{5,}|^\{[\w.-]*\}$|^\$[A-Za-z_]\w*$|%\(\w+\)s|\*{3,}|\.{3}|\u2026|<[^>]*>|\$\{|\{\{|\}\}|process\.env|os\.environ|getenv|replace[_-]?me|insert[_-]?(?:here|your)|0123456789|1234567890|abcdefghij/i
/**
 * Placeholder words after a non-alphanumeric boundary (`your-api-key`,
 * `sk-proj-example-key`). Random token bodies rarely contain separators, so
 * this almost never suppresses a real token.
 */
const PLACEHOLDER_WORDS =
  /(?:^|[^a-z0-9])(?:example|dummy|test|fake|sample|placeholder|redacted|changeme|change[_-]me|your[_-]?(?:api|key|token|secret|pass|own|access|private|client)|yourkey|mykey|secret[_-]?here|here$)/i
/** Longer values (key blocks) are judged by structural validation instead. */
const PLACEHOLDER_CHECK_MAX_LENGTH = 512

const KEY_NAME_EXCLUDE =
  /(?:url|uri|path|file|dir|name|type|field|label|header|endpoint|prefix|suffix|length|len|regex|pattern|count|limit|expiry|expires?|expiration|ttl|format|policy|hint|placeholder|message|msg|error|_at|_id|key_id|keyid|version|algorithm|alg|method|mode|kind|size|location|param|parameter|query|cookie_name|storage_key|_ref)$/i

const MAX_SCAN_CHARS = 2 * 1024 * 1024
const YIELD_EVERY = 50
const SNIPPET_MAX_LINES = 6
const SNIPPET_MAX_LINE_CHARS = 240

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Shannon entropy of a string in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0
  const counts = new Map<string, number>()
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  const total = [...value].length
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / total
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/**
 * Scan every snapshot file with the built-in rules. Files over 2 MB or
 * flagged as generated are skipped. Matches are sorted by path then offset.
 */
export async function scanSecrets(snapshot: Snapshot, signal?: AbortSignal): Promise<SecretMatch[]> {
  const matches: SecretMatch[] = []
  let index = 0
  for (const file of snapshot.files.values()) {
    if (++index % YIELD_EVERY === 0) await yieldToEventLoop()
    signal?.throwIfAborted()
    if (file.isGenerated || file.content.length > MAX_SCAN_CHARS) continue
    matches.push(...scanFileContent(file.path, file.content, { isTest: file.isTest, language: file.language }))
  }
  return matches.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.start - b.start))
}

/** Scan one file's text. Exposed for callers that hold content outside a snapshot. */
export function scanFileContent(
  path: string,
  content: string,
  options: { readonly isTest?: boolean; readonly language?: Language } = {},
): SecretMatch[] {
  const candidates = findCandidates(content, 'scan', options.language)
  if (candidates.length === 0) return []
  const starts = lineStarts(content)
  const downgrade =
    options.isTest === true || isTestPath(path) || /(?:^|[./_-])(?:example|sample|template|dist)$/i.test(path)
  return candidates.map(({ rule, start, end, confidence }) => {
    const secret = content.slice(start, end)
    const from = positionOf(starts, start)
    const to = positionOf(starts, end - 1)
    return {
      ruleId: rule.id,
      description: rule.description,
      path,
      line: from.line,
      column: from.column,
      endLine: to.line,
      endColumn: to.column + 1,
      start,
      end,
      severity: downgrade && severityRank(rule.severity) < severityRank('low') ? 'low' : rule.severity,
      confidence: downgrade ? lowerConfidence(confidence) : confidence,
      fingerprint: secretFingerprint(rule.id, path, secret),
      preview: maskSecret(secret),
    }
  })
}

/** Convert secret matches into analyzer signals with redacted snippets. */
export function secretSignals(matches: readonly SecretMatch[], snapshot: Snapshot): Signal[] {
  const redactor = new Redactor(matches)
  const redactedLines = new Map<string, readonly string[]>()
  const signals: Signal[] = []
  for (const match of matches) {
    let lines = redactedLines.get(match.path)
    if (!lines) {
      const file = snapshot.files.get(match.path)
      lines = file ? redactor.redactFile(match.path, file.content).split('\n') : []
      redactedLines.set(match.path, lines)
    }
    const last = Math.min(match.endLine, match.line + SNIPPET_MAX_LINES - 1)
    const snippet = lines
      .slice(match.line - 1, last)
      .map((line, i) => clipLine(line.replace(/\r$/, ''), i === 0 ? match.column : 1))
      .join('\n')
    const inTest = snapshot.files.get(match.path)?.isTest === true
    signals.push({
      analyzer: 'secrets',
      ruleId: match.ruleId,
      kind: 'secret',
      title: `Hard-coded secret: ${match.description}`,
      category: 'secrets',
      severity: match.severity,
      confidence: match.confidence,
      cwe: 'CWE-798',
      location: { path: match.path, startLine: match.line, endLine: match.endLine },
      snippet,
      message:
        `A value matching the "${match.description}" pattern (${match.preview}) is written directly into the source. ` +
        'Anyone who can read the repository, a fork, a backup, a build artifact, or its git history can copy it ' +
        'and use it to access the connected service as you.' +
        (inTest
          ? ' The file looks like a test or example, so it may be a dummy value; confirm before dismissing.'
          : ''),
      recommendation:
        'Treat the credential as compromised: revoke or rotate it with the provider now. Load it at runtime from an ' +
        'environment variable or a secret manager instead of source code, and purge it from git history ' +
        '(e.g. git filter-repo) because deleting the line does not remove earlier commits.',
      fingerprintParts: [match.ruleId, match.path, match.fingerprint],
      metadata: { preview: match.preview, column: match.column, secretStart: match.start, secretEnd: match.end },
    })
  }
  return signals
}

/**
 * Applies known secret spans to file content before it leaves the Host.
 * Every replacement keeps the original number of lines.
 */
export class Redactor {
  readonly #byPath = new Map<string, SecretMatch[]>()

  constructor(matches: readonly SecretMatch[]) {
    for (const match of matches) {
      const list = this.#byPath.get(match.path)
      if (list) list.push(match)
      else this.#byPath.set(match.path, [match])
    }
    for (const list of this.#byPath.values()) list.sort((a, b) => a.start - b.start)
  }

  /**
   * Replace each matched secret with `[REDACTED:<ruleId>]`, then apply the
   * stateless high-confidence patterns as a backstop. A recorded span whose
   * text no longer hashes to its fingerprint (content changed) is skipped and
   * left to the backstop rather than redacting the wrong characters.
   */
  redactFile(path: string, content: string): string {
    const matches = this.#byPath.get(path) ?? []
    let out = ''
    let cursor = 0
    for (const match of matches) {
      if (match.start < cursor || match.end > content.length) continue
      const secret = content.slice(match.start, match.end)
      if (secretFingerprint(match.ruleId, path, secret) !== match.fingerprint) continue
      out += content.slice(cursor, match.start) + redactSpan(secret, match.ruleId)
      cursor = match.end
    }
    out += content.slice(cursor)
    return redactText(out)
  }

  /**
   * The values behind the recorded secret spans, with their rule ids, longest
   * first. `contentOf` returns a file's current text; a span whose text no
   * longer hashes to its fingerprint is left out. Host-only: the result is
   * for scrubbing other text and must never be stored or sent anywhere.
   */
  secretValues(contentOf: (path: string) => string | undefined): { readonly value: string; readonly ruleId: string }[] {
    const seen = new Map<string, string>()
    for (const [path, matches] of this.#byPath) {
      const content = contentOf(path)
      if (content === undefined) continue
      for (const match of matches) {
        if (match.end > content.length || match.end <= match.start) continue
        const value = content.slice(match.start, match.end)
        if (secretFingerprint(match.ruleId, path, value) !== match.fingerprint) continue
        if (!seen.has(value)) seen.set(value, match.ruleId)
      }
    }
    return [...seen.entries()]
      .map(([value, ruleId]) => ({ value, ruleId }))
      .sort((a, b) => b.value.length - a.value.length)
  }
}

/**
 * Replace each of `secrets` wherever it occurs in `text` with
 * `[REDACTED:<ruleId>]` (line count preserved). A secret cut off at the end
 * of a clipped excerpt (`…`) is caught too when at least 6 characters of it
 * remain.
 */
export function redactKnownSecrets(
  text: string,
  secrets: readonly { readonly value: string; readonly ruleId: string }[],
): string {
  let out = text
  for (const { value, ruleId } of secrets) {
    if (value.length < 4) continue
    if (out.includes(value)) out = out.split(value).join(redactSpan(value, ruleId))
  }
  const clipped = /…\s*$/.exec(out)
  if (clipped) {
    const body = out.slice(0, clipped.index)
    for (const { value, ruleId } of secrets) {
      for (let n = Math.min(value.length - 1, body.length); n >= 6; n--) {
        if (body.endsWith(value.slice(0, n))) {
          out = `${body.slice(0, body.length - n)}[REDACTED:${ruleId}]${out.slice(clipped.index)}`
          return out
        }
      }
    }
  }
  return out
}

/**
 * Stateless redaction for arbitrary text (tool outputs, snippets, model
 * input). Applies every high-confidence rule, skipping only template values,
 * plus a fallback for private-key blocks whose END marker was cut off.
 */
export function redactText(text: string): string {
  if (text.length === 0) return text
  const candidates = findCandidates(text, 'redact', undefined)
  let out = ''
  let cursor = 0
  for (const { rule, start, end } of [...candidates].sort((a, b) => a.start - b.start)) {
    out += text.slice(cursor, start) + redactSpan(text.slice(start, end), rule.id)
    cursor = end
  }
  out += text.slice(cursor)
  return redactDanglingPrivateKeys(out)
}

const BUILTIN_SENSITIVE = ignore().add([
  '.env',
  '.env.*',
  '!.env.example',
  '!.env.sample',
  '!.env.template',
  '*.pem',
  '*.key',
  '*.p12',
  '*.pfx',
  '*.jks',
  '*.keystore',
  'id_rsa*',
  'id_dsa*',
  'id_ed25519*',
  'id_ecdsa*',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '_netrc',
  '.git-credentials',
  '.pgpass',
  '.htpasswd',
  '.dockercfg',
  '.s3cfg',
  // Cloud and container client credentials (anchored to their config directory, at any depth).
  '**/.aws/credentials',
  '**/.aws/config',
  '**/.docker/config.json',
  '**/.kube/config',
  'kubeconfig',
  'kubeconfig.*',
  '*.kubeconfig',
  'credentials.tfrc.json',
  'credentials.json',
  '*serviceaccount*.json',
  '*service-account*.json',
  '*service_account*.json',
  'secrets.yml',
  'secrets.yaml',
  '*.tfstate',
  '*.tfstate.*',
  'terraform.tfvars',
  '*.auto.tfvars',
])
let extraCache: { readonly key: string; readonly ig: ReturnType<typeof ignore> } | undefined

/**
 * Whether a workspace-relative path must never be shown to a model: built-in
 * credential files plus user `extraGlobs` (gitignore syntax). Invalid or
 * escaping paths are treated as sensitive.
 */
export function isSensitivePath(path: string, extraGlobs: readonly string[]): boolean {
  const normalized = path.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '')
  if (normalized === '' || normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) return true
  if (normalized.split('/').some(segment => segment === '..')) return true
  try {
    if (BUILTIN_SENSITIVE.ignores(normalized)) return true
    const globs = extraGlobs.filter(glob => glob.trim() !== '')
    if (globs.length === 0) return false
    const key = globs.join('\n')
    if (extraCache?.key !== key) extraCache = { key, ig: ignore().add(globs) }
    return extraCache.ig.ignores(normalized)
  } catch {
    return true
  }
}

// ---------------------------------------------------------------------------
// Matching engine
// ---------------------------------------------------------------------------

interface Candidate {
  readonly rule: SecretRule
  readonly start: number
  readonly end: number
  readonly confidence: SecretConfidence
}

function findCandidates(text: string, mode: 'scan' | 'redact', language: Language | undefined): Candidate[] {
  const lower = text.toLowerCase()
  const claimed = new SpanSet()
  const accepted: Candidate[] = []
  for (const rule of RULES) {
    if (mode === 'redact' && rule.generic) continue
    if (rule.languages && (!language || !rule.languages.includes(language))) continue
    if (!rule.keywords.some(keyword => lower.includes(keyword))) continue
    if (rule.requires && !rule.requires.test(text)) continue
    for (const match of text.matchAll(rule.pattern)) {
      const span = secretSpan(match)
      if (!span) continue
      let [start, end] = span
      while (start < end && isSpace(text.charCodeAt(start))) start++
      while (end > start && isSpace(text.charCodeAt(end - 1))) end--
      if (end <= start) continue
      const secret = text.slice(start, end)
      const matchStart = match.index ?? start
      const ctx: RuleContext = {
        secret,
        groups: match.groups ?? {},
        before: text.slice(Math.max(0, matchStart - 48), matchStart),
      }
      if (rule.validate && !rule.validate(ctx)) continue
      let confidence = rule.confidence
      if (mode === 'scan') {
        if (isPlaceholder(secret)) continue
        if (rule.minEntropy !== undefined && shannonEntropy(secret) < rule.minEntropy) continue
        const refined = rule.refine?.(ctx)
        if (refined === false) continue
        if (refined) confidence = refined
      } else if (isTemplateValue(secret) || KNOWN_EXAMPLE_VALUES.has(secret)) {
        continue
      }
      if (!claimed.tryClaim(start, end)) continue
      accepted.push({ rule, start, end, confidence })
    }
  }
  return accepted.sort((a, b) => a.start - b.start)
}

function secretSpan(match: RegExpExecArray | RegExpMatchArray): [number, number] | undefined {
  const indices = (match as RegExpExecArray).indices
  const span = indices?.groups?.secret ?? indices?.[0]
  return span ? [span[0], span[1]] : undefined
}

/** Non-overlapping half-open intervals kept sorted by start. */
class SpanSet {
  readonly #starts: number[] = []
  readonly #ends: number[] = []

  tryClaim(start: number, end: number): boolean {
    let lo = 0
    let hi = this.#starts.length
    while (lo < hi) {
      const mid = (lo + hi) >>> 1
      if (this.#starts[mid]! < start) lo = mid + 1
      else hi = mid
    }
    if (lo > 0 && this.#ends[lo - 1]! > start) return false
    if (lo < this.#starts.length && this.#starts[lo]! < end) return false
    this.#starts.splice(lo, 0, start)
    this.#ends.splice(lo, 0, end)
    return true
  }
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

function isPlaceholder(value: string): boolean {
  if (KNOWN_EXAMPLE_VALUES.has(value)) return true
  if (value.length > PLACEHOLDER_CHECK_MAX_LENGTH) return false
  return PLACEHOLDER_MARKERS.test(value) || PLACEHOLDER_WORDS.test(value) || lowDiversity(value)
}

/** All-same-character or nearly so, e.g. `AKIA0000000000000000`. */
function lowDiversity(value: string): boolean {
  if (value.length < 8) return false
  if (new Set(value).size <= 3) return true
  return new Set(value.slice(-16)).size <= 2
}

/** Values that are clearly references to a secret rather than a secret. */
function isTemplateValue(value: string): boolean {
  return /\$\{|\{\{|<[A-Za-z_ -]+>|^\{[\w.-]*\}$|^\$[A-Za-z_]\w*$|%\(\w+\)s|process\.env|os\.environ|getenv/.test(value)
}

/** Generic tokens are usually encoded ASCII; prose can have misleadingly high entropy. */
function isProseValue(value: string): boolean {
  const chars = [...value]
  const nonAsciiLetters = chars.filter(ch => /\p{L}/u.test(ch) && !/[A-Za-z]/.test(ch)).length
  // Whitespace already excludes English sentences; CJK prose often has none.
  // Do not reject an opaque token merely for ending in sentence punctuation.
  return nonAsciiLetters >= 6 && nonAsciiLetters > chars.length / 2
}

function refineGeneric(secret: string, key: string): SecretConfidence | false | undefined {
  if (KEY_NAME_EXCLUDE.test(key) || /token(?:iz|s?[_-]?(?:count|limit|usage|type))/i.test(key)) return false
  if (secret.includes('://') || /^[$%@{<]/.test(secret) || isProseValue(secret)) return false
  if (/^[a-z]+(?:[._-][a-z0-9]+)+$/.test(secret)) return false // dotted.or_snake identifiers
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(secret)) return false // ENV_VAR_NAMES
  if (/^[\w./-]+\.(?:js|ts|json|py|go|rb|php|java|ya?ml|txt|html?|css|png|svg)$/i.test(secret)) return false
  if (!/\d/.test(secret) && !/[^A-Za-z0-9]/.test(secret)) return false // plain words / camelCase identifiers
  return secret.length >= 20 && shannonEntropy(secret) >= 4 ? 'medium' : 'low'
}

/** Body of a PEM block (possibly JSON-escaped or string-concatenated) holds real base64 key material. */
function looksLikeKeyMaterial(body: string): boolean {
  const residue = body
    .replace(/\\[nr]/g, '\n')
    .split('\n')
    .filter(line => !/^\s*["']?[A-Za-z-]+:\s/.test(line))
    .join('')
    .replace(/[\s"'+,;\\]/g, '')
  return residue.length >= 64 && /^[A-Za-z0-9+/=]+$/.test(residue)
}

function isJwtHeader(segment: string): boolean {
  try {
    const header: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))
    return typeof header === 'object' && header !== null && ('alg' in header || 'typ' in header)
  } catch {
    return false
  }
}

function lowerConfidence(confidence: SecretConfidence): SecretConfidence {
  return confidence === 'high' ? 'medium' : 'low'
}

// ---------------------------------------------------------------------------
// Redaction helpers
// ---------------------------------------------------------------------------

/** Replace a span line by line so the text keeps its line structure and indentation. */
function redactSpan(original: string, ruleId: string): string {
  const token = `[REDACTED:${ruleId}]`
  if (!original.includes('\n')) return token
  return original
    .split('\n')
    .map(line => {
      const lead = /^\s*/.exec(line)?.[0] ?? ''
      const trail = line.endsWith('\r') ? '\r' : ''
      return line.trim() === '' ? line : lead + token + trail
    })
    .join('\n')
}

const BEGIN_MARKER = /-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----/
const KEY_ARMOR_HEADER = /^(?:Proc-Type|DEK-Info|Comment|Version|Hash):/

/**
 * A snippet may hold a BEGIN marker whose END was cut off, so the block rule
 * cannot match. Redact key material after such a marker: escaped material on
 * the same line, then following base64 or armor-header lines.
 */
function redactDanglingPrivateKeys(text: string): string {
  if (!text.includes('PRIVATE KEY-----')) return text
  const lines = text.split('\n')
  let inKey = false
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!
    const marker = BEGIN_MARKER.exec(line)
    if (marker) {
      const head = marker.index + marker[0].length
      const after = line.slice(head)
      const inline = /^(?:\\[nr]|[A-Za-z0-9+/=])+/.exec(after)?.[0]
      if (inline && /[A-Za-z0-9+/]{16}/.test(inline)) {
        lines[i] = `${line.slice(0, head)}[REDACTED:private-key]${after.slice(inline.length)}`
        inKey = false
      } else {
        inKey = true
      }
      continue
    }
    if (!inKey) continue
    const body = line
      .trim()
      .replace(/^[+"'`\s]+/, '')
      .replace(/[\s"'`+,;]+$/, '')
      .replace(/(?:\\[rn])+$/, '')
    if (body === '') continue
    if (body.startsWith('-----END') || !(KEY_ARMOR_HEADER.test(body) || /^[A-Za-z0-9+/=]{16,}$/.test(body))) {
      inKey = false
      continue
    }
    lines[i] = redactSpan(line, 'private-key')
  }
  return lines.join('\n')
}

function secretFingerprint(ruleId: string, path: string, secret: string): string {
  return createHash('sha256').update(ruleId).update('\0').update(path).update('\0').update(secret).digest('hex')
}

/** At most the first 4 characters (fewer for short values such as passwords) followed by a mask. */
function maskSecret(secret: string): string {
  const compact = secret.replace(/^(?:\s|\\[nr])+/, '')
  const visible = Math.min(4, Math.floor(compact.length / 8))
  return `${compact.slice(0, visible)}****…`
}

function clipLine(line: string, column: number): string {
  if (line.length <= SNIPPET_MAX_LINE_CHARS) return line
  const start = Math.max(0, Math.min(column - 1 - 40, line.length - SNIPPET_MAX_LINE_CHARS))
  const body = line.slice(start, start + SNIPPET_MAX_LINE_CHARS)
  return (start > 0 ? '…' : '') + body + (start + SNIPPET_MAX_LINE_CHARS < line.length ? '…' : '')
}

// ---------------------------------------------------------------------------
// Positions
// ---------------------------------------------------------------------------

function lineStarts(text: string): number[] {
  const starts = [0]
  for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) starts.push(i + 1)
  return starts
}

function positionOf(starts: readonly number[], offset: number): { line: number; column: number } {
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (starts[mid]! <= offset) lo = mid
    else hi = mid - 1
  }
  return { line: lo + 1, column: offset - starts[lo]! + 1 }
}

function isSpace(code: number): boolean {
  return code === 32 || code === 9 || code === 10 || code === 13
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
