/**
 * Arguments for a built-in secret finding. The stored title, summary and
 * recommendation stay the English sentences reports already emit. The client
 * translates from these arguments. Rows written by 0.4.1 have no `copy`
 * field; {@link recoverSecretCopy} rebuilds the arguments from that English
 * when the rule id and the sentence shape are still recognizable.
 */

export const SECRET_RULE_DESCRIPTIONS = {
  'gcp-service-account': 'Google Cloud service-account private key',
  'private-key': 'Private key block',
  'aws-access-key-id': 'AWS access key ID',
  'aws-secret-access-key': 'AWS secret access key',
  'github-token': 'GitHub token',
  'github-fine-grained-token': 'GitHub fine-grained personal access token',
  'gitlab-token': 'GitLab personal access token',
  'slack-token': 'Slack token',
  'slack-webhook': 'Slack incoming webhook URL',
  'stripe-secret-key': 'Stripe live secret key',
  'stripe-restricted-key': 'Stripe live restricted key',
  'google-api-key': 'Google API key',
  'anthropic-api-key': 'Anthropic API key',
  'openai-api-key': 'OpenAI API key',
  'deepseek-api-key': 'DeepSeek API key',
  'twilio-api-key': 'Twilio API key',
  'twilio-auth-token': 'Twilio auth token',
  'sendgrid-api-key': 'SendGrid API key',
  'npm-token': 'npm access token',
  'pypi-token': 'PyPI upload token',
  'azure-storage-key': 'Azure storage or service-bus access key',
  jwt: 'JSON Web Token',
  'database-url': 'Database or message-broker URL with an inline password',
  'generic-secret': 'Hard-coded password, token, or API key',
  'env-secret': 'Secret value in an environment file',
} as const

export type SecretRuleId = keyof typeof SECRET_RULE_DESCRIPTIONS

export interface SecretCopy {
  readonly kind: 'secret'
  readonly ruleId: string
  readonly description: string
  readonly preview: string
  readonly inTest: boolean
}

const TITLE_PREFIX = 'Hard-coded secret: '
const TEST_NOTE = 'The file looks like a test or example, so it may be a dummy value; confirm before dismissing.'

export const SECRET_RECOMMENDATION =
  'Treat the credential as compromised: revoke or rotate it with the provider now. Load it at runtime from an environment variable or a secret manager instead of source code, and purge it from git history (e.g. git filter-repo) because deleting the line does not remove earlier commits.'

export function isSecretRuleId(ruleId: string): ruleId is SecretRuleId {
  return Object.hasOwn(SECRET_RULE_DESCRIPTIONS, ruleId)
}

export function secretTitle(description: string): string {
  return `${TITLE_PREFIX}${description}`
}

export function secretBody(description: string, preview: string): string {
  return (
    `A value matching the "${description}" pattern (${preview}) is written directly into the source. ` +
    'Anyone who can read the repository, a fork, a backup, a build artifact, or its git history can copy it ' +
    'and use it to access the connected service as you.'
  )
}

export function secretMessage(copy: Pick<SecretCopy, 'description' | 'preview' | 'inTest'>): string {
  const body = secretBody(copy.description, copy.preview)
  return copy.inTest ? `${body} ${TEST_NOTE}` : body
}

/** Accept a stored `copy` object. Unknown rule ids are not translated. */
export function secretCopyFromUnknown(value: unknown): SecretCopy | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const record = value as Record<string, unknown>
  if (record.kind !== 'secret') return undefined
  if (typeof record.ruleId !== 'string' || !isSecretRuleId(record.ruleId)) return undefined
  if (typeof record.description !== 'string' || record.description.trim() === '') return undefined
  if (typeof record.preview !== 'string' || record.preview.trim() === '') return undefined
  if (typeof record.inTest !== 'boolean') return undefined
  return {
    kind: 'secret',
    ruleId: record.ruleId,
    description: record.description,
    preview: record.preview,
    inTest: record.inTest,
  }
}

/**
 * Rebuild arguments from a 0.4.1 finding. Returns undefined when the title,
 * rule id, or preview sentence is not the built-in secret wording.
 */
export function recoverSecretCopy(finding: {
  readonly ruleId?: string
  readonly title: string
  readonly summary: string
  readonly impact?: string
}): SecretCopy | undefined {
  if (finding.ruleId === undefined || !isSecretRuleId(finding.ruleId)) return undefined
  if (!finding.title.startsWith(TITLE_PREFIX)) return undefined
  const description = finding.title.slice(TITLE_PREFIX.length)
  if (description.trim() === '') return undefined
  const source = finding.impact?.includes('pattern (') ? finding.impact : finding.summary
  const preview = previewOf(source, description)
  if (preview === undefined) return undefined
  const inTest = (finding.impact ?? finding.summary).includes(TEST_NOTE)
  return { kind: 'secret', ruleId: finding.ruleId, description, preview, inTest }
}

/**
 * Copy to display. A stored copy is used only while the saved title is still
 * the English template, so a later edit (for example a localized reviewer
 * rewrite) keeps the saved sentences.
 */
export function displaySecretCopy(finding: {
  readonly copy?: unknown
  readonly ruleId?: string
  readonly title: string
  readonly summary: string
  readonly impact?: string
}): SecretCopy | undefined {
  const stored = secretCopyFromUnknown(finding.copy)
  const copy = stored ?? recoverSecretCopy(finding)
  if (copy === undefined) return undefined
  if (finding.title !== secretTitle(copy.description)) return undefined
  return copy
}

function previewOf(text: string, description: string): string | undefined {
  const needle = `A value matching the "${description}" pattern (`
  const start = text.indexOf(needle)
  if (start < 0) return undefined
  const from = start + needle.length
  const end = text.indexOf(') is written directly into the source.', from)
  if (end < 0) return undefined
  const preview = text.slice(from, end)
  return preview.trim() === '' ? undefined : preview
}
