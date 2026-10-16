import { describe, expect, it } from 'vitest'
import {
  isSensitivePath,
  Redactor,
  redactText,
  type SecretMatch,
  scanFileContent,
  scanSecrets,
  secretSignals,
  shannonEntropy,
} from '../../../src/host/analysis/secrets.ts'
import { snapshotOf } from './helpers.ts'

// Test secrets are assembled at runtime so this file never contains a
// contiguous token that other scanners (or push protection) would flag.
const j = (...parts: string[]): string => parts.join('')
const RANDOM40 = 'kR8vN2pQ7xL4mT9wB3zY6cH1jF5gD0sA8eU2iO7q'
const RANDOM36 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'

const SAMPLES: Record<string, string> = {
  'aws-access-key-id': `aws_access_key_id = ${j('AKIA', '4K7QZ2XR9MBT3LPW')}`,
  'aws-secret-access-key': `aws_secret_access_key = "${RANDOM40}"`,
  'github-token': `const t = "${j('ghp', '_', RANDOM36)}"`,
  'github-fine-grained-token': `token: ${j('github', '_pat_', '11ABCDEFG0', RANDOM36, 'xY7zW2vU4tS6rQ8pO0nM3lK5jI')}`,
  'gitlab-token': `GITLAB=${j('glpat', '-', 'aB3dE5fG7hJ9kL1mN3pQ5')}`,
  'slack-token': `slack: ${j('xoxb', '-', '2718281828-3141592653589-aB3dE5fG7hJ9kL1mN3pQ5rS7')}`,
  'slack-webhook': `url = "${j('https://hooks.slack.com/services/', 'T0ABCDEF1/B0ABCDEF2/', 'aB3dE5fG7hJ9kL1mN3pQ5rS7')}"`,
  'stripe-secret-key': `stripe = "${j('sk', '_live_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7')}"`,
  'stripe-restricted-key': `stripe = "${j('rk', '_live_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7')}"`,
  'google-api-key': `key = "${j('AIza', 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q')}"`,
  'openai-api-key': `OPENAI = "${j('sk', '-proj-', 'Ab3De5Fg7Hj9Kl1Mn3Pq5Rs7Tu9Vw1Xy3')}"`,
  'anthropic-api-key': `ANTHROPIC = "${j('sk', '-ant-', 'api03-Ab3De5Fg7Hj9Kl1Mn3Pq5Rs7Tu9Vw1Xy3Za5Bc7De9')}"`,
  'deepseek-api-key': `DEEPSEEK = "${j('sk', '-', '3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c8e')}"`,
  'twilio-api-key': `twilio_key = "${j('SK', '3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c8e')}"`,
  'sendgrid-api-key': `sg = "${j('SG', '.', 'aB3dE5fG7hJ9kL1mN3pQ5r', '.', 'sT7uV9wX1yZ3aB5cD7eF9gH1iJ3kL5mN7oP9qR1sT3u')}"`,
  'npm-token': `//registry.npmjs.org/:_authToken=${j('npm', '_', RANDOM36)}`,
  'pypi-token': `password = ${j('pypi', '-AgE', 'IcHlwaS5vcmcaB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5')}`,
  'azure-storage-key': `conn = "DefaultEndpointsProtocol=https;AccountName=acct;${j('AccountKey', '=', 'q8Zr2mKvT9pL4xN7bW3cY6hJ1fG5dS0aE8uI2oP7rT4yU6iO9pA3sD5fG7hJ1kL3zX5cV7bN9mQ==')};EndpointSuffix=core.windows.net"`,
  jwt: `const jwt = "${j('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', '.', 'eyJzdWIiOiI5ODc2NTQzMjEwIiwibmFtZSI6IkFsaWNlIn0', '.', 'k3Jq8vL2mN5pR7sT9wX1yZ3aB5cD7eF9gH1')}"`,
  'database-url': `DATABASE_URL = "${j('postgres', 'ql://', 'admin:Sup3rS3cr3tP4ss@', 'prod-db.internal.io:5432/app')}"`,
  'generic-secret': `const password = "q8Zr#2mK!vT9pL4x"`,
}

function scanOne(text: string, path = 'src/config.ts'): SecretMatch[] {
  return scanFileContent(path, text)
}

describe('secret rules', () => {
  it.each(Object.entries(SAMPLES))('%s matches its sample', (ruleId, text) => {
    const matches = scanOne(text)
    expect(matches.map(m => m.ruleId)).toEqual([ruleId])
    const match = matches[0]!
    const secret = text.slice(match.start, match.end)
    expect(secret.length).toBeGreaterThanOrEqual(8)
    // Fingerprint never exposes the value; preview shows at most 4 characters.
    expect(match.fingerprint).toMatch(/^[0-9a-f]{64}$/)
    expect(match.fingerprint).not.toContain(secret)
    expect(match.preview).toMatch(/^.{0,4}\*{4}…$/)
    expect(secret.startsWith(match.preview.replace(/\*{4}…$/, ''))).toBe(true)
    expect(match.line).toBe(1)
    expect(match.column).toBe(match.start + 1)
    expect(match.endColumn).toBe(match.end + 1)
  })

  it('detects a GCP service-account key file', () => {
    const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7'.repeat(3)
    const json = JSON.stringify(
      {
        type: 'service_account',
        project_id: 'p',
        private_key: `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`,
        client_email: 'x@p.iam.gserviceaccount.com',
      },
      null,
      2,
    )
    const matches = scanOne(json, 'sa.json')
    expect(matches.map(m => m.ruleId)).toEqual(['gcp-service-account'])
    expect(redactText(json)).not.toContain(body)
  })

  it('reports one finding per span when rules overlap (DeepSeek vs OpenAI vs generic)', () => {
    const key = j('sk', '-', '3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c8e')
    const matches = scanOne(`const api_key = "${key}"`)
    expect(matches).toHaveLength(1)
    expect(matches[0]!.ruleId).toBe('deepseek-api-key')
  })

  it.each([
    ['AWS documentation key', 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE'],
    ['all-same-char key', `id = ${j('AKIA', 'AAAAAAAAAAAAAAAA')}`],
    ['placeholder password', 'password = "your_password_here"'],
    ['changeme', 'password = "changeme-changeme"'],
    ['env reference', 'apiKey: process.env.API_KEY'],
    ['python environ', 'SECRET_KEY = os.environ["SECRET_KEY"]'],
    ['template', `token = "${'$'}{GITHUB_TOKEN_VALUE}"`],
    ['handlebars', 'secret: "{{ .Values.secretValue }}"'],
    ['angle placeholder', 'api_key = "<your-api-key-goes-here>"'],
    ['xxx', `token = "${'x'.repeat(24)}"`],
    ['example word', 'client_secret = "example-client-secret-123"'],
    ['dummy word', 'auth_token = "dummy_token_abc_123456"'],
    ['low entropy generic', 'password = "aaaaaaaabbbbbbbb"'],
    ['identifier value', 'const tokenType = "access_token_type_name"'],
    ['db URL placeholder', 'url = "postgres://user:password@localhost/app"'],
    ['db URL template', `url = "postgres://app:${'$'}{DB_PASS}@db.internal/app"`],
    ['db URL single-brace template', 'url = "mongodb+srv://app:{PASS}@cluster0.mongodb.net"'],
    ['JWT with non-JSON header', `x = "${j('eyJub3Rqc29u', '.', 'eyJzdWIiOiIxIn0', '.', 'abcdefghijklmnopqrstu')}"`],
    ['private key without key material', '-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----'],
  ])('ignores %s', (_label, text) => {
    expect(scanOne(text)).toEqual([])
  })

  it.each([
    [
      'Japanese audit reproduction',
      "'notice.budget-tokens': 'すべての作業が終わる前に、トークンの予算を使い切りました。'",
    ],
    ['Chinese without spaces', 'token: "在所有任务完成之前，令牌预算已经全部用完。"'],
    ['Chinese mixed with ASCII', 'token: "在所有任务完成之前，token 预算已用完。"'],
    ['English', 'token: "The token budget ran out before every task finished."'],
    ['French', 'token: "Le budget de jetons est épuisé avant la fin des tâches !"'],
    ['Japanese without punctuation', 'token: "すべての作業が終わる前にトークンの予算を使い切りました"'],
  ])('ignores natural-language prose: %s', (_label, text) => {
    expect(scanOne(text)).toEqual([])
  })

  it.each(['src/config.ts', 'src/i18n.ts', 'locales/ja.json'])('keeps opaque generic tokens in %s', path => {
    const matches = scanOne(`'notice.budget-tokens': "${RANDOM40}!"`, path)
    expect(matches.map(m => m.ruleId)).toEqual(['generic-secret'])
  })

  it.each(['tests/a.ts', 'test/a.ts', 'fixtures/a.ts', 'examples/a.ts', 'src/a.test.ts'])(
    'caps severity but keeps lowered-confidence secrets in %s',
    path => {
      const text = SAMPLES['github-token']!
      expect(scanFileContent('src/a.ts', text)[0]).toMatchObject({ severity: 'high', confidence: 'high' })
      expect(scanFileContent(path, text)[0]).toMatchObject({ severity: 'low', confidence: 'medium' })
      expect(scanFileContent('src/a.ts', text, { isTest: true })[0]).toMatchObject({
        severity: 'low',
        confidence: 'medium',
      })
    },
  )

  it('gives lower confidence to local or default database credentials', () => {
    const local = scanOne(`url = "${j('mysql', '://', 'app:R4nd0mP4ss@localhost:3306/db')}"`)
    expect(local[0]!.confidence).toBe('medium')
    const weak = scanOne(`url = "${j('postgres', '://', 'postgres:postgres@prod.example.io/db')}"`)
    expect(weak[0]!.confidence).toBe('low')
  })

  it('scans .env files with the env rule', () => {
    const text = `# local config\nSTRIPE_WEBHOOK_SECRET=whsec_${'Q7m'}Lp2Xr9Tz4Kb8Nv\nAPP_NAME=demo\nPUBLIC_URL=https://x.io\n`
    const matches = scanFileContent('.env', text, { language: 'env' })
    expect(matches.map(m => [m.ruleId, m.line])).toEqual([['env-secret', 2]])
    expect(scanFileContent('notes.txt', text, { language: 'other' })).toEqual([])
  })
})

describe('scanSecrets / secretSignals', () => {
  it('skips generated and oversized files and builds redacted signals', async () => {
    const token = j('ghp', '_', RANDOM36)
    const snapshot = snapshotOf({
      'src/a.ts': `const x = 1\nconst token = "${token}"\n`,
      'dist.js': `/* @generated */\nconst token = "${token}"\n`,
      'tests/b.ts': `const token = "${token}"\n`,
    })
    const matches = await scanSecrets(snapshot)
    expect(matches.map(m => m.path)).toEqual(['src/a.ts', 'tests/b.ts'])

    const signals = secretSignals(matches, snapshot)
    expect(signals).toHaveLength(2)
    const signal = signals[0]!
    expect(signal).toMatchObject({
      analyzer: 'secrets',
      kind: 'secret',
      category: 'secrets',
      cwe: 'CWE-798',
      ruleId: 'github-token',
      location: { path: 'src/a.ts', startLine: 2, endLine: 2 },
      snippet: 'const token = "[REDACTED:github-token]"',
    })
    expect(signal.fingerprintParts).toEqual(['github-token', 'src/a.ts', matches[0]!.fingerprint])
    expect(signal.recommendation).toMatch(/rotate/i)
    expect(signal.recommendation).toMatch(/history/i)
    expect(JSON.stringify(signals)).not.toContain(token)
    expect(signals[1]!.confidence).toBe('medium')
  })

  it('honors an aborted signal', async () => {
    const controller = new AbortController()
    controller.abort(new Error('cancelled'))
    await expect(scanSecrets(snapshotOf({ 'a.ts': '' }), controller.signal)).rejects.toThrow('cancelled')
  })
})

describe('Redactor', () => {
  const keyBody = [
    'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB',
    'aJ5mVVYQ3gdZq0tK8Z0Wv2xY4Xg1rQ7pP3yWnL8bQ1mK2nJ3oP4qR5sT6uV7wX8y',
    'Zr2mKvT9pL4xN7bW3cY6hJ1fG5dS0aE8uI2oP7rT4yU6iO9pA3sD5fG7hJ1kL3z',
  ]
  const pem = ['-----BEGIN RSA PRIVATE KEY-----', ...keyBody, '-----END RSA PRIVATE KEY-----'].join('\n')

  it('redacts matched spans while preserving line count', async () => {
    const token = j('ghp', '_', RANDOM36)
    const content = `line1\nconst a = "${token}"\n${pem}\nconst b = 2\n`
    const snapshot = snapshotOf({ 'src/a.ts': content })
    const matches = await scanSecrets(snapshot)
    expect(matches.map(m => m.ruleId)).toEqual(['github-token', 'private-key'])

    const redacted = new Redactor(matches).redactFile('src/a.ts', content)
    expect(redacted.split('\n')).toHaveLength(content.split('\n').length)
    expect(redacted).toContain('const a = "[REDACTED:github-token]"')
    expect(redacted).toContain('-----BEGIN RSA PRIVATE KEY-----\n[REDACTED:private-key]\n')
    expect(redacted).toContain('[REDACTED:private-key]\n-----END RSA PRIVATE KEY-----')
    for (const line of keyBody) expect(redacted).not.toContain(line)
    expect(redacted).not.toContain(token)
  })

  it('preserves CRLF line endings', () => {
    const content = pem.replace(/\n/g, '\r\n')
    const matches = scanFileContent('k.pem', content)
    const redacted = new Redactor(matches).redactFile('k.pem', content)
    expect(redacted.split('\r\n')).toHaveLength(content.split('\r\n').length)
    expect(redacted).not.toContain(keyBody[0])
  })

  it('does not redact stale offsets, but the backstop still catches known patterns', () => {
    const token = j('ghp', '_', RANDOM36)
    const original = `const a = "${token}"\n`
    const matches = scanFileContent('a.ts', original)
    const shifted = `// new header line\n${original}`
    const redacted = new Redactor(matches).redactFile('a.ts', shifted)
    expect(redacted).toBe('// new header line\nconst a = "[REDACTED:github-token]"\n')
  })

  it('leaves unrelated files and text untouched', () => {
    const redactor = new Redactor([])
    expect(redactor.redactFile('x.ts', 'const a = 1\n')).toBe('const a = 1\n')
  })
})

describe('redactText', () => {
  it('redacts every high-confidence sample', () => {
    for (const [ruleId, text] of Object.entries(SAMPLES)) {
      if (ruleId === 'generic-secret') continue
      const out = redactText(text)
      expect(out, ruleId).toContain(`[REDACTED:${ruleId}]`)
    }
  })

  it('does not apply the generic entropy rule', () => {
    expect(redactText(SAMPLES['generic-secret']!)).toBe(SAMPLES['generic-secret'])
  })

  it('redacts key material after a truncated BEGIN marker', () => {
    const snippet = ['const key = `', '-----BEGIN OPENSSH PRIVATE KEY-----', ...keyBodyLines()].join('\n')
    const out = redactText(snippet)
    expect(out.split('\n')).toHaveLength(snippet.split('\n').length)
    expect(out).not.toMatch(/b3BlbnNzaC1rZXktdjE/)
    expect(out).toContain('-----BEGIN OPENSSH PRIVATE KEY-----')
  })

  it('redacts JSON-escaped single-line private keys', () => {
    const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7'.repeat(2)
    const text = `{"key": "-----BEGIN PRIVATE KEY-----\\n${body}\\n-----END PRIVATE KEY-----\\n"}`
    const out = redactText(text)
    expect(out).not.toContain(body)
    expect(out).toContain('[REDACTED:private-key]')
  })

  it('returns plain text unchanged', () => {
    const text = 'function add(a, b) {\n  return a + b\n}\n'
    expect(redactText(text)).toBe(text)
  })
})

function keyBodyLines(): string[] {
  return [
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
    'QyNTUxOQAAACDdFakeButStructurallyValidBase64MaterialForTestingOnly0000',
  ]
}

describe('shannonEntropy', () => {
  it('computes bits per character', () => {
    expect(shannonEntropy('')).toBe(0)
    expect(shannonEntropy('aaaa')).toBe(0)
    expect(shannonEntropy('ab')).toBe(1)
    expect(shannonEntropy('abcd')).toBe(2)
    expect(shannonEntropy(RANDOM40)).toBeGreaterThan(4)
  })
})

describe('isSensitivePath', () => {
  it.each([
    ['.env', true],
    ['config/.env.production', true],
    ['.env.local', true],
    ['.env.example', false],
    ['.env.sample', false],
    ['.env.template', false],
    ['certs/server.pem', true],
    ['server.key', true],
    ['keystore.jks', true],
    ['store.p12', true],
    ['home/.ssh/id_rsa', true],
    ['id_ed25519.pub', true],
    ['.npmrc', true],
    ['.pypirc', true],
    ['.netrc', true],
    ['.git-credentials', true],
    ['gcp/credentials.json', true],
    ['my-ServiceAccount-prod.json', true],
    ['myserviceaccount.json', true],
    ['config/secrets.yml', true],
    ['secrets.yaml', true],
    ['terraform.tfstate', true],
    ['terraform.tfstate.backup', true],
    ['terraform.tfvars', true],
    ['.aws/credentials', true],
    ['deploy/.aws/config', true],
    ['.docker/config.json', true],
    ['ci/.docker/config.json', true],
    ['.kube/config', true],
    ['ops/kubeconfig', true],
    ['kubeconfig.yaml', true],
    ['prod.kubeconfig', true],
    ['.pgpass', true],
    ['web/.htpasswd', true],
    ['.dockercfg', true],
    ['.terraform.d/credentials.tfrc.json', true],
    ['home/.ssh/id_ecdsa', true],
    ['id_dsa', true],
    ['packages/app/.npmrc', true],
    ['src/config.json', false],
    ['docs/aws/credentials.md', false],
    ['src/kube/config.ts', false],
    ['src/index.ts', false],
    ['src/keys.ts', false],
    ['../outside.ts', true],
    ['/etc/passwd', true],
  ])('%s → %s', (path, expected) => {
    expect(isSensitivePath(path, [])).toBe(expected)
  })

  it('applies extra gitignore-style globs', () => {
    expect(isSensitivePath('internal/customers.csv', ['internal/'])).toBe(true)
    expect(isSensitivePath('data/a.sql', ['*.sql'])).toBe(true)
    expect(isSensitivePath('src/a.ts', ['*.sql', ''])).toBe(false)
  })
})
