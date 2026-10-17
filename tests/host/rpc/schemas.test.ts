import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { RPC_METHOD_NAMES } from '../../../src/shared/contracts.ts'
import { badRequestFromZod, RpcError, toRpcFailure } from '../../../src/host/rpc/errors.ts'
import { requestSchemaFor, requestSchemas } from '../../../src/host/rpc/schemas.ts'
import { recordingLogger } from './helpers.ts'

describe('requestSchemas', () => {
  it('has a schema for every method', () => {
    expect(Object.keys(requestSchemas).sort()).toEqual([...RPC_METHOD_NAMES].sort())
  })

  it('rejects unknown keys on every method', () => {
    for (const method of RPC_METHOD_NAMES) {
      const result = requestSchemaFor(method).safeParse({ __proto_extra__: 1 })
      expect(result.success, method).toBe(false)
    }
  })

  it('accepts {} for empty-request methods only', () => {
    expect(requestSchemas.getBootstrap.safeParse({}).success).toBe(true)
    expect(requestSchemas.listWorkspaces.safeParse({}).success).toBe(true)
    expect(requestSchemas.listModels.safeParse({}).success).toBe(true)
    expect(requestSchemas.listToolkit.safeParse({}).success).toBe(true)
    expect(requestSchemas.listScans.safeParse({}).success).toBe(true)
    expect(requestSchemas.getScan.safeParse({}).success).toBe(false)
  })

  it('bounds ids', () => {
    expect(requestSchemas.getScan.safeParse({ scanId: 'a'.repeat(64) }).success).toBe(true)
    expect(requestSchemas.getScan.safeParse({ scanId: 'a'.repeat(65) }).success).toBe(false)
    expect(requestSchemas.getScan.safeParse({ scanId: '' }).success).toBe(false)
    expect(requestSchemas.getScan.safeParse({ scanId: '../etc' }).success).toBe(false)
    expect(requestSchemas.getScan.safeParse({ scanId: 'a b' }).success).toBe(false)
    expect(requestSchemas.getFinding.safeParse({ scanId: 's', findingId: 'f/1' }).success).toBe(false)
  })

  it('validates scan creation', () => {
    expect(requestSchemas.createScan.safeParse({ workspaceId: 'w1', mode: 'deep' }).success).toBe(true)
    expect(requestSchemas.createScan.safeParse({ workspaceId: 'w1', mode: 'ultra' }).success).toBe(false)
    expect(requestSchemas.estimateScan.safeParse({ workspaceId: 'w1' }).success).toBe(false)
  })

  it('bounds triage notes', () => {
    const base = { scanId: 's', findingId: 'f', triage: 'accepted_risk' }
    expect(requestSchemas.setTriage.safeParse({ ...base, note: 'x'.repeat(2000) }).success).toBe(true)
    expect(requestSchemas.setTriage.safeParse({ ...base, note: 'line 1\nline 2\ttab' }).success).toBe(true)
    expect(requestSchemas.setTriage.safeParse({ ...base, note: 'x'.repeat(2001) }).success).toBe(false)
    expect(requestSchemas.setTriage.safeParse({ ...base, note: 'nul\u0000' }).success).toBe(false)
    expect(requestSchemas.setTriage.safeParse({ ...base, triage: 'ignored' }).success).toBe(false)
  })

  it('bounds finding filters', () => {
    const parse = (filter: unknown) => requestSchemas.listFindings.safeParse({ scanId: 's', filter })
    expect(
      parse({ severities: ['high'], closures: ['confirmed'], sources: ['ai'], triage: ['open'], text: 'sql' }).success,
    ).toBe(true)
    expect(parse({ text: 'x'.repeat(201) }).success).toBe(false)
    expect(parse({ severities: ['urgent'] }).success).toBe(false)
    expect(parse({ severities: Array(33).fill('high') }).success).toBe(false)
    expect(parse({ extra: true }).success).toBe(false)
  })

  it('bounds list paging', () => {
    expect(requestSchemas.listScans.safeParse({ limit: 50 }).success).toBe(true)
    expect(requestSchemas.listScans.safeParse({ limit: 50, offset: 0 }).success).toBe(true)
    expect(requestSchemas.listScans.safeParse({ offset: 50 }).success).toBe(true)
    expect(requestSchemas.listScans.safeParse({ offset: -1 }).success).toBe(false)
    expect(requestSchemas.listScans.safeParse({ offset: 0.5 }).success).toBe(false)
    expect(requestSchemas.listScans.safeParse({ offset: Number.MAX_SAFE_INTEGER + 1 }).success).toBe(false)
    expect(requestSchemas.listScans.safeParse({ limit: 0 }).success).toBe(false)
    expect(requestSchemas.listScans.safeParse({ limit: 1.5 }).success).toBe(false)
    expect(requestSchemas.listEvents.safeParse({ scanId: 's', afterSeq: -1 }).success).toBe(false)
    expect(requestSchemas.listEvents.safeParse({ scanId: 's', afterSeq: 0, limit: 1000 }).success).toBe(true)
  })

  it('requires a positive budget addition to extend a scan', () => {
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's', addTokens: 100 }).success).toBe(true)
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's', addMinutes: 30 }).success).toBe(true)
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's' }).success).toBe(false)
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's', addTokens: 0 }).success).toBe(false)
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's', addTokens: -5 }).success).toBe(false)
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's', addTokens: 1.5 }).success).toBe(false)
    expect(requestSchemas.extendScanBudget.safeParse({ scanId: 's', addTokens: 100, extra: 1 }).success).toBe(false)
  })

  it('requires an explicit license acceptance to install a tool', () => {
    expect(requestSchemas.installTool.safeParse({ toolId: 'semgrep', acceptLicense: true }).success).toBe(true)
    expect(requestSchemas.installTool.safeParse({ toolId: 'semgrep', acceptLicense: false }).success).toBe(false)
    expect(requestSchemas.installTool.safeParse({ toolId: 'curl', acceptLicense: true }).success).toBe(false)
  })

  it('validates export formats', () => {
    expect(requestSchemas.exportReport.safeParse({ scanId: 's', format: 'sarif' }).success).toBe(true)
    expect(requestSchemas.exportReport.safeParse({ scanId: 's', format: 'html' }).success).toBe(false)
  })
})

describe('updateSettings schema', () => {
  const parse = (patch: unknown, expectedRevision: unknown = 3) =>
    requestSchemas.updateSettings.safeParse({ patch, expectedRevision })

  it('accepts a deep-partial patch', () => {
    expect(parse({}).success).toBe(true)
    expect(
      parse({
        models: {
          hunter: { provider: 'deepseek', model: 'deepseek-chat', reasoningEffort: 'high', maxOutputTokens: 8192 },
        },
        scan: { parallelWorkers: 4, excludeGlobs: ['dist/**'] },
        budgets: { quick: { maxTokens: 100_000 } },
        privacy: { sendCodeToModel: true },
        storage: { retentionDays: 0 },
        ui: { language: 'ja' },
      }).success,
    ).toBe(true)
  })

  it('allows null to clear a role model', () => {
    const result = parse({ models: { skeptic: null, default: null } })
    expect(result.success).toBe(true)
    expect(result.data?.patch.models).toEqual({ skeptic: null, default: null })
  })

  it('rejects unknown keys at every depth', () => {
    expect(parse({ admin: true }).success).toBe(false)
    expect(parse({ scan: { shell: 'rm' } }).success).toBe(false)
    expect(parse({ models: { root: { provider: 'p', model: 'm' } } }).success).toBe(false)
    expect(parse({ models: { hunter: { provider: 'p', model: 'm', apiKey: 'k' } } }).success).toBe(false)
    expect(parse({ budgets: { turbo: {} } }).success).toBe(false)
    expect(parse({ budgets: { deep: { maxDollars: 1 } } }).success).toBe(false)
    expect(requestSchemas.updateSettings.safeParse({ patch: {}, expectedRevision: 1, force: true }).success).toBe(false)
  })

  it('bounds numbers', () => {
    expect(parse({ scan: { parallelWorkers: 0 } }).success).toBe(false)
    expect(parse({ scan: { parallelWorkers: 65 } }).success).toBe(false)
    expect(parse({ scan: { parallelWorkers: 64 } }).success).toBe(true)
    expect(parse({ storage: { retentionDays: 3651 } }).success).toBe(false)
    expect(parse({ storage: { retentionDays: -1 } }).success).toBe(false)
    expect(parse({ budgets: { deep: { maxTokens: 1e9 } } }).success).toBe(true)
    expect(parse({ budgets: { deep: { maxTokens: 1e9 + 1 } } }).success).toBe(false)
    expect(parse({ budgets: { deep: { maxMinutes: 0 } } }).success).toBe(false)
    expect(parse({}, -1).success).toBe(false)
    expect(parse({}, 1.5).success).toBe(false)
    expect(parse({}, '1').success).toBe(false)
  })

  it('bounds strings and arrays', () => {
    expect(parse({ scan: { excludeGlobs: Array(200).fill('a/**') } }).success).toBe(true)
    expect(parse({ scan: { excludeGlobs: Array(201).fill('a/**') } }).success).toBe(false)
    expect(parse({ privacy: { withheldGlobs: ['x'.repeat(301)] } }).success).toBe(false)
    expect(parse({ privacy: { withheldGlobs: [''] } }).success).toBe(false)
    expect(parse({ privacy: { withheldGlobs: ['a\nb'] } }).success).toBe(false)
    expect(parse({ models: { hunter: { provider: 'p'.repeat(201), model: 'm' } } }).success).toBe(false)
    expect(parse({ models: { hunter: { provider: '', model: 'm' } } }).success).toBe(false)
    expect(parse({ ui: { language: 'fr' } }).success).toBe(false)
  })
})

describe('toRpcFailure', () => {
  it('passes RpcError through', () => {
    const logger = recordingLogger()
    const failure = toRpcFailure(new RpcError('security/busy', 'Busy.', { retryAfterMs: 1000 }), logger)
    expect(failure).toEqual({ code: 'security/busy', message: 'Busy.', details: { retryAfterMs: 1000 } })
    expect(logger.entries).toEqual([])
  })

  it('maps ZodError to bad-request with paths and messages only', () => {
    const result = requestSchemas.updateSettings.safeParse({
      patch: { scan: { parallelWorkers: 'SECRET-INPUT' }, 'evil-key-SECRET': 1 },
      expectedRevision: 0,
    })
    expect(result.success).toBe(false)
    const failure = toRpcFailure(result.error, recordingLogger())
    expect(failure.code).toBe('security/bad-request')
    const issues = failure.details.issues as { path: string; message: string }[]
    expect(issues.map(issue => issue.path).sort()).toEqual(['patch', 'patch.scan.parallelWorkers'])
    for (const issue of issues) expect(Object.keys(issue).sort()).toEqual(['message', 'path'])
    expect(JSON.stringify(failure)).not.toContain('SECRET')
  })

  it('caps the number of issues', () => {
    const schema = z.array(z.string())
    const result = schema.safeParse(Array(50).fill(1))
    const failure = badRequestFromZod(result.error!)
    expect((failure.details.issues as unknown[]).length).toBe(20)
    expect(failure.details.truncated).toBe(30)
  })

  it('hides other errors behind a generic internal failure and logs them', () => {
    const logger = recordingLogger()
    const error = new Error('EACCES: /Users/bob/project/secret.env')
    const failure = toRpcFailure(error, logger)
    expect(failure.code).toBe('security/internal')
    expect(failure.message).not.toContain('/Users/bob')
    expect(failure.details).toEqual({})
    expect(logger.entries).toEqual([{ level: 'error', args: [expect.any(String), error] }])
  })
})

describe('toRpcFailure with core zod errors', () => {
  it('treats a core $ZodError like a ZodError', () => {
    const error = new z.core.$ZodError([{ code: 'custom', path: ['a', 0], message: 'bad', input: 'SECRET' }])
    const failure = toRpcFailure(error, recordingLogger())
    expect(failure).toEqual({
      code: 'security/bad-request',
      message: 'The request is invalid.',
      details: { issues: [{ path: 'a[0]', message: 'bad' }] },
    })
  })
})
