import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { coerceArgs, enumKey, salvageArgs } from '../../../../src/host/agents/runtime/lenient.ts'
import { defineTool, toolSchema } from '../../../../src/host/agents/runtime/tool.ts'

const step = z.object({
  path: z.string().min(1),
  start_line: z.number().int().min(1),
  quote: z.string().min(1),
})
const schema = z.object({
  title: z.string().min(1),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  verdict: z.enum(['true_positive', 'false_positive', 'uncertain']).optional(),
  cwe: z
    .string()
    .regex(/^CWE-\d+$/)
    .optional(),
  preconditions: z.array(z.string()).max(3).default([]),
  steps: z.array(step).min(1),
  flagged: z.boolean().optional(),
})

describe('coerceArgs', () => {
  it('turns null into undefined for optional and defaulted fields, and into [] for required lists', () => {
    expect(coerceArgs(schema, { title: 't', cwe: null, preconditions: null, steps: null })).toEqual({
      title: 't',
      steps: [],
    })
  })

  it('converts numeric strings, boolean strings, and line labels', () => {
    const out = coerceArgs(schema, {
      steps: [
        { path: 'a', start_line: '26', quote: 'q' },
        { path: 'b', start_line: 'L7', quote: 'q' },
      ],
      flagged: 'true',
    }) as { steps: { start_line: unknown }[]; flagged: unknown }
    expect(out.steps.map(s => s.start_line)).toEqual([26, 7])
    expect(out.flagged).toBe(true)
    // Text that is not a number is left for the schema to report.
    expect(coerceArgs(z.object({ n: z.number() }), { n: 'twenty' })).toEqual({ n: 'twenty' })
  })

  it('matches enum values case-insensitively, ignoring separators, then through aliases', () => {
    const aliases = { idor: ['authz'], tp: ['true_positive'], moderate: ['medium'] }
    const category = z.object({ category: z.enum(['authz', 'path-traversal']), severity: schema.shape.severity })
    expect(coerceArgs(category, { category: 'IDOR', severity: 'High' }, { aliases })).toEqual({
      category: 'authz',
      severity: 'high',
    })
    expect(coerceArgs(category, { category: 'Path Traversal', severity: 'Moderate' }, { aliases })).toEqual({
      category: 'path-traversal',
      severity: 'medium',
    })
    expect(coerceArgs(schema, { verdict: 'TP' }, { aliases })).toMatchObject({ verdict: 'true_positive' })
    // An alias whose targets the enum does not accept leaves the value as it was.
    expect(coerceArgs(category, { category: 'tp' }, { aliases })).toEqual({ category: 'tp' })
    expect(enumKey(' True_Positive ')).toBe('truepositive')
  })

  it('fills snake_case keys from camelCase or hyphenated spellings without overwriting', () => {
    expect(coerceArgs(step, { path: 'a', startLine: 3, quote: 'q' })).toEqual({ path: 'a', start_line: 3, quote: 'q' })
    expect(coerceArgs(step, { path: 'a', 'start-line': '4', quote: 'q' })).toEqual({
      path: 'a',
      start_line: 4,
      quote: 'q',
    })
    expect(coerceArgs(step, { path: 'a', start_line: 1, startLine: 9, quote: 'q' })).toMatchObject({ start_line: 1 })
  })

  it('wraps a lone value in a list, decodes JSON-encoded objects, and joins a list of lines', () => {
    const out = coerceArgs(schema, {
      preconditions: 'attacker has an account',
      steps: '{"path":"a","start_line":2,"quote":["line one","line two"]}',
    })
    expect(out).toEqual({
      preconditions: ['attacker has an account'],
      steps: [{ path: 'a', start_line: 2, quote: 'line one\nline two' }],
    })
  })

  it('applies fixups keyed by schema instance before the generic rules', () => {
    const cwe = z
      .string()
      .regex(/^CWE-\d+$/)
      .optional()
    const withCwe = z.object({ cwe })
    const fixups = new Map([[cwe, (value: unknown) => (typeof value === 'number' ? `CWE-${value}` : value)]])
    expect(coerceArgs(withCwe, { cwe: 639 }, { fixups })).toEqual({ cwe: 'CWE-639' })
    // A throwing fixup leaves the value alone.
    const broken = new Map([
      [
        cwe,
        () => {
          throw new Error('boom')
        },
      ],
    ])
    expect(coerceArgs(withCwe, { cwe: 'CWE-1' }, { fixups: broken })).toEqual({ cwe: 'CWE-1' })
  })

  it('never throws, whatever the input', () => {
    for (const value of [undefined, null, 1, 'x', [], [1, 2], { steps: 5 }, { steps: [null] }]) {
      expect(() => coerceArgs(schema, value)).not.toThrow()
    }
  })
})

describe('salvageArgs', () => {
  const valid = { path: 'a', start_line: 1, quote: 'q' }

  it('drops the innermost failing list items and keeps the rest', async () => {
    const result = await salvageArgs(schema, {
      title: 't',
      severity: 'high',
      steps: [valid, { path: '', start_line: 2, quote: 'q' }, { ...valid, start_line: 3 }],
    })
    expect(result).toMatchObject({ ok: true, dropped: 1 })
    expect(result.ok && result.value.steps.map(s => s.start_line)).toEqual([1, 3])
  })

  it('drops an enclosing item once its own list becomes too short', async () => {
    const outer = z.object({ items: z.array(schema).max(5) })
    const finding = (steps: unknown[]) => ({ title: 't', severity: 'low', steps })
    const result = await salvageArgs(outer, {
      items: [finding([valid]), finding([{ path: '' }]), finding([valid, { quote: '' }])],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.items).toHaveLength(2)
    expect(result.value.items[1]?.steps).toHaveLength(1)
  })

  it('removes invalid items before cutting a list over its maximum', async () => {
    const result = await salvageArgs(schema, {
      title: 't',
      severity: 'info',
      preconditions: ['a', 7, 'b', 'c', 'd'],
      steps: [valid],
    })
    expect(result).toMatchObject({ ok: true, dropped: 2, value: { preconditions: ['a', 'b', 'c'] } })
  })

  it('fails when a field outside any list is invalid, without changing the input', async () => {
    const input = { title: '', severity: 'high', steps: [valid] }
    const result = await salvageArgs(schema, input)
    expect(result.ok).toBe(false)
    expect(!result.ok && result.issues[0]?.path).toEqual(['title'])
    expect(input.title).toBe('')
  })
})

describe('toolSchema', () => {
  it('drops the safe-integer bounds zod adds to integers but keeps real ones', () => {
    const tool = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({ line: z.number().int(), count: z.number().int().min(1).max(500) }),
      execute: async () => ({ text: '' }),
    })
    const properties = (toolSchema(tool).parameters as { properties: Record<string, object> }).properties
    expect(properties.line).toEqual({ type: 'integer' })
    expect(properties.count).toEqual({ type: 'integer', minimum: 1, maximum: 500 })
  })
})
