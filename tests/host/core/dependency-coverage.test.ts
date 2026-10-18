import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { runOsvScanner } from '../../../src/host/analysis/external/osv-scanner.ts'
import { osvVulnToSignal } from '../../../src/host/analysis/osv.ts'
import { Toolkit } from '../../../src/host/analysis/toolkit.ts'
import { makeTempDir } from '../analysis/helpers.ts'
import { createHarness, noNetwork } from './helpers.ts'

vi.mock('../../../src/host/analysis/external/osv-scanner.ts', () => ({ runOsvScanner: vi.fn() }))

afterEach(() => vi.restoreAllMocks())

const scannerStates = ['missing', 'no-database', 'failed', 'empty', 'clean', 'vulnerable'] as const
const cases = [0, 2].flatMap(dependencies =>
  [false, true].flatMap(lookup => scannerStates.map(scanner => ({ dependencies, lookup, scanner }))),
)

describe('dependency vulnerability coverage', () => {
  it.each(cases)(
    'dependencies=$dependencies lookup=$lookup scanner=$scanner',
    async ({ dependencies, lookup, scanner }) => {
      const { dir, cleanup } = await makeTempDir()
      const toolkit = new Toolkit({
        dir,
        lock: { schemaVersion: 1, tools: {} },
        allowManagedInstall: false,
        fetch: noNetwork,
      })
      vi.spyOn(toolkit, 'resolveHandle').mockResolvedValue(undefined)
      const checked = scanner === 'clean' || scanner === 'vulnerable'
      const available = checked || scanner === 'empty'
      const reason =
        scanner === 'missing'
          ? 'osv-scanner is not installed'
          : scanner === 'no-database'
            ? 'offline mode is on and no local osv-scanner database was found'
            : 'osv-scanner failed'
      vi.mocked(runOsvScanner).mockResolvedValue({
        status: {
          id: 'osv-scanner',
          available,
          source: scanner === 'failed' || available ? 'path' : 'disabled',
          ...(!available
            ? {
                reason,
                reasonCode:
                  scanner === 'missing' ? 'not-installed' : scanner === 'no-database' ? 'offline-db-missing' : 'failed',
              }
            : {}),
        },
        signals:
          scanner === 'vulnerable'
            ? [
                osvVulnToSignal(
                  { id: 'GHSA-test-coverage', summary: 'Test advisory' },
                  [{ ecosystem: 'npm', name: 'minimist', version: '1.2.5', manifest: 'package.json', line: 1 }],
                  'osv-scanner',
                ),
              ]
            : [],
        durationMs: 1,
        warnings: [],
        ...(available ? { checkedDependencies: checked ? 2 : 0 } : {}),
      })
      const h = createHarness({
        toolkit,
        workspaces: [{ id: 'ws', path: dir, title: 'test' }],
        settings: { privacy: { allowDependencyLookup: lookup, useExternalAnalyzers: true } },
      })
      try {
        await writeFile(
          join(dir, 'package.json'),
          JSON.stringify({ dependencies: dependencies ? { minimist: '1.2.5', lodash: '4.17.20' } : {} }),
        )
        const scan = await h.controller.create({ workspaceId: 'ws', mode: 'quick', aiReview: false })
        expect(await h.settle(scan.id)).toBe('completed')
        expect(runOsvScanner).toHaveBeenLastCalledWith(expect.objectContaining({ offline: !lookup }))
        const gaps =
          h.store
            .getScan(scan.id)
            ?.coverage?.gaps.filter(gap => gap.includes('dependencies were found but not checked')) ?? []
        const expected = dependencies > 0 && !checked
        expect(gaps).toHaveLength(expected ? 1 : 0)
        const details = h.store.getScan(scan.id)?.coverage?.gapDetails ?? []
        expect(details.map(detail => detail.fallback)).toEqual(h.store.getScan(scan.id)?.coverage?.gaps)
        expect(details.filter(detail => detail.code === 'dependencies-unchecked')).toHaveLength(expected ? 1 : 0)
        if (expected) {
          expect(details.find(detail => detail.code === 'dependencies-unchecked')?.params).toEqual({ count: 2 })
          expect(gaps[0]).toContain(
            `2 dependencies were found but not checked for known vulnerabilities: OSV lookup ${lookup ? 'did not complete' : 'is off'}`,
          )
          expect(gaps[0]).not.toContain(dir)
          expect(gaps[0]).not.toContain('minimist')
          expect(gaps[0]).not.toContain('lodash')
          expect(gaps[0]?.includes('not installed')).toBe(scanner === 'missing')
          if (scanner === 'empty') expect(gaps[0]).toContain('returned no dependency results')
        }
        if (scanner === 'vulnerable')
          expect(h.store.listFindings(scan.id).some(f => f.category === 'dependency' && f.source === 'external')).toBe(
            true,
          )
      } finally {
        await h.controller.dispose()
        h.store.close()
        await cleanup()
      }
    },
  )

  it.each([false, true])(
    'reports the gap when external analyzers are enabled=%s but no toolkit is available',
    async enabled => {
      const { dir, cleanup } = await makeTempDir()
      const h = createHarness({
        workspaces: [{ id: 'ws', path: dir, title: 'test' }],
        settings: { privacy: { useExternalAnalyzers: enabled } },
      })
      try {
        await writeFile(join(dir, 'requirements.txt'), 'flask==2.0.0\nrequests==2.20.0\n')
        const scan = await h.controller.create({ workspaceId: 'ws', mode: 'quick', aiReview: false })
        expect(await h.settle(scan.id)).toBe('completed')
        expect(h.store.getScan(scan.id)?.coverage?.gaps).toContain(
          '2 dependencies were found but not checked for known vulnerabilities: OSV lookup is off and OSV-Scanner did not check dependencies. Check dependency lookup in Privacy settings or configure offline OSV-Scanner.',
        )
      } finally {
        await h.controller.dispose()
        h.store.close()
        await cleanup()
      }
    },
  )
})
