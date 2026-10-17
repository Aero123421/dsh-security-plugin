/**
 * Gitleaks runner. The repository's own `.gitleaks.toml` is overridden by a
 * plugin-written config (default rules) so a scanned project cannot switch
 * detection off; secrets are redacted by gitleaks and again by `redactText`.
 */

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import type { Severity } from '../../../shared/domain.ts'
import { redactText } from '../secrets.ts'
import type { AnalyzerRun, Signal } from '../types.ts'
import {
  compareVersions,
  completedRun,
  DEFAULT_EXTERNAL_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  type ExternalRunOptions,
  errorMessage,
  failedRun,
  firstLine,
  normalizeForFingerprint,
  readReport,
  toWorkspacePath,
  unavailableRun,
} from './common.ts'
import { runTool } from './process.ts'

/** First release with the `dir` subcommand. */
const DIR_SUBCOMMAND_SINCE = '8.19.0'
const MAX_REPORT_BYTES = 128 * 1024 * 1024
const MAX_TARGET_MEGABYTES = 10
const MAX_FINDINGS = 5000
const PLUGIN_CONFIG = '# Written by dsh-security: default gitleaks rules only.\n[extend]\nuseDefault = true\n'

const findingSchema = z.object({
  RuleID: z.string().default('unknown'),
  Description: z.string().default(''),
  File: z.string(),
  StartLine: z.number().int().nonnegative().default(1),
  EndLine: z.number().int().nonnegative().default(0),
  StartColumn: z.number().int().optional(),
  EndColumn: z.number().int().optional(),
  Match: z.string().default(''),
  Line: z.string().optional(),
  Entropy: z.number().optional(),
  Tags: z.array(z.string()).nullish(),
  Fingerprint: z.string().optional(),
})
type GitleaksFinding = z.infer<typeof findingSchema>

/** Run gitleaks over the workspace root and convert its findings to signals. */
export async function runGitleaks(options: ExternalRunOptions): Promise<AnalyzerRun> {
  const started = Date.now()
  const { tool } = options
  if (!tool) return unavailableRun('gitleaks', 'gitleaks is not installed', started, [], 'not-installed')
  options.signal?.throwIfAborted()

  const work = await mkdtemp(join(tmpdir(), 'dsh-gitleaks-'))
  try {
    const configPath = join(work, 'gitleaks.toml')
    const reportPath = join(work, 'report.json')
    await writeFile(configPath, PLUGIN_CONFIG, { mode: 0o600 })
    const common = [
      '--no-banner',
      '--redact',
      '--ignore-gitleaks-allow',
      '--report-format',
      'json',
      '--report-path',
      reportPath,
      '--exit-code',
      '0',
      '--config',
      configPath,
      '--gitleaks-ignore-path',
      work,
      '--max-target-megabytes',
      String(MAX_TARGET_MEGABYTES),
      '--log-level',
      'error',
    ]
    const useDir = tool.version === undefined || compareVersions(tool.version, DIR_SUBCOMMAND_SINCE) >= 0
    const run = (args: string[]) =>
      runTool(tool.path, args, {
        cwd: work,
        timeoutMs: options.timeoutMs ?? DEFAULT_EXTERNAL_TIMEOUT_MS,
        maxOutputBytes: options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
        report: { path: reportPath, maxBytes: MAX_REPORT_BYTES },
        ...(options.signal ? { signal: options.signal } : {}),
      })

    let result: Awaited<ReturnType<typeof run>>
    try {
      result = await run(useDir ? ['dir', ...common, options.root] : legacyArgs(common, options.root))
      if (useDir && tool.version === undefined && result.code !== 0 && /unknown command/i.test(result.stderr)) {
        result = await run(legacyArgs(common, options.root))
      }
    } catch (error) {
      if (options.signal?.aborted) throw error
      return failedRun('gitleaks', tool, `could not start gitleaks: ${errorMessage(error)}`, started)
    }
    if (result.reportLimitExceeded)
      return failedRun('gitleaks', tool, 'gitleaks report exceeded the size limit', started)
    if (result.timedOut) return failedRun('gitleaks', tool, 'gitleaks timed out', started)
    if (result.code !== 0) {
      const detail = firstLine(redactText(result.stderr)) || `exit code ${result.code ?? result.signal}`
      return failedRun('gitleaks', tool, `gitleaks failed: ${detail}`, started)
    }

    let raw: unknown
    try {
      const text = await readReport(reportPath, MAX_REPORT_BYTES)
      raw = text.trim() === '' ? [] : JSON.parse(text)
    } catch (error) {
      return failedRun('gitleaks', tool, `could not read the gitleaks report: ${errorMessage(error)}`, started)
    }
    const warnings: string[] = []
    const signals = parseGitleaksReport(raw, options, warnings)
    return completedRun('gitleaks', tool, signals, started, warnings)
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => undefined)
  }
}

/**
 * Convert a parsed gitleaks JSON report into signals. Findings outside the
 * root, or (with a snapshot) in files the snapshot excluded, are dropped.
 */
export function parseGitleaksReport(
  raw: unknown,
  options: Pick<ExternalRunOptions, 'root' | 'snapshot'>,
  warnings: string[],
): Signal[] {
  if (!Array.isArray(raw)) {
    warnings.push('gitleaks report is not a JSON array')
    return []
  }
  if (raw.length > MAX_FINDINGS) warnings.push(`gitleaks reported ${raw.length} findings; only ${MAX_FINDINGS} kept`)
  const signals: Signal[] = []
  let malformed = 0
  for (const item of raw.slice(0, MAX_FINDINGS)) {
    const parsed = findingSchema.safeParse(item)
    if (!parsed.success) {
      malformed++
      continue
    }
    const finding = parsed.data
    const path = toWorkspacePath(options.root, finding.File, options.snapshot?.pathPrefix)
    if (!path) continue
    if (options.snapshot && !options.snapshot.files.has(path)) continue
    signals.push(toSignal(finding, path))
  }
  if (malformed > 0) warnings.push(`${malformed} gitleaks findings had an unexpected shape and were skipped`)
  return signals
}

function toSignal(finding: GitleaksFinding, path: string): Signal {
  const startLine = Math.max(1, finding.StartLine)
  const endLine = Math.max(startLine, finding.EndLine)
  // The tool's own excerpt is used (not snapshot text): gitleaks redacted the
  // secret in it, while the snapshot line may hold a secret our rules missed.
  const snippet = redactText(clip(finding.Line?.trim() ? finding.Line : finding.Match))
  const generic = /generic/i.test(finding.RuleID)
  const severity: Severity = /private-key|pkcs12/i.test(finding.RuleID) ? 'critical' : generic ? 'medium' : 'high'
  const description = finding.Description || finding.RuleID
  return {
    analyzer: 'gitleaks',
    ruleId: finding.RuleID,
    kind: 'secret',
    title: `Hard-coded secret: ${description}`,
    category: 'secrets',
    severity,
    confidence: generic ? 'low' : 'medium',
    cwe: 'CWE-798',
    location: { path, startLine, endLine },
    snippet,
    message:
      `Gitleaks matched its "${description}" rule here. A credential stored in source code can be copied by ` +
      'anyone with access to the repository, its forks, backups, or git history.',
    recommendation:
      'Revoke or rotate the credential with its provider, load it from an environment variable or secret manager ' +
      'instead, and purge it from git history because deleting the line does not remove earlier commits.',
    fingerprintParts: ['gitleaks', finding.RuleID, path, normalizeForFingerprint(snippet)],
    metadata: {
      ...(finding.Entropy !== undefined ? { entropy: Math.round(finding.Entropy * 100) / 100 } : {}),
      ...(finding.Tags && finding.Tags.length > 0 ? { tags: finding.Tags.join(', ') } : {}),
    },
  }
}

/** Pre-8.19 syntax: `detect --no-git --source <root>`. */
function legacyArgs(common: readonly string[], root: string): string[] {
  return ['detect', '--no-git', '--source', root, ...common]
}

function clip(text: string): string {
  const lines = text.replace(/\r/g, '').split('\n').slice(0, 6)
  return lines.map(line => (line.length > 240 ? `${line.slice(0, 239)}…` : line)).join('\n')
}
