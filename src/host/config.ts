/**
 * Operator configuration, set in the profile's `cordis.patch.yml` under the
 * plugin row (`id: dsh-security`). These are deployment ceilings and paths;
 * user preferences live in the plugin's own settings (edited in the UI) and
 * are always clamped to these values.
 */

import { z } from 'zod'
import type { OperatorLimits } from '../shared/contracts.ts'

const positiveInt = (max: number) => z.number().int().min(1).max(max)

export const Config = z.object({
  /**
   * Directory for the plugin database, managed toolkit binaries, and temp
   * files. The bundle patch sets it to `$DSH_HOME/security`.
   */
  dataDir: z.string().min(1).optional().describe('Directory for the database and managed toolkit'),
  /** Upper bound for concurrent AI workers in one scan. */
  maxParallelWorkers: positiveInt(32).default(4),
  /** Scans that may run at once across all workspaces; the rest wait in a queue. */
  maxConcurrentScans: positiveInt(8).default(1),
  /** Files read into one snapshot. */
  maxFiles: positiveInt(1_000_000).default(20_000),
  /** Walked entries, including directories and excluded files (bounds excluded-only trees). */
  maxEntries: positiveInt(10_000_000).default(100_000),
  /** Largest single file read into a snapshot, in bytes. */
  maxFileBytes: positiveInt(64 * 1024 * 1024).default(1024 * 1024),
  /** Total snapshot size, in bytes. */
  maxTotalBytes: positiveInt(4 * 1024 * 1024 * 1024)
    .default(200 * 1024 * 1024)
    .describe('Total bytes read into one snapshot'),
  /** Ceiling for any scan's token budget. */
  maxTokensPerScan: positiveInt(1_000_000_000).default(20_000_000),
  /** Ceiling for any scan's model-request budget. */
  maxLlmCallsPerScan: positiveInt(1_000_000).default(2_000),
  /**
   * Allow pages that are not on the Host machine (remote Web) to turn on
   * settings that widen what leaves the machine (sending code to models,
   * OSV lookups, external analyzers). Turning them off is always allowed.
   */
  allowRemoteHighRiskSettings: z.boolean().default(true),
  /** Allow downloading pinned, hash-verified analyzer binaries into `dataDir`. */
  allowManagedToolkit: z.boolean().default(true),
  /** OSV API base URL (a mirror can be configured for air-gapped setups). */
  osvEndpoint: z.url().default('https://api.osv.dev'),
  /** Optional local Semgrep rules file or directory. Registry rules are never fetched. */
  semgrepConfig: z.string().min(1).optional(),
  /** Timeout for one external analyzer run, in milliseconds. */
  externalTimeoutMs: positiveInt(24 * 60 * 60 * 1000).default(10 * 60 * 1000),
  /**
   * Abandon a model request when its stream sends nothing for this long, in
   * milliseconds (the wait for the first chunk included). The request is
   * retried with backoff like any other transient `TIMEOUT`.
   */
  llmIdleTimeoutMs: z
    .number()
    .int()
    .min(1_000)
    .max(60 * 60 * 1000)
    .default(120_000),
  /** Disable the native ast-grep engine (fall back to the built-in lexer). */
  disableAstGrep: z.boolean().default(false),
})

export type Config = z.output<typeof Config>

export function operatorLimits(config: Config): OperatorLimits {
  return {
    maxParallelWorkers: config.maxParallelWorkers,
    maxConcurrentScans: config.maxConcurrentScans,
    maxFiles: config.maxFiles,
    maxFileBytes: config.maxFileBytes,
    maxTotalBytes: config.maxTotalBytes,
    maxTokensPerScan: config.maxTokensPerScan,
    maxLlmCallsPerScan: config.maxLlmCallsPerScan,
  }
}
