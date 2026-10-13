/**
 * Labels and explanatory text for the Markdown report, in English and
 * Japanese. Machine-readable formats (JSON, SARIF) keep stable English ids.
 */

import type {
  Closure,
  FindingSource,
  RoleName,
  ScanMode,
  ScanStatus,
  Severity,
  TriageState,
  Verification,
} from '../../shared/domain.ts'

/** Every string the Markdown report prints that is not finding data. */
export interface ReportLabels {
  readonly title: string
  readonly generated: (at: string, tool: string) => string

  readonly sections: {
    readonly scan: string
    readonly howToRead: string
    readonly summary: string
    readonly coverage: string
    readonly threatModel: string
    readonly findings: string
  }

  readonly field: string
  readonly value: string
  readonly scanFields: {
    readonly workspace: string
    readonly scanId: string
    readonly mode: string
    readonly status: string
    readonly phase: string
    readonly commit: string
    readonly dirty: string
    readonly started: string
    readonly finished: string
    readonly model: (role: string) => string
    readonly usage: string
    readonly budget: string
    readonly error: string
  }
  readonly notRecorded: string
  readonly noModels: string
  readonly usageLine: (calls: string, input: string, output: string, tools: string, elapsed: string) => string
  readonly budgetLine: (calls: string, tokens: string, minutes: string) => string
  readonly elapsed: (hours: number, minutes: number, seconds: number) => string

  readonly howToRead: {
    readonly intro: string
    readonly severity: string
    readonly verification: string
    readonly groups: string
    readonly quoteCheck: string
  }

  readonly summary: {
    readonly severity: string
    readonly total: string
    readonly triageLine: (parts: string) => string
    readonly newLine: (count: number) => string
  }

  readonly zeroFindingsNote: { readonly heading: string; readonly noneReported: string; readonly body: string }

  readonly coverage: {
    readonly item: string
    readonly count: string
    readonly filesAnalyzed: string
    readonly filesReadByAi: string
    readonly filesExcluded: string
    readonly endpointsReviewed: string
    readonly tasks: string
    readonly tasksLine: (planned: string, completed: string, failed: string, skipped: string) => string
    readonly discardedUnverifiable: string
    readonly analyzers: string
    readonly available: string
    readonly unavailable: string
    readonly gaps: string
    readonly noGaps: string
    readonly notices: string
    readonly missing: string
  }

  readonly threatModel: {
    readonly assets: string
    readonly actors: string
    readonly trustBoundaries: string
  }

  readonly groupHeading: (closure: Closure, count: number) => string
  /** Text of the `<summary>` that expands the collapsed ruled-out findings. */
  readonly showRuledOut: (count: number) => string
  readonly noFindingsInGroup: string

  readonly finding: {
    readonly severity: string
    readonly verification: string
    readonly cwe: string
    readonly location: string
    readonly noLocation: string
    readonly source: string
    readonly rule: string
    readonly category: string
    readonly reportedBy: string
    readonly triage: string
    readonly isNew: string
    readonly yes: string
    readonly id: string
    readonly fingerprint: string
    readonly summary: string
    readonly impact: string
    readonly preconditions: string
    readonly attackPath: string
    readonly evidence: string
    readonly counterevidence: string
    readonly review: string
    readonly reviewModel: (model: string) => string
    readonly limitations: string
    readonly recommendation: string
    readonly references: string
    readonly triageNote: string
    readonly none: string
  }

  readonly severities: Readonly<Record<Severity, string>>
  readonly verifications: Readonly<Record<Verification, string>>
  readonly verificationHelp: Readonly<Record<Verification, string>>
  readonly closures: Readonly<Record<Closure, string>>
  readonly triage: Readonly<Record<TriageState, string>>
  readonly statuses: Readonly<Record<ScanStatus, string>>
  readonly modes: Readonly<Record<ScanMode, string>>
  readonly sources: Readonly<Record<FindingSource, string>>
  readonly roles: Readonly<Record<RoleName | 'default' | 'analyzer', string>>
  readonly reviewVerdicts: Readonly<Record<'confirmed' | 'refuted' | 'inconclusive', string>>
  readonly quoteChecks: {
    readonly match: string
    readonly relocated: string
    readonly mismatch: string
    readonly stale: string
    readonly unchecked: string
  }
}

const EN_CLOSURES: Readonly<Record<Closure, string>> = {
  confirmed: 'Confirmed',
  open_proof_gap: 'Needs proof',
  ruled_out: 'Ruled out',
}
const JA_CLOSURES: Readonly<Record<Closure, string>> = {
  confirmed: '確認済み',
  open_proof_gap: '要検証',
  ruled_out: '除外',
}

const EN: ReportLabels = {
  title: 'DSH Security report',
  generated: (at, tool) => `Generated ${at} by ${tool}.`,

  sections: {
    scan: 'Scan',
    howToRead: 'How to read this report',
    summary: 'Summary',
    coverage: 'Coverage',
    threatModel: 'Threat model',
    findings: 'Findings',
  },

  field: 'Field',
  value: 'Value',
  scanFields: {
    workspace: 'Workspace',
    scanId: 'Scan ID',
    mode: 'Mode',
    status: 'Status',
    phase: 'Last phase',
    commit: 'Commit',
    dirty: '(uncommitted changes)',
    started: 'Started',
    finished: 'Finished',
    model: role => `Model (${role})`,
    usage: 'Usage',
    budget: 'Budget',
    error: 'Error',
  },
  notRecorded: 'not recorded',
  noModels: 'no model was used',
  usageLine: (calls, input, output, tools, elapsed) =>
    `${calls} model calls · ${input} input tokens · ${output} output tokens · ${tools} tool calls · ${elapsed}`,
  budgetLine: (calls, tokens, minutes) => `${calls} model calls · ${tokens} tokens · ${minutes} min`,
  elapsed: (h, m, s) => (h > 0 ? `${h}h ${pad2(m)}m ${pad2(s)}s` : m > 0 ? `${m}m ${pad2(s)}s` : `${s}s`),

  howToRead: {
    intro:
      'Every finding carries two separate ratings. Read both before deciding what to fix first: a critical issue can still be unproven, and a low one can be firmly confirmed.',
    severity:
      '**Severity** answers "how bad would this be if it is real?" It ranges from **Critical** (an attacker could take over the system or its data) through High, Medium, and Low to **Info** (worth knowing, no direct risk).',
    verification: '**Verification** answers "how sure are we that it is real?" The levels, strongest first:',
    groups:
      'Findings are grouped by that answer: **Confirmed** (proven or strong static evidence), **Needs proof** (potential or inconclusive; check these by hand), and **Ruled out** (refuted by an independent review; listed for transparency).',
    quoteCheck:
      'Next to each quoted code excerpt, ✓ means the Host found that exact code at the cited location, and ⚠ means it could not (the quote was not found, the file changed, or there was nothing to check).',
  },

  summary: {
    severity: 'Severity',
    total: 'Total',
    triageLine: parts => `Triage: ${parts}.`,
    newLine: count => `${count} finding${count === 1 ? ' is' : 's are'} new since the previous scan.`,
  },

  zeroFindingsNote: {
    heading: 'No findings is not proof of safety.',
    noneReported: 'This scan reported no confirmed or unproven findings.',
    body: 'This is an AI-assisted review with a limited budget and limited coverage (see Coverage). It can miss vulnerabilities, especially in code it did not read, configuration it could not see, and behavior that only appears at runtime. Use it alongside tests, code review, and dedicated security assessments.',
  },

  coverage: {
    item: 'Item',
    count: 'Count',
    filesAnalyzed: 'Files analyzed',
    filesReadByAi: 'Files read by AI',
    filesExcluded: 'Files excluded',
    endpointsReviewed: 'Endpoints reviewed',
    tasks: 'Review tasks',
    tasksLine: (planned, completed, failed, skipped) =>
      `${planned} planned · ${completed} completed · ${failed} failed · ${skipped} skipped`,
    discardedUnverifiable: 'Candidates dropped as unverifiable',
    analyzers: 'Analyzers',
    available: 'available',
    unavailable: 'unavailable',
    gaps: 'Known gaps',
    noGaps: 'No coverage gaps were recorded.',
    notices: 'Scan notices',
    missing: 'Coverage was not recorded for this scan (it may not have finished).',
  },

  threatModel: {
    assets: 'Assets',
    actors: 'Actors',
    trustBoundaries: 'Trust boundaries',
  },

  groupHeading: (closure, count) => `${EN_CLOSURES[closure]} (${count})`,
  showRuledOut: count => `Show ${count} ruled-out finding${count === 1 ? '' : 's'}`,
  noFindingsInGroup: 'None.',

  finding: {
    severity: 'Severity',
    verification: 'Verification',
    cwe: 'CWE',
    location: 'Location',
    noLocation: 'not tied to one location',
    source: 'Source',
    rule: 'rule',
    category: 'category',
    reportedBy: 'reported by',
    triage: 'Triage',
    isNew: 'New since previous scan',
    yes: 'yes',
    id: 'ID',
    fingerprint: 'Fingerprint',
    summary: 'Summary',
    impact: 'Impact',
    preconditions: 'Preconditions',
    attackPath: 'Attack path',
    evidence: 'Evidence',
    counterevidence: 'Counter-evidence',
    review: 'Independent review',
    reviewModel: model => `model: ${model}`,
    limitations: 'Limitations',
    recommendation: 'Recommendation',
    references: 'References',
    triageNote: 'Triage note',
    none: 'None recorded.',
  },

  severities: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' },
  verifications: {
    proven_dynamic: 'Proven (dynamic)',
    strong_static_evidence: 'Strong static evidence',
    potential: 'Potential',
    inconclusive: 'Inconclusive',
    refuted: 'Refuted',
  },
  verificationHelp: {
    proven_dynamic: 'reproduced in an isolated environment. Code-only scans never assign this.',
    strong_static_evidence:
      'a reachable code path and its preconditions were confirmed against source quotes the Host checked, and an independent review found no effective defense.',
    potential: 'a hypothesis or an automated signal that nobody has confirmed yet. Treat it as a lead, not a verdict.',
    inconclusive: 'the independent review could neither confirm nor refute it.',
    refuted: 'an independent review pointed to a concrete defense in the code.',
  },
  closures: EN_CLOSURES,
  triage: { open: 'Open', accepted_risk: 'Accepted risk', false_positive: 'False positive', fixed: 'Fixed' },
  statuses: {
    queued: 'Queued',
    running: 'Running',
    paused: 'Paused',
    completed: 'Completed',
    failed: 'Failed',
    cancelled: 'Cancelled',
    interrupted: 'Interrupted',
  },
  modes: { quick: 'Quick', deep: 'Deep', research: 'Research' },
  sources: {
    secret: 'Secret detection',
    dependency: 'Dependency audit',
    sast: 'Static analysis rule',
    ai: 'AI review',
    external: 'External analyzer',
  },
  roles: {
    default: 'default',
    planner: 'planner',
    hunter: 'hunter',
    skeptic: 'skeptic',
    chain: 'chain',
    analyzer: 'analyzer',
  },
  reviewVerdicts: { confirmed: 'Confirmed', refuted: 'Refuted', inconclusive: 'Inconclusive' },
  quoteChecks: {
    match: '✓ quote verified',
    relocated: '✓ quote verified (line numbers corrected)',
    mismatch: '⚠ quote not found in the source',
    stale: '⚠ file changed after the snapshot',
    unchecked: '⚠ not checked',
  },
}

const JA: ReportLabels = {
  title: 'DSH Security レポート',
  generated: (at, tool) => `${at} に ${tool} で生成。`,

  sections: {
    scan: 'スキャン情報',
    howToRead: 'このレポートの読み方',
    summary: '集計',
    coverage: 'カバレッジ',
    threatModel: '脅威モデル',
    findings: '検出事項',
  },

  field: '項目',
  value: '値',
  scanFields: {
    workspace: 'ワークスペース',
    scanId: 'スキャン ID',
    mode: 'モード',
    status: '状態',
    phase: '最終フェーズ',
    commit: 'コミット',
    dirty: '（未コミットの変更あり）',
    started: '開始',
    finished: '終了',
    model: role => `モデル（${role}）`,
    usage: '使用量',
    budget: '予算',
    error: 'エラー',
  },
  notRecorded: '記録なし',
  noModels: 'モデルは使用されていません',
  usageLine: (calls, input, output, tools, elapsed) =>
    `モデル呼び出し ${calls} 回 · 入力 ${input} トークン · 出力 ${output} トークン · ツール呼び出し ${tools} 回 · ${elapsed}`,
  budgetLine: (calls, tokens, minutes) => `モデル呼び出し ${calls} 回 · ${tokens} トークン · ${minutes} 分`,
  elapsed: (h, m, s) => (h > 0 ? `${h}時間${pad2(m)}分${pad2(s)}秒` : m > 0 ? `${m}分${pad2(s)}秒` : `${s}秒`),

  howToRead: {
    intro:
      '各検出事項には、互いに独立した 2 つの評価があります。どれから直すかを決める前に、両方を確認してください。重大度が「重大」でも未確認のことがあり、「低」でも確実に確認されていることがあります。',
    severity:
      '**重大度** は「もし本当なら、どれくらい深刻か」を表します。**重大**（攻撃者がシステムやデータを乗っ取れる可能性）から、高・中・低を経て、**情報**（知っておくべきだが直接の危険はない）まであります。',
    verification: '**検証度** は「それが本当だと、どれくらい確かめられているか」を表します。強いものから順に:',
    groups:
      '検出事項はこの検証度でグループ分けされています。**確認済み**（動的に実証済み、または強い静的証拠あり）、**要検証**（可能性あり、または判定不能。手作業で確認してください）、**除外**（独立レビューで反証済み。透明性のために掲載）です。',
    quoteCheck:
      '引用されたコード片の横の ✓ は、ホストが引用どおりのコードを指定箇所で確認できたことを、⚠ は確認できなかったこと（引用が見つからない、ファイルが変更された、確認対象がない）を示します。',
  },

  summary: {
    severity: '重大度',
    total: '合計',
    triageLine: parts => `トリアージ: ${parts}。`,
    newLine: count => `前回のスキャン以降の新規検出は ${count} 件です。`,
  },

  zeroFindingsNote: {
    heading: '検出事項がゼロでも、安全とは限りません。',
    noneReported: 'このスキャンでは、確認済みまたは要検証の検出事項は報告されませんでした。',
    body: 'これは予算と対象範囲が限られた AI 支援のレビューです（カバレッジを参照）。特に、読まれなかったコード、見えない設定、実行時にしか現れない挙動に関する脆弱性を見逃すことがあります。テスト、コードレビュー、専門のセキュリティ診断と併用してください。',
  },

  coverage: {
    item: '項目',
    count: '件数',
    filesAnalyzed: '解析したファイル',
    filesReadByAi: 'AI が読んだファイル',
    filesExcluded: '除外したファイル',
    endpointsReviewed: 'レビューしたエンドポイント',
    tasks: 'レビュータスク',
    tasksLine: (planned, completed, failed, skipped) =>
      `計画 ${planned} · 完了 ${completed} · 失敗 ${failed} · スキップ ${skipped}`,
    discardedUnverifiable: '検証不能として破棄した候補',
    analyzers: 'アナライザー',
    available: '利用可能',
    unavailable: '利用不可',
    gaps: '既知の抜け漏れ',
    noGaps: '記録された抜け漏れはありません。',
    notices: 'スキャン中の通知',
    missing: 'このスキャンのカバレッジは記録されていません（完了していない可能性があります）。',
  },

  threatModel: {
    assets: '保護対象',
    actors: '関与者',
    trustBoundaries: '信頼境界',
  },

  groupHeading: (closure, count) => `${JA_CLOSURES[closure]}（${count} 件）`,
  showRuledOut: count => `除外された検出事項 ${count} 件を表示`,
  noFindingsInGroup: 'なし。',

  finding: {
    severity: '重大度',
    verification: '検証度',
    cwe: 'CWE',
    location: '場所',
    noLocation: '特定の場所なし',
    source: '検出元',
    rule: 'ルール',
    category: 'カテゴリ',
    reportedBy: '報告者',
    triage: 'トリアージ',
    isNew: '前回スキャン以降の新規',
    yes: 'はい',
    id: 'ID',
    fingerprint: 'フィンガープリント',
    summary: '概要',
    impact: '影響',
    preconditions: '前提条件',
    attackPath: '攻撃経路',
    evidence: '証拠',
    counterevidence: '反証',
    review: '独立レビュー',
    reviewModel: model => `モデル: ${model}`,
    limitations: '制約',
    recommendation: '推奨対応',
    references: '参考資料',
    triageNote: 'トリアージメモ',
    none: '記録なし。',
  },

  severities: { critical: '重大', high: '高', medium: '中', low: '低', info: '情報' },
  verifications: {
    proven_dynamic: '動的に実証済み',
    strong_static_evidence: '強い静的証拠あり',
    potential: '可能性あり',
    inconclusive: '判定不能',
    refuted: '反証済み',
  },
  verificationHelp: {
    proven_dynamic: '隔離環境で再現できた。コードだけのスキャンでは付与されません。',
    strong_static_evidence:
      '到達可能なコード経路と前提条件を、ホストが照合したソース引用で確認でき、独立レビューでも有効な防御が見つからなかった。',
    potential: 'まだ誰も確認していない仮説や自動検出のシグナル。結論ではなく手がかりとして扱ってください。',
    inconclusive: '独立レビューで確認も反証もできなかった。',
    refuted: '独立レビューが、コード中の具体的な防御を示した。',
  },
  closures: JA_CLOSURES,
  triage: { open: '未対応', accepted_risk: 'リスク受容', false_positive: '誤検知', fixed: '修正済み' },
  statuses: {
    queued: '待機中',
    running: '実行中',
    paused: '一時停止',
    completed: '完了',
    failed: '失敗',
    cancelled: 'キャンセル',
    interrupted: '中断',
  },
  modes: { quick: 'クイック', deep: 'ディープ', research: 'リサーチ' },
  sources: {
    secret: 'シークレット検出',
    dependency: '依存関係の監査',
    sast: '静的解析ルール',
    ai: 'AI レビュー',
    external: '外部アナライザー',
  },
  roles: {
    default: '既定',
    planner: 'プランナー',
    hunter: 'ハンター',
    skeptic: 'スケプティック',
    chain: 'チェーン',
    analyzer: 'アナライザー',
  },
  reviewVerdicts: { confirmed: '確認', refuted: '反証', inconclusive: '判定不能' },
  quoteChecks: {
    match: '✓ 引用を確認済み',
    relocated: '✓ 引用を確認済み（行番号を補正）',
    mismatch: '⚠ 引用がソースに見つからない',
    stale: '⚠ スナップショット後にファイルが変更された',
    unchecked: '⚠ 未確認',
  },
}

function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

/** Report labels for one language. */
export function labelsFor(language: 'en' | 'ja'): ReportLabels {
  return language === 'ja' ? JA : EN
}
