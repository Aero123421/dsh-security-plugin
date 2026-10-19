/**
 * Labels and explanatory text for the Markdown report, in English, Japanese
 * and Simplified Chinese. Machine-readable formats (JSON, SARIF) keep stable
 * English ids.
 */

import type { CoverageUnit, CoverageUnitStatus, ReportLanguage } from '../../shared/contracts.ts'
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
    /** The coverage ledger: what the AI review set out to examine and what became of each part. */
    readonly units: string
    readonly unitsLine: (covered: string, finding: string, blocked: string, notRun: string) => string
    readonly unitColumns: {
      readonly status: string
      readonly unit: string
      readonly where: string
      readonly note: string
    }
    readonly unitStatus: Readonly<Record<CoverageUnitStatus, string>>
    readonly unitOrigin: Readonly<Record<CoverageUnit['origin'], string>>
    /** Reason texts by `CoverageUnit.reason.code`; unknown codes use the Host's fallback text. */
    readonly unitReasons: Readonly<Record<string, string>>
    readonly unassignedFiles: string
    readonly unitsMore: (count: number) => string
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

const ZH_CLOSURES: Readonly<Record<Closure, string>> = {
  confirmed: '已通过代码确认',
  open_proof_gap: '需要确认',
  ruled_out: '已排除',
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
    units: 'Review units',
    unitsLine: (covered, finding, blocked, notRun) =>
      `${covered} examined without findings · ${finding} with findings · ${blocked} undecided · ${notRun} not examined`,
    unitColumns: { status: 'Status', unit: 'Unit', where: 'Where', note: 'Note' },
    unitStatus: { covered: 'Examined', finding: 'Findings', blocked: 'Undecided', 'not-run': 'Not examined' },
    unitOrigin: { recon: 'review plan', critic: 'coverage check', gap: 'added from the analyzers' },
    unitReasons: {
      budget: 'The scan budget ran out.',
      'task-limit': 'Beyond the task limit for this mode.',
      failed: 'The review did not finish.',
      'consent-revoked': 'Sending code to models was turned off.',
      'provider-rejected': 'The model provider rejected the request.',
      'no-tools': 'The model answered without calling tools.',
      'stale-target': 'Its files or endpoints no longer exist.',
      'needs-runtime': 'Depends on runtime or deployment the source does not show.',
      partial: 'The reviewer could not finish this part.',
    },
    unassignedFiles: 'Source files in no review unit',
    unitsMore: count => `${count} more units are listed in the JSON report.`,
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
    units: 'レビュー単位',
    unitsLine: (covered, finding, blocked, notRun) =>
      `検出なしで確認 ${covered} · 検出あり ${finding} · 判断保留 ${blocked} · 未確認 ${notRun}`,
    unitColumns: { status: '状態', unit: 'レビュー単位', where: '対象', note: '補足' },
    unitStatus: { covered: '確認済み', finding: '検出あり', blocked: '判断保留', 'not-run': '未確認' },
    unitOrigin: { recon: 'レビュー計画', critic: 'カバレッジ確認', gap: 'アナライザーから追加' },
    unitReasons: {
      budget: 'スキャンの予算を使い切りました。',
      'task-limit': 'このモードのタスク上限を超えました。',
      failed: 'レビューが完了しませんでした。',
      'consent-revoked': 'モデルへのコード送信がオフにされました。',
      'provider-rejected': 'モデルのプロバイダーがリクエストを拒否しました。',
      'no-tools': 'モデルがツールを呼ばずに回答しました。',
      'stale-target': '対象のファイルやエンドポイントがなくなりました。',
      'needs-runtime': 'ソースからは分からない実行環境やデプロイ設定に依存します。',
      partial: 'レビュー担当がこの部分を最後まで確認できませんでした。',
    },
    unassignedFiles: 'どのレビュー単位にも入らなかったソースファイル',
    unitsMore: count => `ほか ${count} 件のレビュー単位は JSON レポートにあります。`,
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

const ZH: ReportLabels = {
  title: 'DSH Security 报告',
  generated: (at, tool) => `由 ${tool} 于 ${at} 生成。`,

  sections: {
    scan: '扫描信息',
    howToRead: '如何阅读本报告',
    summary: '汇总',
    coverage: '覆盖范围',
    threatModel: '威胁模型',
    findings: '发现的问题',
  },

  field: '项目',
  value: '值',
  scanFields: {
    workspace: '工作区',
    scanId: '扫描 ID',
    mode: '模式',
    status: '状态',
    phase: '最后阶段',
    commit: '提交',
    dirty: '（有未提交的更改）',
    started: '开始时间',
    finished: '结束时间',
    model: role => `模型（${role}）`,
    usage: '用量',
    budget: '预算',
    error: '错误',
  },
  notRecorded: '未记录',
  noModels: '未使用模型',
  usageLine: (calls, input, output, tools, elapsed) =>
    `模型调用 ${calls} 次 · 输入 ${input} 个 token · 输出 ${output} 个 token · 工具调用 ${tools} 次 · ${elapsed}`,
  budgetLine: (calls, tokens, minutes) => `模型调用 ${calls} 次 · ${tokens} 个 token · ${minutes} 分钟`,
  elapsed: (h, m, s) => (h > 0 ? `${h} 小时 ${pad2(m)} 分 ${pad2(s)} 秒` : m > 0 ? `${m} 分 ${pad2(s)} 秒` : `${s} 秒`),

  howToRead: {
    intro:
      '每个问题都有两个相互独立的评级。在决定先修复哪个之前，请同时查看这两项：严重的问题也可能尚未得到证实，而低风险的问题也可能已经被确认。',
    severity:
      '**严重程度** 回答的是“如果问题属实，后果有多严重？”从 **严重**（攻击者可能接管系统或其数据），依次经过高、中、低，到 **信息**（值得了解，但没有直接风险）。',
    verification: '**确认程度** 回答的是“我们有多确定它是真实存在的？”各级别从强到弱依次为：',
    groups:
      '问题按确认程度分组：**已通过代码确认**（已实际验证，或有强有力的静态证据）、**需要确认**（可能存在或无法判定，请人工核实）、**已排除**（独立审查已予以否定，为保持透明仍列出）。',
    quoteCheck:
      '引用的代码片段旁的 ✓ 表示主机在所引用的位置找到了完全一致的代码；⚠ 表示未能找到（找不到引用、文件已更改，或没有可检查的内容）。',
  },

  summary: {
    severity: '严重程度',
    total: '合计',
    triageLine: parts => `处理状态：${parts}。`,
    newLine: count => `与上次扫描相比新增 ${count} 个问题。`,
  },

  zeroFindingsNote: {
    heading: '没有发现问题，并不代表就是安全的。',
    noneReported: '本次扫描没有报告已确认或需要确认的问题。',
    body: '这是一次预算和覆盖范围都有限的 AI 辅助审查（参见“覆盖范围”）。它可能遗漏漏洞，尤其是未读取的代码、无法看到的配置，以及只在运行时才出现的行为。请将其与测试、代码审查和专业的安全评估结合使用。',
  },

  coverage: {
    item: '项目',
    count: '数量',
    filesAnalyzed: '已分析的文件',
    filesReadByAi: 'AI 读取的文件',
    filesExcluded: '已排除的文件',
    endpointsReviewed: '已审查的接口',
    tasks: '审查任务',
    tasksLine: (planned, completed, failed, skipped) =>
      `计划 ${planned} · 完成 ${completed} · 失败 ${failed} · 跳过 ${skipped}`,
    discardedUnverifiable: '因无法验证而丢弃的候选问题',
    analyzers: '分析器',
    available: '可用',
    unavailable: '不可用',
    gaps: '已知的覆盖缺口',
    noGaps: '没有记录到覆盖缺口。',
    notices: '扫描提示',
    missing: '本次扫描未记录覆盖范围（扫描可能尚未完成）。',
    units: '审查单元',
    unitsLine: (covered, finding, blocked, notRun) =>
      `已审查且无发现 ${covered} · 有发现 ${finding} · 无法判定 ${blocked} · 未审查 ${notRun}`,
    unitColumns: { status: '状态', unit: '审查单元', where: '位置', note: '说明' },
    unitStatus: { covered: '已审查', finding: '有发现', blocked: '无法判定', 'not-run': '未审查' },
    unitOrigin: { recon: '审查计划', critic: '覆盖检查', gap: '根据分析器补充' },
    unitReasons: {
      budget: '扫描预算已用完。',
      'task-limit': '超出了此模式的任务上限。',
      failed: '审查未完成。',
      'consent-revoked': '已关闭向模型发送代码。',
      'provider-rejected': '模型提供方拒绝了请求。',
      'no-tools': '模型没有调用工具就作答了。',
      'stale-target': '相关文件或接口已不存在。',
      'needs-runtime': '取决于源代码中看不到的运行时或部署配置。',
      partial: '审查者未能完成这一部分。',
    },
    unassignedFiles: '未纳入任何审查单元的源文件',
    unitsMore: count => `其余 ${count} 个审查单元见 JSON 报告。`,
  },

  threatModel: {
    assets: '需要保护的资产',
    actors: '参与者',
    trustBoundaries: '信任边界',
  },

  groupHeading: (closure, count) => `${ZH_CLOSURES[closure]}（${count} 个）`,
  showRuledOut: count => `显示 ${count} 个已排除的问题`,
  noFindingsInGroup: '无。',

  finding: {
    severity: '严重程度',
    verification: '确认程度',
    cwe: 'CWE',
    location: '位置',
    noLocation: '不对应特定位置',
    source: '来源',
    rule: '规则',
    category: '类别',
    reportedBy: '报告者',
    triage: '处理状态',
    isNew: '上次扫描后新增',
    yes: '是',
    id: 'ID',
    fingerprint: '指纹',
    summary: '概要',
    impact: '影响',
    preconditions: '前提条件',
    attackPath: '攻击路径',
    evidence: '证据',
    counterevidence: '反证',
    review: '独立审查',
    reviewModel: model => `模型：${model}`,
    limitations: '局限性',
    recommendation: '修复建议',
    references: '参考资料',
    triageNote: '处理备注',
    none: '无记录。',
  },

  severities: { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' },
  verifications: {
    proven_dynamic: '已实际验证',
    strong_static_evidence: '强有力的静态证据',
    potential: '可能存在',
    inconclusive: '无法判定',
    refuted: '已否定',
  },
  verificationHelp: {
    proven_dynamic: '已在隔离环境中复现。仅检查代码的扫描不会给出此级别。',
    strong_static_evidence:
      '主机已对照源代码引用确认了一条可到达的代码路径及其前提条件，且独立审查没有发现有效的防护措施。',
    potential: '尚未经任何人确认的假设或自动检测信号。请把它当作线索，而不是结论。',
    inconclusive: '独立审查既无法确认，也无法否定。',
    refuted: '独立审查指出了代码中具体的防护措施。',
  },
  closures: ZH_CLOSURES,
  triage: { open: '待处理', accepted_risk: '已接受风险', false_positive: '误报', fixed: '已修复' },
  statuses: {
    queued: '排队中',
    running: '运行中',
    paused: '已暂停',
    completed: '已完成',
    failed: '失败',
    cancelled: '已取消',
    interrupted: '已中断',
  },
  modes: { quick: '快速', deep: '深入', research: '研究' },
  sources: {
    secret: '密钥检测',
    dependency: '依赖项审计',
    sast: '静态分析规则',
    ai: 'AI 审查',
    external: '外部分析器',
  },
  roles: {
    default: '默认',
    planner: '规划者',
    hunter: '猎手',
    skeptic: '审查者',
    chain: '攻击链分析',
    analyzer: '分析器',
  },
  reviewVerdicts: { confirmed: '确认', refuted: '否定', inconclusive: '无法判定' },
  quoteChecks: {
    match: '✓ 引用已核实',
    relocated: '✓ 引用已核实（已更正行号）',
    mismatch: '⚠ 在源代码中找不到该引用',
    stale: '⚠ 快照之后文件已更改',
    unchecked: '⚠ 未检查',
  },
}

function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

/** Report labels for one language. */
export function labelsFor(language: ReportLanguage): ReportLabels {
  return language === 'ja' ? JA : language === 'zh' ? ZH : EN
}
