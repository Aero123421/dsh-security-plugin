/**
 * Shared "is this user-controlled?" heuristics and expression helpers.
 *
 * Taint is intra-procedural and deliberately conservative:
 * - Sources are recognized syntactically (`req.query`, `request.args`, ...).
 * - It flows through plain expressions (concatenation, templates, object and
 *   array literals, member access on a tainted value) and through a short
 *   list of transparent calls (`String`, `path.join`, `.format`, ...).
 * - Any other call is opaque: its arguments do not taint the result. This
 *   treats unknown helpers as potential sanitizers (`escapeHtml(x)`,
 *   `path.basename(x)`, `int(x)`), trading some recall for precision.
 * - Local aliases propagate in source order within the enclosing function
 *   chain (`const { id } = req.params` taints `id`); a later plain
 *   assignment of an untainted value clears the alias.
 */

import { allOf, anyOf, type Charset, findGuards, type Guard, guardAt, subjectText } from './guards.ts'
import { JS_KEYWORDS, PY_KEYWORDS, stringContent, type Token, tokenRange } from './lexer.ts'
import {
  type AssignFact,
  type CallFact,
  type FileModel,
  type FnFact,
  fnChain,
  innermostFn,
  type Span,
} from './model.ts'

/**
 * Where tainted data comes from: a remote HTTP request, the command line /
 * stdin of a CLI tool, or the browser (URL fragments, `window.name`) in
 * client-side code.
 */
export type TaintOrigin = 'request' | 'cli' | 'browser'

export interface Taint {
  /** Human-readable source, e.g. `req.query` or `route parameter 'name'`. */
  readonly source: string
  /** The source appears literally in the analyzed expression (not via an alias or parameter). */
  readonly direct: boolean
  readonly origin: TaintOrigin
  /**
   * Every tainted part passed an allow-list check first (`if (!/^[\w.-]+$/.test(x)) return`) that admits only
   * these characters. Rules decide whether that is enough for their sink.
   */
  readonly guard?: Charset
}

/** Properties and methods whose result is a number or a boolean, never attacker-chosen text. */
const JS_NON_STRING_TAIL =
  /\.(?:length|size|byteLength)$|\.(?:includes|startsWith|endsWith|has|indexOf|lastIndexOf|findIndex|findLastIndex|some|every|test|toFixed|getTime|valueOf|charCodeAt|codePointAt|localeCompare|isInteger|isSafeInteger|isFinite|isNaN)\(\)$/
const PY_NON_STRING_TAIL =
  /\.(?:isdigit|isnumeric|isdecimal|isalpha|isalnum|isspace|isupper|islower|startswith|endswith|count|find|rfind|index|rindex)\(\)$/
/** Operators whose operands are converted to numbers, or whose result is a boolean. */
const JS_NUMERIC_OPERATORS: ReadonlySet<string> = new Set([
  '*',
  '/',
  '%',
  '-',
  '**',
  '<',
  '>',
  '<=',
  '>=',
  '==',
  '===',
  '!=',
  '!==',
  '&',
  '|',
  '^',
  '<<',
  '>>',
  '>>>',
])
/** Python operators that reject or convert text operands (`*`, `%` and `+` keep strings). */
const PY_NUMERIC_OPERATORS: ReadonlySet<string> = new Set(['-', '/', '//', '**', '<', '>', '<=', '>=', '==', '!='])
/** `.map(Number)`, `.map(n => parseInt(n, 10))`, `.map(x => +x)`: every element becomes a number. */
const NUMERIC_MAPPER =
  /^(?:Number|parseInt|parseFloat|BigInt|Boolean|Math\.\w+|\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*(?:(?:Number|parseInt|parseFloat|BigInt|Boolean|Math\.\w+)\(\s*\1\s*(?:,\s*\d+\s*)?\)|\+\s*\1|\1\s*\|\s*0))$/
/** Nesting depth of brackets and conditionals the taint scan follows structurally. */
const MAX_SCAN_DEPTH = 48

/** Merge two allow-listed taints: the result is only as safe as both. */
function mergeGuarded(a: Taint | undefined, b: Taint | undefined): Taint | undefined {
  if (!a) return b
  if (!b?.guard || !a.guard) return a
  return { ...a, guard: allOf(a.guard, b.guard) }
}

/** Token index ranges of a conditional expression's parts. */
interface TernaryParts {
  readonly cond: readonly [number, number]
  readonly yes: readonly [number, number]
  readonly no: readonly [number, number]
}

interface SourcePattern {
  readonly re: RegExp
  readonly origin?: TaintOrigin
}

const JS_SOURCES: readonly SourcePattern[] = [
  {
    re: /^(?:req|request)\.(?:body|query|params|headers|cookies|signedCookies|files?|ip|ips|hostname)(?![\w$])/,
  },
  { re: /^(?:req|request)\.(?:get|header|param)\(\)/ },
  { re: /^(?:req|request)\.(?:json|formData|text)\(\)/ },
  { re: /^(?:req|request)\.nextUrl\.(?:searchParams|pathname|search)/ },
  {
    re: /^ctx\.(?:request\.(?:body|query|files|headers|querystring)|query|params|querystring|headers|req\.body)(?![\w$])/,
  },
  { re: /^ctx\.(?:get|cookies\.get)\(\)/ },
  { re: /^c\.req\.(?:query|queries|param|json|header|parseBody|formData|text|valid)\(\)/ },
  {
    re: /^event\.(?:body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers|multiValueHeaders|rawPath|rawQueryString)(?![\w$])/,
  },
  { re: /(?:^|\.)searchParams\.(?:get|getAll)\(\)/ },
  { re: /^formData\.(?:get|getAll)\(\)/ },
  { re: /^(?:window\.|document\.|self\.|globalThis\.)?location\.(?:hash|search|href)(?![\w$])/, origin: 'browser' },
  { re: /^document\.(?:URL|documentURI|referrer|baseURI)(?![\w$])/, origin: 'browser' },
  { re: /^window\.name$/, origin: 'browser' },
  { re: /^(?:useSearchParams|useParams)\(\)/, origin: 'browser' },
  { re: /^process\.argv(?![\w$])/, origin: 'cli' },
]

/** Next.js route handlers and pages: `params`/`searchParams` props are user input. */
const JS_NEXT_SOURCES: readonly SourcePattern[] = [
  { re: /^(?:params|searchParams)(?![\w$])/ },
  { re: /^(?:context|ctx)\.(?:params|query)(?![\w$])/ },
  { re: /^router\.query(?![\w$])/ },
]

const PY_SOURCES: readonly SourcePattern[] = [
  {
    re: /^(?:self\.)?request\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|FILES|COOKIES|META|body|query_params|path_params|query|match_info|stream|get_json\(\)|get_data\(\)|form\(\)|json\(\)|body\(\)|post\(\)|text\(\))(?!\w)/,
  },
  { re: /^sys\.argv(?!\w)/, origin: 'cli' },
  { re: /^input\(\)/, origin: 'cli' },
]

/** Calls whose result carries the taint of their arguments. */
const JS_TRANSPARENT_CALLEES =
  /^(?:String|Array\.from|Object\.(?:assign|values|entries|keys)|JSON\.(?:parse|stringify)|decodeURI(?:Component)?|unescape|atob|Buffer\.from|(?:path|posix|win32|\w*[pP]ath)\.(?:join|resolve|normalize)|url\.(?:resolve|parse)|URL|util\.format|format|sprintf|vsprintf|Promise\.resolve|String\.raw|Base64\.decode)$/
const JS_TRANSPARENT_METHODS: ReadonlySet<string> = new Set([
  'concat',
  'join',
  'format',
  'map',
  'flatMap',
  'filter',
  'find',
  'reduce',
])

const PY_TRANSPARENT_CALLEES =
  /^(?:str|repr|dict|list|tuple|set|bytes|bytearray|os\.path\.(?:join|normpath|abspath|realpath|expanduser)|posixpath\.join|(?:pathlib\.)?(?:Pure)?Path|(?:urllib\.parse\.)?(?:urljoin|unquote|unquote_plus)|json\.loads|base64\.(?:b64decode|urlsafe_b64decode)|codecs\.decode|textwrap\.dedent)$/
const PY_TRANSPARENT_METHODS: ReadonlySet<string> = new Set([
  'format',
  'join',
  'strip',
  'lstrip',
  'rstrip',
  'lower',
  'upper',
  'replace',
  'encode',
  'decode',
  'get',
  'getlist',
  'items',
  'values',
  'joinpath',
])

/** Configuration values the operator controls: never "dynamic user input". */
const JS_TRUSTED_CHAIN =
  /^(?:process\.env|import\.meta\.(?:env|url|dirname|filename)|config|CONFIG|settings|env|__dirname|__filename|process\.cwd\(\))(?:[.[]|$)/
const PY_TRUSTED_CHAIN =
  /^(?:os\.environ|os\.getenv\(\)|settings|config|current_app\.config|app\.config|__file__|BASE_DIR|os\.getcwd\(\))(?:[.[(]|$)/

/** Calls whose result is constant when their arguments are. */
const JS_PURE_CALLEES =
  /^(?:path\.(?:join|resolve|normalize|basename|dirname|extname|relative)|join|resolve|String|Number|parseInt|parseFloat|Boolean|encodeURIComponent|encodeURI|JSON\.stringify|Math\.\w+|Date\.now|os\.(?:tmpdir|homedir|platform|EOL)|url\.fileURLToPath|fileURLToPath|require\.resolve|URL)$/
const PY_PURE_CALLEES =
  /^(?:os\.path\.\w+|str|int|float|len|repr|Path|pathlib\.Path|tempfile\.gettempdir|json\.dumps|os\.getcwd)$/

const CONST_IDENTS: ReadonlySet<string> = new Set([
  'true',
  'false',
  'null',
  'undefined',
  'NaN',
  'Infinity',
  'None',
  'True',
  'False',
  'typeof',
  'void',
  'in',
  'of',
  'instanceof',
  'not',
  'and',
  'or',
  'is',
  'if',
  'else',
  'as',
  'satisfies',
])

const SAFE_PY_PARAM_TYPES =
  /^(?:int|float|bool|complex|Decimal|UUID|uuid\.UUID|datetime|date|time|timedelta|(?:\w+\.)?(?:Request|Response|WebSocket|HTTPConnection|BackgroundTasks|Session|AsyncSession|SecurityScopes|Connection)|Optional\[(?:int|float|bool|UUID)\])$/
const PY_ROUTE_DECORATOR =
  /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.(?:route|get|post|put|patch|delete|head|options|api_route|websocket)$/
const PY_SAFE_PARAM_NAMES: ReadonlySet<string> = new Set(['self', 'cls', 'request', 'req', 'db', 'session', 'response'])

interface AliasEvent {
  readonly at: number
  readonly names: readonly string[]
  readonly taint: Taint | undefined
  readonly whole: string | undefined
  readonly augmented: boolean
}

interface ScopeState {
  readonly aliases: Pick<ReadonlyMap<string, Taint>, 'get'>
  /** Names bound to a whole request body (`const data = req.body`). */
  readonly wholeBody: Pick<ReadonlyMap<string, string>, 'get'>
}

interface ScopeCursor {
  at: number
  index: number
  readonly aliases: Map<string, Taint>
  readonly wholeBody: Map<string, string>
  readonly assignedInside: Set<string>
  readonly view: ScopeState
}

const WHOLE_BODY_JS =
  /^(?:(?:req|request)\.body|ctx\.request\.body|(?:req|request)\.(?:json|formData)\(\)|c\.req\.(?:json|parseBody)\(\))$/
const WHOLE_BODY_PY =
  /^(?:self\.)?request\.(?:json|form|data|values|POST|GET|args|get_json\(\)|json\(\)|form\(\)|query_params)$|^(?:self\.)?request\.(?:form|args|POST|GET|data|json|values)\.(?:to_dict|dict|copy)\(\)$/

export interface ExprOptions {
  /**
   * Canonical callee for a callee as written, mapping its first segment through the file's imports
   * (`join` → `path.join` after `import { join } from 'node:path'`). Without it, callees are matched as written.
   */
  readonly qualify?: (callee: string) => string
  /** Function name → parameters that hold numbers or UUIDs because every route fills them through a converter. */
  readonly scalarParams?: ReadonlyMap<string, ReadonlySet<string>>
}

/** Per-file analysis context. */
export class Expr {
  readonly model: FileModel
  readonly #qualify: ((callee: string) => string) | undefined
  readonly #scalarParams: ReadonlyMap<string, ReadonlySet<string>> | undefined
  readonly #sources: readonly SourcePattern[]
  readonly #keywords: ReadonlySet<string>
  readonly #stateByFn = new Map<FnFact | undefined, ScopeCursor>()
  readonly #eventsByFn = new Map<FnFact | undefined, AliasEvent[]>()
  readonly #paramTaint = new Map<FnFact, Map<string, Taint>>()
  #flaskConverters: Map<FnFact, Set<string>> | undefined
  #guards: readonly Guard[] | undefined
  readonly #clientFile: boolean

  constructor(model: FileModel, options: ExprOptions = {}) {
    this.model = model
    this.#qualify = options.qualify
    this.#scalarParams = options.scalarParams
    this.#clientFile = model.lang === 'js' && /^\s*(?:\/\/[^\n]*\n\s*)*['"]use client['"]/.test(model.source)
    const next = model.lang === 'js' && isNextFile(model.path)
    this.#sources = model.lang === 'py' ? PY_SOURCES : next ? [...JS_SOURCES, ...JS_NEXT_SOURCES] : JS_SOURCES
    this.#keywords = model.lang === 'py' ? PY_KEYWORDS : JS_KEYWORDS
  }

  get tokens(): readonly Token[] {
    return this.model.tokens
  }

  /**
   * `name` is a parameter of an enclosing function annotated with a numeric
   * or boolean type, or bound by a Flask `<int:…>`/`<float:…>`/`<uuid:…>`
   * converter.
   */
  #isScalarParam(name: string, at: number): boolean {
    for (const fn of fnChain(innermostFn(this.model.fns, at))) {
      const param = fn.params.find(p => p.names.includes(name))
      if (!param) continue
      if (this.model.lang === 'py' && this.#flaskSafeParams(fn).has(name)) return true
      if (fn.name !== undefined && this.#scalarParams?.get(fn.name)?.has(name)) return true
      const ann = (param.annotation ?? '').replace(/\s+/g, '')
      return /^(?:int|float|bool|number|boolean|bigint|Decimal|UUID|uuid\.UUID|Optional\[(?:int|float|bool)\]|(?:int|float|bool|number|boolean)\|None|(?:number|boolean)\|(?:undefined|null))$/.test(
        ann,
      )
    }
    return false
  }

  /** Token index range of a span. */
  range(span: Span): [number, number] {
    return tokenRange(this.model.tokens, span.start, span.end)
  }

  text(span: Span): string {
    return this.model.source.slice(span.start, span.end)
  }

  // -------------------------------------------------------------------------
  // Literals and shapes
  // -------------------------------------------------------------------------

  /** Content of a plain string literal span (no interpolation), else undefined. */
  literal(span: Span): string | undefined {
    const [a, b] = this.range(span)
    if (b - a !== 1) {
      // Implicit concatenation of adjacent Python literals, or parenthesized literal.
      if (b - a >= 3 && this.#isPunct(a, '(') && this.#isPunct(b - 1, ')')) {
        return this.literal({ start: this.tokens[a + 1]!.start, end: this.tokens[b - 2]!.end })
      }
      if (this.model.lang === 'py' && b - a > 1) {
        let out = ''
        for (let k = a; k < b; k++) {
          const t = this.tokens[k]!
          if (t.type !== 'str' || t.interp) return undefined
          out += stringContent(t)
        }
        return out
      }
      return undefined
    }
    const t = this.tokens[a]!
    if (t.type !== 'str' || t.interp) return undefined
    if (/^[bB]/.test(t.value) && this.model.lang === 'py') return stringContent(t)
    return stringContent(t)
  }

  /** The span is a single token of the given identifier value (`true`, `True`, `false`...). */
  isWord(span: Span, ...words: string[]): boolean {
    const [a, b] = this.range(span)
    if (b - a !== 1) return false
    const t = this.tokens[a]!
    return (t.type === 'ident' || t.type === 'num') && words.includes(t.value)
  }

  /** The span is an object (JS) or dict (Python) literal. */
  isObjectLiteral(span: Span): boolean {
    const [a, b] = this.range(span)
    return b > a && this.#isPunct(a, '{') && this.model.match[a] === b - 1
  }

  isArrayLiteral(span: Span): boolean {
    const [a, b] = this.range(span)
    return b > a && this.#isPunct(a, '[') && this.model.match[a] === b - 1
  }

  /** Whether the span is a function/lambda expression. */
  isFunctionLike(span: Span): boolean {
    const [a, b] = this.range(span)
    const t = this.tokens[a]
    if (!t) return false
    if (t.type === 'ident' && (t.value === 'function' || t.value === 'lambda')) return true
    if (t.type === 'ident' && t.value === 'async') return true
    for (let k = a; k < b; k++) {
      const u = this.tokens[k]!
      if (u.type === 'punct' && u.value === '=>') return true
      if (u.type === 'punct' && (u.value === '(' || u.value === '[' || u.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0) return false
        k = m
        continue
      }
      if (u.type !== 'ident' && !(u.type === 'punct' && (u.value === ':' || u.value === '<' || u.value === '>'))) {
        return false
      }
    }
    return false
  }

  /** Top-level `key: value` entries of an object/dict literal. */
  objectEntries(span: Span): { key: string | undefined; keySpan: Span; value: Span | undefined; spread: boolean }[] {
    const [a, b] = this.range(span)
    if (!this.isObjectLiteral(span)) return []
    const out: { key: string | undefined; keySpan: Span; value: Span | undefined; spread: boolean }[] = []
    for (const [s, e] of this.#splitTop(a + 1, b - 1)) {
      const first = this.tokens[s]!
      if (first.type === 'punct' && (first.value === '...' || first.value === '**')) {
        out.push({ key: undefined, keySpan: this.#span(s, s + 1), value: this.#span(s + 1, e), spread: true })
        continue
      }
      const colon = this.#findTop(s, e, ':')
      let key: string | undefined
      if (first.type === 'str') key = stringContent(first)
      else if (first.type === 'ident' || first.type === 'num') key = first.value
      if (colon < 0) {
        // shorthand `{ a }` or method `{ a() {} }`
        out.push({
          key,
          keySpan: this.#span(s, s + 1),
          value: e - s === 1 ? this.#span(s, e) : undefined,
          spread: false,
        })
        continue
      }
      out.push({
        key: colon === s + 1 ? key : undefined,
        keySpan: this.#span(s, colon),
        value: colon + 1 < e ? this.#span(colon + 1, e) : undefined,
        spread: false,
      })
    }
    return out
  }

  /** Value of `key` in an object/dict literal (first match), searching only the top level. */
  prop(span: Span, key: string): Span | undefined {
    for (const entry of this.objectEntries(span)) if (entry.key === key && entry.value) return entry.value
    return undefined
  }

  /** Elements of an array/list/tuple literal. */
  elements(span: Span): Span[] {
    const [a, b] = this.range(span)
    if (b - a < 2) return []
    const open = this.tokens[a]!
    if (!(open.type === 'punct' && (open.value === '[' || open.value === '(')) || this.model.match[a] !== b - 1)
      return []
    return this.#splitTop(a + 1, b - 1).map(([s, e]) => this.#span(s, e))
  }

  /**
   * Whether the expression builds a string dynamically: a template/f-string
   * with substitutions, `+` concatenation, `.concat`/`.join`, Python
   * `%`-formatting or `.format()` on a literal.
   */
  isStringBuilt(span: Span): boolean {
    const [a, b] = this.range(span)
    for (let k = a; k < b; k++) {
      const t = this.tokens[k]!
      if (t.type === 'str' && t.interp && this.#isTaggedTemplate(k)) {
        k = this.#templateEnd(k) - 1
        continue
      }
      if (t.type === 'str' && t.interp) return true
      if (t.type !== 'punct' || t.sub !== undefined) continue
      if (t.value === '(' && k > a && this.#isCallParen(k)) {
        // Arguments of an opaque call do not make the result a built string.
        const callee = this.tokens[k - 1]!
        const transparent =
          callee.type === 'ident' && /^(?:format|join|concat|str|String|text|sprintf)$/.test(callee.value)
        const m = this.model.match[k]!
        if (!transparent && m > k && m < b) {
          k = m
          continue
        }
      }
      if (t.value === '+' || t.value === '+=') return true
      if (this.model.lang === 'py' && t.value === '%' && k > a && this.tokens[k - 1]!.type === 'str') return true
      if (t.value === '.' && k + 1 < b) {
        const name = this.tokens[k + 1]!
        if (name.type === 'ident' && (name.value === 'format' || name.value === 'concat' || name.value === 'join')) {
          return true
        }
      }
    }
    return false
  }

  /**
   * Whether the expression is built only from literals, trusted configuration
   * (`process.env`, `settings`), constant-looking names (`UPPER_CASE`) and
   * local variables that were assigned such values.
   */
  isConstant(span: Span, at = span.start, depth = 0): boolean {
    const [a, b] = this.range(span)
    if (b <= a) return true
    // `cond ? 'ASC' : 'DESC'` / `'ASC' if cond else 'DESC'`: only the branches reach the result.
    const branches = this.#ternaryBranches(a, b)
    if (branches) return branches.every(branch => this.isConstant(branch, at, depth))
    for (let k = a; k < b; k++) {
      const t = this.tokens[k]!
      if (t.type === 'punct' && t.sub === 'open') {
        const close = this.model.match[k]!
        if (close > k && close < b) {
          if (close > k + 1 && !this.isConstant(this.#span(k + 1, close), at, depth)) return false
          k = close
          continue
        }
      }
      if (t.type !== 'ident') continue
      if (this.#isMemberName(k)) continue
      if (CONST_IDENTS.has(t.value)) continue
      const chain = this.#chain(k, b)
      const norm = chain.norm
      const trusted = this.model.lang === 'py' ? PY_TRUSTED_CHAIN : JS_TRUSTED_CHAIN
      if (trusted.test(norm)) {
        k = chain.end - 1
        continue
      }
      if (/^[A-Z][A-Z0-9_]*$/.test(t.value) && t.value.length > 1 && !chain.hasCall) {
        k = chain.end - 1
        continue
      }
      if (chain.hasCall) {
        const pure = this.model.lang === 'py' ? PY_PURE_CALLEES : JS_PURE_CALLEES
        // A pure helper is constant when its arguments are: keep scanning into them.
        if (chain.calls.length === 1 && this.#matchesCallee(pure, chain.calls[0]!.callee)) continue
      }
      if (chain.parts === 1 && !chain.hasCall && this.#isScalarParam(t.value, at)) continue
      if (chain.parts === 1 && !chain.hasCall && depth < 2) {
        const values = this.resolve({ start: t.start, end: t.end }, at)
        if (values.length > 0 && values.every(v => v.start !== t.start && this.isConstant(v, v.start, depth + 1)))
          continue
      }
      if (t.value === 'new' || t.value === 'await' || t.value === 'lambda' || t.value === 'function') continue
      if (this.#keywords.has(t.value) && t.value !== 'this') continue
      return false
    }
    return true
  }

  /**
   * Values an identifier was last assigned before `at` within the enclosing
   * function chain (plus later augmented assignments). Returns `[span]` for
   * anything that is not a bare identifier or has no visible assignment.
   */
  resolve(span: Span, at = span.start): Span[] {
    const [a, b] = this.range(span)
    if (b - a !== 1 || this.tokens[a]!.type !== 'ident') return [span]
    const name = this.tokens[a]!.value
    const fn = innermostFn(this.model.fns, at)
    const scope = new Set<FnFact | undefined>([undefined, ...fnChain(fn)])
    let values: Span[] | undefined
    for (const assign of this.model.assigns) {
      if (assign.start >= at) break
      if (!scope.has(assign.fn) || assign.end > at) continue
      if (!assign.targets.some(t => t.name === name)) continue
      if (assign.op === '=' && !assign.destructured) values = [assign.value]
      else if (assign.op === '=' || assign.op === 'for' || assign.op === 'with') values = undefined
      else if (values) values.push(assign.value)
    }
    return values ?? [span]
  }

  /**
   * Whether the expression's leading literal pins the scheme and host
   * (`https://api.example.com/...`) or is a same-site path (`/users/...`),
   * so input appended later can only change the path.
   */
  hasFixedOrigin(span: Span): boolean {
    const [a, b] = this.range(span)
    let k = a
    while (this.#isPunct(k, '(')) k++
    const t = this.tokens[k]
    if (!t) return false
    if (t.type === 'str') {
      const content = stringContent(t)
      if (/^[a-z][a-z0-9+.-]*:\/\/[^/?#\s@]+[/?#]/i.test(content)) return true
      if (/^\/[^/\\]/.test(content)) return true
      // `${BASE}/path/${x}` / f"{BASE}/path/{x}": a constant base followed by a path.
      if (t.part === 'head' && content === '' && this.tokens[k + 1]?.sub === 'open') {
        const close = this.model.match[k + 1]!
        if (close <= k + 2 || close >= b) return false
        const base = this.#span(k + 2, close)
        const next = this.tokens[close + 1]
        return next?.type === 'str' && isPathStart(stringContent(next)) && this.isConstant(base)
      }
      return false
    }
    // `BASE + '/path/' + x`
    if (t.type === 'ident') {
      const chain = this.#chain(k, b)
      const plus = this.tokens[chain.end]
      const next = this.tokens[chain.end + 1]
      if (plus?.type !== 'punct' || plus.value !== '+' || next?.type !== 'str') return false
      return isPathStart(stringContent(next)) && this.isConstant(this.#span(k, chain.end))
    }
    return false
  }

  /**
   * Substitutions of a template literal / f-string and the operands of `+`
   * concatenation at the top level of `span`: the parts that are not
   * literal text. Returns `undefined` when the span is not built that way.
   */
  dynamicParts(span: Span): Span[] | undefined {
    const [a, b] = this.range(span)
    const parts: Span[] = []
    let built = false
    let operandStart = a
    const flush = (end: number): void => {
      if (end <= operandStart) return
      const t = this.tokens[operandStart]!
      if (!(end - operandStart === 1 && t.type === 'str' && !t.interp)) parts.push(this.#span(operandStart, end))
    }
    for (let k = a; k < b; k++) {
      const t = this.tokens[k]!
      if (t.type === 'str' && t.interp) {
        if (this.#isTaggedTemplate(k)) return undefined
        built = true
        // Walk the chunks of this literal, collecting substitutions.
        let i = k
        while (i < b) {
          const open = this.tokens[i + 1]
          if (open?.sub !== 'open') break
          const close = this.model.match[i + 1]!
          if (close < 0 || close >= b) return undefined
          if (close > i + 2) parts.push(this.#span(i + 2, close))
          i = close + 1
        }
        if (k === operandStart) operandStart = i + 1
        k = i
        continue
      }
      if (t.type === 'punct' && t.sub === undefined && (t.value === '(' || t.value === '[' || t.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0 || m >= b) return undefined
        k = m
        continue
      }
      if (t.type === 'punct' && t.sub === undefined && t.value === '+') {
        built = true
        flush(k)
        operandStart = k + 1
      }
    }
    if (!built) return undefined
    flush(b)
    return parts
  }

  /** Branch spans of a top-level conditional expression in tokens `[a, b)`. */
  #ternaryBranches(a: number, b: number): Span[] | undefined {
    const parts = this.#ternaryParts(a, b)
    return parts ? [this.#span(parts.yes[0], parts.yes[1]), this.#span(parts.no[0], parts.no[1])] : undefined
  }

  /** Condition and branches of a top-level conditional expression in tokens `[a, b)`. */
  #ternaryParts(a: number, b: number): TernaryParts | undefined {
    const skip = (k: number): number => {
      const t = this.tokens[k]!
      if (t.type === 'punct' && (t.sub === 'open' || (t.sub === undefined && /^[([{]$/.test(t.value)))) {
        const m = this.model.match[k]!
        return m < 0 || m >= b ? -1 : m
      }
      return k
    }
    if (this.model.lang === 'py') {
      let ifAt = -1
      for (let k = a; k < b; k++) {
        const next = skip(k)
        if (next < 0) return undefined
        if (next !== k) {
          k = next
          continue
        }
        const t = this.tokens[k]!
        if (t.type !== 'ident') continue
        if (t.value === 'lambda' || t.value === 'for') return undefined
        if (t.value === 'if' && ifAt < 0 && k > a) ifAt = k
        else if (t.value === 'else' && ifAt >= 0 && k + 1 < b) {
          return { cond: [ifAt + 1, k], yes: [a, ifAt], no: [k + 1, b] }
        }
      }
      return undefined
    }
    let question = -1
    let nested = 0
    for (let k = a; k < b; k++) {
      const next = skip(k)
      if (next < 0) return undefined
      if (next !== k) {
        k = next
        continue
      }
      const t = this.tokens[k]!
      if (t.type !== 'punct' || t.sub !== undefined) continue
      if (t.value === '=>' || t.value === '=' || t.value === ',') return undefined
      if (t.value === '?') {
        if (question < 0) question = k
        else nested++
      } else if (t.value === ':' && question >= 0) {
        if (nested > 0) nested--
        else if (k > question + 1 && k + 1 < b) return { cond: [a, question], yes: [question + 1, k], no: [k + 1, b] }
        else return undefined
      }
    }
    return undefined
  }

  /** `(` at `k` opens call arguments (preceded by a callee), not a parenthesized expression. */
  #isCallParen(k: number): boolean {
    const prev = this.tokens[k - 1]
    if (!prev) return false
    if (prev.type === 'ident') return !this.#keywords.has(prev.value) || prev.value === 'this'
    return prev.type === 'punct' && (prev.value === ')' || prev.value === ']') && prev.sub === undefined
  }

  // -------------------------------------------------------------------------
  // Taint
  // -------------------------------------------------------------------------

  /**
   * First user-controlled source that reaches the value of `span`, or
   * undefined. Aliases are evaluated as of offset `at` (default: span start).
   */
  taint(span: Span, at = span.start): Taint | undefined {
    const state = this.#stateAt(at)
    const [a, b] = this.range(span)
    return this.#scan(a, b, state)
  }

  /** Taint of the span or, for a bare identifier, of the values it was assigned. */
  taintResolved(span: Span, at = span.start): Taint | undefined {
    const direct = this.taint(span, at)
    if (direct) return direct
    for (const value of this.resolve(span, at)) {
      if (value.start === span.start && value.end === span.end) continue
      const t = this.taint(value, value.start)
      if (t) return { ...t, direct: false }
    }
    return undefined
  }

  /** Whether `span` is exactly a whole request body (or an alias bound to one). */
  wholeBody(span: Span, at = span.start): string | undefined {
    const [a, b] = this.range(span)
    let k = a
    if (this.model.lang === 'js' && this.tokens[k]?.type === 'ident' && this.tokens[k]!.value === 'await') k++
    if (this.model.lang === 'py' && this.tokens[k]?.type === 'ident' && this.tokens[k]!.value === 'await') k++
    if (k >= b || this.tokens[k]!.type !== 'ident') return undefined
    const chain = this.#chain(k, b)
    if (chain.end !== b) return undefined
    const re = this.model.lang === 'py' ? WHOLE_BODY_PY : WHOLE_BODY_JS
    if (re.test(chain.norm)) return chain.norm
    if (chain.parts === 1 && !chain.hasCall) {
      const state = this.#stateAt(at)
      return state.wholeBody.get(chain.norm)
    }
    return undefined
  }

  /**
   * Taint when the span is exactly a source expression (`req.query`,
   * `req.body.name`), or an identifier holding one unchanged (bound by
   * destructuring, a loop, a parameter, or a plain copy). Values passed
   * through any call (`String(x)`) do not count.
   */
  exactSource(span: Span, at = span.start, depth = 0): Taint | undefined {
    const [a, b] = this.range(span)
    let k = a
    if (this.tokens[k]?.type === 'ident' && this.tokens[k]!.value === 'await') k++
    if (k >= b || this.tokens[k]!.type !== 'ident') return undefined
    const chain = this.#chain(k, b)
    if (chain.end !== b) return undefined
    if (this.#nonStringChain(chain)) return undefined
    const src = this.#matchSource(chain.norm)
    if (src) return src
    if (chain.hasCall) return undefined
    const name = this.tokens[k]!
    const nameSpan = { start: name.start, end: name.end }
    const values = this.resolve(nameSpan, at)
    if (values.length === 1 && values[0]!.start === name.start) {
      const alias = this.#stateAt(at).aliases.get(name.value)
      return alias ? { ...alias, direct: false } : undefined
    }
    if (depth >= 3 || chain.parts > 1) return undefined
    for (const value of values) {
      const t = this.exactSource(value, value.start, depth + 1)
      if (t) return { ...t, direct: false }
    }
    return undefined
  }

  /** Normalized member chain if the span is exactly one chain (`db.query`, `req.body`). */
  chainOf(span: Span): string | undefined {
    const [a, b] = this.range(span)
    if (a >= b || this.tokens[a]!.type !== 'ident') return undefined
    const chain = this.#chain(a, b)
    return chain.end === b ? chain.norm : undefined
  }

  #matchSource(norm: string): Taint | undefined {
    for (const pattern of this.#sources) {
      const m = pattern.re.exec(norm)
      if (m) {
        let origin = pattern.origin ?? 'request'
        if (origin === 'request' && this.#clientFile && /searchParams|formData/.test(norm)) origin = 'browser'
        return { source: displaySource(norm, m), direct: true, origin }
      }
    }
    return undefined
  }

  /**
   * First taint reaching the value of tokens `[a, b)`. Only the branches of a conditional count (and not a
   * branch the condition restricts to an allow-list), comprehension elements carry the taint of their loop
   * variables only, and numbers or booleans derived from input (`items.length`, `x === 'a'`, `ids.map(Number)`)
   * are not tainted text. A taint that passed an allow-list guard is returned only when nothing unguarded is found.
   */
  #scan(a: number, b: number, state: ScopeState, depth = 0): Taint | undefined {
    if (depth < MAX_SCAN_DEPTH) {
      const parts = this.#ternaryParts(a, b)
      if (parts) return this.#scanTernary(parts, state, depth + 1)
      if (this.model.lang === 'py') {
        const comprehension = this.#scanComprehension(a, b, state, depth + 1)
        if (comprehension !== false) return comprehension
      }
    }
    const tokens = this.tokens
    let guarded: Taint | undefined
    for (let k = a; k < b; k++) {
      const t = tokens[k]!
      if (
        depth < MAX_SCAN_DEPTH &&
        t.type === 'punct' &&
        (t.sub === 'open' || (t.sub === undefined && (t.value === '(' || t.value === '[' || t.value === '{')))
      ) {
        // Groupings, literals and substitutions are scanned as expressions of their own.
        const m = this.model.match[k]!
        if (m > k + 1 && m < b) {
          const inner = this.#scan(k + 1, m, state, depth + 1)
          if (inner && !inner.guard) return inner
          guarded = mergeGuarded(guarded, inner)
          k = m
          continue
        }
      }
      if (t.type !== 'ident' || this.#isMemberName(k)) continue
      if (this.#keywords.has(t.value) && t.value !== 'this') continue
      const chain = this.#chain(k, b)
      if (this.#nonStringChain(chain) || this.#nonStringOperand(k, chain.end)) {
        k = chain.end - 1
        continue
      }
      const src = this.#matchSource(chain.norm)
      if (src) {
        const guard = this.#guardAt(subjectText(this.model, k, chain.end), t.start)
        if (!guard) return src
        guarded = mergeGuarded(guarded, { ...src, guard })
        k = chain.end - 1
        continue
      }
      const alias = state.aliases.get(t.value)
      if (alias && !this.#isCalledDirectly(k)) {
        if (!(this.model.lang === 'js' && this.#isPunct(k + 1, ':') && this.#isObjectKey(k))) {
          if (!(this.model.lang === 'py' && this.#isPunct(k + 1, '=') && !this.#isPunct(k + 2, '='))) {
            const here = this.#guardAt(t.value, t.start)
            const guard = here && alias.guard ? anyOf(here, alias.guard) : (here ?? alias.guard)
            if (!guard) return { ...alias, direct: false }
            guarded = mergeGuarded(guarded, { ...alias, direct: false, guard })
            k = chain.end - 1
            continue
          }
        }
      }
      for (const call of chain.calls) {
        if (this.#isTransparent(call.callee, call.method)) {
          const inner = this.#scan(call.open + 1, call.close, state, depth + 1)
          if (inner && !inner.guard) return inner
          guarded = mergeGuarded(guarded, inner)
        }
      }
      k = chain.end - 1
    }
    return guarded
  }

  /** Taint of a conditional's branches, leaving out a branch its condition restricts to an allow-list. */
  #scanTernary(parts: TernaryParts, state: ScopeState, depth: number): Taint | undefined {
    const allowed = this.#allowListTest(parts.cond[0], parts.cond[1], state)
    let guarded: Taint | undefined
    for (const [range, whenTrue] of [
      [parts.yes, true],
      [parts.no, false],
    ] as const) {
      if (allowed && allowed.negated !== whenTrue && this.#textOf(range[0], range[1]) === allowed.subject) continue
      const found = this.#scan(range[0], range[1], state, depth)
      if (found && !found.guard) return found
      guarded = mergeGuarded(guarded, found)
    }
    return guarded
  }

  /**
   * A condition that holds only when `subject` is one of a list of values not taken from the input:
   * `LIST.includes(x)`, `SET.has(x)`, `LIST.indexOf(x) !== -1`, `x in OBJ` (JS keys or a Python
   * collection), or `x === 'a' || x === 'b'` (`or` in Python). `negated` for a leading `!`/`not`
   * or Python `not in`.
   */
  #allowListTest(a: number, b: number, state: ScopeState): { subject: string; negated: boolean } | undefined {
    const py = this.model.lang === 'py'
    let negated = false
    let s = a
    let e = b
    for (let guard = 0; guard < 8; guard++) {
      if (this.#isPunct(s, '!') || (py && this.tokens[s]?.type === 'ident' && this.tokens[s]!.value === 'not')) {
        negated = !negated
        s++
        continue
      }
      if (this.#isPunct(s, '(') && this.model.match[s] === e - 1) {
        s++
        e--
        continue
      }
      break
    }
    if (e <= s) return undefined
    const clean = (x: number, y: number): boolean => y > x && !this.#scan(x, y, state, MAX_SCAN_DEPTH)
    // Equality chains: `x === 'a' || x === 'b'`.
    const alternatives = this.#splitTopOn(s, e, py ? 'or' : '||')
    const equalities = alternatives.map(([x, y]) => this.#equalitySubject(x, y))
    if (equalities.every(Boolean) && new Set(equalities).size === 1) return { subject: equalities[0]!, negated }
    if (alternatives.length > 1) return undefined
    // Membership: `x in LIST` (`not in` negates).
    for (let k = s + 1; k < e - 1; k++) {
      const t = this.tokens[k]!
      if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0) return undefined
        k = m
        continue
      }
      if (t.type !== 'ident' || t.value !== 'in') continue
      const not = py && this.tokens[k - 1]?.type === 'ident' && this.tokens[k - 1]!.value === 'not'
      const subjectEnd = not ? k - 1 : k
      if (!clean(k + 1, e) || subjectEnd <= s) return undefined
      return { subject: this.#textOf(s, subjectEnd), negated: not ? !negated : negated }
    }
    if (py) return undefined
    // `LIST.includes(x)`, `SET.has(x)`, `LIST.indexOf(x) !== -1`.
    let end = e
    let call = e - 1
    const cmp = this.tokens[e - 2]
    const last = this.tokens[e - 1]
    if (
      cmp?.type === 'punct' &&
      ['!==', '!=', '>', '>='].includes(cmp.value) &&
      (last?.type === 'num' || last?.value === '1')
    ) {
      const negative = this.#isPunct(e - 3, '-') && last.value === '1'
      const valid =
        ((cmp.value === '!==' || cmp.value === '!=' || cmp.value === '>') && negative) ||
        (cmp.value === '>=' && last.value === '0')
      if (!valid) return undefined
      end = negative ? e - 3 : e - 2
      call = end - 1
    }
    if (!this.#isPunct(call, ')')) return undefined
    const open = this.model.match[call]!
    const method = this.tokens[open - 1]
    if (open < s + 2 || method?.type !== 'ident' || !this.#isPunct(open - 2, '.')) return undefined
    const indexOf = end !== e
    if (indexOf ? method.value !== 'indexOf' : method.value !== 'includes' && method.value !== 'has') return undefined
    if (!clean(s, open - 2) || open + 1 >= call) return undefined
    return { subject: this.#textOf(open + 1, call), negated }
  }

  /** `x === 'lit'`, `'lit' == x` (Python `==` too): the non-literal side, or undefined. */
  #equalitySubject(a: number, b: number): string | undefined {
    for (let k = a + 1; k < b - 1; k++) {
      const t = this.tokens[k]!
      if (t.type !== 'punct' || !['===', '=='].includes(t.value)) continue
      const literal = (x: number, y: number) => y === x + 1 && this.literal(this.#span(x, y)) !== undefined
      if (literal(k + 1, b)) return this.#textOf(a, k)
      if (literal(a, k)) return this.#textOf(k + 1, b)
      return undefined
    }
    return undefined
  }

  /** Token ranges of `[a, b)` split at a top-level operator (`||`, Python `or`). */
  #splitTopOn(a: number, b: number, op: string): [number, number][] {
    const out: [number, number][] = []
    let s = a
    for (let k = a; k < b; k++) {
      const t = this.tokens[k]!
      if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0 || m >= b) return [[a, b]]
        k = m
        continue
      }
      if (t.value === op && (t.type === 'punct' || t.type === 'ident')) {
        out.push([s, k])
        s = k + 1
      }
    }
    out.push([s, b])
    return out
  }

  /**
   * Python comprehensions and generator expressions in `[a, b)`: the element carries the taint of the loop
   * variables (bound to their iterables), not of the iterables themselves, so
   * `','.join(str(int(i)) for i in ids)` is clean. `false` when `[a, b)` is not a comprehension.
   */
  #scanComprehension(a: number, b: number, state: ScopeState, depth: number): Taint | undefined | false {
    const fors: number[] = []
    for (let k = a + 1; k < b; k++) {
      const t = this.tokens[k]!
      if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0 || m >= b) return false
        k = m
        continue
      }
      if (t.type === 'ident' && t.value === 'for') fors.push(k)
    }
    if (fors.length === 0) return false
    const loop = new Map<string, Taint | undefined>()
    const view: ScopeState = {
      aliases: { get: name => (loop.has(name) ? loop.get(name) : state.aliases.get(name)) },
      wholeBody: state.wholeBody,
    }
    for (const [i, f] of fors.entries()) {
      const limit = fors[i + 1] ?? b
      let inAt = -1
      for (let k = f + 1; k < limit; k++) {
        if (this.tokens[k]!.type === 'ident' && this.tokens[k]!.value === 'in') {
          inAt = k
          break
        }
      }
      if (inAt < 0) return false
      let iterableEnd = limit
      for (let k = inAt + 1; k < limit; k++) {
        const t = this.tokens[k]!
        if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
          const m = this.model.match[k]!
          if (m > k) k = m
          continue
        }
        if (t.type === 'ident' && t.value === 'if') {
          iterableEnd = k
          break
        }
      }
      const taint = inAt + 1 < iterableEnd ? this.#scan(inAt + 1, iterableEnd, view, depth) : undefined
      for (let k = f + 1; k < inAt; k++) {
        const t = this.tokens[k]!
        if (t.type === 'ident') loop.set(t.value, taint ? { ...taint, direct: false } : undefined)
      }
    }
    return this.#scan(a, fors[0]!, view, depth)
  }

  /** The chain's value is a number or a boolean: `.length`, `.includes(x)`, or a `.map(Number)` step. */
  #nonStringChain(chain: ChainInfo): boolean {
    if (this.model.lang === 'py') return PY_NON_STRING_TAIL.test(chain.norm)
    if (JS_NON_STRING_TAIL.test(chain.norm)) return true
    return chain.calls.some(
      call =>
        (call.method === 'map' || call.method === 'flatMap') &&
        call.close > call.open + 1 &&
        NUMERIC_MAPPER.test(this.#textOf(call.open + 1, call.close)),
    )
  }

  /** The operand ending before token `end` (starting at `k`) is converted to a number or compared. */
  #nonStringOperand(k: number, end: number): boolean {
    const py = this.model.lang === 'py'
    const ops = py ? PY_NUMERIC_OPERATORS : JS_NUMERIC_OPERATORS
    const before = this.tokens[k - 1]
    const after = this.tokens[end]
    if (after?.type === 'punct' && after.sub === undefined && ops.has(after.value)) return true
    if (after?.type === 'ident' && (py ? /^(?:in|is|not)$/ : /^(?:instanceof|in)$/).test(after.value)) return true
    if (!before) return false
    if (before.type === 'ident') return py ? before.value === 'not' : /^(?:typeof|void|delete)$/.test(before.value)
    if (before.type !== 'punct' || before.sub !== undefined) return false
    if (before.value === '!' || before.value === '~' || before.value === '-') return true
    if (!py && before.value === '+') {
      // Unary plus converts to a number; binary plus concatenates.
      const prev = this.tokens[k - 2]
      return !prev || (prev.type === 'punct' && !/^(?:\)|\]|\}|\+\+|--)$/.test(prev.value)) || prev.value === 'return'
    }
    return ops.has(before.value) && before.value !== '-'
  }

  /** Allow-list guard on `subject` holding at offset `at`. */
  #guardAt(subject: string, at: number): Charset | undefined {
    this.#guards ??= findGuards(this.model)
    return this.#guards.length === 0 ? undefined : guardAt(this.model, this.#guards, subject, at)
  }

  /** Whitespace-free source text of tokens `[a, b)`. */
  #textOf(a: number, b: number): string {
    return subjectText(this.model, a, b)
  }

  #isTransparent(callee: string, method: string | undefined): boolean {
    if (this.model.lang === 'py') {
      if (this.#matchesCallee(PY_TRANSPARENT_CALLEES, callee)) return true
      return method !== undefined && PY_TRANSPARENT_METHODS.has(method)
    }
    if (this.#matchesCallee(JS_TRANSPARENT_CALLEES, callee)) return true
    return method !== undefined && JS_TRANSPARENT_METHODS.has(method)
  }

  /** The callee as written or as qualified through the file's imports matches `re`. */
  #matchesCallee(re: RegExp, callee: string): boolean {
    if (re.test(callee)) return true
    const qualified = this.#qualify?.(callee)
    return qualified !== undefined && qualified !== callee && re.test(qualified)
  }

  /** Reuse the per-function cursor for increasing offsets; backward queries rebuild exact state.
   * The cache belongs to this immutable file model/Expr only and is released with it.
   */
  #stateAt(at: number): ScopeState {
    const fn = innermostFn(this.model.fns, at)
    const events = this.#events(fn)
    let cursor = this.#stateByFn.get(fn)
    if (!cursor || at < cursor.at) {
      const aliases = new Map<string, Taint>()
      const wholeBody = new Map<string, string>()
      for (const chainFn of [...fnChain(fn)].reverse()) {
        for (const [name, taint] of this.#paramTaints(chainFn)) aliases.set(name, taint)
      }
      const own = fn ? this.#paramTaints(fn) : undefined
      const shadowed = new Set(fn?.params.flatMap(param => param.names.filter(name => !own?.has(name))))
      const assignedInside = new Set<string>()
      const hidden = (name: string) => shadowed.has(name) && !assignedInside.has(name)
      cursor = {
        at: Number.NEGATIVE_INFINITY,
        index: 0,
        aliases,
        wholeBody,
        assignedInside,
        // Filter shadowed parameters without copying every alias map or mutating the replay state.
        view: {
          aliases: { get: name => (hidden(name) ? undefined : aliases.get(name)) },
          wholeBody: { get: name => (hidden(name) ? undefined : wholeBody.get(name)) },
        },
      }
      this.#stateByFn.set(fn, cursor)
    }
    while (cursor.index < events.length) {
      const event = events[cursor.index]!
      if (event.at > at) break
      cursor.index++
      for (const name of event.names) {
        if (event.taint) cursor.aliases.set(name, event.taint)
        else if (!event.augmented) cursor.aliases.delete(name)
        if (event.whole) cursor.wholeBody.set(name, event.whole)
        else if (!event.augmented) cursor.wholeBody.delete(name)
        if (fn && event.at >= fn.start) cursor.assignedInside.add(name)
      }
    }
    cursor.at = at
    return cursor.view
  }

  #events(fn: FnFact | undefined): AliasEvent[] {
    const cached = this.#eventsByFn.get(fn)
    if (cached) return cached
    const scope = new Set<FnFact | undefined>([undefined, ...fnChain(fn)])
    const relevant = this.model.assigns.filter(assign => scope.has(assign.fn))
    const events: AliasEvent[] = []
    const state = { aliases: new Map<string, Taint>(), wholeBody: new Map<string, string>() }
    for (const chainFn of [...fnChain(fn)].reverse()) {
      for (const [name, taint] of this.#paramTaints(chainFn)) state.aliases.set(name, taint)
    }
    for (const assign of relevant) {
      const [a, b] = this.range(assign.value)
      const taint = this.#scan(a, b, state)
      const augmented = assign.op !== '=' && assign.op !== 'for' && assign.op !== 'with'
      const whole = !assign.destructured && assign.op === '=' ? this.#wholeBodyOf(assign, state) : undefined
      const perTarget = taint ? undefined : this.#destructuredSources(assign)
      const groups: [string[], Taint | undefined, string | undefined][] = perTarget
        ? perTarget.map(([name, t, w]) => [[name], t, w])
        : [[assign.targets.map(target => target.name), taint ? { ...taint, direct: false } : undefined, whole]]
      for (const [names, groupTaint, groupWhole] of groups) {
        const event: AliasEvent = { at: assign.end, names, taint: groupTaint, whole: groupWhole, augmented }
        events.push(event)
        for (const name of names) {
          if (event.taint) state.aliases.set(name, event.taint)
          else if (!augmented) state.aliases.delete(name)
          if (event.whole) state.wholeBody.set(name, event.whole)
          else if (!augmented) state.wholeBody.delete(name)
        }
      }
    }
    events.sort((x, y) => x.at - y.at)
    this.#eventsByFn.set(fn, events)
    return events
  }

  /**
   * `const { body, query: { q } } = req`: destructuring the request object
   * itself binds each target to `req.<key path>`, which is a source only for
   * some keys (`body`, `query`, not `method` or `user`). Returns per-target
   * `[name, taint, wholeBody]`, or `undefined` when the value is not a plain
   * request-object chain.
   */
  #destructuredSources(assign: AssignFact): [string, Taint | undefined, string | undefined][] | undefined {
    if (!assign.destructured || assign.op !== '=' || this.model.lang !== 'js') return undefined
    const [a, b] = this.range(assign.value)
    let k = a
    if (this.tokens[k]?.type === 'ident' && this.tokens[k]!.value === 'await') k++
    if (k >= b || this.tokens[k]!.type !== 'ident') return undefined
    const chain = this.#chain(k, b)
    if (chain.end !== b || chain.hasCall) return undefined
    if (!/^(?:req|request|ctx|ctx\.request|c\.req|event|context)$/.test(chain.norm)) return undefined
    const out: [string, Taint | undefined, string | undefined][] = []
    for (const target of assign.targets) {
      const key = target.key
      if (!key || key.startsWith('...') || /(?:^|\.)\d+(?:\.|$)/.test(key)) {
        out.push([target.name, undefined, undefined])
        continue
      }
      const norm = `${chain.norm}.${key.replace(/\.\.\.$/, '')}`
      const src = this.#matchSource(norm)
      const whole = (this.model.lang === 'js' ? WHOLE_BODY_JS : WHOLE_BODY_PY).test(norm) ? norm : undefined
      out.push([target.name, src ? { ...src, source: norm, direct: false } : undefined, whole])
    }
    return out
  }

  #wholeBodyOf(assign: AssignFact, state: ScopeState): string | undefined {
    const [a, b] = this.range(assign.value)
    let k = a
    if (this.tokens[k]?.type === 'ident' && this.tokens[k]!.value === 'await') k++
    if (k >= b || this.tokens[k]!.type !== 'ident') return undefined
    const chain = this.#chain(k, b)
    if (chain.end !== b) return undefined
    const re = this.model.lang === 'py' ? WHOLE_BODY_PY : WHOLE_BODY_JS
    if (re.test(chain.norm)) return chain.norm
    if (chain.parts === 1 && !chain.hasCall) return state.wholeBody.get(chain.norm)
    return undefined
  }

  /** Parameters of `fn` that carry user input (FastAPI/Flask/Django route parameters, NestJS `@Body()`...). */
  #paramTaints(fn: FnFact): Map<string, Taint> {
    const cached = this.#paramTaint.get(fn)
    if (cached) return cached
    const out = new Map<string, Taint>()
    if (this.model.lang === 'js') {
      for (const param of fn.params) {
        const dec = param.decorators.find(d =>
          /^(?:Body|Query|Param|Params|Headers|Req|Request|UploadedFiles?|Cookies)$/.test(d.replace(/^.*\./, '')),
        )
        if (!dec) continue
        if (/Parse(?:Int|Float|Bool|UUID|Enum|Array)Pipe/.test(this.text(param))) continue
        for (const name of param.names) out.set(name, { source: `@${dec}() ${name}`, direct: false, origin: 'request' })
      }
    } else {
      const route = fn.decorators.some(d => PY_ROUTE_DECORATOR.test(d.name))
      const converters = this.#flaskSafeParams(fn)
      const first = fn.params[0]?.name === 'self' ? fn.params[1] : fn.params[0]
      const djangoView =
        !route && first?.name === 'request' && fn.className === undefined && /views?(?:\/|\.py$)/.test(this.model.path)
      for (const param of fn.params) {
        if (PY_SAFE_PARAM_NAMES.has(param.name) || param.splat) continue
        const ann = param.annotation ?? ''
        const def = param.defaultValue ? this.text(param.defaultValue) : ''
        if (/^(?:Depends|Security)\(/.test(def) || /\b(?:Depends|Security)\(/.test(ann)) continue
        const explicit =
          /^(?:Query|Body|Form|Path|Header|Cookie|File|UploadFile)\(/.test(def) ||
          /\b(?:Query|Body|Form|Path|Header|Cookie|File)\(/.test(ann)
        if (!route && !explicit && !djangoView) continue
        const baseType = ann.replace(/^Annotated\[\s*([^,\]]+).*$/s, '$1').trim()
        if (SAFE_PY_PARAM_TYPES.test(baseType)) continue
        if (converters.has(param.name)) continue
        if (fn.name !== undefined && this.#scalarParams?.get(fn.name)?.has(param.name)) continue
        out.set(param.name, {
          source: djangoView ? `URL parameter '${param.name}'` : `route parameter '${param.name}'`,
          direct: false,
          origin: 'request',
        })
      }
    }
    this.#paramTaint.set(fn, out)
    return out
  }

  /** Flask `<int:id>`-style converters make a parameter numeric. */
  #flaskSafeParams(fn: FnFact): Set<string> {
    this.#flaskConverters ??= new Map()
    const cached = this.#flaskConverters.get(fn)
    if (cached) return cached
    const out = new Set<string>()
    for (const dec of fn.decorators) {
      for (const arg of dec.args ?? []) {
        const route = this.literal(arg)
        if (!route) continue
        for (const m of route.matchAll(/<(int|float|uuid):(\w+)>/g)) out.add(m[2]!)
      }
    }
    this.#flaskConverters.set(fn, out)
    return out
  }

  // -------------------------------------------------------------------------
  // Token helpers
  // -------------------------------------------------------------------------

  #chain(k: number, limit: number): ChainInfo {
    return readChain(this.tokens, this.model.match, k, limit, this.model.lang)
  }

  /** Template chunk `k` (head) belongs to a tagged template such as ``sql`...` ``. */
  #isTaggedTemplate(k: number): boolean {
    if (this.model.lang !== 'js') return false
    const t = this.tokens[k]!
    if (!t.value.startsWith('`')) return false
    const prev = this.tokens[k - 1]
    if (!prev) return false
    if (prev.type === 'ident') return !this.#keywords.has(prev.value)
    return prev.type === 'punct' && (prev.value === ')' || prev.value === ']') && prev.sub === undefined
  }

  /** Exclusive token index just past the template literal whose head chunk is `k`. */
  #templateEnd(k: number): number {
    let i = k
    while (i < this.tokens.length) {
      const next = this.tokens[i + 1]
      if (next?.sub === 'open') {
        const m = this.model.match[i + 1]!
        if (m < 0) return this.tokens.length
        i = m + 1
        if (this.tokens[i]?.type === 'str' && this.tokens[i]!.part !== undefined) {
          if (this.tokens[i]!.part === 'tail') return i + 1
          continue
        }
        return i
      }
      return i + 1
    }
    return i
  }

  #isPunct(k: number, value: string): boolean {
    const t = this.tokens[k]
    return t !== undefined && t.type === 'punct' && t.value === value && t.sub === undefined
  }

  #isMemberName(k: number): boolean {
    return this.#isPunct(k - 1, '.') || this.#isPunct(k - 1, '?.')
  }

  #isCalledDirectly(k: number): boolean {
    return this.#isPunct(k + 1, '(')
  }

  #isObjectKey(k: number): boolean {
    return this.#isPunct(k - 1, '{') || this.#isPunct(k - 1, ',')
  }

  #span(a: number, b: number): Span {
    return { start: this.tokens[a]!.start, end: this.tokens[Math.max(a, b - 1)]!.end }
  }

  #splitTop(a: number, b: number): [number, number][] {
    const out: [number, number][] = []
    let s = a
    let k = a
    while (k < b) {
      const t = this.tokens[k]!
      if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0 || m >= b) break
        k = m + 1
        continue
      }
      if (t.type === 'punct' && t.value === ',' && t.sub === undefined) {
        if (k > s) out.push([s, k])
        s = k + 1
      }
      k++
    }
    if (b > s) out.push([s, b])
    return out
  }

  #findTop(a: number, b: number, value: string): number {
    let k = a
    while (k < b) {
      const t = this.tokens[k]!
      if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
        const m = this.model.match[k]!
        if (m < 0 || m >= b) return -1
        k = m + 1
        continue
      }
      if (t.type === 'punct' && t.value === value && t.sub === undefined) return k
      k++
    }
    return -1
  }
}

export interface ChainCall {
  /** Callee chain text before the call parentheses. */
  readonly callee: string
  /** Last member name of the callee (`format` in `'x'.format`). */
  readonly method: string | undefined
  readonly open: number
  readonly close: number
}

export interface ChainInfo {
  /** Normalized chain: `req.query[]`, `request.args.get()`. */
  readonly norm: string
  /** Exclusive token end. */
  readonly end: number
  readonly parts: number
  readonly hasCall: boolean
  readonly calls: readonly ChainCall[]
}

/** Read the member/call/index chain starting at identifier token `k`. */
export function readChain(
  tokens: readonly Token[],
  match: Int32Array,
  k: number,
  limit: number,
  lang: 'js' | 'py',
): ChainInfo {
  const isP = (i: number, v: string): boolean => {
    const t = tokens[i]
    return t !== undefined && t.type === 'punct' && t.value === v && t.sub === undefined
  }
  let norm = tokens[k]!.value
  let parts = 1
  let i = k + 1
  let hasCall = false
  let lastName: string | undefined = tokens[k]!.value
  const calls: ChainCall[] = []
  // A Python string literal receiver (`"...".format(x)`) is handled by the caller via `.format` method detection.
  while (i < limit) {
    if (lang === 'js' && isP(i, '!') && (isP(i + 1, '.') || isP(i + 1, '?.'))) {
      i++
      continue
    }
    if ((isP(i, '.') || (lang === 'js' && isP(i, '?.'))) && tokens[i + 1]?.type === 'ident' && i + 1 < limit) {
      norm += `.${tokens[i + 1]!.value}`
      lastName = tokens[i + 1]!.value
      parts++
      i += 2
      continue
    }
    if (lang === 'js' && isP(i, '?.') && (isP(i + 1, '(') || isP(i + 1, '['))) {
      i++
      continue
    }
    if (isP(i, '(')) {
      const m = match[i]!
      if (m < 0 || m >= limit) break
      calls.push({ callee: norm, method: parts > 1 ? lastName : undefined, open: i, close: m })
      norm += '()'
      hasCall = true
      lastName = undefined
      i = m + 1
      continue
    }
    if (isP(i, '[')) {
      const m = match[i]!
      if (m < 0 || m >= limit) break
      norm += '[]'
      lastName = undefined
      i = m + 1
      continue
    }
    if (lang === 'js' && tokens[i]?.type === 'str' && tokens[i]!.value.startsWith('`') && !tokens[i]!.nl) {
      // tagged template: treat like a call
      break
    }
    break
  }
  return { norm, end: i, parts, hasCall, calls }
}

/** Find the call fact whose span is exactly `span` (e.g. an argument that is itself a call). */
export function callAt(model: FileModel, span: Span): CallFact | undefined {
  let lo = 0
  let hi = model.calls.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (model.calls[mid]!.start < span.start) lo = mid + 1
    else hi = mid
  }
  for (let i = lo; i < model.calls.length && model.calls[i]!.start === span.start; i++) {
    const call = model.calls[i]!
    if (call.end === span.end) return call
  }
  return undefined
}

/** Whether a workspace path is a Next.js route handler, page, or pages-router file. */
export function isNextFile(path: string): boolean {
  if (/(?:^|\/)pages\/(?!.*\/_(?:app|document)\.)[\s\S]*\.(?:[jt]sx?|mjs)$/.test(path)) return true
  return /(?:^|\/)app\/(?:[^/]+\/)*(?:route|page|layout|template|default)\.(?:[jt]sx?|mjs)$/.test(path)
}

/** A URL fragment that starts a path or query on a fixed host (`/users/`, `?q=`), but not `//host`. */
function isPathStart(content: string): boolean {
  return /^(?:\/(?![/\\])|\?)/.test(content)
}

function displaySource(norm: string, m: RegExpExecArray): string {
  const end = m.index + m[0].length
  let label = norm.slice(0, Math.max(end, m.index + 1))
  // Keep one more member for readability: `req.query.name`.
  const rest = /^\.[A-Za-z_$][\w$]*/.exec(norm.slice(end))
  if (rest && !label.endsWith('()')) label += rest[0]
  return label.replace(/\(\)$/, '()')
}
