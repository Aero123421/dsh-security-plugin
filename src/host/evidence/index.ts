/**
 * Evidence verification: checks model-cited quotes against the frozen,
 * redacted snapshot before any AI evidence is trusted.
 */

export { commentMask, isCommentOnlyRange } from './comments.ts'
export {
  isWhitespace,
  type NormalizedText,
  normalizeForMatch,
  normalizePath,
  normalizeWithOffsets,
} from './normalize.ts'
export {
  type CitedQuote,
  checkStaleness,
  excerpt,
  MAX_EXTRA_CITED_LINES,
  type QuoteSource,
  type QuoteVerification,
  SNIPPET_MAX_CHARS,
  SNIPPET_MAX_LINES,
  snapshotQuoteSource,
  type VerifyQuoteOptions,
  verifyQuote,
} from './quote.ts'
export { clipText, countLines, lineOfOffset, lineStarts, numberLines, splitLines, stripCr } from './text.ts'
