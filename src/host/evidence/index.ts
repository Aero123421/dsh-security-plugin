/**
 * Evidence verification: checks model-cited quotes against the frozen,
 * redacted snapshot before any AI evidence is trusted.
 */

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
  type QuoteSource,
  type QuoteVerification,
  SNIPPET_MAX_CHARS,
  SNIPPET_MAX_LINES,
  snapshotQuoteSource,
  type VerifyQuoteOptions,
  verifyQuote,
} from './quote.ts'
export { clipText, countLines, lineOfOffset, lineStarts, numberLines, splitLines, stripCr } from './text.ts'
