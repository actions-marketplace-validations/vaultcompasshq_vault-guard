import type { DiagnosticCode } from '../diagnostics';

/**
 * Heuristic safety checks for user-supplied regex patterns.
 *
 * Why this exists
 * ---------------
 * `VaultGuardConfig.extra_patterns[].regex` is compiled with `new RegExp(src, 'g')`
 * and run against every line of every scanned file. A malicious or careless
 * `.vault-guard.json` (anywhere in the repo, after the `loadConfig` git-boundary
 * fix) can therefore implant a catastrophic-backtracking regex that pins the
 * scanner CPU on the first file with the right shape.
 *
 * What this does (and does not) catch
 * -----------------------------------
 * This is a **conservative, dependency-free** static check:
 *
 *   1. Hard length cap (256 chars): real-world secret patterns are <100 chars;
 *      anything longer is suspicious and also bounds compile-time RAM use.
 *   2. Quantifier-density cap (>25 of `* + ? {`): the academic ReDoS literature
 *      shows pathological patterns concentrate quantifiers; this is the same
 *      threshold `safe-regex` uses.
 *   3. Nested-quantifier shape: `(…[*+]…)[*+]` -- catches `(a+)+`, `(\d+)*`.
 *   4. Alternation-quantifier shape: `(.|.)[*+]` -- catches `(a|a)+`, `(\d|\d)*`.
 *
 * What this does NOT catch
 * ------------------------
 * - Cross-group backtracking like `(.*x)(y.*)` chains.
 * - Pathological lookaheads.
 * - Anything a determined attacker can hide behind character classes.
 *
 * Real defence in depth requires execution-time bounds (e.g. `re2`). That is
 * tracked as a Phase 8 follow-up; this module is the pre-launch backstop.
 *
 * Users who need to bypass the heuristic for a known-safe pattern can set
 * `extra_patterns_unsafe: true` in `.vault-guard.json`. The length cap still
 * applies as a memory-use backstop even in unsafe mode.
 */

/**
 * Maximum allowed source length for user-provided regex strings.
 *
 * @remarks
 * This cap is both a safety and performance bound. Real-world secret patterns
 * are usually well under 100 characters; 256 leaves margin for legitimate
 * patterns while rejecting pathological or accidental megaregex input.
 */
export const REGEX_MAX_LENGTH = 256;

/**
 * Maximum number of quantifier tokens (`* + ? {`) allowed in a user pattern.
 *
 * @remarks
 * High quantifier density correlates strongly with catastrophic backtracking.
 * The threshold intentionally matches common static-check heuristics.
 */
export const REGEX_MAX_QUANTIFIERS = 25;

const NESTED_QUANTIFIER = /\([^()]*[*+][^()]*\)[*+]/;
const ALT_QUANTIFIER = /\([^()|]*\|[^()|]*\)[*+]/;

export type RegexSafetyReason =
  | 'too_long'
  | 'too_many_quantifiers'
  | 'nested_quantifier'
  | 'alternation_quantifier'
  | 'invalid_syntax';

/**
 * Canonical mapping from regex-safety rejections to diagnostics codes.
 *
 * Keep this mapping in one place so scan/reporting surfaces don't drift.
 */
export const REGEX_REASON_TO_DIAGNOSTIC_CODE: Record<RegexSafetyReason, DiagnosticCode> = {
  invalid_syntax: 'pattern.invalid',
  too_long: 'pattern.too_long',
  too_many_quantifiers: 'pattern.redos_unsafe',
  nested_quantifier: 'pattern.redos_unsafe',
  alternation_quantifier: 'pattern.redos_unsafe',
};

export interface RegexSafetyResult {
  ok: boolean;
  reason?: RegexSafetyReason;
  detail?: string;
}

/**
 * Validate a user-supplied regex source string with heuristic ReDoS guards.
 *
 * @param source - Raw regex source from `.vault-guard.json` (without delimiters).
 * @returns `ok: true` when accepted, otherwise `ok: false` with machine-readable
 * `reason` and human-readable `detail` for diagnostics output.
 */
export function validateRegexSafety(source: string): RegexSafetyResult {
  if (source.length > REGEX_MAX_LENGTH) {
    return {
      ok: false,
      reason: 'too_long',
      detail: `regex source is ${source.length} chars (max ${REGEX_MAX_LENGTH})`,
    };
  }

  const quantifierCount = countQuantifiers(source);
  if (quantifierCount > REGEX_MAX_QUANTIFIERS) {
    return {
      ok: false,
      reason: 'too_many_quantifiers',
      detail: `regex contains ${quantifierCount} quantifiers (max ${REGEX_MAX_QUANTIFIERS})`,
    };
  }

  if (NESTED_QUANTIFIER.test(source)) {
    return {
      ok: false,
      reason: 'nested_quantifier',
      detail: 'nested quantifier of the form `(…[*+]…)[*+]` detected (catastrophic backtracking)',
    };
  }

  if (ALT_QUANTIFIER.test(source)) {
    return {
      ok: false,
      reason: 'alternation_quantifier',
      detail: 'alternation under quantifier `(a|b)[*+]` detected (potential exponential backtracking)',
    };
  }

  return { ok: true };
}

/**
 * Perform a length-only safety check.
 *
 * @param source - Raw regex source from `.vault-guard.json`.
 * @returns `ok: false` with `reason: 'too_long'` when the source exceeds
 * `REGEX_MAX_LENGTH`, otherwise `ok: true`.
 *
 * @remarks
 * This is intentionally used even when `extra_patterns_unsafe: true` so there
 * is always a hard memory backstop.
 */
export function validateRegexLength(source: string): RegexSafetyResult {
  if (source.length > REGEX_MAX_LENGTH) {
    return {
      ok: false,
      reason: 'too_long',
      detail: `regex source is ${source.length} chars (max ${REGEX_MAX_LENGTH})`,
    };
  }
  return { ok: true };
}

/**
 * Convert a regex safety rejection reason to the canonical diagnostic code.
 *
 * @param reason - Safety rejection identifier.
 * @returns Stable diagnostics code for JSON/SARIF/text reporting.
 */
export function mapRegexSafetyReasonToDiagnosticCode(reason: RegexSafetyReason): DiagnosticCode {
  return REGEX_REASON_TO_DIAGNOSTIC_CODE[reason];
}

/**
 * Safely map an untyped rejection reason string to a diagnostics code.
 *
 * @param reason - Rejection reason coming from runtime validation paths.
 * @returns Canonical diagnostics code, defaulting to `pattern.redos_unsafe`
 * when the reason is unknown.
 */
export function mapPatternRejectionReasonToDiagnosticCode(reason: string): DiagnosticCode {
  if (reason in REGEX_REASON_TO_DIAGNOSTIC_CODE) {
    return REGEX_REASON_TO_DIAGNOSTIC_CODE[reason as RegexSafetyReason];
  }
  return 'pattern.redos_unsafe';
}

/**
 * Count `* + ? {` quantifier characters outside character classes.
 *
 * Approximation only -- doesn't fully tokenise the regex, just skips `[…]`
 * blocks where these characters are literal. Good enough to flag pathological
 * patterns without false-positiving on `[a-z?]` or `\?`.
 */
function countQuantifiers(source: string): number {
  let count = 0;
  let inClass = false;
  let escape = false;

  for (let i = 0; i < source.length; i++) {
    const c = source[i];

    if (escape) {
      escape = false;
      continue;
    }
    if (c === '\\') {
      escape = true;
      continue;
    }
    if (c === '[' && !inClass) {
      inClass = true;
      continue;
    }
    if (c === ']' && inClass) {
      inClass = false;
      continue;
    }
    if (inClass) continue;

    if (c === '*' || c === '+' || c === '?' || c === '{') count++;
  }

  return count;
}
