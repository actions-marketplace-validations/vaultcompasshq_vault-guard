import type { SecretMatch } from '../types';
import type { FileScanResult } from '../scan-output';

/**
 * Severity threshold at or above which a finding makes the scan **fail**
 * (non-zero exit). `'none'` never fails the gate -- findings are still
 * reported, which is the right mode for an advisory / observe-only rollout.
 */
export type FailOnThreshold = SecretMatch['severity'] | 'none';

/**
 * Default gate threshold.
 *
 * `medium` (not `low`) because the scanner deliberately downgrades findings to
 * `low` in exactly the places where they are not real leaks:
 *
 *   - `path-severity.ts` downgrades generic patterns inside test / fixture /
 *     docs / `*.example` paths;
 *   - public identifiers that are documented as safe to embed (`gcp-oauth`)
 *     are `low` by definition.
 *
 * Blocking a commit on those was the dominant real-world complaint: the
 * downgrade existed but bought the user nothing because any match at all
 * returned exit 1. Findings below the threshold are still printed and still
 * appear in JSON / SARIF; they just do not fail the build.
 */
export const DEFAULT_FAIL_ON: FailOnThreshold = 'medium';

const SEVERITY_RANK: Record<SecretMatch['severity'], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Accepted `--fail-on` / `fail_on` values, in descending strictness. */
export const FAIL_ON_VALUES: readonly FailOnThreshold[] = [
  'low',
  'medium',
  'high',
  'critical',
  'none',
];

export function isFailOnThreshold(v: unknown): v is FailOnThreshold {
  return typeof v === 'string' && (FAIL_ON_VALUES as readonly string[]).includes(v);
}

/** True when `severity` is at or above the gate `threshold`. */
export function meetsFailThreshold(
  severity: SecretMatch['severity'],
  threshold: FailOnThreshold,
): boolean {
  if (threshold === 'none') return false;
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

/**
 * Count findings at or above `threshold` across scan results. A non-zero
 * count is what drives the CLI exit code; the full result set is still what
 * gets displayed and serialized.
 */
export function countBlockingMatches(
  results: FileScanResult[],
  threshold: FailOnThreshold,
): number {
  let n = 0;
  for (const r of results) {
    for (const m of r.matches) {
      if (meetsFailThreshold(m.severity, threshold)) n++;
    }
  }
  return n;
}

/**
 * Resolve the effective threshold from (highest priority first) the CLI flag,
 * the repo config, then {@link DEFAULT_FAIL_ON}.
 */
export function resolveFailOn(
  flagValue: string | undefined,
  configValue: unknown,
): { ok: true; threshold: FailOnThreshold } | { ok: false; invalid: string } {
  if (flagValue !== undefined) {
    if (!isFailOnThreshold(flagValue)) return { ok: false, invalid: flagValue };
    return { ok: true, threshold: flagValue };
  }
  if (configValue !== undefined) {
    if (!isFailOnThreshold(configValue)) return { ok: false, invalid: String(configValue) };
    return { ok: true, threshold: configValue };
  }
  return { ok: true, threshold: DEFAULT_FAIL_ON };
}
