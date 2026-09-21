/**
 * DiagnosticBus -- lightweight structured error channel for vault-guard.
 *
 * Motivation (Audit §14): the codebase had pervasive `catch {}` silent swallows.
 * For a security tool, every silent fallback is an undetected miss:
 *   - A corrupt `.vault-guard.json` silently reverts to defaults
 *   - `git diff --cached` failing produces a false ✅ on pre-commit
 *   - A `>10 MB` file is skipped without any output
 *   - A ReDoS-unsafe `extra_pattern` is dropped with no feedback
 *
 * Instead of adding a third-party logging dep, we funnel every "would have
 * been silently swallowed" event through this typed channel, emit it in
 * JSON/SARIF output, and print a one-line summary in text mode.
 */

export type DiagnosticSeverity = 'warning' | 'error';

export type DiagnosticCode =
  | 'config.parse_error'
  | 'config.read_error'
  | 'config.unsafe_extra_pattern'
  | 'pattern.invalid'
  | 'pattern.too_long'
  | 'pattern.redos_unsafe'
  | 'file.too_large'
  | 'file.line_too_long'
  | 'file.read_error'
  | 'file.scan_timeout'
  | 'fs.permission_denied'
  | 'git.staged_files_failed'
  | 'baseline.invalid'
  | 'suppression.inline';

/**
 * Structured non-fatal warning/error emitted during a scan.
 */
export interface Diagnostic {
  /** Stable machine-readable diagnostic identifier. */
  code: DiagnosticCode;
  /** Severity level for UI/reporting surfaces. */
  severity: DiagnosticSeverity;
  /**
   * Free-form context payload (file path, error message, pattern id, etc.).
   *
   * Keep values JSON-serializable because this object is emitted in JSON and SARIF.
   */
  ctx: Record<string, unknown>;
}

/**
 * Collects diagnostics during a single scan run.
 *
 * Callers add diagnostics with `bus.add(...)`. At the end of a run the CLI
 * calls `bus.drain()` to retrieve them all and include them in JSON/SARIF
 * output and/or print a summary to stderr.
 *
 * Intentionally not a singleton -- one bus per `scanCommand` / `proxyCommand`
 * invocation so that concurrent processes don't share state.
 *
 * @example
 * ```ts
 * const bus = new DiagnosticBus();
 * bus.add({
 *   code: 'file.too_large',
 *   severity: 'warning',
 *   ctx: { file: 'assets/dump.bin', bytes: 73400320 },
 * });
 *
 * const diagnostics = bus.drain();
 * // Pass diagnostics to formatJson/formatSarif.
 * ```
 */
export class DiagnosticBus {
  private readonly items: Diagnostic[] = [];

  add(d: Diagnostic): void {
    this.items.push(d);
  }

  /** Returns all diagnostics and clears the bus. */
  drain(): Diagnostic[] {
    return this.items.splice(0);
  }

  /** Returns all diagnostics without clearing. */
  peek(): readonly Diagnostic[] {
    return this.items;
  }

  get size(): number {
    return this.items.length;
  }
}
