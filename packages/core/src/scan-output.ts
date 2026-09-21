import path from 'path';
import type { SecretMatch } from './types';
import type { Diagnostic } from './diagnostics';
import { fingerprintForMatch } from './match-fingerprint';

/** One file's scan outcome -- shared by CLI, MCP, and SARIF/JSON formatters. */
export interface FileScanResult {
  file: string;
  matches: SecretMatch[];
}

/** Optional machine-readable scan run metadata (JSON + SARIF driver properties). */
export interface JsonRunMetadata {
  duration_ms: number;
  /** Files opened and scanned for secrets (excludes skipped binaries). */
  files_scanned: number;
  /** Total bytes read from disk for those scans (capped at per-file read limit when streaming). */
  bytes_scanned: number;
  /** Active regex rules after config (built-ins minus "off", plus accepted extra_patterns). */
  patterns_active: number;
  diagnostics_count?: number;
  /** Matches removed because they appeared in `.vault-guard.baseline.json`. */
  baseline_suppressed?: number;
  /**
   * Findings suppressed by an inline `vault-guard: ignore-line` /
   * `ignore-next-line` directive. Emitted even at zero so a run always states
   * whether the scanner was silenced inline -- a suppression is the user's
   * decision and must be visible.
   */
  inline_suppressed?: number;
  /**
   * The subset of {@link inline_suppressed} that hid a critical finding from a
   * vendor- or context-anchored rule. Emitted even at zero, for the same reason
   * the total is: a directive over a generic fixture assignment and a directive
   * on the same line as a provider-issued key are not the same event, and one
   * total lets the second hide inside the first.
   */
  inline_suppressed_critical_vendor?: number;
  /**
   * Directories skipped by name at the scan root on a pull-request run. Only
   * a direct child of the scan root can be skipped in that mode, so this
   * number is small and worth stating; a committed `src/vendor/` is scanned.
   */
  vendored_dirs_skipped?: number;
  /**
   * Files in the head tree dropped by the extension, lockfile-name and
   * generated-artifact filters on a pull-request run. Those filters skip on a
   * name alone, so a key committed as `src/leak.min.js` or `src/leak.lock`
   * never reached the scanner and the run said nothing about it. What they
   * skip is unchanged; this is the number that makes the silence visible.
   */
  type_filtered_files?: number;
  /** Effective gate threshold for this run (`--fail-on` / `fail_on` / default). */
  fail_on?: string;
  /**
   * Matches at or above {@link fail_on}. This, not the total match count, is
   * what drives the process exit code; integrators gating a build should read
   * this field rather than `summary.secrets`.
   */
  blocking_matches?: number;
  /**
   * Files the scan opened but could not read, so their contents were never
   * examined. Omitted when zero.
   *
   * A non-zero value means the run is INCOMPLETE: `blocking_matches` counts
   * only what the scanner actually looked at, so a clean gate result sits on
   * top of files nobody checked. On the `--staged` path this is fatal on its
   * own (exit 2) because that file list is exactly what is about to be
   * committed; on a directory scan it is reported and counted but does not
   * fail the gate, since an unreadable file inside a walked tree is an
   * ordinary occurrence. Unreadable DIRECTORIES are not counted here -- they
   * surface as `fs.permission_denied` diagnostics instead.
   */
  unscannable_files?: number;
}

/**
 * What a pull-request run took from the base ref, and what the head proposed
 * to change about it.
 *
 * Present only on a run given `--trust-base`, so its absence means the run was
 * inside the trust boundary already (a local scan, a pre-commit hook) rather
 * than that it found nothing. `proposals` is the field an umbrella sums across
 * gates to say, in one sentence, that a pull request tried to loosen them.
 */
export interface TrustBaseReport {
  /** The ref every control input was read from. */
  ref: string;
  /** One line per control input the head proposes to change. Never applied. */
  proposals: string[];
  configChanged: boolean;
  baselineChanged: boolean;
  /** How the head changed the config file's type or mode, or null. */
  configShapeChange: 'symlink' | 'not-a-file' | 'removed' | 'mode' | null;
  /** The same for the baseline file. */
  baselineShapeChange: 'symlink' | 'not-a-file' | 'removed' | 'mode' | null;
}

export interface JsonOutput {
  version: string;
  scannedAt: string;
  summary: { files: number; secrets: number };
  /** Present when the caller passes {@link FormatOptions.run}. */
  run?: JsonRunMetadata;
  /** Present only on a pull-request run. See {@link TrustBaseReport}. */
  trustBase?: TrustBaseReport;
  results: Array<{
    file: string;
    matches: Array<{
      type: string;
      severity: string;
      line: number;
      /** 0-based line-relative column. */
      column: number;
      /** 0-based absolute UTF-16 offset in the scanned content. */
      offset: number;
      /** Redacted form, e.g. `sk-a…(37c)`. Never the raw secret. */
      value: string;
      /** SHA-256 hex of `relPath|type|line|offset|matchLength` for baselines (no raw secret). */
      fingerprint: string;
    }>;
  }>;
  /** Non-fatal scan warnings (skipped files, rejected patterns, git issues). */
  diagnostics?: Array<{
    code: string;
    severity: string;
    ctx: Record<string, unknown>;
  }>;
}

export interface FormatOptions {
  /**
   * Base directory to render `file` paths relative to.
   * Defaults to `process.cwd()`. Files outside this root are kept absolute.
   * Pass `null` to skip relativization for `formatJson`'s `file` paths and
   * for SARIF when no {@link scanRoot} is given either. A `scanRoot` still
   * relativizes SARIF `artifactLocation.uri` (and diagnostic ctx) against
   * itself in that case, so `cwd: null` does not skip SARIF relativization
   * on its own.
   */
  cwd?: string | null;
  /**
   * Directory actually being scanned (the scan target), when it differs from
   * {@link cwd}. SARIF only: `artifactLocation.uri` is relativized against
   * this instead of `cwd`, so a finding outside the process cwd but inside the
   * scan target still gets a relative uri. Defaults to `cwd`.
   *
   * `formatJson` ignores this field. Its `file` paths stay cwd-relative,
   * because they are what the terminal output and the baseline fingerprints
   * are keyed on.
   */
  scanRoot?: string;
  /** Non-fatal diagnostics to include in structured output. */
  diagnostics?: Diagnostic[];
  /** Scan timing / coverage stats for JSON and SARIF `runs[].properties`. */
  run?: JsonRunMetadata;
  /**
   * Pull-request mode's report. Emitted as a `trustBase` block in JSON and as
   * one SARIF `toolExecutionNotification` per proposal: a proposal is a
   * statement about the run's configuration, not a finding in a file, so it
   * has no artifact location and does not belong in `results`.
   */
  trustBase?: TrustBaseReport;
}

/**
 * Normalize a file path for output: cwd-relative when inside `cwd`, absolute
 * otherwise (so we never emit `../../..` traversals).
 *
 * Why this matters: absolute paths in JSON / SARIF leak the developer's home
 * directory and OS username when the output is shared (PR comments, GitHub
 * Code Scanning UI, support tickets, screenshots).
 */
function normalizeFilePath(file: string, cwd: string | null | undefined): string {
  if (cwd === null) return file;
  const base = cwd ?? process.cwd();
  if (!path.isAbsolute(file)) return file;
  const rel = path.relative(base, file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return file;
  return rel || '.';
}

/** Matches a Windows drive-letter absolute path (`C:\...`, `C:/...`) or a UNC path (`\\server\share`). */
const WINDOWS_ABSOLUTE_PATH_RE = /^(?:[a-zA-Z]:[\\/]|\\\\)/;

function isWindowsStylePath(p: string): boolean {
  return WINDOWS_ABSOLUTE_PATH_RE.test(p);
}

/**
 * SARIF `artifactLocation.uri` must be a relative-reference URI: forward
 * slashes only, no leading `./`, no leading `/` (the GitHub Code Scanning
 * SARIF spec requires this even when the scanner itself runs on Windows,
 * where `path.relative` returns backslash-separated paths).
 *
 * The base is the scan root (the directory actually being scanned), not the
 * process cwd. Scanning an out-of-tree target from somewhere else used to
 * leave every uri absolute, which published the developer's home directory
 * and OS username to whoever reads the Code Scanning upload.
 *
 * A file genuinely outside the scan root still stays absolute rather than
 * becoming a `../..` traversal: SARIF relative references are resolved
 * against `%SRCROOT%`, so a traversal out of it is not a legal uri, and there
 * is no other root to express such a path against. In practice this only
 * happens for a path a caller injected from outside the scan, since every
 * file the scanner itself walks is under the target it was given -- and a
 * non-absolute `file` is resolved against cwd below before that check runs,
 * so a literal `..` traversal segment never reaches the returned uri either.
 *
 * Picks `path.win32` when either side of the comparison looks like a
 * Windows-style path, so this is correct both when the process itself runs
 * on Windows (native `path` is already `path.win32`) and when a
 * Windows-style path is normalized on a POSIX host (tests, or a SARIF file
 * produced elsewhere and re-normalized).
 */
function toSarifArtifactUri(
  file: string,
  cwd: string | null | undefined,
  scanRoot: string | undefined,
): string {
  if (cwd === null && scanRoot === undefined) return file.split('\\').join('/');
  const anchor = cwd ?? process.cwd();
  const impl = isWindowsStylePath(file) || isWindowsStylePath(anchor) ? path.win32 : path;
  const abs = impl.isAbsolute(file) ? file : impl.resolve(anchor, file);
  const base = resolveSarifBase(anchor, scanRoot, impl);
  const rel = impl.relative(base, abs);
  if (rel.startsWith('..') || impl.isAbsolute(rel)) return abs.split('\\').join('/');
  return (rel || '.').split('\\').join('/');
}

/**
 * The effective SARIF `%SRCROOT%` base. `scanRoot` is honored only when it
 * is genuinely outside `cwd`: a scan root nested inside cwd (or equal to
 * it) must not narrow `%SRCROOT%` to a subdirectory, because GitHub Code
 * Scanning (and any other SARIF consumer) resolves `%SRCROOT%` from its own
 * knowledge of the checkout, not from this uri -- a uri relative to a
 * subdirectory would then name a different file entirely. Mirrors
 * `resolveScanRoot` in `packages/cli/src/utils/scan-utils.ts`, which applies
 * the same rule when it derives `scanRoot` from the CLI's scan target in the
 * first place.
 */
function resolveSarifBase(
  cwd: string,
  scanRoot: string | undefined,
  impl: typeof path,
): string {
  if (scanRoot === undefined) return cwd;
  const rel = impl.relative(cwd, scanRoot);
  if (rel === '' || (!rel.startsWith('..') && !impl.isAbsolute(rel))) return cwd;
  return scanRoot;
}

/**
 * Diagnostic `ctx` reaches SARIF notifications as `JSON.stringify(d.ctx)`
 * (see `formatSarif` above), and some diagnostic sources (`fs.permission_denied`,
 * `file.read_error`) carry the scanned directory or file as an absolute path,
 * plus a `detail` field that is `String(error)` -- Node's own fs error text
 * often bakes that same absolute path in (e.g. "EACCES: permission denied,
 * scandir '/abs/dir'"). Both leak exactly what `artifactLocation.uri`
 * exists to avoid leaking, so ctx gets the same relativize-or-keep-absolute
 * treatment before it is stringified into a notification: any absolute-path
 * ctx value (`dir`, `path`, `file`, or any other field shaped that way) is
 * run through {@link toSarifArtifactUri}, and any other string value has
 * literal occurrences of the base directory stripped out.
 */
function sanitizeDiagnosticCtxForSarif(
  ctx: Record<string, unknown>,
  cwd: string | null | undefined,
  scanRoot: string | undefined,
): Record<string, unknown> {
  if (cwd === null && scanRoot === undefined) return ctx;
  const anchor = cwd ?? process.cwd();
  const base = resolveSarifBase(anchor, scanRoot, path);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(ctx)) {
    if (typeof value !== 'string') {
      out[key] = value;
    } else if (path.isAbsolute(value)) {
      out[key] = toSarifArtifactUri(value, cwd, scanRoot);
    } else {
      out[key] = stripSarifBasePath(value, base);
    }
  }
  return out;
}

/**
 * Removes literal occurrences of the SARIF base directory from a free-form
 * string (diagnostic `detail`, which is `String(error)` and can embed the
 * scanned path inside Node's own message text). This is not a full
 * relative-path rewrite of the string, just enough to keep the base
 * directory out of the document, matching what `artifactLocation.uri` does
 * for the path fields themselves.
 */
function stripSarifBasePath(text: string, base: string): string {
  if (!text.includes(base)) return text;
  const withTrailingSep = base.endsWith(path.sep) ? base : base + path.sep;
  return text.split(withTrailingSep).join('').split(base).join('.');
}

export function formatJson(results: FileScanResult[], opts: FormatOptions = {}): string {
  const fpCwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const output: JsonOutput = {
    version: '1',
    scannedAt: new Date().toISOString(),
    summary: {
      files: results.length,
      secrets: results.reduce((n, r) => n + r.matches.length, 0),
    },
    ...(opts.run ? { run: opts.run } : {}),
    ...(opts.trustBase ? { trustBase: opts.trustBase } : {}),
    results: results.map(({ file, matches }) => ({
      file: normalizeFilePath(file, opts.cwd),
      matches: matches.map(m => ({
        type: m.type,
        severity: m.severity,
        line: m.line,
        column: m.column,
        offset: m.offset,
        value: m.value,
        fingerprint: fingerprintForMatch(fpCwd, file, m),
      })),
    })),
  };
  if (opts.diagnostics && opts.diagnostics.length > 0) {
    output.diagnostics = opts.diagnostics.map(d => ({
      code: d.code,
      severity: d.severity,
      ctx: d.ctx,
    }));
  }
  return JSON.stringify(output, null, 2);
}

/** SARIF 2.1.0 -- compatible with GitHub Code Scanning (upload-sarif action). */
export function formatSarif(results: FileScanResult[], opts: FormatOptions = {}): string {
  const fpCwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const rules = [
    ...new Set(results.flatMap(r => r.matches.map(m => m.type))),
  ].map(id => ({
    id,
    name: id
      .split(/[-_]/)
      .map(p => p.charAt(0).toUpperCase() + p.slice(1))
      .join(''),
    shortDescription: { text: `Secret detected: ${id}` },
    helpUri: `https://github.com/vaultcompasshq/vault-guard/blob/main/docs/rules/${id}.md`,
    properties: { tags: ['security', 'secrets'] },
  }));

  const sarifResults = results.flatMap(({ file, matches }) =>
    matches.map(m => ({
      ruleId: m.type,
      level: m.severity === 'critical' ? 'error' : m.severity === 'high' ? 'warning' : 'note',
      // Intentionally do NOT include the masked value here. Reviewers have the
      // exact byte region (startLine/startColumn/endColumn) and the rule id;
      // the masked prefix adds no signal and grows the leak surface area.
      message: { text: `Possible secret of type '${m.type}'` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: toSarifArtifactUri(file, opts.cwd, opts.scanRoot),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: m.line,
              startColumn: m.column + 1,
              endColumn: m.column + m.matchLength + 1,
            },
          },
        },
      ],
      // Same fingerprint the JSON output emits per finding (positional: keyed
      // on relative path + type + line + offset + matchLength). Lets GitHub
      // Code Scanning track a finding's identity across runs.
      partialFingerprints: { 'vault-guard/v1': fingerprintForMatch(fpCwd, file, m) },
    }))
  );

  // Diagnostics are emitted as SARIF notifications (tool/driver/notifications)
  // so they appear in the GitHub Code Scanning UI as tool warnings rather than
  // results. This keeps the results array clean for triage.
  const notifications =
    opts.diagnostics && opts.diagnostics.length > 0
      ? opts.diagnostics.map(d => ({
          id: d.code,
          level: d.severity === 'error' ? 'error' : 'warning',
          message: {
            text: `${d.code}: ${JSON.stringify(sanitizeDiagnosticCtxForSarif(d.ctx, opts.cwd, opts.scanRoot))}`,
          },
        }))
      : undefined;

  const runProps =
    opts.run !== undefined
      ? {
          vault_guard_run: {
            duration_ms: opts.run.duration_ms,
            files_scanned: opts.run.files_scanned,
            bytes_scanned: opts.run.bytes_scanned,
            patterns_active: opts.run.patterns_active,
            ...(opts.run.diagnostics_count !== undefined
              ? { diagnostics_count: opts.run.diagnostics_count }
              : {}),
            ...(opts.run.baseline_suppressed !== undefined
              ? { baseline_suppressed: opts.run.baseline_suppressed }
              : {}),
            ...(opts.run.inline_suppressed !== undefined
              ? { inline_suppressed: opts.run.inline_suppressed }
              : {}),
            ...(opts.run.inline_suppressed_critical_vendor !== undefined
              ? {
                  inline_suppressed_critical_vendor:
                    opts.run.inline_suppressed_critical_vendor,
                }
              : {}),
            ...(opts.run.vendored_dirs_skipped !== undefined
              ? { vendored_dirs_skipped: opts.run.vendored_dirs_skipped }
              : {}),
            ...(opts.run.type_filtered_files !== undefined
              ? { type_filtered_files: opts.run.type_filtered_files }
              : {}),
            ...(opts.run.unscannable_files !== undefined
              ? { unscannable_files: opts.run.unscannable_files }
              : {}),
          },
        }
      : undefined;

  // A proposal is a statement about the run's CONFIGURATION -- "this pull
  // request also tried to turn the gate down" -- not a finding at a location in
  // a file. SARIF has a place for exactly that, and it is not `results`:
  // `invocations[].toolExecutionNotifications`. Putting it in `results` would
  // make it a code-scanning alert with no file to point at, and a triager would
  // have to dismiss it.
  const invocations =
    opts.trustBase !== undefined
      ? [
          {
            executionSuccessful: true,
            toolExecutionNotifications: opts.trustBase.proposals.map(text => ({
              descriptor: { id: 'vault-guard/trust-base/proposal' },
              level: 'warning',
              message: { text },
            })),
          },
        ]
      : undefined;

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
      {
        ...(runProps ? { properties: runProps } : {}),
        ...(invocations ? { invocations } : {}),
        tool: {
          driver: {
            name: 'vault-guard',
            informationUri: 'https://github.com/vaultcompasshq/vault-guard',
            rules,
            ...(notifications ? { notifications } : {}),
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
