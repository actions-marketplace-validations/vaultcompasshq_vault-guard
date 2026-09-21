import fs from 'fs';
import path from 'path';
import { SecretMatch } from './types';
import { ConfigError } from './errors';
import { validateVaultGuardConfig } from './config-validate';
import type { FailOnThreshold } from './utils/fail-on';

/**
 * Shape of .vault-guard.json in a repository root.
 *
 * YAML support (.vault-guard.yml) deferred to a follow-up to avoid adding a runtime
 * dependency on the core package.
 */
export interface VaultGuardConfig {
  /** Glob patterns or file paths to skip entirely during scanning. */
  ignore?: {
    paths?: string[];
    patterns?: string[];
  };
  /**
   * Override severity for built-in pattern keys, or set to "off" to disable a
   * pattern entirely.  Keys match the pattern id strings in secret-scanner.ts.
   */
  severity_overrides?: Record<string, SecretMatch['severity'] | 'off'>;
  /**
   * Additional patterns to run alongside the built-in set.  Regex strings are
   * compiled at scanner construction time and validated by
   * `utils/regex-safety.ts` against catastrophic-backtracking shapes.
   */
  extra_patterns?: Array<{
    id: string;
    regex: string;
    severity: SecretMatch['severity'];
    description?: string;
    /** Optional minimum Shannon entropy (bits/char) for the matched value. */
    min_entropy?: number;
  }>;
  /**
   * Bypass the ReDoS-safety heuristic for `extra_patterns`. Length cap still
   * applies as a backstop. Set this only if you have audited every pattern
   * and accept the catastrophic-backtracking risk.
   */
  extra_patterns_unsafe?: boolean;
  /**
   * Override the default Shannon entropy threshold (3.5 bits/char) used by
   * generic catch-all patterns.  Lower = more matches but more false positives.
   */
  entropy_threshold?: number;
  /**
   * Minimum severity that fails the scan (non-zero exit). Findings below the
   * threshold are still reported in text/JSON/SARIF, they just do not break
   * the build. `"none"` reports everything and never fails, for advisory
   * rollouts. Defaults to `"medium"`; overridden by `--fail-on`.
   */
  fail_on?: FailOnThreshold;
}

const CONFIG_FILENAMES = ['.vault-guard.json', '.vault-guard.local.json'];

/**
 * Walk up from `startDir` looking for a `.git` entry (directory in regular
 * checkouts, file in worktrees). Returns the first directory containing one,
 * or `null` if no git repo is found before the filesystem root.
 */
function findRepoRoot(startDir: string): string | null {
  let dir = startDir;
  while (true) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Build `[startDir, ..., root]` (inclusive on both ends). */
function ascendInclusive(startDir: string, root: string): string[] {
  const out: string[] = [];
  let dir = startDir;
  while (true) {
    out.push(dir);
    if (dir === root) return out;
    const parent = path.dirname(dir);
    if (parent === dir) return out;
    dir = parent;
  }
}

/**
 * Directories searched for `.vault-guard.json` / baseline files, in order
 * (nearest to `startDir` first). Same policy as {@link loadConfig}.
 */
export function listConfigSearchDirs(startDir: string = process.cwd()): string[] {
  const repoRoot = findRepoRoot(startDir);
  return repoRoot ? ascendInclusive(startDir, repoRoot) : [startDir];
}

/**
 * Load the nearest Vault Guard config file.
 *
 * Search policy (security-relevant):
 *   - If `startDir` is inside a git repository: search from `startDir` up to
 *     the repo root (inclusive). Never ascend past `.git` -- a config in a
 *     parent directory of the repo root could change what counts as a secret
 *     for the user (severity overrides, extra patterns) without their consent.
 *   - If `startDir` is NOT inside a git repository: search **only** `startDir`.
 *     This prevents accidental loading of `~/.vault-guard.json` (or any other
 *     ancestor) when the user runs the CLI in `/tmp` or similar.
 *
 * Throws `ConfigError` on JSON parse failure (do not fail silent -- a typo in
 * `.vault-guard.json` is indistinguishable from "no config" if we swallow it).
 */
/**
 * First existing config path on the {@link listConfigSearchDirs} walk, or `null`.
 */
export function findVaultGuardConfigPath(startDir: string = process.cwd()): string | null {
  const dirs = listConfigSearchDirs(startDir);
  for (const dir of dirs) {
    for (const filename of CONFIG_FILENAMES) {
      const filePath = path.join(dir, filename);
      if (fs.existsSync(filePath)) return filePath;
    }
  }
  return null;
}

/**
 * Parse and validate one config document.
 *
 * The schema check used to live only in `vault-guard config validate`, an
 * opt-in command, so every ordinary scan accepted a config the validator would
 * have refused: an unknown top-level key was silently dropped, and a
 * mistyped `severity_overrides` value was carried into the scanner as-is. A
 * check the gate does not run is documentation, not a control, and pull-request
 * mode makes that worse rather than better, because the config it reads comes
 * from a ref nobody is looking at during the run. One parser, validated, for
 * every load: the working tree, the MCP server, the editor extension, and the
 * base ref alike.
 *
 * `sourceLabel` names the document for the error message. It is a file path
 * for a working-tree load and `<ref>:<path>` for a base-ref load, so the
 * message says which of the two a reader has to go and fix.
 */
export function parseConfigText(raw: string, sourceLabel: string): VaultGuardConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new ConfigError(
      `Failed to parse Vault Guard config at ${sourceLabel}: ${detail}`,
      sourceLabel,
    );
  }

  const result = validateVaultGuardConfig(parsed);
  if (!result.ok) {
    throw new ConfigError(
      `Invalid Vault Guard config at ${sourceLabel}: ${result.errors.join('; ')}`,
      sourceLabel,
    );
  }
  return result.config;
}

export function loadConfig(startDir: string = process.cwd()): VaultGuardConfig {
  const dirs = listConfigSearchDirs(startDir);

  for (const dir of dirs) {
    for (const filename of CONFIG_FILENAMES) {
      const filePath = path.join(dir, filename);
      if (!fs.existsSync(filePath)) continue;

      let raw: string;
      try {
        raw = fs.readFileSync(filePath, 'utf-8');
      } catch (e) {
        const detail = e instanceof Error ? e.message : String(e);
        throw new ConfigError(
          `Failed to read Vault Guard config at ${filePath}: ${detail}`,
          filePath,
        );
      }

      return parseConfigText(raw, filePath);
    }
  }

  return {};
}
