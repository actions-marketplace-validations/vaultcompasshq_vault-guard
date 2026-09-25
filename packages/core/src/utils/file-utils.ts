import fs, { promises as fsPromises } from 'fs';
import path from 'path';
import ignore from 'ignore';

import { DiagnosticBus } from '../diagnostics';

/**
 * Build a filter from `config.ignore.paths` / `config.ignore.patterns` entries.
 *
 * Patterns follow gitignore syntax (handled by the `ignore` package). Paths are
 * matched against file paths relative to `root` so that patterns like
 * `packages/**\/__tests__\/**` work as expected from the repo root.
 *
 * @returns A predicate that returns `true` when a file should be **excluded**.
 */
export function buildConfigIgnoreFilter(
  patterns: string[],
  root: string,
): (filePath: string) => boolean {
  if (patterns.length === 0) return () => false;
  const ig = ignore().add(patterns);
  return (filePath: string): boolean => {
    const rel = path.relative(root, path.resolve(filePath)).split(path.sep).join('/');
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return false;
    return ig.ignores(rel);
  };
}

const GITIGNORE_CACHE_MAX = 32;

type CachedIgnoreFilter = {
  lastUsed: number;
  /** Returns true if `filePath` should be excluded by `.gitignore` rules. */
  tester: (filePath: string) => boolean;
  /** Absolute paths of `.gitignore` files whose mtimes are tracked. */
  watchPaths: string[];
  /** Expected `mtimeMs` for each path in `watchPaths` (same order). */
  mtimesMs: number[];
};

const gitignoreCache = new Map<string, CachedIgnoreFilter>();

/**
 * Drop all cached `.gitignore` matchers. Call after long-lived processes
 * detect an out-of-band change that `mtime` cannot observe, or in tests.
 */
export function clearGitignoreCache(): void {
  gitignoreCache.clear();
}

function touchCache(key: string, entry: CachedIgnoreFilter): void {
  gitignoreCache.delete(key);
  gitignoreCache.set(key, { ...entry, lastUsed: Date.now() });
  while (gitignoreCache.size > GITIGNORE_CACHE_MAX) {
    const oldest = gitignoreCache.keys().next().value;
    if (oldest === undefined) break;
    gitignoreCache.delete(oldest);
  }
}

function isStale(entry: CachedIgnoreFilter): boolean {
  for (let i = 0; i < entry.watchPaths.length; i++) {
    const p = entry.watchPaths[i];
    const expected = entry.mtimesMs[i];
    try {
      if (fs.statSync(p).mtimeMs !== expected) return true;
    } catch {
      return true;
    }
  }
  return false;
}

function findGitRoot(startDir: string): string | null {
  let dir = path.resolve(startDir);
  while (true) {
    if (fs.existsSync(path.join(dir, '.git'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function filesystemRootFor(resolvedPath: string): string {
  return path.parse(resolvedPath).root;
}

interface GitignoreChainEntry {
  readonly dir: string;
  readonly absGitignore: string;
  readonly content: string;
}

/** Prefix a single `.gitignore` line for rules defined in a subdirectory. */
function qualifyGitignoreLine(line: string, posixPrefix: string): string {
  if (!posixPrefix) return line;
  const trimmed = line.trimEnd();
  if (!trimmed || trimmed.startsWith('#')) return line;

  const neg = trimmed.startsWith('!');
  const body = neg ? trimmed.slice(1) : trimmed;
  if (!body) return line;

  let out: string;
  if (body.startsWith('/')) {
    out = `${posixPrefix}${body}`;
  } else if (body.includes('/')) {
    out = `${posixPrefix}/${body}`;
  } else {
    out = `${posixPrefix}/**/${body}`;
  }
  return neg ? `!${out}` : out;
}

function qualifyGitignoreContent(content: string, posixPrefix: string): string {
  if (!posixPrefix) return content;
  return content.split('\n').map(l => qualifyGitignoreLine(l, posixPrefix)).join('\n');
}

/**
 * Walk upward from `resolvedScan` through `stopAt` (inclusive), collect each
 * `.gitignore`, then return entries in shallow-to-deep order for merging.
 */
function collectGitignoreChain(resolvedScan: string, stopAt: string): GitignoreChainEntry[] {
  const stop = path.resolve(stopAt);
  const raw: GitignoreChainEntry[] = [];
  let dir = path.resolve(resolvedScan);

  while (true) {
    const absGitignore = path.join(dir, '.gitignore');
    if (fs.existsSync(absGitignore)) {
      try {
        raw.push({
          dir,
          absGitignore,
          content: fs.readFileSync(absGitignore, 'utf-8'),
        });
      } catch {
        /* unreadable .gitignore -- treat as absent */
      }
    }
    if (dir === stop) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  raw.reverse();
  return raw;
}

/**
 * Recursively discover `.gitignore` files inside `root` (inclusive of `root`
 * itself), skipping directories the walk never descends into anyway
 * ({@link shouldIgnoreDirectory}) so this pre-pass stays cheap. Scanning from
 * an ancestor of a nested `.gitignore` (e.g. `vault-guard scan .` in a repo
 * with a per-package `.gitignore`) otherwise never sees that file: the ignore
 * filter was only ever built from ancestors of the scan root, not descendants.
 */
function collectDescendantGitignores(root: string): GitignoreChainEntry[] {
  const found: GitignoreChainEntry[] = [];
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (shouldIgnoreDirectory(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile() && entry.name === '.gitignore') {
        try {
          found.push({ dir, absGitignore: full, content: fs.readFileSync(full, 'utf-8') });
        } catch {
          /* unreadable .gitignore -- treat as absent */
        }
      }
    }
  }

  // Shallow-to-deep, matching collectGitignoreChain's ordering, so more
  // specific nested rules are added (and can override) after broader ones.
  found.sort((a, b) => a.dir.split(path.sep).length - b.dir.split(path.sep).length);
  return found;
}

function buildIgnoreFilter(resolvedScanRoot: string): CachedIgnoreFilter {
  const gitRoot = findGitRoot(resolvedScanRoot);
  const stopAt = gitRoot ?? filesystemRootFor(resolvedScanRoot);
  const ancestorChain = collectGitignoreChain(resolvedScanRoot, stopAt);
  const seen = new Set(ancestorChain.map(c => c.absGitignore));
  const descendantChain = collectDescendantGitignores(resolvedScanRoot).filter(
    c => !seen.has(c.absGitignore),
  );
  const chain = [...ancestorChain, ...descendantChain];

  const ig = ignore();
  for (const { dir, content } of chain) {
    const relDir = path.relative(stopAt, dir).split(path.sep).join('/');
    const posixPrefix = relDir === '' || relDir === '.' ? '' : relDir;
    ig.add(qualifyGitignoreContent(content, posixPrefix));
  }

  const watchPaths = chain.map(c => c.absGitignore);
  const mtimesMs = watchPaths.map(p => {
    try {
      return fs.statSync(p).mtimeMs;
    } catch {
      return -1;
    }
  });

  const tester = (filePath: string): boolean => {
    const rel = path.relative(stopAt, path.resolve(filePath)).split(path.sep).join('/');
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      return false;
    }
    const posixPath = rel === '' ? '.' : rel;
    return ig.ignores(posixPath);
  };

  return {
    lastUsed: Date.now(),
    tester,
    watchPaths,
    mtimesMs,
  };
}

function getGitignoreTester(scanRoot: string): (filePath: string) => boolean {
  const key = path.resolve(scanRoot);
  const hit = gitignoreCache.get(key);
  if (hit && !isStale(hit)) {
    touchCache(key, hit);
    return hit.tester;
  }
  const built = buildIgnoreFilter(key);
  touchCache(key, built);
  return built.tester;
}

/**
 * Get all files in directory recursively (async version)
 */
export async function getAllFilesAsync(
  dirPath: string,
  visited = new Set<string>(),
  verbose = false,
  bus?: DiagnosticBus,
): Promise<string[]> {
  const files: string[] = [];

  try {
    try {
      await fsPromises.access(dirPath);
    } catch {
      if (bus) {
        bus.add({
          code: 'fs.permission_denied',
          severity: 'warning',
          ctx: { dir: dirPath },
        });
      }
      return files;
    }

    const realPath = fs.realpathSync(dirPath);
    if (visited.has(realPath)) {
      return files;
    }
    visited.add(realPath);

    const items = await fsPromises.readdir(dirPath);

    for (const item of items) {
      try {
        const fullPath = path.join(dirPath, item);
        const lstat = await fsPromises.lstat(fullPath);

        if (lstat.isSymbolicLink()) {
          continue;
        }

        if (lstat.isDirectory() && !shouldIgnoreDirectory(item)) {
          const subFiles = await getAllFilesAsync(fullPath, visited, verbose, bus);
          files.push(...subFiles);
        } else if (lstat.isFile() && !shouldIgnoreFile(fullPath)) {
          files.push(fullPath);
        }
      } catch (error) {
        if (bus) {
          bus.add({
            code: 'fs.permission_denied',
            severity: 'warning',
            ctx: { path: path.join(dirPath, item), detail: String(error) },
          });
        }
        if (verbose) {
          console.error(`Warning: Cannot access ${path.join(dirPath, item)}:`, error);
        }
      }
    }
  } catch (error) {
    if (bus) {
      bus.add({
        code: 'fs.permission_denied',
        severity: 'warning',
        ctx: { dir: dirPath, detail: String(error) },
      });
    }
    if (verbose) {
      console.error(`Warning: Cannot read directory ${dirPath}:`, error);
    }
  }

  return files;
}

/**
 * Get all files in directory recursively (sync version for backwards compatibility)
 */
export function getAllFiles(
  dirPath: string,
  visited = new Set<string>(),
  verbose = false,
  bus?: DiagnosticBus,
): string[] {
  const files: string[] = [];

  try {
    if (!fs.existsSync(dirPath)) {
      if (bus) {
        bus.add({
          code: 'fs.permission_denied',
          severity: 'warning',
          ctx: { dir: dirPath },
        });
      }
      return files;
    }

    const realPath = fs.realpathSync(dirPath);
    if (visited.has(realPath)) {
      return files;
    }
    visited.add(realPath);

    const items = fs.readdirSync(dirPath);

    for (const item of items) {
      try {
        const fullPath = path.join(dirPath, item);
        const lstat = fs.lstatSync(fullPath);

        if (lstat.isSymbolicLink()) {
          continue;
        }

        if (lstat.isDirectory() && !shouldIgnoreDirectory(item)) {
          files.push(...getAllFiles(fullPath, visited, verbose, bus));
        } else if (lstat.isFile() && !shouldIgnoreFile(fullPath)) {
          files.push(fullPath);
        }
      } catch (error) {
        if (bus) {
          bus.add({
            code: 'fs.permission_denied',
            severity: 'warning',
            ctx: { path: path.join(dirPath, item), detail: String(error) },
          });
        }
        if (verbose) {
          console.error(`Warning: Cannot access ${path.join(dirPath, item)}:`, error);
        }
      }
    }
  } catch (error) {
    if (bus) {
      bus.add({
        code: 'fs.permission_denied',
        severity: 'warning',
        ctx: { dir: dirPath, detail: String(error) },
      });
    }
    if (verbose) {
      console.error(`Warning: Cannot read directory ${dirPath}:`, error);
    }
  }

  return files;
}

/**
 * Get files to scan (filters out ignored directories/files) - async version
 *
 * @param configIgnorePatterns - gitignore-style patterns from `config.ignore.paths`
 *   / `config.ignore.patterns`. Matched relative to `targetPath`.
 */
export async function getFilesToScanAsync(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
  configIgnorePatterns: string[] = [],
): Promise<string[]> {
  const allFiles = await getAllFilesAsync(targetPath, new Set(), verbose, bus);
  const gitignoreTester = getGitignoreTester(targetPath);
  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, targetPath);
  return allFiles.filter(
    file => !shouldIgnoreFile(file, gitignoreTester) && !configIgnoreTester(file),
  );
}

/**
 * Get files to scan (filters out ignored directories/files) - sync version
 *
 * @param configIgnorePatterns - gitignore-style patterns from `config.ignore.paths`
 *   / `config.ignore.patterns`. Matched relative to `targetPath`.
 */
export function getFilesToScan(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
  configIgnorePatterns: string[] = [],
): string[] {
  const allFiles = getAllFiles(targetPath, new Set(), verbose, bus);
  const gitignoreTester = getGitignoreTester(targetPath);
  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, targetPath);
  return allFiles.filter(
    file => !shouldIgnoreFile(file, gitignoreTester) && !configIgnoreTester(file),
  );
}

/**
 * What a pull-request run declined to look at, and how much of it there was.
 *
 * Reported rather than silent for the same reason every suppression in this
 * tool is reported: something the scanner declined to look at is a decision the
 * run made on the user's behalf, and a run that makes it invisibly manufactures
 * confidence it has not earned.
 */
export interface PullRequestSkips {
  /** Directories skipped by name at the scan root. */
  dirCount: number;
  /** Those directory names, for a one-line summary. */
  dirNames: string[];
  /**
   * Files in the head tree dropped by the extension, lockfile-name and
   * generated-artifact filters.
   *
   * Counted because those filters are silent mutes of the same shape as the
   * ones this mode exists to close: a key committed as `src/leak.min.js` or
   * `src/leak.lock` is skipped on its name alone, and the run used to say
   * nothing at all about it. What gets skipped is unchanged; that something
   * was is now visible.
   */
  typeFilteredFiles: number;
}

/**
 * The file set for a pull-request run: the head tree, filtered like the walk.
 *
 * Two things are deliberately different from {@link getFilesToScan}, and both
 * of them close a way a pull request could mute the scanner in the same commit
 * that carried a secret.
 *
 * FIRST, THE SET COMES FROM GIT, NOT FROM `.gitignore`. The ordinary walk asks
 * the gitignore tester whether to skip each file, which means a `.gitignore`
 * the pull request itself added decides what the pull request is scanned on. A
 * `src/.gitignore` containing the name of the file the key sits in was enough,
 * measured, to turn exit 1 into exit 0. A file already in the head tree cannot
 * be muted that way: `.gitignore` governs what git will ADD and says nothing
 * about a file already committed. The tester stays in place for the untracked
 * working-tree scans that have no flag, where it is doing an honest job.
 *
 * SECOND, THE VENDORED-DIRECTORY NAMES ARE ANCHORED TO THE SCAN ROOT. The walk
 * skips any directory called `vendor`, `venv`, `dist` and so on at any depth,
 * which a pull request can satisfy by committing its key to `src/vendor/`. Here
 * only a direct child of the scan root can be skipped by name, so a committed
 * `src/vendor/` is scanned. Anchoring is safe here precisely because the set is
 * the head tree: a nested `node_modules` is not committed, so nothing is gained
 * by pretending to skip it and no cost is paid for walking it, since there is
 * no walk.
 *
 * Everything else is the walk's own filtering, applied to the same paths:
 * binaries and lockfiles by extension and name, generated artifacts, the
 * config's own `ignore` patterns (from the BASE ref, in this mode), and
 * anything that is not a regular file on disk. Those name-and-extension drops
 * are COUNTED into {@link PullRequestSkips.typeFilteredFiles}: what they skip
 * is unchanged, but `src/leak.min.js` used to disappear without the run saying
 * so, which is the same silence this mode exists to remove.
 */
export function getPullRequestFilesToScan(
  targetPath: string,
  headTreeFiles: Iterable<string>,
  configIgnorePatterns: string[] = [],
  skipped: PullRequestSkips = { dirCount: 0, dirNames: [], typeFilteredFiles: 0 },
): string[] {
  const target = path.resolve(targetPath);
  const targetIsDirectory = (() => {
    try {
      return fs.statSync(target).isDirectory();
    } catch {
      return true;
    }
  })();

  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, target);
  const skippedNames = new Set<string>();
  let typeFiltered = 0;
  const out: string[] = [];

  for (const file of headTreeFiles) {
    const abs = path.resolve(file);

    if (!targetIsDirectory) {
      if (abs !== target) continue;
    } else {
      const rel = path.relative(target, abs);
      if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) continue;
      const segments = rel.split(path.sep);
      // Anchored: only a direct child of the scan root is skipped by name.
      if (segments.length > 1 && shouldIgnoreDirectory(segments[0])) {
        skippedNames.add(segments[0]);
        continue;
      }
    }

    // No gitignore tester: see the note above. The rest of the walk's file
    // filtering still applies, and is counted.
    if (shouldIgnoreFile(abs)) {
      typeFiltered++;
      continue;
    }
    // A config `ignore` pattern is not counted here: it is the project's own
    // written decision, it comes from the BASE ref in this mode, and a head
    // that changed it is already reported as a proposal. The counts above are
    // for the skips nobody wrote down.
    if (configIgnoreTester(abs)) continue;

    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(abs);
    } catch {
      // In the head tree but not on disk. There is nothing to read, and the
      // walk would never have produced it either.
      continue;
    }
    if (!stat.isFile()) continue;

    out.push(abs);
  }

  skipped.dirNames = [...skippedNames].sort();
  skipped.dirCount = skipped.dirNames.length;
  skipped.typeFilteredFiles = typeFiltered;
  return out;
}

function shouldIgnoreDirectory(name: string): boolean {
  const ignoreDirs = [
    'node_modules',
    '.git',
    'dist',
    'build',
    'coverage',
    '.next',
    '.turbo',
    // Vendored / generated trees: third-party or tool-managed content where
    // matches are not the user's secrets and the volume drowns real findings.
    '.yarn',
    'vendor',
    '.venv',
    'venv',
    '__pycache__',
    '.mypy_cache',
    '.pytest_cache',
    '.gradle',
    '.svelte-kit',
  ];
  return ignoreDirs.includes(name);
}

/**
 * Minified / bundled / generated single-file artifacts. These are never
 * hand-authored, routinely committed, and a major false-positive source:
 * broad key shapes (e.g. `AKIA…`) occur by chance inside large minified blobs.
 */
function isGeneratedArtifact(basename: string): boolean {
  return (
    /\.min\.(js|mjs|cjs|css)$/.test(basename) ||
    /\.bundle\.(js|mjs|cjs)$/.test(basename) ||
    basename === '.pnp.cjs' ||
    basename === '.pnp.loader.mjs'
  );
}

function shouldIgnoreFile(
  filePath: string,
  gitignoreTester?: (filePath: string) => boolean,
): boolean {
  const ext = path.extname(filePath);
  const ignoreExts = [
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.ico',
    '.pdf',
    '.zip',
    '.tar',
    '.gz',
    '.lock',
    '.log',
    '.map',
  ];

  if (ignoreExts.includes(ext)) {
    return true;
  }

  const basename = path.basename(filePath);
  if (basename === 'package-lock.json' || basename === 'pnpm-lock.yaml' || basename === 'yarn.lock') {
    return true;
  }

  if (isGeneratedArtifact(basename)) {
    return true;
  }

  if (gitignoreTester && gitignoreTester(filePath)) {
    return true;
  }

  return false;
}
