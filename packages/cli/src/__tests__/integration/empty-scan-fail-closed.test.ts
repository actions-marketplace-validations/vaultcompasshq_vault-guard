import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';

/**
 * The fail-closed invariant for a scan that examined nothing.
 *
 * A WHOLE-TREE / target scan (a plain `vault-guard scan <path>`, with or
 * without `--trust-base`) walks a directory it was told holds the tree to
 * judge. If that walk resolves to zero files, the run has established
 * NOTHING about the repository, and "no secrets found" is not a true
 * description of what happened. It is a stronger false signal than no gate
 * at all, because a consumer reading a green check believes something was
 * looked at.
 *
 * The mechanism found in the wild: a check script's scan root resolves
 * relative to the script's own (possibly relocated, possibly
 * wrong-working-directory) location rather than the repository, silently
 * scans zero files, and sits green in a required check. See the identical
 * shape action.yml already defends against with `pwd -P` for the scan root
 * (search "SCAN_ROOT" there) -- this closes the same hole one level down, at
 * the scanner itself, for anyone driving vault-guard directly rather than
 * through the Action.
 *
 * The DISTINGUISHING SIGNAL is imposed-vs-discovered emptiness:
 *
 *   - `--staged` with an empty index is an EXPLICIT empty scope: the caller
 *     asked "what's in the index" and got a true, legitimate answer of
 *     "nothing". That must stay a clean pass -- see
 *     `../staged-index-scan.test.ts` for the non-empty case this must not
 *     regress, and the "explicit empty scope" describe block below for the
 *     empty one.
 *
 *   - A directory / target walk (plain or `--trust-base`) that resolves to
 *     zero files is DISCOVERED emptiness: the caller asked to scan a tree
 *     that was expected to hold content, and the walk found none. That is
 *     could-not-run (exit 2), not clean.
 */

interface Captured {
  code: number;
  /** console.log text (text-mode summary lines). */
  log: string;
  /** console.error text (warnings, the could-not-run message). */
  err: string;
  /** process.stdout.write payload (the JSON / SARIF document, if any). */
  stdout: string;
}

async function capture(fn: () => Promise<number>): Promise<Captured> {
  const logs: string[] = [];
  const errs: string[] = [];
  const outs: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const origOut = process.stdout.write;
  const origErrW = process.stderr.write;
  console.log = (...a: unknown[]): boolean => {
    logs.push(a.map(String).join(' '));
    return true;
  };
  console.error = (...a: unknown[]): boolean => {
    errs.push(a.map(String).join(' '));
    return true;
  };
  process.stdout.write = ((s: string | Uint8Array): boolean => {
    outs.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((): boolean => true) as typeof process.stderr.write;
  let code: number;
  try {
    code = await fn();
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.stdout.write = origOut;
    process.stderr.write = origErrW;
  }
  return { code, log: logs.join('\n'), err: errs.join('\n'), stdout: outs.join('') };
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

describe('a whole-tree scan that examines zero files is could-not-run', () => {
  let dir: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-empty-scan-')));
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('a genuinely empty directory exits 2, not 0', async () => {
    const r = await capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(2);
    expect(r.err).toContain('nothing was scanned');
    expect(r.err).toContain('could-not-run');
  });

  it('does not write a JSON document for the empty case (no document to trust)', async () => {
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(2);
    expect(r.stdout).toBe('');
  });

  it('does not write a SARIF document for the empty case either', async () => {
    const r = await capture(() => scanCommand('.', 'sarif', false));
    expect(r.code).toBe(2);
    expect(r.stdout).toBe('');
  });

  it('a directory whose only entry is filtered out by the walk (node_modules) still exits 2', async () => {
    // Every file here is real and readable; every one of them is filtered
    // by the walk's own built-in ignore rules, so the RESULT is the same
    // "zero files examined" as an empty directory, discovered rather than
    // declared. This is judgment call #2 from the task: Option A treats
    // "everything present is filtered out" the same as "nothing is there".
    fs.mkdirSync(path.join(dir, 'node_modules'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'node_modules', 'leak.js'),
      'module.exports = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";\n',
    );
    const r = await capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(2);
    expect(r.err).toContain('nothing was scanned');
  });

  it('a normal scan of a non-empty, clean tree is unchanged: exit 0', async () => {
    fs.writeFileSync(path.join(dir, 'clean.ts'), 'export const x = 1;\n');
    const r = await capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(0);
    expect(r.log).toContain('No secrets found');
  });

  it('a normal scan of a tree with a secret is unchanged: exit 1', async () => {
    fs.writeFileSync(
      path.join(dir, 'leak.env'),
      'ANTHROPIC_API_KEY=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n',
    );
    const r = await capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(1);
  });
});

describe('explicit empty scope stays clean (imposed, not discovered)', () => {
  let dir: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-empty-staged-')));
    git(dir, ['init', '-q', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.invalid']);
    git(dir, ['config', 'user.name', 'test']);
    git(dir, ['config', 'commit.gpgsign', 'false']);
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /**
   * Judgment call #1 from the task: `--staged` with an empty index is the
   * caller explicitly asking "what's staged" and getting a true "nothing".
   * That is an imposed empty scope, not a discovered one, and must stay
   * clean. Pinned across every output format, because `text` mode returns
   * early (see scan.ts's `stagedFiles.length === 0` branch) while `json`
   * and `sarif` fall through the normal zero-results path -- both have to
   * land on exit 0, and neither should be caught by the new whole-tree
   * check, which is gated on `!staged`.
   */
  it('nothing staged, text format: exit 0, clean', async () => {
    const r = await capture(() => scanCommand('.', 'text', true));
    expect(r.code).toBe(0);
    expect(r.log).toContain('Nothing staged');
  });

  it('nothing staged, json format: exit 0, clean, and a document is still written', async () => {
    const r = await capture(() => scanCommand('.', 'json', true));
    expect(r.code).toBe(0);
    const body = JSON.parse(r.stdout) as { run?: { files_scanned?: number } };
    expect(body.run?.files_scanned).toBe(0);
  });

  it('nothing staged, sarif format: exit 0, clean', async () => {
    const r = await capture(() => scanCommand('.', 'sarif', true));
    expect(r.code).toBe(0);
  });
});

describe('trust-base (pull-request) mode target resolving to zero files', () => {
  let dir: string;
  const originalCwd = process.cwd();

  function write(rel: string, text: string): void {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
  }

  function commit(message: string): void {
    git(dir, ['add', '-A', '-f']);
    git(dir, ['commit', '-q', '-m', message]);
  }

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-trust-base-empty-')));
    git(dir, ['init', '-q', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.invalid']);
    git(dir, ['config', 'user.name', 'test']);
    git(dir, ['config', 'commit.gpgsign', 'false']);
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /**
   * Regression for the exact defect named in the task: a scan root that
   * resolves inside the repository, and inside the ref's boundary checks,
   * but that has no tracked files under it in the head tree. Before this
   * change that scanned zero files and reported a clean 0-file result;
   * this is the scenario a relocated or misconfigured `path:` input
   * produces in CI.
   */
  it('a target directory with no tracked files at head exits 2 under --trust-base', async () => {
    write('.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [] }));
    write('src/app.ts', 'export const greeting = "hello";\n');
    commit('base: adopt vault-guard');
    git(dir, ['branch', 'base-snapshot']);
    git(dir, ['checkout', '-q', '-b', 'feature']);

    // The head tree must differ from the base tree, or trust-base mode
    // refuses the run as "identical tree" before the target is ever
    // resolved (see trust-base.ts). Committed elsewhere in the tree, so it
    // does not put anything under the scan target below.
    write('src/app.ts', 'export const greeting = "hello there";\n');
    commit('feature: change something outside the scan target');

    // Exists on disk, but nothing under it is tracked at HEAD.
    fs.mkdirSync(path.join(dir, 'empty-dir'), { recursive: true });

    const r = await capture(() =>
      scanCommand('empty-dir', 'text', false, undefined, 'base-snapshot'),
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain('nothing was scanned');
  });
});
