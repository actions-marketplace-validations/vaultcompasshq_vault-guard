import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';

/**
 * Pull-request mode, end to end: every muting change a pull request can make
 * in the same commit as the secret it is hiding.
 *
 * Each case here was first measured WITHOUT the flag on a scratch repository,
 * where it turned exit 1 into exit 0 with no line of output saying anything had
 * been muted. The before state is pinned by `the before state` block at the
 * bottom, so the muting these tests close cannot quietly come back.
 */

/**
 * Synthetic Anthropic-shaped key, joined at runtime. A committed provider-key
 * shape trips credential scanners regardless of the value being fake and the
 * file being a test, so no fragment matches a rule on its own. Same convention
 * as bench/generate-fixtures.cjs.
 */
const FAKE_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

/** Symlinks and file modes; the Windows CI job is not a required check. */
const itPosix = process.platform === 'win32' ? it.skip : it;

interface Captured {
  code: number;
  log: string;
  err: string;
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

describe('pull-request mode (--trust-base)', () => {
  let dir: string;
  const originalCwd = process.cwd();

  function write(rel: string, text: string): void {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
  }

  /**
   * `-f` so a file the pull request's own `.gitignore` covers is still
   * committed. That is the shape of the attack: the key is tracked, and the
   * `.gitignore` exists to keep the scanner from looking at it, not to keep
   * git from storing it.
   */
  function commit(message: string): void {
    git(dir, ['add', '-A', '-f']);
    git(dir, ['commit', '-q', '-m', message]);
  }

  /** Base branch: a committed config, an empty baseline, one benign file. */
  function seedBase(config: unknown = { fail_on: 'medium' }): void {
    write('.vault-guard.json', JSON.stringify(config));
    write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [] }));
    write('src/app.ts', 'export const greeting = "hello";\n');
    commit('base: adopt vault-guard');
    git(dir, ['branch', 'base-snapshot']);
    git(dir, ['checkout', '-q', '-b', 'feature']);
  }

  function addSecret(rel = 'src/leak.ts'): void {
    write(rel, `export const key = "${FAKE_KEY}";\n`);
  }

  beforeEach(() => {
    // `.native`: the scan is anchored here and compared against the worktree
    // root git reports, and on Windows `os.tmpdir()` is the 8.3 short form that
    // plain realpathSync keeps while git uses the long one.
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-trust-base-cli-')));
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

  describe('every muting change is reported and ignored, and the secret still blocks', () => {
    it('ignore: ["**"] added to the config', async () => {
      seedBase();
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'medium', ignore: { paths: ['**'] } }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('config changed in this pull request');
      expect(r.log).toContain('1 pattern added to ignore');
    });

    it('severity_overrides turning the matching rule off', async () => {
      seedBase();
      addSecret();
      write(
        '.vault-guard.json',
        JSON.stringify({ fail_on: 'medium', severity_overrides: { anthropic: 'off' } }),
      );
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('config changed in this pull request');
      expect(r.log).toContain('1 severity override added');
    });

    it('fail_on lowered to none', async () => {
      seedBase();
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('fail_on lowered');
    });

    it('a .vault-guard.local.json swapped in for the committed config', async () => {
      seedBase();
      addSecret();
      fs.rmSync(path.join(dir, '.vault-guard.json'));
      write('.vault-guard.local.json', JSON.stringify({ fail_on: 'none' }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('config changed in this pull request');
    });

    it('a baseline rewritten to carry the new finding', async () => {
      seedBase();
      addSecret();
      commit('feature: add a key');
      const first = await capture(() => scanCommand('.', 'json'));
      const fp = (
        JSON.parse(first.stdout) as { results: Array<{ matches: Array<{ fingerprint: string }> }> }
      ).results[0].matches[0].fingerprint;
      write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [fp] }));
      commit('feature: baseline it');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('baseline changed in this pull request');
      expect(r.log).toContain('1 baseline entry added');
    });

    it('a .gitignore covering the file the key is committed in', async () => {
      seedBase();
      addSecret();
      write('src/.gitignore', 'leak.ts\n');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('src/leak.ts');
    });

    it('the key placed under a vendored-looking directory', async () => {
      seedBase();
      addSecret('src/vendor/leak.ts');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('Vendored directories skipped: 0');
    });

    it('still skips a vendored directory at the scan root and says how many', async () => {
      seedBase();
      addSecret();
      write('vendor/thing.ts', 'export const v = 1;\n');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('Vendored directories skipped: 1 (vendor)');
    });

    it('the key committed and then dropped from the index with git rm --cached', async () => {
      seedBase();
      addSecret();
      commit('feature');
      // The file stays on disk and stays in HEAD; only the index forgets it.
      // A file set read from the index loses it, which is a mute costing one
      // command with the key exactly where it was.
      git(dir, ['rm', '--cached', '-q', 'src/leak.ts']);
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('src/leak.ts');
    });
  });

  describe('what the run declined to look at', () => {
    it('counts a key hidden behind a generated-artifact name, without unhiding it', async () => {
      seedBase();
      addSecret('src/leak.min.js');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      // Still skipped, deliberately: this changes what the run SAYS, not what
      // it scans. The count is what a reviewer needs to notice it happened.
      expect(r.code).toBe(0);
      expect(r.log).toContain('Files skipped by type or name: 1');
    });

    it('counts a key hidden behind a .lock extension', async () => {
      seedBase();
      addSecret('src/leak.lock');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(0);
      expect(r.log).toContain('Files skipped by type or name: 1');
    });

    it('carries both skip counts in JSON', async () => {
      seedBase();
      addSecret('src/leak.min.js');
      write('vendor/thing.ts', 'export const v = 1;\n');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
      const doc = JSON.parse(r.stdout) as {
        run: { vendored_dirs_skipped: number; type_filtered_files: number };
      };
      expect(doc.run.vendored_dirs_skipped).toBe(1);
      expect(doc.run.type_filtered_files).toBe(1);
    });

    it('says nothing about either count on a staged run, where neither can be filled', async () => {
      seedBase();
      // A commit first, so HEAD differs from the base and the ref is accepted;
      // then the key staged but not committed, which is what `--staged` reads.
      write('src/other.ts', 'export const y = 2;\n');
      commit('feature');
      addSecret();
      git(dir, ['add', '-A', '-f']);
      const r = await capture(() => scanCommand('.', 'text', true, undefined, 'base-snapshot'));
      expect(r.log).not.toContain('Vendored directories skipped');
      expect(r.log).not.toContain('Files skipped by type or name');

      const json = await capture(() => scanCommand('.', 'json', true, undefined, 'base-snapshot'));
      const run = (JSON.parse(json.stdout) as { run: Record<string, unknown> }).run;
      expect(run).not.toHaveProperty('vendored_dirs_skipped');
      expect(run).not.toHaveProperty('type_filtered_files');
    });
  });

  describe('first adoption and honest changes', () => {
    it('uses the defaults when the config exists only at the head, and says so', async () => {
      write('src/app.ts', 'export const greeting = "hello";\n');
      commit('base');
      git(dir, ['branch', 'base-snapshot']);
      git(dir, ['checkout', '-q', '-b', 'feature']);
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('config added in this pull request');
    });

    it('accepts a base that differs only in a file that is not a control input', async () => {
      seedBase();
      write('src/other.ts', 'export const y = 2;\n');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(0);
      expect(r.log).toContain('Proposed, not applied: none');
    });

    itPosix('reports a config the head turned into a symlink and ignores it', async () => {
      seedBase();
      addSecret();
      write('decoy.json', JSON.stringify({ fail_on: 'none' }));
      fs.rmSync(path.join(dir, '.vault-guard.json'));
      fs.symlinkSync('decoy.json', path.join(dir, '.vault-guard.json'));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(1);
      expect(r.log).toContain('config is a symlink at the head commit, not a regular file');
    });
  });

  describe('failing closed on the ref', () => {
    it('exits 2 and scans nothing when the ref does not resolve', async () => {
      seedBase();
      addSecret();
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'origin/nope'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('origin/nope');
      expect(r.err).toContain('fetch-depth: 0');
      expect(r.log).not.toContain('Scanning');
      expect(r.log).not.toContain('SUCCESS');
    });

    it('exits 2 when the ref is the head commit', async () => {
      seedBase();
      addSecret();
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'HEAD'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('the same commit as HEAD');
    });

    it('exits 2 when the ref is a different commit carrying the head tree', async () => {
      seedBase();
      addSecret();
      commit('feature');
      git(dir, ['branch', 'twin']);
      git(dir, ['checkout', '-q', 'twin']);
      git(dir, ['commit', '-q', '--allow-empty', '-m', 'merge ref shape']);
      git(dir, ['checkout', '-q', 'feature']);
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'twin'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('identical tree');
    });

    it('exits 2 when the scan target is outside the repository the base ref lives in', async () => {
      seedBase();
      addSecret();
      commit('feature');
      // A target in another tree. The trust base is resolved from the process
      // cwd, so before this guard the tracked-file set came from THIS
      // repository, intersected with a target none of it was under, and the
      // run reported "no secrets found" over zero files scanned.
      const outside = fs.realpathSync.native(
        fs.mkdtempSync(path.join(os.tmpdir(), 'vg-outside-')),
      );
      fs.writeFileSync(path.join(outside, 'leak.ts'), `export const key = "${FAKE_KEY}";\n`);
      try {
        const r = await capture(() =>
          scanCommand(outside, 'text', false, undefined, 'base-snapshot'),
        );
        expect(r.code).toBe(2);
        expect(r.err).toContain('outside');
        expect(r.log).not.toContain('SUCCESS');
      } finally {
        fs.rmSync(outside, { recursive: true, force: true });
      }
    });

    it('exits 2 when the config at the base ref fails schema validation', async () => {
      seedBase({ fail_on: 'medium', ignore: { unknown_key: [] } });
      addSecret();
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('unknown key');
      expect(r.log).not.toContain('SUCCESS');
    });
  });

  describe('structured output', () => {
    it('carries a trustBase block in JSON', async () => {
      seedBase();
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
      const doc = JSON.parse(r.stdout) as {
        trustBase: {
          ref: string;
          proposals: string[];
          configChanged: boolean;
          baselineChanged: boolean;
          configShapeChange: string | null;
          baselineShapeChange: string | null;
        };
      };
      expect(doc.trustBase.ref).toBe('base-snapshot');
      expect(doc.trustBase.configChanged).toBe(true);
      expect(doc.trustBase.baselineChanged).toBe(false);
      expect(doc.trustBase.configShapeChange).toBeNull();
      expect(doc.trustBase.baselineShapeChange).toBeNull();
      expect(doc.trustBase.proposals.some(p => p.startsWith('config changed in this pull request')))
        .toBe(true);
    });

    it('emits one SARIF toolExecutionNotification per proposal', async () => {
      seedBase();
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: ['zz'] }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'sarif', false, undefined, 'base-snapshot'));
      const doc = JSON.parse(r.stdout) as {
        runs: Array<{
          invocations?: Array<{
            executionSuccessful: boolean;
            toolExecutionNotifications: Array<{ message: { text: string } }>;
          }>;
        }>;
      };
      const notes = doc.runs[0].invocations?.[0].toolExecutionNotifications ?? [];
      expect(notes.length).toBe(2);
      expect(notes.some(n => n.message.text.startsWith('config changed in this pull request')))
        .toBe(true);
      expect(notes.some(n => n.message.text.startsWith('baseline changed in this pull request')))
        .toBe(true);
    });

    it('reports the inline critical vendor-anchored suppression count', async () => {
      seedBase();
      write('src/leak.ts', `export const key = "${FAKE_KEY}"; // vault-guard: ignore-line\n`);
      commit('feature');
      const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
      const doc = JSON.parse(r.stdout) as {
        run: { inline_suppressed: number; inline_suppressed_critical_vendor: number };
      };
      expect(doc.run.inline_suppressed).toBe(1);
      expect(doc.run.inline_suppressed_critical_vendor).toBe(1);
    });
  });

  describe('the before state, pinned', () => {
    /**
     * Updated by the empty-scan fail-closed invariant (see
     * empty-scan-fail-closed.test.ts). `ignore: ["**"]` does not merely mute
     * every finding any more: it makes the walk examine zero files, which is
     * now its own could-not-run rather than a silent clean pass. This is a
     * SECOND, independent closure of the same mutation-attack class this
     * describe block documents, and it applies even without `--trust-base`,
     * which is why the assertion changed from "still mutes the key" (exit 0)
     * to "still hits could-not-run" (exit 2) here.
     *
     * The other "before state" cases below are untouched: severity_overrides
     * and a swapped-in .vault-guard.local.json suppress the FINDING without
     * suppressing every FILE (the fixture's other file, src/app.ts, is still
     * examined), so they do not trip the zero-files check and still
     * demonstrate the original silent-clean vulnerability that only
     * --trust-base closes.
     */
    it('without the flag ignore: ["**"] now hits the empty-scan invariant instead of silently muting', async () => {
      seedBase();
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'medium', ignore: { paths: ['**'] } }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('nothing was scanned');
    });

    it('without the flag a severity_overrides off still mutes the key', async () => {
      seedBase();
      addSecret();
      write(
        '.vault-guard.json',
        JSON.stringify({ fail_on: 'medium', severity_overrides: { anthropic: 'off' } }),
      );
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(0);
      expect(r.log).toContain('No secrets found');
    });

    it('without the flag a head-added .vault-guard.local.json still mutes the key', async () => {
      seedBase();
      addSecret();
      // The swap is what makes this bite. Beside a `.vault-guard.json` in the
      // same directory the local file never wins, because the two filenames are
      // tried in order and the first hit ends the search on both sides.
      fs.rmSync(path.join(dir, '.vault-guard.json'));
      write('.vault-guard.local.json', JSON.stringify({ fail_on: 'none' }));
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(0);
    });

    it('without the flag a rewritten baseline still mutes the key', async () => {
      seedBase();
      addSecret();
      commit('feature: add a key');
      const first = await capture(() => scanCommand('.', 'json'));
      const fp = (
        JSON.parse(first.stdout) as { results: Array<{ matches: Array<{ fingerprint: string }> }> }
      ).results[0].matches[0].fingerprint;
      write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [fp] }));
      commit('feature: baseline it');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(0);
      expect(r.log).toContain('No secrets found');
    });

    it('without the flag a head-added .gitignore still mutes a tracked file', async () => {
      seedBase();
      addSecret();
      write('src/.gitignore', 'leak.ts\n');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(0);
      expect(r.log).toContain('No secrets found');
    });

    it('without the flag a committed src/vendor is still skipped', async () => {
      seedBase();
      addSecret('src/vendor/leak.ts');
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(0);
      expect(r.log).toContain('No secrets found');
    });

    it('without the flag the head config decides, and no trust-base output appears', async () => {
      seedBase();
      addSecret();
      write('.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      commit('feature');
      const text = await capture(() => scanCommand('.', 'text'));
      expect(text.code).toBe(0);
      expect(text.log).not.toContain('pull request');
      expect(text.log).not.toContain('Vendored directories skipped');
      expect(text.log).not.toContain('Control inputs');

      const json = await capture(() => scanCommand('.', 'json'));
      expect(JSON.parse(json.stdout)).not.toHaveProperty('trustBase');
    });

    it('without the flag the text summary is byte for byte what 1.6.0 printed', async () => {
      seedBase();
      addSecret();
      commit('feature');
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(1);
      expect(r.log.split('\n')).toEqual([
        '🔍 Scanning .',
        'Suppressed: 0 by baseline, 0 by inline ignore directives',
        '🚨 BLOCKED: Found 1 secret',
        '',
        expect.stringMatching(/^ {2}🔴 src\/leak\.ts:1:21 {2}critical {2}anthropic {2}sk-a/),
        '',
        expect.stringContaining('❌ BLOCKED: Commit blocked'),
        '',
      ]);
    });
  });
});
