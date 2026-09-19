import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Contract for the 1.4.0 severity gate.
 *
 * Before 1.4.0 any match at all returned exit 1, which made the scanner's own
 * `low` downgrades (test/docs/example paths, public identifiers) pointless: a
 * `.env.example` still blocked the commit. The gate now defaults to `medium`.
 */
describe('CLI --fail-on gate', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');

  let workdir: string;

  const run = (args: string[]) =>
    spawnSync(process.execPath, [cliEntry, ...args], {
      cwd: workdir,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  beforeEach(() => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-fail-on-'));
    // `low` only: a docs-path generic finding gets downgraded by path-severity.
    fs.mkdirSync(path.join(workdir, 'docs'));
    fs.writeFileSync(
      path.join(workdir, 'docs', 'setup.md'),
      'Set `api_key = "aB3cD4eF5gH6iJ7kLmNoPqRs"` in your config.\n',
    );
  });

  afterEach(() => {
    fs.rmSync(workdir, { recursive: true, force: true });
  });

  const writeCriticalFinding = () => {
    fs.writeFileSync(
      path.join(workdir, 'prod.ts'),
      `const k = ${JSON.stringify(['sk-ant-', 'api03-', 'Zg7kP2mQxN4RvT8wYhLs6FjEbDcA9uKp'].join(''))};\n`,
    );
  };

  it('does not fail the gate on low-severity findings by default', () => {
    const proc = run(['scan', '.', '--format', 'json']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.summary.secrets).toBeGreaterThan(0);
    expect(out.run.fail_on).toBe('medium');
    expect(out.run.blocking_matches).toBe(0);
    expect(proc.status).toBe(0);
  });

  it('still fails the gate on a critical finding', () => {
    writeCriticalFinding();
    const proc = run(['scan', '.', '--format', 'json']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.blocking_matches).toBeGreaterThan(0);
    expect(proc.status).toBe(1);
  });

  it('--fail-on low restores the pre-1.4.0 block-on-anything behaviour', () => {
    const proc = run(['scan', '.', '--format', 'json', '--fail-on', 'low']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.fail_on).toBe('low');
    expect(out.run.blocking_matches).toBeGreaterThan(0);
    expect(proc.status).toBe(1);
  });

  it('--fail-on none reports findings but never fails', () => {
    writeCriticalFinding();
    const proc = run(['scan', '.', '--format', 'json', '--fail-on', 'none']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.summary.secrets).toBeGreaterThan(0);
    expect(out.run.blocking_matches).toBe(0);
    expect(proc.status).toBe(0);
  });

  it('reads fail_on from .vault-guard.json', () => {
    fs.writeFileSync(
      path.join(workdir, '.vault-guard.json'),
      JSON.stringify({ fail_on: 'low' }),
    );
    const proc = run(['scan', '.', '--format', 'json']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.fail_on).toBe('low');
    expect(proc.status).toBe(1);
  });

  it('lets --fail-on override the config value', () => {
    fs.writeFileSync(
      path.join(workdir, '.vault-guard.json'),
      JSON.stringify({ fail_on: 'low' }),
    );
    const proc = run(['scan', '.', '--format', 'json', '--fail-on', 'critical']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.fail_on).toBe('critical');
    expect(proc.status).toBe(0);
  });

  it('rejects an invalid --fail-on value instead of silently defaulting', () => {
    const proc = run(['scan', '.', '--fail-on', 'sometimes']);
    expect(proc.status).toBe(1);
    expect(proc.stderr).toMatch(/Invalid fail-on value/);
  });

  it('text mode explains why findings did not fail the gate', () => {
    const proc = run(['scan', '.']);
    expect(proc.status).toBe(0);
    expect(proc.stdout).toMatch(/none at or above severity "medium"/);
  });

  it('does not print BLOCKED over a run that exits 0', () => {
    const proc = run(['scan', '.']);

    // The headline used to be written before the threshold existed, so a run
    // with only sub-threshold findings announced "BLOCKED: Found 1 secret",
    // listed it, said "Commit blocked", and then exited 0.
    expect(proc.status).toBe(0);
    expect(proc.stdout).not.toMatch(/BLOCKED/);
    expect(proc.stdout).toMatch(/below the fail threshold/);
  });

  it('does print BLOCKED when the run exits 1', () => {
    writeCriticalFinding();
    const proc = run(['scan', '.']);

    expect(proc.status).toBe(1);
    expect(proc.stdout).toMatch(/BLOCKED/);
  });

  it('does not mark a finding with a success checkmark', () => {
    const proc = run(['scan', '.']);
    const findingLine = proc.stdout
      .split('\n')
      .find(l => l.includes('api-key-generic'));

    expect(findingLine).toBeDefined();
    expect(findingLine).not.toContain('\u2705');
  });

  describe('1.4.0 default-change upgrade notice', () => {
    // The notice exists because upgrading users silently stop blocking on
    // low findings. It must appear exactly when the default decided the
    // outcome, and choosing any threshold explicitly must silence it.

    it('appears when the implicit default is what saved the run', () => {
      const proc = run(['scan', '.']);
      expect(proc.status).toBe(0);
      expect(proc.stderr).toMatch(/since 1\.4\.0 the default gate is "medium"/);
      expect(proc.stderr).toMatch(/would have failed before/);
    });

    it('stays quiet when --fail-on was given, even at the same value', () => {
      const proc = run(['scan', '.', '--fail-on', 'medium']);
      expect(proc.status).toBe(0);
      expect(proc.stderr).not.toMatch(/1\.4\.0/);
    });

    it('stays quiet when fail_on is set in config', () => {
      fs.writeFileSync(
        path.join(workdir, '.vault-guard.json'),
        JSON.stringify({ fail_on: 'medium' }),
      );
      const proc = run(['scan', '.']);
      expect(proc.status).toBe(0);
      expect(proc.stderr).not.toMatch(/1\.4\.0/);
    });

    it('stays quiet when there are no findings at all', () => {
      // Overwritten rather than removed: an empty `workdir` (zero files
      // examined) now exits 2 under the fail-closed empty-scan invariant
      // (see empty-scan-fail-closed.test.ts), which would make this test
      // assert something the code no longer does for an unrelated reason.
      // One clean file keeps "no findings" true while keeping the scan
      // non-empty.
      fs.writeFileSync(
        path.join(workdir, 'docs', 'setup.md'),
        '# Setup\n\nNothing sensitive here.\n',
      );
      const proc = run(['scan', '.']);
      expect(proc.status).toBe(0);
      expect(proc.stderr).not.toMatch(/1\.4\.0/);
    });

    it('stays quiet when the run fails anyway', () => {
      writeCriticalFinding();
      const proc = run(['scan', '.']);
      expect(proc.status).toBe(1);
      expect(proc.stderr).not.toMatch(/1\.4\.0/);
    });

    it('goes to stderr in json mode and stdout stays parseable', () => {
      const proc = run(['scan', '.', '--format', 'json']);
      expect(proc.status).toBe(0);
      expect(proc.stderr).toMatch(/since 1\.4\.0/);
      const out = JSON.parse(proc.stdout.trim());
      expect(out.run.blocking_matches).toBe(0);
    });
  });

  it('applies the same gate to `check`', () => {
    const proc = run(['check', 'docs/setup.md']);
    expect(proc.status).toBe(0);
  });
});
