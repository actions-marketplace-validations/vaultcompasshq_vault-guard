import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Contract: `--format sarif` must write parseable SARIF JSON to stdout only.
 * A leading `--` in argv (forwarded by some npx invocations) must not disable
 * option parsing -- otherwise text banners land in the SARIF file and GitHub
 * upload-sarif rejects it.
 */
describe('CLI SARIF stdout contract', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');
  const monorepoRoot = path.join(packageRoot, '..', '..');

  const runSarifScan = (args: string[], cwd: string) => {
    return spawnSync(process.execPath, [cliEntry, ...args], {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });
  };

  const parseStdoutSarif = (stdout: string): { version?: string; runs?: unknown[] } => {
    const trimmed = stdout.trim();
    expect(trimmed.startsWith('{')).toBe(true);
    expect(trimmed).not.toMatch(/🔍/);
    return JSON.parse(trimmed) as { version?: string; runs?: unknown[] };
  };

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  it('writes parseable SARIF only to stdout', () => {
    const fixtureDir = path.join(monorepoRoot, 'fixtures', 'release-smoke');
    const proc = runSarifScan(['scan', fixtureDir, '--format', 'sarif'], monorepoRoot);
    expect(proc.error).toBeUndefined();

    const body = parseStdoutSarif(proc.stdout);
    expect(body.version).toBe('2.1.0');
    expect(Array.isArray(body.runs)).toBe(true);
    expect(proc.status).not.toBe(0);

    // Regression: fixtureDir is an absolute target, but it sits IN TREE under
    // monorepoRoot (the cwd this scan runs from). The uri must stay rooted at
    // cwd (fixtures/release-smoke/leaked.ts), not become root-relative to the
    // target itself (leaked.ts) -- the latter names a different file once
    // GitHub Code Scanning resolves %SRCROOT% back to the real checkout root.
    const runs = body.runs as Array<{
      results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>;
    }>;
    const loc = runs[0].results[0].locations[0].physicalLocation.artifactLocation;
    expect(loc.uri).toBe('fixtures/release-smoke/leaked.ts');
  });

  it('emits a scan-root-relative uri for a target outside the cwd', () => {
    // Run from the monorepo root but scan an out-of-tree directory. Before the
    // scan root was threaded through, every uri here stayed absolute and the
    // SARIF file published the machine's home directory and username.
    //
    // Also covers diagnostics: an unreadable subdirectory makes the scanner
    // emit an fs.permission_denied diagnostic whose ctx carries the locked
    // directory's absolute path (and a `detail` string with that same path
    // baked into Node's own error text). That diagnostic renders into a SARIF
    // notification, so this is what makes the "no absolute path anywhere"
    // assertion below non-vacuous -- without a diagnostic in the document,
    // it would pass even if notification ctx were never sanitized at all.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-sarif-root-'));
    const lockedDir = path.join(tmp, 'locked');
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    try {
      fs.mkdirSync(path.join(tmp, 'src'));
      fs.writeFileSync(
        path.join(tmp, 'src', 'leaked.ts'),
        "export const k = 'sk-ant-api03-fakekeyfortesting1234567890ABCDEFGHIJ';\n",
        'utf-8',
      );
      fs.mkdirSync(lockedDir);
      if (!isRoot) {
        fs.chmodSync(lockedDir, 0o000);
      }

      const proc = runSarifScan(['scan', tmp, '--format', 'sarif'], monorepoRoot);
      expect(proc.error).toBeUndefined();

      const body = parseStdoutSarif(proc.stdout) as {
        runs: Array<{
          results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string; uriBaseId: string } } }> }>;
          tool: { driver: { notifications?: Array<{ message: { text: string } }> } };
        }>;
      };
      const loc = body.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
      expect(loc.uri).toBe('src/leaked.ts');
      expect(loc.uriBaseId).toBe('%SRCROOT%');

      if (!isRoot) {
        // root ignores the 0o000 mode, so the locked directory reads fine and
        // no diagnostic (and no notification) is ever emitted for it.
        expect(body.runs[0].tool.driver.notifications?.length).toBeGreaterThan(0);
      }

      // The whole point: no absolute filesystem path anywhere in the document,
      // including inside a diagnostic notification's ctx and detail text.
      expect(proc.stdout).not.toContain(tmp);
    } finally {
      if (!isRoot) {
        fs.chmodSync(lockedDir, 0o755);
      }
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('still honors --format when argv has a leading -- (npx passthrough)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-sarif-ddash-'));
    try {
      fs.writeFileSync(path.join(tmp, 'clean.ts'), "export const x = 'hello';\n", 'utf-8');

      const proc = runSarifScan(['--', 'scan', tmp, '--format', 'sarif'], tmp);
      expect(proc.error).toBeUndefined();

      const body = parseStdoutSarif(proc.stdout);
      expect(body.version).toBe('2.1.0');
      expect(proc.status).toBe(0);
      expect(proc.stdout).not.toMatch(/Scanning/);
    } finally {
      fs.unlinkSync(path.join(tmp, 'clean.ts'));
      fs.rmdirSync(tmp);
    }
  });
});
