import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { clearGitignoreCache, getFilesToScan, buildConfigIgnoreFilter } from '../utils/file-utils';

function tmp(name: string): string {
  return path.join(os.tmpdir(), `vg-ignore-${name}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
}

describe('getFilesToScan + ignore package', () => {
  afterEach(() => {
    clearGitignoreCache();
  });

  it('respects root .gitignore patterns', () => {
    const root = tmp('root');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, '.gitignore'), '*.secret\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'ok.ts'), 'export const x = 1\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'nope.secret'), 'data\n', 'utf-8');

    const names = getFilesToScan(root).map(f => path.basename(f));
    expect(names).toContain('ok.ts');
    expect(names).not.toContain('nope.secret');
  });

  it('applies negation patterns', () => {
    const root = tmp('neg');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(
      path.join(root, '.gitignore'),
      ['*.secret', '!keep.secret', ''].join('\n'),
      'utf-8',
    );
    fs.writeFileSync(path.join(root, 'drop.secret'), 'x\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'keep.secret'), 'y\n', 'utf-8');

    const files = getFilesToScan(root).map(f => path.basename(f)).sort();
    expect(files).toContain('keep.secret');
    expect(files).not.toContain('drop.secret');
  });

  it('loads nested .gitignore relative to git root', () => {
    const root = tmp('nested');
    fs.mkdirSync(path.join(root, 'pkg', 'src'), { recursive: true });
    fs.mkdirSync(path.join(root, '.git'), { recursive: true });
    fs.writeFileSync(path.join(root, '.gitignore'), '*.log\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', '.gitignore'), '*.tmp\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', 'src', 'a.ts'), 'ok\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', 'src', 'x.tmp'), 'no\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'noise.log'), 'no\n', 'utf-8');

    const files = getFilesToScan(path.join(root, 'pkg', 'src')).map(f => path.basename(f)).sort();
    expect(files).toEqual(['a.ts']);
  });

  it('applies a nested .gitignore when scanning from an ancestor directory', () => {
    const root = tmp('nested-from-ancestor');
    fs.mkdirSync(path.join(root, 'pkg', 'src'), { recursive: true });
    fs.mkdirSync(path.join(root, '.git'), { recursive: true });
    fs.writeFileSync(path.join(root, '.gitignore'), '*.log\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', '.gitignore'), '*.tmp\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', 'src', 'a.ts'), 'ok\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', 'src', 'x.tmp'), 'no\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'noise.log'), 'no\n', 'utf-8');

    // Scan from the repo ROOT, the normal `vault-guard scan .` case -- the
    // nested pkg/.gitignore should still apply to files under pkg/src/.
    const files = getFilesToScan(root).map(f => path.basename(f));
    expect(files).toContain('a.ts');
    expect(files).not.toContain('x.tmp');
    expect(files).not.toContain('noise.log');
  });

  it('skips vendored / generated directories and minified artifacts', () => {
    const root = tmp('vendored');
    fs.mkdirSync(path.join(root, '.yarn', 'releases'), { recursive: true });
    fs.mkdirSync(path.join(root, 'vendor'), { recursive: true });
    fs.mkdirSync(path.join(root, 'src'), { recursive: true });

    fs.writeFileSync(path.join(root, '.yarn', 'releases', 'yarn-4.12.0.cjs'), 'AKIAABCDEFGHIJKLMNOP\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'vendor', 'dep.go'), 'package x\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'app.min.js'), 'var a=1\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'app.js.map'), '{"version":3}\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'src', 'index.ts'), 'export const x = 1\n', 'utf-8');

    const names = getFilesToScan(root).map(f => path.basename(f));
    expect(names).toContain('index.ts');
    expect(names).not.toContain('yarn-4.12.0.cjs');
    expect(names).not.toContain('dep.go');
    expect(names).not.toContain('app.min.js');
    expect(names).not.toContain('app.js.map');
  });

  it('invalidates cache when .gitignore mtime changes', () => {
    const root = tmp('mtime');
    fs.mkdirSync(root, { recursive: true });
    const gi = path.join(root, '.gitignore');
    fs.writeFileSync(gi, '', 'utf-8');
    fs.writeFileSync(path.join(root, 'f.secret'), 'x\n', 'utf-8');

    let files = getFilesToScan(root).map(f => path.basename(f));
    expect(files).toContain('f.secret');

    fs.writeFileSync(gi, '*.secret\n', 'utf-8');
    files = getFilesToScan(root).map(f => path.basename(f));
    expect(files).not.toContain('f.secret');
  });
});

describe('buildConfigIgnoreFilter', () => {
  it('returns a no-op when patterns is empty', () => {
    const filter = buildConfigIgnoreFilter([], '/repo');
    expect(filter('/repo/src/index.ts')).toBe(false);
  });

  it('excludes files matching a glob pattern', () => {
    const filter = buildConfigIgnoreFilter(['**/__tests__/**'], '/repo');
    expect(filter('/repo/packages/core/src/__tests__/foo.test.ts')).toBe(true);
    expect(filter('/repo/packages/core/src/scanner.ts')).toBe(false);
  });

  it('excludes files matching a wildcard extension pattern', () => {
    const filter = buildConfigIgnoreFilter(['**/*.test.ts'], '/repo');
    expect(filter('/repo/src/foo.test.ts')).toBe(true);
    expect(filter('/repo/src/foo.ts')).toBe(false);
  });

  it('handles multiple patterns', () => {
    const filter = buildConfigIgnoreFilter(['fixtures/**', 'docs/**'], '/repo');
    expect(filter('/repo/fixtures/release-smoke/leaked.ts')).toBe(true);
    expect(filter('/repo/docs/README.md')).toBe(true);
    expect(filter('/repo/src/app.ts')).toBe(false);
  });

  it('ignores paths outside the root (returns false, does not throw)', () => {
    const filter = buildConfigIgnoreFilter(['**/*.ts'], '/repo');
    expect(filter('/other/project/src/app.ts')).toBe(false);
  });
});

describe('getFilesToScan with configIgnorePatterns', () => {
  afterEach(() => {
    clearGitignoreCache();
  });

  it('excludes files matching config ignore patterns', () => {
    const root = path.join(os.tmpdir(), `vg-cfg-ignore-${Date.now()}`);
    const testDir = path.join(root, '__tests__');
    const srcDir = path.join(root, 'src');
    fs.mkdirSync(testDir, { recursive: true });
    fs.mkdirSync(srcDir, { recursive: true });

    fs.writeFileSync(path.join(testDir, 'scanner.test.ts'), 'const k = "AKIA1234567890123456";', 'utf-8');
    fs.writeFileSync(path.join(srcDir, 'scanner.ts'), 'export const x = 1;', 'utf-8');

    const withoutIgnore = getFilesToScan(root);
    expect(withoutIgnore.map(f => path.basename(f))).toContain('scanner.test.ts');

    const withIgnore = getFilesToScan(root, false, undefined, ['**/__tests__/**']);
    expect(withIgnore.map(f => path.basename(f))).not.toContain('scanner.test.ts');
    expect(withIgnore.map(f => path.basename(f))).toContain('scanner.ts');
  });
});
