import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { scanCommand } from '../commands/scan';

/**
 * Synthetic Anthropic-shaped key, joined at runtime. A committed provider-key
 * shape trips credential scanners regardless of the value being fake and the
 * file being a test, so no fragment matches a rule on its own.
 */
const ANTHROPIC_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

/**
 * Regression: staged files must be read from the git index, not the worktree.
 * Otherwise `AD` (added in index, deleted on disk) secrets bypass pre-commit.
 */
describe('scan --staged reads git index', () => {
  let repo: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-staged-scan-'));
    execSync('git init -q', { cwd: repo, stdio: 'ignore' });
    execSync('git config user.email "test@example.com"', { cwd: repo, stdio: 'ignore' });
    execSync('git config user.name "Test"', { cwd: repo, stdio: 'ignore' });
    execSync('git config --local core.hooksPath hooks', { cwd: repo, stdio: 'ignore' });
    process.chdir(repo);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('blocks a staged secret whose worktree file was deleted', async () => {
    fs.writeFileSync(
      'leak.env',
      `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}\n`,
    );
    execSync('git add leak.env', { cwd: repo, stdio: 'ignore' });
    fs.unlinkSync('leak.env');
    fs.writeFileSync('clean.md', '# ok\n');
    execSync('git add clean.md', { cwd: repo, stdio: 'ignore' });

    const code = await scanCommand('.', 'text', true);
    expect(code).toBe(1);
  });

  it('scans the index blob when the worktree was edited after staging', async () => {
    fs.writeFileSync(
      'partial.env',
      `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}\n`,
    );
    execSync('git add partial.env', { cwd: repo, stdio: 'ignore' });
    // Worktree cleaned -- index still has the secret.
    fs.writeFileSync('partial.env', 'CLEAN=1\n');

    const code = await scanCommand('.', 'text', true);
    expect(code).toBe(1);
  });
});
