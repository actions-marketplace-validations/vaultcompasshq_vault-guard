import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SecretScanner } from '../scanners/secret-scanner';
import { scanTextFileAsync, scanTextFileSync } from '../utils/scan-file';

function tmp(name: string): string {
  return path.join(os.tmpdir(), `vg-scanfile-${name}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
}

/** Legacy OpenAI key format: sk-<20 alphanum>T3BlbkFJ<20 alphanum> -- matches built-in openai pattern. */
const OPENAI_LIKE = `sk-${'a'.repeat(20)}T3BlbkFJ${'b'.repeat(20)}`;

describe('scanTextFileAsync', () => {
  it('reads small files in one shot', async () => {
    const p = tmp('small');
    const scanner = new SecretScanner();
    fs.writeFileSync(p, `export const k = '${OPENAI_LIKE}'\n`, 'utf-8');
    const matches = await scanTextFileAsync(scanner, p, { maxFileBytes: 1024 });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].line).toBe(1);
  });

  it('streams line-by-line when file exceeds maxFileBytes', async () => {
    const p = tmp('stream');
    const scanner = new SecretScanner();
    const padding = 'x'.repeat(12 * 1024);
    const body = `${padding}\nexport const k = '${OPENAI_LIKE}'\n`;
    fs.writeFileSync(p, body, 'utf-8');
    const st = fs.statSync(p);
    expect(st.size).toBeGreaterThan(10 * 1024);

    const matches = await scanTextFileAsync(scanner, p, { maxFileBytes: 10 * 1024 });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].line).toBe(2);
  });
});

describe('scanTextFileSync', () => {
  it('scans when under maxFileBytes', () => {
    const p = tmp('sync-small');
    const scanner = new SecretScanner();
    fs.writeFileSync(p, `const k = '${OPENAI_LIKE}'\n`, 'utf-8');
    const matches = scanTextFileSync(scanner, p, { maxFileBytes: 1024 });
    expect(matches.length).toBeGreaterThan(0);
  });

  it('returns empty matches for oversized files', () => {
    const p = tmp('sync-big');
    const scanner = new SecretScanner();
    fs.writeFileSync(p, 'y'.repeat(20 * 1024), 'utf-8');
    const matches = scanTextFileSync(scanner, p, { maxFileBytes: 1024 });
    expect(matches).toEqual([]);
  });
});
