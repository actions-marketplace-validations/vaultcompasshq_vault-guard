import path from 'path';
import { formatJson, formatSarif, type FileScanResult } from '../../scan-output';
import { fingerprintForMatch } from '../../match-fingerprint';
import type { SecretMatch } from '../../types';
import type { Diagnostic } from '../../diagnostics';

function makeMatch(over: Partial<SecretMatch> = {}): SecretMatch {
  return {
    type: 'anthropic',
    value: 'sk-a…(37c)',
    line: 4,
    column: 12,
    offset: 112,
    matchLength: 37,
    severity: 'critical',
    ...over,
  };
}

describe('scan-output formatters', () => {
  describe('relative path normalization', () => {
    const cwd = '/repo/project';
    const insideFile = '/repo/project/src/leak.ts';
    const outsideFile = '/somewhere/else/leak.ts';

    it('formatJson rewrites absolute paths inside cwd as relative', () => {
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const out = JSON.parse(formatJson(results, { cwd }));
      expect(out.results[0].file).toBe(path.join('src', 'leak.ts'));
    });

    it('formatJson preserves paths that are outside cwd (no .. traversal)', () => {
      const results: FileScanResult[] = [{ file: outsideFile, matches: [makeMatch()] }];
      const out = JSON.parse(formatJson(results, { cwd }));
      expect(out.results[0].file).toBe(outsideFile);
    });

    it('formatSarif rewrites absolute paths inside cwd as relative', () => {
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      // SARIF uris are always forward-slash, unlike formatJson's platform-native
      // `file` field (asserted with path.join two tests up) -- literal, not
      // path.join, so this stays correct under path.win32 (src\leak.ts) too.
      expect(uri).toBe('src/leak.ts');
    });

    it('formatSarif keeps the uri cwd-relative when the scan root is nested inside cwd', () => {
      // Regression: a scan root narrower than cwd must not become %SRCROOT%.
      // GitHub Code Scanning resolves %SRCROOT% from its own knowledge of the
      // checkout (== cwd here), so a uri relative to a subdirectory would
      // name a different file under that root.
      const results: FileScanResult[] = [
        { file: '/repo/a/src/leak.ts', matches: [makeMatch()] },
      ];
      const sarif = JSON.parse(formatSarif(results, { cwd: '/repo', scanRoot: '/repo/a' }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe('a/src/leak.ts');
    });

    it('formatSarif relativizes a file outside cwd but inside the scan root', () => {
      // `vault-guard scan /repo/other` run from /repo/project: the finding is
      // outside cwd, so relativizing against cwd would have to keep it absolute
      // and leak the local filesystem layout into a Code Scanning upload.
      const results: FileScanResult[] = [
        { file: '/repo/other/src/leak.ts', matches: [makeMatch()] },
      ];
      const sarif = JSON.parse(formatSarif(results, { cwd, scanRoot: '/repo/other' }));
      const loc = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
      expect(loc.uri).toBe('src/leak.ts');
      expect(loc.uriBaseId).toBe('%SRCROOT%');
    });

    it('formatSarif resolves a relative target outside cwd to a uri relative to that target', () => {
      // Regression: `vault-guard scan ../b` run from /repo/a used to return
      // the relative file value verbatim ("../b/src/leak.ts"), a literal `..`
      // traversal in the uri. Non-absolute inputs must be resolved against
      // cwd first, then relativized against the (outside-cwd) scan root.
      const results: FileScanResult[] = [{ file: '../b/src/leak.ts', matches: [makeMatch()] }];
      const sarif = JSON.parse(
        formatSarif(results, { cwd: '/repo/a', scanRoot: '/repo/b' }),
      );
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe('src/leak.ts');
    });

    it('formatSarif resolves a relative in-tree target to the cwd-relative uri', () => {
      const results: FileScanResult[] = [{ file: 'a/src/leak.ts', matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd: '/repo' }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe('a/src/leak.ts');
    });

    it('formatSarif preserves paths that are outside the scan root itself', () => {
      // Weaker version of this test used a file outside BOTH cwd and
      // scanRoot, which would also pass if the function relativized against
      // cwd and ignored scanRoot entirely. insideFile is outside scanRoot but
      // inside cwd, so this only passes if scanRoot -- not cwd -- is the base
      // actually being checked against.
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd, scanRoot: '/repo/other' }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe(insideFile);
    });

    it('formatSarif falls back to cwd as the base when no scan root is given', () => {
      // Weaker version of this test used outsideFile, which stays absolute
      // and so would also pass if the fallback were literally
      // process.cwd() (the real vault-guard checkout, unrelated to `cwd`
      // here) rather than the actual opts.cwd value. insideFile only comes
      // back relative if the fallback is genuinely `cwd`.
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe('src/leak.ts');
    });

    it('formatJson ignores the scan root and stays relative to cwd', () => {
      const results: FileScanResult[] = [
        { file: '/repo/other/src/leak.ts', matches: [makeMatch()] },
      ];
      const out = JSON.parse(formatJson(results, { cwd, scanRoot: '/repo/other' }));
      expect(out.results[0].file).toBe('/repo/other/src/leak.ts');
    });

    it('formatSarif emits a forward-slash relative uri with no leading ./ or /', () => {
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe('src/leak.ts');
      expect(uri).not.toMatch(/^\.\//);
      expect(uri).not.toMatch(/^\//);
      expect(uri).not.toContain('\\');
    });

    it('formatSarif keeps uriBaseId as %SRCROOT% alongside the relative uri', () => {
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const loc = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
      expect(loc.uriBaseId).toBe('%SRCROOT%');
    });

    it('formatSarif normalizes a Windows-style absolute input path to a forward-slash relative uri', () => {
      const winCwd = 'C:\\repo\\project';
      const winFile = 'C:\\repo\\project\\src\\leak.ts';
      const results: FileScanResult[] = [{ file: winFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd: winCwd }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe('src/leak.ts');
    });
  });

  describe('SARIF partialFingerprints', () => {
    it('carries the same fingerprint value the JSON output emits, keyed vault-guard/v1', () => {
      const cwd = '/repo/project';
      const file = '/repo/project/src/leak.ts';
      const match = makeMatch();
      const results: FileScanResult[] = [{ file, matches: [match] }];

      const jsonOut = JSON.parse(formatJson(results, { cwd }));
      const expectedFingerprint = jsonOut.results[0].matches[0].fingerprint as string;

      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const partialFingerprints = sarif.runs[0].results[0].partialFingerprints;
      expect(partialFingerprints).toBeDefined();
      expect(partialFingerprints['vault-guard/v1']).toBe(expectedFingerprint);
      expect(partialFingerprints['vault-guard/v1']).toBe(fingerprintForMatch(cwd, file, match));
    });
  });

  describe('value redaction in formatter output', () => {
    it('SARIF message does not contain the masked value at all', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ value: 'sk-a…(37c)' })] }];
      const sarif = formatSarif(results, { cwd: null });
      expect(sarif).not.toContain('masked:');
      expect(sarif).not.toContain('sk-a…(37c)');
    });

    it('JSON output exposes only the redacted value field', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ value: 'sk-a…(37c)' })] }];
      const out = JSON.parse(formatJson(results, { cwd: null }));
      expect(out.results[0].matches[0].value).toBe('sk-a…(37c)');
      expect(JSON.stringify(out)).not.toContain('verylongkeyhere');
    });

    it('JSON matches include a 64-char sha256 fingerprint', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch()] }];
      const out = JSON.parse(formatJson(results, { cwd: null }));
      const fp = out.results[0].matches[0].fingerprint as string;
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    it('formatJson includes line-relative column and absolute offset', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ column: 7, offset: 207 })] }];
      const out = JSON.parse(formatJson(results, { cwd: null }));
      expect(out.results[0].matches[0].column).toBe(7);
      expect(out.results[0].matches[0].offset).toBe(207);
    });

    it('formatSarif embeds run metadata under runs[0].properties when opts.run is set', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch()] }];
      const sarif = JSON.parse(
        formatSarif(results, {
          cwd: null,
          run: {
            duration_ms: 12,
            files_scanned: 3,
            bytes_scanned: 99,
            patterns_active: 40,
          },
        }),
      );
      expect(sarif.runs[0].properties.vault_guard_run.patterns_active).toBe(40);
      expect(sarif.runs[0].properties.vault_guard_run.bytes_scanned).toBe(99);
    });

    it('formatSarif emits inline_suppressed in vault_guard_run, even at zero', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch()] }];
      const sarif = JSON.parse(
        formatSarif(results, {
          cwd: null,
          run: {
            duration_ms: 12,
            files_scanned: 3,
            bytes_scanned: 99,
            patterns_active: 40,
            inline_suppressed: 0,
          },
        }),
      );
      expect(sarif.runs[0].properties.vault_guard_run.inline_suppressed).toBe(0);
    });

    it('formatSarif uses line-relative columns for regions', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ column: 12, offset: 212 })] }];
      const sarif = JSON.parse(formatSarif(results, { cwd: null }));
      const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;
      expect(region.startLine).toBe(4);
      expect(region.startColumn).toBe(13);
      expect(region.endColumn).toBe(50);
    });
  });

  describe('diagnostic ctx in SARIF notifications', () => {
    it('does not leak the scan base through ctx path fields or detail text', () => {
      // Diagnostics render into tool.driver.notifications via
      // JSON.stringify(d.ctx). fs.permission_denied and file.read_error carry
      // an absolute dir/path plus a `detail` field that is String(error),
      // which for a Node fs error embeds that same absolute path inside its
      // own message text (e.g. "EACCES: permission denied, scandir '...'").
      // Both must get the same treatment as artifactLocation.uri.
      const diagnostics: Diagnostic[] = [
        {
          code: 'fs.permission_denied',
          severity: 'warning',
          ctx: {
            dir: '/repo/other/locked',
            detail: "Error: EACCES: permission denied, scandir '/repo/other/locked'",
          },
        },
      ];
      const sarif = formatSarif([], { cwd: '/repo/project', scanRoot: '/repo/other', diagnostics });
      expect(sarif).not.toContain('/repo/other');
    });

    it('relativizes a ctx path field the same way artifactLocation.uri is relativized', () => {
      const diagnostics: Diagnostic[] = [
        {
          code: 'fs.permission_denied',
          severity: 'warning',
          ctx: { dir: '/repo/other/locked' },
        },
      ];
      const sarif = JSON.parse(
        formatSarif([], { cwd: '/repo/project', scanRoot: '/repo/other', diagnostics }),
      );
      const notification = sarif.runs[0].tool.driver.notifications[0];
      expect(notification.message.text).toContain('locked');
      expect(notification.message.text).not.toContain('/repo/other');
    });
  });
});
