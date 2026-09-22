import fs from 'fs';
import { createReadStream } from 'fs';
import * as readline from 'readline';

import type { DiagnosticBus } from '../diagnostics';
import { SecretScanner } from '../scanners/secret-scanner';
import { applyPathAwareSeverity } from './path-severity';
import type { SecretMatch } from '../types';

const DEFAULT_MAX_LINE_UTF16 = 1024 * 1024;

export interface ScanTextFileOptions {
  maxFileBytes: number;
  /** Skip scanning lines longer than this (UTF-16 code units, same as `String#length`). */
  maxLineUtf16Units?: number;
  bus?: DiagnosticBus;
}

/**
 * Read `filePath` as UTF-8 and run {@link SecretScanner.scanContent}.
 *
 * Files larger than `maxFileBytes` are scanned **line-by-line** so the
 * process does not load the entire file into memory. Multi-line secrets
 * (e.g. PEM blocks split across lines) may be missed in that mode -- the
 * trade-off is intentional for very large text files.
 *
 * Line breaks are normalised to a single trailing `\n` per line for the
 * scanner (same as {@link readline}).
 */
export async function scanTextFileAsync(
  scanner: SecretScanner,
  filePath: string,
  options: ScanTextFileOptions,
): Promise<SecretMatch[]> {
  const maxLine = options.maxLineUtf16Units ?? DEFAULT_MAX_LINE_UTF16;
  const st = await fs.promises.stat(filePath);
  if (st.size <= options.maxFileBytes) {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    return applyPathAwareSeverity(scanner.scanContent(content, { filePath }), filePath);
  }

  const raw: SecretMatch[] = [];
  let utf16Offset = 0;
  let lineNo = 0;

  const rl = readline.createInterface({
    input: createReadStream(filePath, { encoding: 'utf-8' }),
    crlfDelay: Infinity,
  });

  try {
    for await (const line of rl) {
      lineNo++;
      if (line.length > maxLine) {
        options.bus?.add({
          code: 'file.line_too_long',
          severity: 'warning',
          ctx: {
            file: filePath,
            line: lineNo,
            units: line.length,
            max_units: maxLine,
          },
        });
        utf16Offset += line.length + 1;
        continue;
      }

      const slice = `${line}\n`;
      const found = scanner.scanContent(slice).map(m => ({
        ...m,
        line: lineNo,
        offset: utf16Offset + m.offset,
      }));
      raw.push(...found);
      utf16Offset += line.length + 1;
    }
  } finally {
    rl.close();
  }

  return applyPathAwareSeverity(scanner.mergeChunkedMatches(raw), filePath);
}

/**
 * Synchronous variant of {@link scanTextFileAsync}. For files larger than
 * `maxFileBytes` this path **does not** stream (it would block on a full read
 * or require a heavy incremental decoder); callers receive an empty match list
 * and should prefer the async API for large files.
 */
export function scanTextFileSync(
  scanner: SecretScanner,
  filePath: string,
  options: ScanTextFileOptions,
): SecretMatch[] {
  const st = fs.statSync(filePath);
  if (st.size <= options.maxFileBytes) {
    return applyPathAwareSeverity(
      scanner.scanContent(fs.readFileSync(filePath, 'utf-8'), { filePath }),
      filePath,
    );
  }
  options.bus?.add({
    code: 'file.too_large',
    severity: 'warning',
    ctx: {
      file: filePath,
      bytes: st.size,
      note: 'sync_scan_requires_async_for_streaming',
    },
  });
  return [];
}
