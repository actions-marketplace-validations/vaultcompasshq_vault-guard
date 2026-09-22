/**
 * Shared helpers for proxy integration tests.
 *
 * Each test file that uses these helpers must call `jest.mock('https')`
 * at the module level (Jest hoists it before imports, ensuring proxy.ts
 * gets the mocked version when it requires 'https').
 *
 * Usage in a test file:
 *   jest.mock('https');
 *   import * as https from 'https';
 *   // Then call setupUpstreamMock(https, { ... }) inside each test.
 */
import * as http from 'http';
import { EventEmitter } from 'events';
import { Readable } from 'stream';
import os from 'os';
import path from 'path';
import fs from 'fs';

// ---------------------------------------------------------------------------
// Upstream mock factory
// ---------------------------------------------------------------------------

export interface MockUpstreamOptions {
  statusCode?: number;
  contentType?: string;
  body?: Buffer | string;
  /** Milliseconds before the response body is emitted (simulate slow upstream). */
  delayMs?: number;
  /** If true, never emit 'end' -- simulate a hung upstream. */
  hang?: boolean;
}

interface MockClientRequest extends EventEmitter {
  write: jest.Mock<boolean, [chunk?: unknown, encoding?: BufferEncoding, cb?: () => void]>;
  end: jest.Mock<void, [chunk?: unknown, encoding?: BufferEncoding, cb?: () => void]>;
}

/**
 * Configure the already-mocked `https` module to behave as a specific upstream.
 *
 * @param mockHttps   The `https` module, which must have been replaced by
 *                    `jest.mock('https')` before this file was imported.
 * @param opts        Upstream response options.
 * @returns           Arrays of captured request options and headers, populated
 *                    on each upstream call.
 */
export function setupUpstreamMock(
  mockHttps: { request: jest.Mock },
  opts: MockUpstreamOptions = {},
): {
  capturedOpts: http.RequestOptions[];
  capturedHeaders: Record<string, string | string[] | undefined>[];
} {
  const capturedOpts: http.RequestOptions[] = [];
  const capturedHeaders: Record<string, string | string[] | undefined>[] = [];

  const {
    statusCode = 200,
    contentType = 'application/json',
    body = Buffer.from('{}'),
    delayMs = 0,
    hang = false,
  } = opts;

  const bodyBuf = typeof body === 'string' ? Buffer.from(body) : body;

  mockHttps.request.mockImplementation(
    (reqOpts: http.RequestOptions, callback?: (res: http.IncomingMessage) => void) => {
      capturedOpts.push(reqOpts);
      capturedHeaders.push(
        (reqOpts.headers ?? {}) as Record<string, string | string[] | undefined>,
      );

      const mockReq = new EventEmitter() as MockClientRequest;
      mockReq.write = jest.fn(() => true);
      mockReq.end = jest.fn(() => {
        if (!callback) return;

        const res = Object.assign(new Readable({ read() {} }), {
          statusCode,
          headers: { 'content-type': contentType } as Record<string, string>,
        }) as http.IncomingMessage;

        if (hang) {
          callback(res);
          return;
        }

        callback(res);

        const emit = () => {
          res.push(bodyBuf);
          res.push(null);
        };

        if (delayMs > 0) {
          setTimeout(emit, delayMs);
        } else {
          process.nextTick(emit);
        }
      });

      return mockReq;
    },
  );

  return { capturedOpts, capturedHeaders };
}

// ---------------------------------------------------------------------------
// HTTP client helper
// ---------------------------------------------------------------------------

export interface RequestResult {
  status: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}

/** Make a POST request to the local proxy (not the upstream). */
export function postToProxy(
  port: number,
  urlPath: string,
  body: string | object,
  extraHeaders: Record<string, string> = {},
): Promise<RequestResult> {
  const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
  const bodyBuf = Buffer.from(bodyStr);

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(bodyBuf.length),
          ...extraHeaders,
        },
      },
      res => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
            headers: res.headers,
          });
        });
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.write(bodyBuf);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Temp DB helpers -- each test suite gets a fresh isolated DB path
// ---------------------------------------------------------------------------

/** Create a fresh temp dir and return a sqlite path inside it. */
export function makeTmpDbPath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-proxy-test-'));
  return path.join(dir, 'test.sqlite');
}
