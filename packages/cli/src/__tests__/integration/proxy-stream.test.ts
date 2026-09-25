// Must be hoisted before imports so proxy.ts gets the mocked module.
jest.mock('https');

import * as https from 'https';
import { proxyCommand } from '../../commands/proxy';
import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';
import { postToProxy, setupUpstreamMock, makeTmpDbPath } from './proxy-test-helpers';

const DB_PATH = makeTmpDbPath();

jest.mock('@vaultcompass/vault-guard-telemetry', () => {
  const actual = jest.requireActual<typeof import('@vaultcompass/vault-guard-telemetry')>(
    '@vaultcompass/vault-guard-telemetry',
  );
  return {
    ...actual,
    TelemetryStore: class extends actual.TelemetryStore {
      constructor() {
        super(DB_PATH);
      }
    },
  };
});

const mockHttps = https as unknown as { request: jest.Mock };

beforeEach(() => {
  mockHttps.request.mockReset();
});

describe('proxy response streaming + tee behaviour', () => {
  // -------------------------------------------------------------------------
  // Non-streaming JSON -- happy path
  // -------------------------------------------------------------------------

  it('pipes non-streaming JSON response to client and parses usage tokens', async () => {
    const upstreamBody = JSON.stringify({
      model: 'claude-3-opus-20240229',
      usage: { input_tokens: 100, output_tokens: 50 },
    });
    setupUpstreamMock(mockHttps, { statusCode: 200, contentType: 'application/json', body: upstreamBody });

    const recordSpy = jest.spyOn(TelemetryStore.prototype, 'recordUsage');
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3-opus-20240229' },
        { 'x-api-key': 'k' },
      );
      expect(result.status).toBe(200);
      expect(result.body).toBe(upstreamBody);

      // Give the async tee parse a tick to record
      await new Promise(r => setTimeout(r, 50));

      const lastCall = recordSpy.mock.calls.at(-1)?.[0];
      expect(lastCall?.inputTokens).toBe(100);
      expect(lastCall?.outputTokens).toBe(50);
      expect(lastCall?.source).toBe('proxy');
    } finally {
      recordSpy.mockRestore();
      await handle.shutdown('test-cleanup');
    }
  });

  // -------------------------------------------------------------------------
  // Tee overflow -- client still gets the full response
  // -------------------------------------------------------------------------

  it('abandons tee when response exceeds 1 MB but client receives full body', async () => {
    const bigBody = Buffer.alloc(2 * 1024 * 1024, 'x');
    setupUpstreamMock(mockHttps, { statusCode: 200, contentType: 'application/json', body: bigBody });

    const recordSpy = jest.spyOn(TelemetryStore.prototype, 'recordUsage');
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3' },
        { 'x-api-key': 'k' },
      );
      expect(result.status).toBe(200);
      expect(result.body.length).toBe(bigBody.length);

      await new Promise(r => setTimeout(r, 50));

      const lastCall = recordSpy.mock.calls.at(-1)?.[0];
      expect(lastCall?.source).toBe('proxy-tee-overflow');
      expect(lastCall?.inputTokens).toBe(0);
    } finally {
      recordSpy.mockRestore();
      await handle.shutdown('test-cleanup');
    }
  });

  // -------------------------------------------------------------------------
  // Non-JSON upstream response
  // -------------------------------------------------------------------------

  it('handles non-JSON response and records proxy-non-json telemetry', async () => {
    const htmlBody = '<html><body>Bad Gateway</body></html>';
    setupUpstreamMock(mockHttps, {
      statusCode: 502,
      contentType: 'text/html; charset=utf-8',
      body: htmlBody,
    });

    const recordSpy = jest.spyOn(TelemetryStore.prototype, 'recordUsage');
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3' },
        { 'x-api-key': 'k' },
      );
      expect(result.status).toBe(502);
      expect(result.body).toBe(htmlBody);

      await new Promise(r => setTimeout(r, 50));
      const lastCall = recordSpy.mock.calls.at(-1)?.[0];
      expect(lastCall?.source).toBe('proxy-non-json');
    } finally {
      recordSpy.mockRestore();
      await handle.shutdown('test-cleanup');
    }
  });

  // -------------------------------------------------------------------------
  // Streaming SSE response -- parses real usage tokens
  // -------------------------------------------------------------------------

  it('forwards streaming response byte-for-byte and parses input/output tokens', async () => {
    const sseBody =
      'event: message_start\n' +
      'data: {"type":"message_start","message":{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1200,"output_tokens":1}}}\n\n' +
      'event: message_delta\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":350}}\n\n' +
      'event: message_stop\n' +
      'data: {"type":"message_stop"}\n\n';
    setupUpstreamMock(mockHttps, {
      statusCode: 200,
      contentType: 'text/event-stream',
      body: sseBody,
    });

    const recordSpy = jest.spyOn(TelemetryStore.prototype, 'recordUsage');
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3', stream: true },
        { 'x-api-key': 'k' },
      );
      expect(result.status).toBe(200);
      expect(result.body).toBe(sseBody);

      await new Promise(r => setTimeout(r, 50));
      const lastCall = recordSpy.mock.calls.at(-1)?.[0];
      expect(lastCall?.source).toBe('proxy-stream');
      expect(lastCall?.inputTokens).toBe(1200);
      expect(lastCall?.outputTokens).toBe(350);
      expect(lastCall?.model).toBe('claude-3-5-sonnet-20241022');
    } finally {
      recordSpy.mockRestore();
      await handle.shutdown('test-cleanup');
    }
  });

  it('records proxy-stream-overflow when streaming response exceeds tee cap but client gets full body', async () => {
    const bigBody = Buffer.alloc(2 * 1024 * 1024, 'x');
    setupUpstreamMock(mockHttps, {
      statusCode: 200,
      contentType: 'text/event-stream',
      body: bigBody,
    });

    const recordSpy = jest.spyOn(TelemetryStore.prototype, 'recordUsage');
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3', stream: true },
        { 'x-api-key': 'k' },
      );
      expect(result.status).toBe(200);
      expect(result.body.length).toBe(bigBody.length);

      await new Promise(r => setTimeout(r, 50));
      const lastCall = recordSpy.mock.calls.at(-1)?.[0];
      expect(lastCall?.source).toBe('proxy-stream-overflow');
      expect(lastCall?.inputTokens).toBe(0);
    } finally {
      recordSpy.mockRestore();
      await handle.shutdown('test-cleanup');
    }
  });
});
