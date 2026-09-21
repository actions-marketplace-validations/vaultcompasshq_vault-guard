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

/** Avoid racing shutdown before the proxy has accepted the POST (inflight > 0). */
async function waitForUpstreamInvoked(timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (mockHttps.request.mock.calls.length === 0) {
    if (Date.now() - start > timeoutMs) {
      throw new Error('timed out waiting for upstream https.request');
    }
    await new Promise(r => setTimeout(r, 10));
  }
}

describe('proxy lifecycle -- shutdown()', () => {
  // -------------------------------------------------------------------------
  // Fast path: no inflight requests
  // -------------------------------------------------------------------------

  it('resolves within 1 s when there are no inflight requests', async () => {
    setupUpstreamMock(mockHttps);
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    expect(handle.server.listening).toBe(true);

    const start = Date.now();
    await handle.shutdown('TEST');
    const elapsed = Date.now() - start;

    expect(handle.server.listening).toBe(false);
    expect(elapsed).toBeLessThan(1000);
  });

  // -------------------------------------------------------------------------
  // Drain an inflight request
  // -------------------------------------------------------------------------

  it('waits for an inflight request to complete before resolving', async () => {
    setupUpstreamMock(mockHttps, {
      body: JSON.stringify({ model: 'claude-3', usage: { input_tokens: 1, output_tokens: 1 } }),
      delayMs: 300,
    });

    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    const requestPromise = postToProxy(
      port,
      '/v1/messages',
      { model: 'claude-3' },
      { 'x-api-key': 'k' },
    );

    await waitForUpstreamInvoked();
    const shutdownPromise = handle.shutdown('TEST');

    const [result] = await Promise.all([requestPromise, shutdownPromise]);
    expect(result.status).toBe(200);
    expect(handle.server.listening).toBe(false);
  }, 10_000);

  // -------------------------------------------------------------------------
  // Force-close after grace window
  // -------------------------------------------------------------------------

  it('force-closes connections after the grace window for hung upstream', async () => {
    setupUpstreamMock(mockHttps, { hang: true });

    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    // Fire a request that will never complete
    const requestPromise = postToProxy(
      port,
      '/v1/messages',
      { model: 'claude-3' },
      { 'x-api-key': 'k' },
    ).catch(() => null);

    await waitForUpstreamInvoked();

    const start = Date.now();
    await handle.shutdown('TEST');
    const elapsed = Date.now() - start;

    // grace is 5000ms; allow generous slack for coverage / slow CI runners
    expect(elapsed).toBeLessThan(20_000);
    expect(handle.server.listening).toBe(false);

    await requestPromise;
  }, 35_000);

  // -------------------------------------------------------------------------
  // closeAndCheckpoint on the telemetry store
  // -------------------------------------------------------------------------

  it('calls closeAndCheckpoint on the telemetry store during shutdown', async () => {
    setupUpstreamMock(mockHttps);
    const checkpointSpy = jest.spyOn(TelemetryStore.prototype, 'closeAndCheckpoint');

    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    await handle.shutdown('TEST');

    expect(checkpointSpy).toHaveBeenCalledTimes(1);
    checkpointSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // Idempotent
  // -------------------------------------------------------------------------

  it('is idempotent -- calling shutdown() twice has the same side-effects as once', async () => {
    setupUpstreamMock(mockHttps);
    const checkpointSpy = jest.spyOn(TelemetryStore.prototype, 'closeAndCheckpoint');

    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    await Promise.all([handle.shutdown('A'), handle.shutdown('B')]);

    expect(checkpointSpy).toHaveBeenCalledTimes(1);
    expect(handle.server.listening).toBe(false);
    checkpointSpy.mockRestore();
  });
});
