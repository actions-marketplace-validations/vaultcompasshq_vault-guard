import * as http from 'http';
import * as https from 'https';
import path from 'path';
import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';
import { parseAnthropicSseUsage } from './proxy-sse';

/**
 * Bound inbound request buffering. 32 MB is a generous ceiling for
 * Anthropic-shaped JSON bodies (multi-megabyte system prompts, large
 * conversation histories) without enabling trivial OOM amplification.
 */
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;

/**
 * Hard cap on the in-memory **tee** of the upstream response body, used only
 * for usage-token parsing on non-streaming responses. The wire response is
 * piped to the client independently and is **not** bounded here -- backpressure
 * is handled by the OS pipe.
 *
 * If a response exceeds this cap before `end`, we abandon the tee (the user
 * still gets their full response) and record a `proxy-tee-overflow` telemetry
 * row so the operator can see usage data is missing for that request.
 */
const MAX_TEE_BYTES = 1 * 1024 * 1024;

/**
 * Grace period for inflight requests during shutdown. After this, any
 * lingering connections are force-closed via `server.closeAllConnections()`
 * (Node ≥ 18.2).
 */
const SHUTDOWN_GRACE_MS = 5_000;

export interface ProxyOptions {
  /**
   * Bind address in `host:port` form, e.g. `127.0.0.1:8765`.
   *
   * @remarks
   * Use loopback hosts unless you explicitly want LAN exposure.
   */
  listen: string;

  /**
   * If true, requests with no `x-api-key` header fall back to the
   * `ANTHROPIC_API_KEY` env var on the proxy host.
   *
   * **Security:** Default is `false`. Without this flag any local process
   * that can connect to the proxy (other CLIs, browser fetch from a phishing
   * page, malicious npm postinstall) could spend the operator's Anthropic
   * budget. With it enabled, you accept that risk in exchange for being able
   * to point existing tools at the proxy without rewriting their auth.
   */
  allowEnvFallback?: boolean;

  /**
   * If true, the proxy is allowed to bind a non-loopback address
   * (anything other than `127.0.0.1`, `localhost`, `::1`, `::ffff:127.0.0.1`).
   *
   * **Security:** Default is `false`. Binding `0.0.0.0` or a LAN IP exposes
   * the proxy to anyone reachable on the network -- combined with the
   * env-fallback path above, this is a credit-card-draining footgun. Refuse
   * by default and require explicit opt-in.
   */
  allowPublic?: boolean;

  /**
   * Optional cap on forwarded requests per rolling 60-second window (per process).
   * When exceeded, the proxy responds with HTTP 429 until the window slides.
   */
  maxRpm?: number;
}

/**
 * Returned from `proxyCommand` so the caller (cli.ts) can register signal
 * handlers and unit tests can drive a clean shutdown without sending real
 * signals.
 */
export interface ProxyHandle {
  /** Active HTTP server instance backing the proxy. */
  server: http.Server;
  /** Telemetry store used for usage event recording. */
  store: TelemetryStore;
  /**
   * Cleanly stop accepting connections, drain inflight, and checkpoint DB.
   *
   * @param reason - Optional shutdown cause for stderr logs.
   */
  shutdown(reason?: string): Promise<void>;
}

/**
 * Minimal opt-in Anthropic forwarder: POST /v1/messages → api.anthropic.com.
 *
 * - Authentication: requires `x-api-key` from the caller. Falls back to
 *   `ANTHROPIC_API_KEY` only when `allowEnvFallback === true`.
 * - Bind: refuses non-loopback addresses unless `allowPublic === true`.
 * - Streaming requests: forwarded byte-for-byte; usage logged with token
 *   counts of 0 (real SSE usage parsing is a Phase 8 follow-up).
 * - Non-streaming requests: response is **piped** to the client immediately
 *   and **teed** (capped at 1 MB) for `usage` parsing into local SQLite.
 *   The tee never blocks the wire; on overflow it is silently abandoned.
 */
export async function proxyCommand(opts: ProxyOptions | string): Promise<ProxyHandle> {
  // Backwards-compatible call shape: previous signature accepted a bare
  // `listen` string. Tests and external callers may still pass that.
  const options: ProxyOptions = typeof opts === 'string' ? { listen: opts } : opts;

  const [host, portStr] = parseListen(options.listen);
  const port = Number(portStr);
  if (!Number.isFinite(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid port in --listen "${options.listen}"`);
  }

  if (!isLoopbackHost(host) && options.allowPublic !== true) {
    throw new Error(
      `Refusing to bind non-loopback address "${host}". This would expose the proxy ` +
        `to anyone reachable on the network. Re-run with --allow-public to override ` +
        `(see SECURITY.md → "vault-guard proxy" before doing so).`,
    );
  }

  const store = new TelemetryStore();
  const takeRateSlot = createRollingMinuteLimiter(options.maxRpm);

  // Track inflight requests so shutdown() can drain them before force-closing.
  let inflightCount = 0;
  let drainResolve: (() => void) | null = null;

  const server = http.createServer((req, res) => {
    inflightCount++;
    let settled = false;
    const onDone = () => {
      if (settled) return;
      settled = true;
      inflightCount--;
      if (inflightCount === 0 && drainResolve) {
        drainResolve();
        drainResolve = null;
      }
    };
    res.on('finish', onDone);
    res.on('close', onDone);

    handleRequest(req, res, store, options, takeRateSlot).catch(err => {
      // Defence-in-depth: surface unexpected handler errors as 502 rather than
      // crashing the server. The handler should not throw on its own; if it
      // does, that's a bug we want to know about (logged) but not one that
      // takes down the proxy for other inflight requests.
      try {
        if (!res.headersSent) {
          res.statusCode = 502;
          res.setHeader('content-type', 'text/plain; charset=utf-8');
        }
      } catch {
        /* response may already be torn down */
      }
      try {
        res.end(`vault-guard proxy: handler error: ${String(err)}`);
      } catch {
        /* same */
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(port, host, () => resolve());
    server.on('error', reject);
  });

  const telemetryAvailable = store.isAvailable();
  process.stderr.write(
    `vault-guard proxy listening on http://${host}:${port}\n` +
      `Forward Anthropic traffic here (e.g. ANTHROPIC_BASE_URL=http://${host}:${port}).` +
      (telemetryAvailable
        ? ` Non-stream JSON responses log usage to ${path.join('~', '.vault-guard', 'usage.sqlite')}.\n`
        : '\n'),
  );
  if (!telemetryAvailable) {
    // Telemetry degrades silently to a no-op store when better-sqlite3 is
    // unavailable (packages/telemetry/src/store.ts); the banner above must
    // not claim usage is being logged when it is not. One notice, matching
    // the MCP server's wording style (see server.ts's getTelemetry()).
    process.stderr.write(
      `vault-guard proxy: telemetry unavailable, usage will NOT be recorded: ${
        store.getUnavailableReason() ?? 'better-sqlite3 native bindings unavailable.'
      }\n`,
    );
  }
  if (options.allowEnvFallback) {
    process.stderr.write(
      `⚠️  --allow-env-fallback is active: requests without x-api-key will use ` +
        `ANTHROPIC_API_KEY from the proxy host's environment.\n`,
    );
  }

  let shuttingDown = false;
  const shutdown = async (reason?: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    if (reason) {
      process.stderr.write(`\nvault-guard proxy: ${reason} received, shutting down...\n`);
    }

    // Stop accepting new connections immediately.
    server.close();

    // Wait for inflight requests to drain, up to the grace window.
    await new Promise<void>(resolve => {
      if (inflightCount === 0) {
        resolve();
        return;
      }
      drainResolve = resolve;
      setTimeout(() => {
        drainResolve = null;
        // Force-close any connections still open after the grace window.
        const closer = (server as unknown as { closeAllConnections?: () => void }).closeAllConnections;
        if (typeof closer === 'function') closer.call(server);
        resolve();
      }, SHUTDOWN_GRACE_MS).unref();
    });

    try {
      store.closeAndCheckpoint();
    } catch {
      /* best-effort */
    }
  };

  return { server, store, shutdown };
}

function createRollingMinuteLimiter(maxRpm: number | undefined): () => boolean {
  if (maxRpm === undefined || !Number.isFinite(maxRpm) || maxRpm < 1) {
    return () => true;
  }
  const cap = Math.floor(maxRpm);
  const windowMs = 60_000;
  const stamps: number[] = [];
  return (): boolean => {
    const now = Date.now();
    while (stamps.length > 0) {
      const head = stamps[0];
      if (head === undefined || now - head < windowMs) break;
      stamps.shift();
    }
    if (stamps.length >= cap) return false;
    stamps.push(now);
    return true;
  };
}

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  store: TelemetryStore,
  options: ProxyOptions,
  takeRateSlot: () => boolean,
): Promise<void> {
  const u = req.url ?? '/';
  if (req.method !== 'POST' || !u.startsWith('/v1/messages')) {
    res.statusCode = 404;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.end(
      'vault-guard proxy (MVP): only POST /v1/messages is forwarded to https://api.anthropic.com\n',
    );
    return;
  }

  if (!takeRateSlot()) {
    res.statusCode = 429;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(
      JSON.stringify({
        error: 'rate_limited',
        message: `Exceeded --max-rpm (${options.maxRpm}) for the rolling 60s window`,
      }),
    );
    return;
  }

  const bodyBuf = await readRequestBody(req, res);
  if (bodyBuf === null) return; // 413 already sent

  let bodyJson: { stream?: boolean; model?: string } = {};
  try {
    bodyJson = JSON.parse(bodyBuf.toString('utf8')) as typeof bodyJson;
  } catch {
    /* forward raw body; some Anthropic endpoints accept non-JSON bodies */
  }

  // ----- Authentication ----------------------------------------------------
  // Caller-provided x-api-key always wins. Env fallback is opt-in.
  const callerKey =
    typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'] : undefined;
  let apiKey = callerKey;
  if (!apiKey && options.allowEnvFallback) {
    apiKey = process.env.ANTHROPIC_API_KEY ?? undefined;
  }
  if (!apiKey) {
    res.statusCode = 401;
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        error: 'missing_api_key',
        message: options.allowEnvFallback
          ? 'send x-api-key, or set ANTHROPIC_API_KEY in the proxy host environment'
          : 'send x-api-key, or restart proxy with --allow-env-fallback to use ANTHROPIC_API_KEY',
      }),
    );
    return;
  }

  const anthropicVersion =
    (typeof req.headers['anthropic-version'] === 'string'
      ? req.headers['anthropic-version']
      : undefined) ?? '2023-06-01';

  const cwd = process.cwd();
  const upstreamOpts: https.RequestOptions = {
    hostname: 'api.anthropic.com',
    port: 443,
    path: u.startsWith('/') ? u : `/${u}`,
    method: 'POST',
    headers: {
      'content-type': (req.headers['content-type'] as string) ?? 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': anthropicVersion,
      'content-length': String(bodyBuf.length),
    },
  };

  await new Promise<void>(resolve => {
    const preq = https.request(upstreamOpts, pres => {
      const stream = Boolean(bodyJson.stream);
      const headers = { ...pres.headers };
      res.writeHead(pres.statusCode ?? 502, headers);

      if (stream) {
        // Pipe to client immediately (bounded by the OS pipe, not us). Tee a
        // bounded copy purely to parse SSE usage events after the stream ends.
        // On tee overflow the client still receives the full stream; we record
        // a distinct source so missing usage is visible in telemetry.
        pres.pipe(res);

        const teeChunks: Buffer[] = [];
        let teeLen = 0;
        let teeAbandoned = false;

        pres.on('data', chunk => {
          if (teeAbandoned) return;
          const b = chunk as Buffer;
          teeLen += b.length;
          if (teeLen > MAX_TEE_BYTES) {
            teeAbandoned = true;
            teeChunks.length = 0;
            return;
          }
          teeChunks.push(b);
        });

        pres.on('end', () => {
          const model = typeof bodyJson.model === 'string' ? bodyJson.model : null;
          if (teeAbandoned) {
            store.recordUsage({
              provider: 'anthropic',
              model,
              cwd,
              inputTokens: 0,
              outputTokens: 0,
              source: 'proxy-stream-overflow',
            });
            resolve();
            return;
          }
          const usage = parseAnthropicSseUsage(
            Buffer.concat(teeChunks).toString('utf8'),
            model,
          );
          store.recordUsage({
            provider: 'anthropic',
            model: usage.model,
            cwd,
            inputTokens: usage.inputTokens,
            outputTokens: usage.outputTokens,
            source: 'proxy-stream',
          });
          resolve();
        });

        pres.on('error', () => resolve());
        return;
      }

      // ----- Non-streaming path ------------------------------------------
      // Pipe upstream -> client immediately so memory use is bounded by the
      // OS pipe, not by us. Tee a *separate* PassThrough for usage parsing,
      // capped at MAX_TEE_BYTES. If the tee overflows, drop it: the wire
      // pipe is not affected.
      const isJsonResponse =
        typeof pres.headers['content-type'] === 'string' &&
        pres.headers['content-type'].includes('application/json');

      pres.pipe(res);

      if (!isJsonResponse) {
        // Non-JSON response (e.g. error HTML) -- no usage to extract.
        pres.on('end', () => {
          store.recordUsage({
            provider: 'anthropic',
            model: typeof bodyJson.model === 'string' ? bodyJson.model : null,
            cwd,
            inputTokens: 0,
            outputTokens: 0,
            source: 'proxy-non-json',
          });
          resolve();
        });
        pres.on('error', () => resolve());
        return;
      }

      const teeChunks: Buffer[] = [];
      let teeLen = 0;
      let teeAbandoned = false;

      pres.on('data', chunk => {
        if (teeAbandoned) return;
        const b = chunk as Buffer;
        teeLen += b.length;
        if (teeLen > MAX_TEE_BYTES) {
          teeAbandoned = true;
          // Drop accumulated chunks so we release the memory immediately.
          teeChunks.length = 0;
          return;
        }
        teeChunks.push(b);
      });

      pres.on('end', () => {
        if (teeAbandoned) {
          store.recordUsage({
            provider: 'anthropic',
            model: typeof bodyJson.model === 'string' ? bodyJson.model : null,
            cwd,
            inputTokens: 0,
            outputTokens: 0,
            source: 'proxy-tee-overflow',
          });
          resolve();
          return;
        }
        try {
          const raw = Buffer.concat(teeChunks);
          const parsed = JSON.parse(raw.toString('utf8')) as {
            model?: string;
            usage?: { input_tokens?: number; output_tokens?: number };
          };
          const input = parsed.usage?.input_tokens ?? 0;
          const output = parsed.usage?.output_tokens ?? 0;
          const model = parsed.model ?? (typeof bodyJson.model === 'string' ? bodyJson.model : null);
          store.recordUsage({
            provider: 'anthropic',
            model,
            cwd,
            inputTokens: input,
            outputTokens: output,
            source: 'proxy',
          });
        } catch {
          store.recordUsage({
            provider: 'anthropic',
            model: typeof bodyJson.model === 'string' ? bodyJson.model : null,
            cwd,
            inputTokens: 0,
            outputTokens: 0,
            source: 'proxy-parse-failed',
          });
        }
        resolve();
      });

      pres.on('error', () => resolve());
    });

    preq.on('error', e => {
      if (!res.headersSent) {
        res.statusCode = 502;
        res.setHeader('content-type', 'text/plain; charset=utf-8');
      }
      try {
        res.end(String(e));
      } catch {
        /* response may already be torn down */
      }
      resolve();
    });

    preq.write(bodyBuf);
    preq.end();
  });
}

/**
 * Read the inbound request body up to `MAX_REQUEST_BYTES`. Returns `null` if
 * the cap was exceeded (a 413 has already been written to `res`).
 */
function readRequestBody(
  req: http.IncomingMessage,
  res: http.ServerResponse,
): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;
    let aborted = false;

    req.on('data', c => {
      if (aborted) return;
      const b = c as Buffer;
      received += b.length;
      if (received > MAX_REQUEST_BYTES) {
        aborted = true;
        res.statusCode = 413;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ error: 'payload_too_large', max_bytes: MAX_REQUEST_BYTES }));
        // Drain the remaining body bytes so the connection isn't torn down
        // abruptly before the client receives the 413 response.
        req.resume();
        resolve(null);
        return;
      }
      chunks.push(b);
    });
    req.on('end', () => {
      if (aborted) return;
      resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

function parseListen(listen: string): [string, string] {
  const m = /^(.*):(\d+)$/.exec(listen.trim());
  if (!m) {
    throw new Error(`Invalid --listen "${listen}" (expected host:port, e.g. 127.0.0.1:8765)`);
  }
  return [m[1], m[2]];
}

/**
 * Loopback host detector. Recognises:
 *   - `127.0.0.1`, `localhost`
 *   - `::1`, `[::1]`
 *   - `::ffff:127.0.0.1` (IPv4-mapped IPv6 loopback -- Linux/macOS dual-stack
 *     sockets sometimes report this)
 *
 * Anything else (including `0.0.0.0`, `::`, the empty string, LAN IPs) is
 * treated as non-loopback and refused unless `--allow-public` is set.
 */
function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().trim();
  return (
    h === '127.0.0.1' ||
    h === 'localhost' ||
    h === '::1' ||
    h === '[::1]' ||
    h === '::ffff:127.0.0.1' ||
    h === '[::ffff:127.0.0.1]'
  );
}
