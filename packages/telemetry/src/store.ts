import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { createHmac, randomBytes } from 'crypto';
import { TokenCounter } from '@vaultcompass/vault-guard-core';

// Lazy native-binding loader uses createRequire so that:
// (a) the native binding is not loaded at module import time (saves startup
//     cost and allows graceful degradation on platforms without pre-built binaries)
// (b) @typescript-eslint/no-require-imports is not violated
const _require = createRequire(__filename);

// ---------------------------------------------------------------------------
// TelemetryUnavailableError
// ---------------------------------------------------------------------------

/**
 * Thrown internally when `better-sqlite3` native bindings are missing or
 * incompatible. This happens when:
 *   - The package was installed with `--ignore-scripts` (skips node-gyp compile)
 *   - The Node.js ABI changed after install (e.g. nvm version switch)
 *   - The pre-built binary is missing for the current platform/arch (e.g. a
 *     Windows install where node-gyp could not find a Visual Studio toolchain)
 *
 * {@link TelemetryStore} catches this internally and degrades to a no-op
 * store rather than letting it escape the constructor. See "Graceful
 * degradation" below. It stays exported for callers that want to distinguish
 * this failure mode from a genuine bug when they inject their own loader
 * (tests, or a factory such as the MCP server's `telemetryFactory`).
 */
export class TelemetryUnavailableError extends Error {
  constructor(cause: unknown) {
    const msg =
      `better-sqlite3 native bindings could not be loaded.\n` +
      `Re-install to rebuild them: npm install -g @vaultcompass/vault-guard\n` +
      `Underlying error: ${String(cause)}`;
    super(msg);
    this.name = 'TelemetryUnavailableError';
  }
}

// ---------------------------------------------------------------------------
// Once-per-process "unavailable" notice
// ---------------------------------------------------------------------------

let hasNotedUnavailable = false;

/**
 * Graceful degradation, in one place: when the native binding can't load,
 * every {@link TelemetryStore} entry point (record*, get*, export*) becomes a
 * safe no-op instead of throwing. This function logs that fact **at most
 * once per process**, and only when `VG_DEBUG=1` is set. Telemetry is
 * opt-in local tooling, so a missing native binding must never print a
 * warning on every command (`statusline` in particular can be invoked by an
 * editor every few seconds).
 */
function noteTelemetryUnavailable(cause: unknown): void {
  if (hasNotedUnavailable) return;
  hasNotedUnavailable = true;
  if (process.env.VG_DEBUG === '1') {
    process.stderr.write(
      `vault-guard telemetry: native bindings unavailable, recording nothing this run: ${String(cause)}\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// Lazy DB loader
// ---------------------------------------------------------------------------

type DatabaseType = import('better-sqlite3').Database;
type DatabaseConstructor = typeof import('better-sqlite3');

let _DbClass: DatabaseConstructor | null = null;

function getDbClass(): DatabaseConstructor {
  if (_DbClass) return _DbClass;
  try {
    // Dynamic import to defer native binding load until first use.
    // We need synchronous access here (TelemetryStore constructor is sync),
    // so we use createRequire from the module system rather than top-level await.
    const mod = _require('better-sqlite3') as DatabaseConstructor;
    _DbClass = mod;
    return _DbClass;
  } catch (err) {
    throw new TelemetryUnavailableError(err);
  }
}

export interface UsageRecordInput {
  createdAt?: Date;
  provider?: 'anthropic' | 'openai' | 'unknown';
  model?: string | null;
  cwd?: string | null;
  inputTokens: number;
  outputTokens: number;
  estCostUsd?: number;
  source?: string | null;
}

export interface SessionRecordInput {
  createdAt?: Date;
  eventType: string;
  model?: string | null;
  cwd?: string | null;
  language?: string | null;
  linesAccepted?: number;
  linesSuggested?: number;
  linesReverted?: number;
  extra?: Record<string, unknown>;
}

export interface StatuslineJson {
  secrets_today: number;
  tokens_today_input: number;
  tokens_today_output: number;
  est_cost_usd: number;
  model: string | null;
  window_start_utc: string;
}

export interface ModelSuggestion {
  suggested_model: string | null;
  reason: string;
  by_model: Array<{
    model: string;
    usage_events: number;
    revert_rate: number | null;
    avg_cost_usd: number;
  }>;
}

function defaultDbPath(): string {
  const dir = path.join(os.homedir(), '.vault-guard');
  return path.join(dir, 'usage.sqlite');
}

/** 64-char lowercase hex = SHA-256 digest written to the `cwd` column. */
const HASHED_CWD_RE = /^[a-f0-9]{64}$/;

function telemetrySaltPath(): string {
  return path.join(os.homedir(), '.vault-guard', 'salt');
}

/**
 * Per-machine random salt (32 bytes, hex-encoded on disk, mode `0600`).
 * Used only to hash `cwd` before persistence -- not a secret, but treated as
 * private local state alongside `usage.sqlite`.
 */
export function getOrCreateTelemetrySalt(): Buffer {
  const p = telemetrySaltPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  if (fs.existsSync(p)) {
    const hex = fs.readFileSync(p, 'utf8').trim();
    if (/^[a-f0-9]{64}$/i.test(hex)) {
      return Buffer.from(hex, 'hex');
    }
  }
  const b = randomBytes(32);
  fs.writeFileSync(p, b.toString('hex'), { mode: 0o600 });
  return b;
}

function hashCwdForStore(plain: string | null | undefined, salt: Buffer): string | null {
  if (plain == null || plain === '') return null;
  return createHmac('sha256', salt).update(plain, 'utf8').digest('hex');
}

function isStoredCwdDigest(v: string | null): boolean {
  return v != null && v !== '' && HASHED_CWD_RE.test(v);
}

/**
 * Default **90** days. Set `VG_TELEMETRY_RETENTION_DAYS=0` to disable automatic
 * deletion (database still grows unbounded).
 */
export function getTelemetryRetentionDays(): number {
  const raw = process.env.VG_TELEMETRY_RETENTION_DAYS;
  if (raw === undefined || raw === '') return 90;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(n, 3650);
}

const MIN_MS_BETWEEN_RETENTION_PURGES = 3600 * 1000;

function retentionThrottleMs(): number {
  if (process.env.VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE === '1') return 0;
  return MIN_MS_BETWEEN_RETENTION_PURGES;
}

/**
 * Resolve the default `~/.vault-guard/usage.sqlite` path without instantiating
 * a {@link TelemetryStore}. Useful for `vault-guard data reset` which needs
 * the path even when telemetry native bindings are unavailable.
 */
export function getDefaultDbPath(): string {
  return defaultDbPath();
}

/**
 * SQLite WAL mode produces two sidecar files alongside the main DB. They must
 * be deleted as a set during `vault-guard data reset`, otherwise the next
 * reader recovers stale rows from the WAL.
 */
export function getDbSidecarPaths(dbPath: string): readonly string[] {
  return [`${dbPath}-wal`, `${dbPath}-shm`, `${dbPath}-journal`];
}

/**
 * Raw row shape for the `usage_events` table. Returned by
 * {@link TelemetryStore.exportUsageEvents}. The `cwd` column stores a
 * **64-char hex HMAC-SHA256** of the original path (see `docs/PRIVACY.md`), not
 * the plaintext working directory.
 */
export interface UsageEventRow {
  id: number;
  created_at: string;
  provider: string | null;
  model: string | null;
  cwd: string | null;
  input_tokens: number;
  output_tokens: number;
  est_cost_usd: number;
  source: string | null;
}

/**
 * Raw row shape for the `session_events` table. Returned by
 * {@link TelemetryStore.exportSessionEvents}. The `cwd` column is an HMAC digest
 * (same scheme as {@link UsageEventRow}); `extra_json` is stored as provided.
 */
export interface SessionEventRow {
  id: number;
  created_at: string;
  event_type: string;
  model: string | null;
  cwd: string | null;
  language: string | null;
  lines_accepted: number | null;
  lines_suggested: number | null;
  lines_reverted: number | null;
  extra_json: string | null;
}

/**
 * Privacy-respecting summary of `~/.vault-guard/usage.sqlite`.
 *
 * **What this intentionally does NOT expose:** raw `cwd` strings (which
 * include OS username and project names -- see `docs/PRIVACY.md`),
 * `extra_json` payloads, model prompts, or token totals (those are already
 * available via `vault-guard statusline --json`).
 *
 * Only counts and aggregates land here, so the JSON output is safe to paste
 * into a support ticket or screenshot.
 */
export interface DataStatusJson {
  /** Absolute path to the SQLite database file. */
  db_path: string;
  /** True if the database file exists on disk. */
  db_exists: boolean;
  /** File size in bytes (0 when `db_exists` is false). */
  db_size_bytes: number;
  /** Last write time of the database file as ISO timestamp, or null. */
  last_write_iso: string | null;
  /** Sidecar files (WAL, SHM, journal) that exist alongside the main DB. */
  sidecars: Array<{ path: string; size_bytes: number }>;
  /** Row count in `usage_events`. */
  usage_events: number;
  /** Row count in `session_events`. */
  session_events: number;
  /** Earliest `created_at` across both tables (ISO), or null when empty. */
  earliest_event_iso: string | null;
  /** Latest `created_at` across both tables (ISO), or null when empty. */
  latest_event_iso: string | null;
  /** Distinct non-null `cwd` values across both tables (count only -- never the values). */
  distinct_cwd_count: number;
  /** Distinct non-null `model` values across both tables (count only). */
  distinct_model_count: number;
  /** Most recently observed model name, or null when no usage rows exist. */
  last_model: string | null;
}

function utcDayStart(d = new Date()): string {
  return d.toISOString().slice(0, 10);
}

export class TelemetryStore {
  private readonly db: DatabaseType | null;
  private readonly counter = new TokenCounter();
  private readonly saltBuf: Buffer | null;
  private readonly available: boolean;
  private readonly unavailableMessage: string | null;
  private lastRetentionPurgeMs = 0;

  /**
   * @param dbPath Defaults to `~/.vault-guard/usage.sqlite`.
   *
   * Never throws, even when `better-sqlite3` native bindings are missing or
   * incompatible: in that case the store degrades to a no-op (see
   * {@link isAvailable}) instead of raising {@link TelemetryUnavailableError}.
   */
  constructor(dbPath?: string) {
    const resolved = dbPath ?? defaultDbPath();
    let db: DatabaseType | null = null;
    let salt: Buffer | null = null;
    let unavailableMessage: string | null = null;

    try {
      const DbCtor = getDbClass(); // throws TelemetryUnavailableError if bindings missing.
      const dir = path.dirname(resolved);
      fs.mkdirSync(dir, { recursive: true });
      salt = getOrCreateTelemetrySalt();
      const opened = new DbCtor(resolved);
      opened.pragma('journal_mode = WAL');
      db = opened;
    } catch (err) {
      db = null;
      salt = null;
      unavailableMessage = new TelemetryUnavailableError(err).message;
      noteTelemetryUnavailable(err);
    }

    this.db = db;
    this.saltBuf = salt;
    this.available = db !== null;
    this.unavailableMessage = unavailableMessage;

    if (this.db) {
      this.initSchema();
      this.applyTelemetryMigrations();
      this.maybePurgeStaleRows();
    }
  }

  /** True when `better-sqlite3` loaded and this store is backed by a real DB. */
  isAvailable(): boolean {
    return this.available;
  }

  /**
   * Human-readable reason telemetry is unavailable, or `null` when
   * {@link isAvailable} is true. Lets callers that are specifically about
   * inspecting telemetry (`vault-guard data status`, `data export`) report
   * "unavailable" explicitly rather than silently show all-zero results.
   */
  getUnavailableReason(): string | null {
    return this.unavailableMessage;
  }

  /**
   * Non-null accessor for the handful of private methods that only ever run
   * from inside `if (this.db)` (constructor init) or after an
   * `isAvailable`/`this.db` guard in a public method. Never reachable while
   * degraded; exists so those method bodies don't each repeat the guard.
   */
  private requireDb(): DatabaseType {
    if (!this.db) {
      throw new Error('vault-guard telemetry: internal invariant violated (db unavailable)');
    }
    return this.db;
  }

  /** Same invariant as {@link requireDb}: only ever reached while available, where saltBuf is always set alongside db. */
  private requireSalt(): Buffer {
    if (!this.saltBuf) {
      throw new Error('vault-guard telemetry: internal invariant violated (salt unavailable)');
    }
    return this.saltBuf;
  }

  /**
   * One-time migration (pragma `user_version` &lt; 2): replace plaintext `cwd`
   * values with HMAC-SHA256 hex digests using the current salt file.
   */
  private applyTelemetryMigrations(): void {
    const db = this.requireDb();
    const ver = Number(db.pragma('user_version', { simple: true }));
    if (ver >= 2) return;

    const salt = this.requireSalt();
    const uRows = db
      .prepare(`SELECT id, cwd FROM usage_events WHERE cwd IS NOT NULL AND cwd != ''`)
      .all() as Array<{ id: number; cwd: string }>;
    const uUpd = db.prepare(`UPDATE usage_events SET cwd = ? WHERE id = ?`);
    for (const r of uRows) {
      if (isStoredCwdDigest(r.cwd)) continue;
      uUpd.run(hashCwdForStore(r.cwd, salt), r.id);
    }

    const sRows = db
      .prepare(`SELECT id, cwd FROM session_events WHERE cwd IS NOT NULL AND cwd != ''`)
      .all() as Array<{ id: number; cwd: string }>;
    const sUpd = db.prepare(`UPDATE session_events SET cwd = ? WHERE id = ?`);
    for (const r of sRows) {
      if (isStoredCwdDigest(r.cwd)) continue;
      sUpd.run(hashCwdForStore(r.cwd, salt), r.id);
    }

    db.pragma('user_version = 2');
  }

  /**
   * Delete rows older than {@link getTelemetryRetentionDays}. Throttled to at
   * most once per hour per process to avoid hammering SQLite on hot paths.
   * No-op when the store is unavailable.
   */
  private maybePurgeStaleRows(): void {
    if (!this.db) return;
    const days = getTelemetryRetentionDays();
    if (days <= 0) return;

    const now = Date.now();
    if (now - this.lastRetentionPurgeMs < retentionThrottleMs()) return;
    this.lastRetentionPurgeMs = now;

    const cutoff = new Date(Date.now() - days * 86400000).toISOString();
    this.db.prepare(`DELETE FROM usage_events WHERE created_at < ?`).run(cutoff);
    this.db.prepare(`DELETE FROM session_events WHERE created_at < ?`).run(cutoff);
  }

  private initSchema(): void {
    const db = this.requireDb();
    db.exec(`
      CREATE TABLE IF NOT EXISTS usage_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        provider TEXT,
        model TEXT,
        cwd TEXT,
        input_tokens INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        est_cost_usd REAL NOT NULL DEFAULT 0,
        source TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_events(created_at);

      CREATE TABLE IF NOT EXISTS session_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        model TEXT,
        cwd TEXT,
        language TEXT,
        lines_accepted INTEGER,
        lines_suggested INTEGER,
        lines_reverted INTEGER,
        extra_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_session_created ON session_events(created_at);
      CREATE INDEX IF NOT EXISTS idx_session_type ON session_events(event_type);
    `);
  }

  /** No-op when the store is unavailable: there is no handle to close. */
  close(): void {
    this.db?.close();
  }

  /**
   * Force a WAL checkpoint (TRUNCATE) and close the database.
   *
   * Why: in WAL mode the main DB file lags behind the `-wal` sidecar until a
   * checkpoint runs. If the process is killed (SIGINT/SIGTERM during proxy
   * shutdown) without checkpointing, recent rows live only in the WAL and
   * survive only as long as that file does. TRUNCATE both checkpoints and
   * shrinks the WAL to zero so the next reader sees an up-to-date main file
   * with no recovery surprises.
   *
   * Best-effort: if the pragma fails (e.g. handle already closed by another
   * shutdown path) we still attempt to close the underlying handle. No-op
   * when the store is unavailable.
   */
  closeAndCheckpoint(): void {
    if (!this.db) return;
    try {
      this.db.pragma('wal_checkpoint(TRUNCATE)');
    } catch {
      // Handle may already be in a shutting-down state; safe to ignore.
    }
    try {
      this.db.close();
    } catch {
      // Best-effort: nothing useful we can do on shutdown if close throws.
    }
  }

  /** No-op (records nothing) when the store is unavailable. */
  recordUsage(input: UsageRecordInput): void {
    if (!this.db) return;
    this.maybePurgeStaleRows();
    const created = (input.createdAt ?? new Date()).toISOString();
    let cost = input.estCostUsd;
    if (cost === undefined) {
      const p = input.provider ?? 'anthropic';
      if (p === 'anthropic' || p === 'openai') {
        cost = this.counter.calculateCost(p, input.inputTokens, input.outputTokens);
      } else {
        cost = 0;
      }
    }
    const stmt = this.db.prepare(`
      INSERT INTO usage_events (created_at, provider, model, cwd, input_tokens, output_tokens, est_cost_usd, source)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      created,
      input.provider ?? 'unknown',
      input.model ?? null,
      hashCwdForStore(input.cwd, this.requireSalt()),
      input.inputTokens,
      input.outputTokens,
      cost,
      input.source ?? null,
    );
  }

  /** No-op (records nothing) when the store is unavailable. */
  recordSession(input: SessionRecordInput): void {
    if (!this.db) return;
    this.maybePurgeStaleRows();
    const created = (input.createdAt ?? new Date()).toISOString();
    const extra =
      input.extra && Object.keys(input.extra).length > 0 ? JSON.stringify(input.extra) : null;
    const stmt = this.db.prepare(`
      INSERT INTO session_events (
        created_at, event_type, model, cwd, language,
        lines_accepted, lines_suggested, lines_reverted, extra_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      created,
      input.eventType,
      input.model ?? null,
      hashCwdForStore(input.cwd, this.requireSalt()),
      input.language ?? null,
      input.linesAccepted ?? null,
      input.linesSuggested ?? null,
      input.linesReverted ?? null,
      extra,
    );
  }

  /** Count session events that represent blocked secrets today (UTC date). Returns 0 when unavailable. */
  secretsBlockedToday(day = utcDayStart()): number {
    if (!this.db) return 0;
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM session_events
         WHERE event_type = 'secret_blocked' AND substr(created_at, 1, 10) = ?`,
      )
      .get(day) as { c: number };
    return row.c;
  }

  /** Returns a zeroed payload (never throws) when the store is unavailable. */
  getStatuslinePayload(now = new Date()): StatuslineJson {
    const day = utcDayStart(now);
    const windowStart = `${day}T00:00:00.000Z`;

    if (!this.db) {
      return {
        secrets_today: 0,
        tokens_today_input: 0,
        tokens_today_output: 0,
        est_cost_usd: 0,
        model: null,
        window_start_utc: windowStart,
      };
    }

    const usage = this.db
      .prepare(
        `SELECT
           COALESCE(SUM(input_tokens), 0) AS tin,
           COALESCE(SUM(output_tokens), 0) AS tout,
           COALESCE(SUM(est_cost_usd), 0) AS cost
         FROM usage_events
         WHERE substr(created_at, 1, 10) = ?`,
      )
      .get(day) as { tin: number; tout: number; cost: number };

    const lastModel = this.db
      .prepare(
        `SELECT model FROM usage_events
         WHERE substr(created_at, 1, 10) = ? AND model IS NOT NULL AND model != ''
         ORDER BY created_at DESC LIMIT 1`,
      )
      .get(day) as { model: string } | undefined;

    return {
      secrets_today: this.secretsBlockedToday(day),
      tokens_today_input: usage.tin,
      tokens_today_output: usage.tout,
      est_cost_usd: Math.round(usage.cost * 10_000) / 10_000,
      model: lastModel?.model ?? null,
      window_start_utc: windowStart,
    };
  }

  /**
   * Heuristic model hint from the last 7 days of session + usage data.
   * Prefer models with more usage and lower revert_rate when session metrics exist.
   * Returns an empty suggestion (never throws) when the store is unavailable.
   */
  suggestModel(opts: { cwd?: string; language?: string } = {}): ModelSuggestion {
    if (!this.db) {
      return {
        suggested_model: null,
        reason: 'Telemetry is unavailable (better-sqlite3 native bindings not installed); no suggestion.',
        by_model: [],
      };
    }

    const since = new Date();
    since.setUTCDate(since.getUTCDate() - 7);
    const sinceIso = since.toISOString();

    const usageByModel = this.db
      .prepare(
        `SELECT model AS m,
                COUNT(*) AS n,
                AVG(est_cost_usd) AS avg_cost
         FROM usage_events
         WHERE created_at >= ? AND model IS NOT NULL AND model != ''
         GROUP BY model`,
      )
      .all(sinceIso) as Array<{ m: string; n: number; avg_cost: number }>;

    const revertRows = this.db
      .prepare(
        `SELECT model AS m,
                SUM(COALESCE(lines_reverted, 0)) AS rev,
                SUM(COALESCE(lines_suggested, 0)) AS sug
         FROM session_events
         WHERE created_at >= ?
           AND event_type IN ('apply', 'completion', 'revert')
           AND model IS NOT NULL AND model != ''
         GROUP BY model`,
      )
      .all(sinceIso) as Array<{ m: string; rev: number; sug: number }>;

    const revertMap = new Map<string, { rev: number; sug: number }>();
    for (const r of revertRows) {
      revertMap.set(r.m, { rev: r.rev, sug: r.sug });
    }

    const by_model = usageByModel.map(u => {
      const rr = revertMap.get(u.m);
      let revert_rate: number | null = null;
      if (rr && rr.sug > 0) {
        revert_rate = rr.rev / rr.sug;
      }
      return {
        model: u.m,
        usage_events: u.n,
        revert_rate,
        avg_cost_usd: Math.round((u.avg_cost ?? 0) * 10_000) / 10_000,
      };
    });

    if (by_model.length === 0) {
      return {
        suggested_model: null,
        reason: 'No recent usage with a model label. Use the proxy or MCP report_token_usage first.',
        by_model: [],
      };
    }

    by_model.sort((a, b) => {
      const ar = a.revert_rate ?? 0.5;
      const br = b.revert_rate ?? 0.5;
      if (ar !== br) return ar - br;
      return b.usage_events - a.usage_events;
    });

    const best = by_model[0];
    let reason = `Lowest observed revert pressure among recent models (${best.usage_events} logged usage row(s)).`;
    if (opts.language) reason += ` Context: language=${opts.language}.`;
    if (opts.cwd) reason += ` cwd hint recorded.`;

    return {
      suggested_model: best.model,
      reason,
      by_model,
    };
  }

  /**
   * Read all rows from `usage_events` ordered by `id ASC`.
   *
   * Intended for `vault-guard data export`. Returns raw `cwd` strings -- see
   * {@link DataStatusJson} for the privacy-respecting alternative. Returns an
   * empty array (never throws) when the store is unavailable.
   */
  exportUsageEvents(): UsageEventRow[] {
    if (!this.db) return [];
    return this.db
      .prepare(
        `SELECT id, created_at, provider, model, cwd, input_tokens, output_tokens, est_cost_usd, source
         FROM usage_events ORDER BY id ASC`,
      )
      .all() as UsageEventRow[];
  }

  /**
   * Read all rows from `session_events` ordered by `id ASC`.
   *
   * Intended for `vault-guard data export`. Returns raw `cwd` strings and
   * the `extra_json` payload as stored. Returns an empty array (never
   * throws) when the store is unavailable.
   */
  exportSessionEvents(): SessionEventRow[] {
    if (!this.db) return [];
    return this.db
      .prepare(
        `SELECT id, created_at, event_type, model, cwd, language,
                lines_accepted, lines_suggested, lines_reverted, extra_json
         FROM session_events ORDER BY id ASC`,
      )
      .all() as SessionEventRow[];
  }

  /**
   * Compute a privacy-respecting summary of the local telemetry database
   * (file location, size, row counts, distinct-value *counts*). Never
   * returns raw `cwd` strings or `extra_json`.
   *
   * Used by `vault-guard data status`. Safe to paste into a support ticket.
   */
  getDataStatus(dbFilePath: string): DataStatusJson {
    let dbExists = false;
    let dbSize = 0;
    let lastWriteIso: string | null = null;

    try {
      const stat = fs.statSync(dbFilePath);
      dbExists = true;
      dbSize = stat.size;
      lastWriteIso = stat.mtime.toISOString();
    } catch {
      // File missing is a valid state -- open() can create it; status reports it.
    }

    const sidecars = getDbSidecarPaths(dbFilePath)
      .map(p => {
        try {
          const s = fs.statSync(p);
          return { path: p, size_bytes: s.size };
        } catch {
          return null;
        }
      })
      .filter((x): x is { path: string; size_bytes: number } => x !== null);

    // File-level facts (db_exists / db_size_bytes / last_write_iso / sidecars)
    // come from fs, not the DB handle, so they stay accurate even when the
    // store is unavailable. Row-level facts default to zero/null below.
    if (!this.db) {
      return {
        db_path: dbFilePath,
        db_exists: dbExists,
        db_size_bytes: dbSize,
        last_write_iso: lastWriteIso,
        sidecars,
        usage_events: 0,
        session_events: 0,
        earliest_event_iso: null,
        latest_event_iso: null,
        distinct_cwd_count: 0,
        distinct_model_count: 0,
        last_model: null,
      };
    }

    // COUNT(*) on indexed tables is cheap; we don't need to bound it.
    const usageEvents = (
      this.db.prepare('SELECT COUNT(*) AS n FROM usage_events').get() as { n: number }
    ).n;
    const sessionEvents = (
      this.db.prepare('SELECT COUNT(*) AS n FROM session_events').get() as { n: number }
    ).n;

    // Earliest / latest across the union of both tables. NULL when both tables
    // are empty, in which case MIN/MAX return NULL on the union.
    const range = this.db
      .prepare(
        `SELECT MIN(created_at) AS earliest, MAX(created_at) AS latest
         FROM (
           SELECT created_at FROM usage_events
           UNION ALL
           SELECT created_at FROM session_events
         )`,
      )
      .get() as { earliest: string | null; latest: string | null };

    const distinctCwd = (
      this.db
        .prepare(
          `SELECT COUNT(DISTINCT cwd) AS n FROM (
             SELECT cwd FROM usage_events WHERE cwd IS NOT NULL AND cwd != ''
             UNION
             SELECT cwd FROM session_events WHERE cwd IS NOT NULL AND cwd != ''
           )`,
        )
        .get() as { n: number }
    ).n;

    const distinctModel = (
      this.db
        .prepare(
          `SELECT COUNT(DISTINCT model) AS n FROM (
             SELECT model FROM usage_events WHERE model IS NOT NULL AND model != ''
             UNION
             SELECT model FROM session_events WHERE model IS NOT NULL AND model != ''
           )`,
        )
        .get() as { n: number }
    ).n;

    const lastModelRow = this.db
      .prepare(
        `SELECT model FROM usage_events
         WHERE model IS NOT NULL AND model != ''
         ORDER BY created_at DESC
         LIMIT 1`,
      )
      .get() as { model: string } | undefined;

    return {
      db_path: dbFilePath,
      db_exists: dbExists,
      db_size_bytes: dbSize,
      last_write_iso: lastWriteIso,
      sidecars,
      usage_events: usageEvents,
      session_events: sessionEvents,
      earliest_event_iso: range.earliest,
      latest_event_iso: range.latest,
      distinct_cwd_count: distinctCwd,
      distinct_model_count: distinctModel,
      last_model: lastModelRow?.model ?? null,
    };
  }
}
