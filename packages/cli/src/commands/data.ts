import * as fs from 'fs';
import * as readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import {
  TelemetryStore,
  getDefaultDbPath,
  getDbSidecarPaths,
  type DataStatusJson,
} from '@vaultcompass/vault-guard-telemetry';



/**
 * Options for {@link dataStatusCommand}.
 *
 * `dbPath` overrides the default `~/.vault-guard/usage.sqlite` location and
 * exists primarily for tests. Production callers should leave it undefined.
 */
export interface DataStatusOptions {
  json?: boolean;
  dbPath?: string;
}

/**
 * Options for {@link dataResetCommand}.
 *
 * - `yes` skips the interactive `y/N` prompt. Required for non-interactive
 *   contexts (CI, scripts).
 * - `dryRun` reports what would be deleted without touching the filesystem.
 * - `confirmFn` is a test seam -- when omitted the command reads from stdin.
 */
export interface DataResetOptions {
  yes?: boolean;
  dryRun?: boolean;
  json?: boolean;
  dbPath?: string;
  confirmFn?: () => Promise<boolean>;
}

/**
 * Options for {@link dataExportCommand}. `output` is the destination path
 * (a file; `-` is not currently supported -- keeps the implementation honest
 * about file permissions and atomic writes).
 */
export interface DataExportOptions {
  output: string;
  format?: 'json' | 'jsonl';
  dbPath?: string;
}

/**
 * Print a privacy-respecting summary of the local telemetry database.
 *
 * Prefers JSON when `options.json` is true. Returns the process exit code.
 * Returns 2 (not 1) when telemetry is unavailable so callers can distinguish
 * "expected degradation" from "real failure".
 */
export async function dataStatusCommand(options: DataStatusOptions = {}): Promise<number> {
  const dbPath = options.dbPath ?? getDefaultDbPath();
  const asJson = Boolean(options.json);

  const store = new TelemetryStore(dbPath);
  try {
    // TelemetryStore never throws; `data status` is specifically a telemetry
    // diagnostic, so unlike scan/statusline/MCP (which just get zeroed
    // no-op results) it keeps reporting "unavailable" explicitly via exit
    // code 2 rather than silently showing an all-zero status that would be
    // indistinguishable from "genuinely no usage yet".
    if (!store.isAvailable()) {
      const message = store.getUnavailableReason() ?? 'better-sqlite3 native bindings unavailable.';
      const payload = { error: 'telemetry_unavailable', message, db_path: dbPath };
      if (asJson) {
        process.stdout.write(`${JSON.stringify(payload)}\n`);
      } else {
        process.stderr.write(
          `vault-guard data status: telemetry unavailable -- ${message}\n` +
            `expected db path: ${dbPath}\n`,
        );
      }
      return 2;
    }

    const status: DataStatusJson = store.getDataStatus(dbPath);
    if (asJson) {
      process.stdout.write(`${JSON.stringify(status)}\n`);
      return 0;
    }

    printStatusHuman(status);
    return 0;
  } finally {
    store.close();
  }
}

function printStatusHuman(s: DataStatusJson): void {
  const sizeKb = (s.db_size_bytes / 1024).toFixed(1);
  const lines: string[] = [
    'Vault Guard local telemetry status',
    '',
    `  db path           : ${s.db_path}`,
    `  db exists         : ${s.db_exists ? 'yes' : 'no'}`,
    `  db size           : ${sizeKb} KB`,
    `  last write        : ${s.last_write_iso ?? ' -- '}`,
    `  usage events      : ${s.usage_events}`,
    `  session events    : ${s.session_events}`,
    `  earliest event    : ${s.earliest_event_iso ?? ' -- '}`,
    `  latest event      : ${s.latest_event_iso ?? ' -- '}`,
    `  distinct cwd      : ${s.distinct_cwd_count} (count only -- values redacted; see docs/PRIVACY.md)`,
    `  distinct models   : ${s.distinct_model_count}`,
    `  last model        : ${s.last_model ?? ' -- '}`,
  ];
  if (s.sidecars.length > 0) {
    lines.push('  sidecar files     :');
    for (const side of s.sidecars) {
      lines.push(`    - ${side.path} (${side.size_bytes} B)`);
    }
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}

/**
 * Delete `~/.vault-guard/usage.sqlite` and its WAL/SHM/journal sidecars.
 *
 * Safety:
 *   - Interactive `y/N` prompt unless `--yes`. Refuses to proceed when
 *     stdin is not a TTY and `--yes` was not passed (prevents accidental
 *     pipe-driven nukes in CI).
 *   - `--dry-run` prints the plan without touching the filesystem.
 *   - Only deletes the four expected files; never `rm -rf`s the directory.
 *
 * Returns the process exit code.
 */
export async function dataResetCommand(options: DataResetOptions = {}): Promise<number> {
  const dbPath = options.dbPath ?? getDefaultDbPath();
  const asJson = Boolean(options.json);
  const dryRun = Boolean(options.dryRun);

  const candidates = [dbPath, ...getDbSidecarPaths(dbPath)];
  const existing = candidates.filter(p => {
    try {
      fs.statSync(p);
      return true;
    } catch {
      return false;
    }
  });

  if (existing.length === 0) {
    const payload = {
      action: 'reset',
      removed: [],
      dry_run: dryRun,
      message: 'No telemetry files to delete.',
      db_path: dbPath,
    };
    if (asJson) {
      process.stdout.write(`${JSON.stringify(payload)}\n`);
    } else {
      process.stdout.write(
        `vault-guard data reset: nothing to delete (no telemetry files at ${dbPath}).\n`,
      );
    }
    return 0;
  }

  // Confirmation gate. Order matters: --yes wins, then dry-run is treated as
  // implicitly confirmed (no destructive side effect), otherwise prompt.
  if (!options.yes && !dryRun) {
    const confirmed = await confirmReset(options.confirmFn, existing);
    if (!confirmed) {
      const payload = {
        action: 'reset',
        removed: [],
        dry_run: false,
        cancelled: true,
        db_path: dbPath,
      };
      if (asJson) {
        process.stdout.write(`${JSON.stringify(payload)}\n`);
      } else {
        process.stdout.write('vault-guard data reset: cancelled.\n');
      }
      return 0;
    }
  }

  const removed: string[] = [];
  const errors: Array<{ path: string; message: string }> = [];

  for (const p of existing) {
    if (dryRun) {
      removed.push(p);
      continue;
    }
    try {
      fs.unlinkSync(p);
      removed.push(p);
    } catch (e) {
      errors.push({
        path: p,
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  const payload = {
    action: 'reset',
    removed,
    errors,
    dry_run: dryRun,
    db_path: dbPath,
  };

  if (asJson) {
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  } else {
    const verb = dryRun ? 'would delete' : 'deleted';
    process.stdout.write(`vault-guard data reset: ${verb} ${removed.length} file(s):\n`);
    for (const p of removed) process.stdout.write(`  - ${p}\n`);
    if (errors.length > 0) {
      process.stderr.write(`vault-guard data reset: ${errors.length} error(s):\n`);
      for (const err of errors) {
        process.stderr.write(`  - ${err.path}: ${err.message}\n`);
      }
    }
  }

  return errors.length > 0 ? 1 : 0;
}

async function confirmReset(
  confirmFn: (() => Promise<boolean>) | undefined,
  files: readonly string[],
): Promise<boolean> {
  if (confirmFn) {
    return confirmFn();
  }
  // Refuse to silently proceed in non-interactive contexts. The user can pass
  // --yes if that's actually what they want.
  if (!input.isTTY) {
    process.stderr.write(
      'vault-guard data reset: stdin is not a TTY. Re-run with --yes to confirm non-interactively.\n',
    );
    return false;
  }
  process.stdout.write('About to delete the following files:\n');
  for (const p of files) process.stdout.write(`  - ${p}\n`);
  const rl = readline.createInterface({ input, output });
  try {
    const answer = await rl.question('Continue? [y/N] ');
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

/**
 * Export the raw contents of `usage_events` and `session_events` to a file.
 *
 * **Privacy note:** unlike `data status`, the export includes the `cwd`
 * column as persisted (64-char **HMAC-SHA256** digests -- not plaintext paths).
 * The user explicitly chose the output path; nothing is transmitted off-device.
 *
 * Returns the process exit code.
 */
export async function dataExportCommand(options: DataExportOptions): Promise<number> {
  const dbPath = options.dbPath ?? getDefaultDbPath();
  const format = options.format ?? 'json';

  const store = new TelemetryStore(dbPath);
  try {
    // See dataStatusCommand: `data export` is a telemetry diagnostic, so it
    // keeps reporting "unavailable" explicitly rather than silently writing
    // an empty export file.
    if (!store.isAvailable()) {
      const message = store.getUnavailableReason() ?? 'better-sqlite3 native bindings unavailable.';
      process.stderr.write(`vault-guard data export: telemetry unavailable -- ${message}\n`);
      return 2;
    }

    const usage = store.exportUsageEvents();
    const sessions = store.exportSessionEvents();

    if (format === 'jsonl') {
      const lines: string[] = [];
      for (const r of usage) lines.push(JSON.stringify({ table: 'usage_events', ...r }));
      for (const r of sessions) lines.push(JSON.stringify({ table: 'session_events', ...r }));
      // 0o600 mode: export contains raw paths/cwd; restrict to the user.
      fs.writeFileSync(options.output, `${lines.join('\n')}\n`, { mode: 0o600 });
    } else {
      const payload = {
        exported_at: new Date().toISOString(),
        db_path: dbPath,
        usage_events: usage,
        session_events: sessions,
      };
      fs.writeFileSync(options.output, `${JSON.stringify(payload, null, 2)}\n`, {
        mode: 0o600,
      });
    }

    process.stdout.write(
      `vault-guard data export: wrote ${usage.length} usage row(s) and ${sessions.length} session row(s) to ${options.output}\n`,
    );
    return 0;
  } finally {
    store.close();
  }
}
