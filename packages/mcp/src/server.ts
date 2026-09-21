import path from 'path';
import fs from 'fs';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  SecretScanner,
  loadConfig,
  ConfigError,
  TokenCounter,
  formatJson,
  formatSarif,
  type FileScanResult,
  type JsonRunMetadata,
  type VaultGuardConfig,
} from '@vaultcompass/vault-guard-core';
import { TelemetryStore, TelemetryUnavailableError } from '@vaultcompass/vault-guard-telemetry';
import { scanWorkspaceDirectory, MCP_SCAN_BUDGET_MS } from './workspace-scan';

// Injected by esbuild (`define`) at build time from package.json. Falls back
// to a dev sentinel under ts-jest / unbundled execution where it is undefined.
declare const __VG_MCP_VERSION__: string | undefined;
const SERVER_VERSION =
  typeof __VG_MCP_VERSION__ !== 'undefined' ? __VG_MCP_VERSION__ : '0.0.0-dev';

export interface McpServerOptions {
  /**
   * Factory for the telemetry store. Injectable for tests; defaults to a real
   * {@link TelemetryStore}. Telemetry is strictly optional: with
   * `better-sqlite3` native bindings missing (e.g. under `npx` on a machine
   * without them), the real factory's store just reports `isAvailable()
   * === false` rather than throwing, and a test-injected factory may still
   * throw {@link TelemetryUnavailableError} to simulate the same outcome.
   * Either way the scan tools remain fully functional and only
   * `record_session_event` degrades.
   */
  telemetryFactory?: () => TelemetryStore;
  /** Workspace root the MCP server is allowed to read. Defaults to `process.cwd()`. */
  workspaceRoot?: string;
}

/**
 * Build a scanner for the current MCP request.
 *
 * Policy: the MCP server runs as a stdio child of an editor / agent. If the
 * user has a typo in `.vault-guard.json` we must not take the host down  -- 
 * log to stderr (visible in the editor's MCP output channel) and fall back
 * to default config. The CLI surface, by contrast, hard-fails on
 * `ConfigError` because a human is at the terminal to read the message.
 */
function loadMcpConfig(workspaceRoot: string): VaultGuardConfig {
  let cfg: VaultGuardConfig;
  try {
    cfg = loadConfig(workspaceRoot);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(
        `vault-guard MCP: ignoring broken config at ${e.filePath} -- ${e.message}\n`,
      );
      cfg = {};
    } else {
      throw e;
    }
  }
  return cfg;
}

function makeScanner(config: VaultGuardConfig): SecretScanner {
  return new SecretScanner(config);
}

/**
 * Largest input any single scan tool will read into memory. Matches the
 * per-file cap `scanWorkspaceDirectory` already enforces (see
 * `workspace-scan.ts`), so `scan_file` and `scan_text` cannot be pointed at an
 * arbitrarily large blob to exhaust the host process that `scan_workspace`
 * would have streamed within the same bound.
 */
const MAX_SCAN_BYTES = 10 * 1024 * 1024;

function toolPayload(obj: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }],
  };
}

function isPathInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function realpathIfExists(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

function resolveWorkspacePath(
  workspaceRoot: string,
  input: string,
): { ok: true; path: string } | { ok: false; error: 'path_outside_workspace'; path: string } {
  const root = path.resolve(workspaceRoot);
  const requested = path.resolve(root, input);
  if (!isPathInside(root, requested)) {
    return { ok: false, error: 'path_outside_workspace', path: requested };
  }

  const realRoot = realpathIfExists(root);
  const realRequested = realpathIfExists(requested);
  if (!isPathInside(realRoot, realRequested)) {
    return { ok: false, error: 'path_outside_workspace', path: requested };
  }

  return { ok: true, path: requested };
}

function configIgnorePatterns(config: VaultGuardConfig): string[] {
  return [
    ...(config.ignore?.paths ?? []),
    ...(config.ignore?.patterns ?? []),
  ];
}

export function createMcpServer(options: McpServerOptions = {}): McpServer {
  const workspaceRoot = path.resolve(options.workspaceRoot ?? process.cwd());

  const server = new McpServer(
    { name: 'vault-guard', version: SERVER_VERSION },
    {
      capabilities: {
        tools: {},
      },
      instructions:
        'Vault Guard MCP: scan workspaces/files/text for secrets (SARIF-shaped JSON), report token estimates, and record opt-in session/usage events to local ~/.vault-guard/usage.sqlite.',
    },
  );

  // Telemetry is optional and lazily constructed. The scan tools (the primary
  // value of this server) must never be taken down by a missing/incompatible
  // `better-sqlite3` binding: TelemetryStore itself never throws (it degrades
  // to a no-op store; see @vaultcompass/vault-guard-telemetry's store.ts),
  // so `getTelemetry()` treats `!store.isAvailable()` the same way it treats
  // a thrown TelemetryUnavailableError from a test-injected `telemetryFactory`
  // (kept below for that seam, and for any future factory that still throws).
  const telemetryFactory = options.telemetryFactory ?? ((): TelemetryStore => new TelemetryStore());
  let telemetry: TelemetryStore | null = null;
  let telemetryUnavailable = false;

  function getTelemetry(): TelemetryStore | null {
    if (telemetry) return telemetry;
    if (telemetryUnavailable) return null;
    try {
      const store = telemetryFactory();
      // Guard both calls: an injected telemetryFactory (test double, or an
      // older-shaped store from before isAvailable()/getUnavailableReason()
      // existed) may not implement them. Treat that as available rather than
      // letting a TypeError escape record_session_event.
      const isAvailable = typeof store.isAvailable === 'function' ? store.isAvailable() : true;
      if (!isAvailable) {
        telemetryUnavailable = true;
        const reason =
          typeof store.getUnavailableReason === 'function' ? store.getUnavailableReason() : null;
        process.stderr.write(
          `vault-guard MCP: telemetry unavailable; session events will not be recorded: ${reason ?? 'better-sqlite3 native bindings unavailable.'}\n`,
        );
        return null;
      }
      telemetry = store;
      return telemetry;
    } catch (e) {
      if (e instanceof TelemetryUnavailableError) {
        telemetryUnavailable = true;
        process.stderr.write(
          `vault-guard MCP: telemetry unavailable; session events will not be recorded: ${e.message}\n`,
        );
        return null;
      }
      throw e;
    }
  }

  const tokenCounter = new TokenCounter();

  server.registerTool(
    'scan_workspace',
    {
      title: 'Scan workspace directory',
      description:
        'Run the Vault Guard secret scanner on a directory (respects .gitignore). Returns JSON, SARIF string, and summary.',
      inputSchema: {
        root: z.string().optional().describe('Directory to scan (default: process.cwd())'),
      },
    },
    async ({ root }) => {
      const config = loadMcpConfig(workspaceRoot);
      const scanner = makeScanner(config);
      const resolved = resolveWorkspacePath(workspaceRoot, root ?? '.');
      if (!resolved.ok) {
        return toolPayload({ error: resolved.error, path: resolved.path });
      }
      const dir = resolved.path;
      const t0 = Date.now();
      const { results, filesScanned, bytesScanned, overBudget } = await scanWorkspaceDirectory(
        dir,
        scanner,
        10,
        configIgnorePatterns(config),
      );
      const run: JsonRunMetadata = {
        duration_ms: Date.now() - t0,
        files_scanned: filesScanned,
        bytes_scanned: bytesScanned,
        patterns_active: scanner.getActivePatternCount(),
      };
      return toolPayload({
        summary: {
          files_with_secrets: results.length,
          total_matches: results.reduce((n, r) => n + r.matches.length, 0),
          // Post-hoc: these files WERE scanned, but took long enough that the
          // result is not trusted. Surfaced so an agent is not handed a silent
          // "clean" for a file whose scan behaved pathologically.
          ...(overBudget.length > 0 ? { files_over_scan_budget: overBudget.length } : {}),
        },
        ...(overBudget.length > 0 ? { over_budget: overBudget } : {}),
        json: JSON.parse(formatJson(results, { cwd: dir, run })) as unknown,
        sarif: formatSarif(results, { cwd: dir, run }),
        results,
      });
    },
  );

  server.registerTool(
    'scan_file',
    {
      title: 'Scan a single file',
      description: 'Scan one file on disk for secrets. Returns JSON + SARIF.',
      inputSchema: {
        file_path: z.string().describe('Absolute or relative path to a file'),
      },
    },
    async ({ file_path }) => {
      const config = loadMcpConfig(workspaceRoot);
      const scanner = makeScanner(config);
      const resolved = resolveWorkspacePath(workspaceRoot, file_path);
      if (!resolved.ok) {
        return toolPayload({ error: resolved.error, path: resolved.path });
      }
      const fp = resolved.path;
      if (!fs.existsSync(fp) || !fs.statSync(fp).isFile()) {
        return toolPayload({ error: 'not_a_file', path: fp });
      }
      const st = fs.statSync(fp);
      if (st.size > MAX_SCAN_BYTES) {
        return toolPayload({ error: 'file_too_large', path: fp, bytes: st.size, max_bytes: MAX_SCAN_BYTES });
      }
      const t0 = Date.now();
      const matches = scanner.scan(fp);
      const elapsed = Date.now() - t0;
      const run: JsonRunMetadata = {
        duration_ms: elapsed,
        files_scanned: 1,
        bytes_scanned: st.size,
        patterns_active: scanner.getActivePatternCount(),
      };
      const results: FileScanResult[] = matches.length ? [{ file: fp, matches }] : [];
      // Post-hoc budget: the scan is synchronous and already finished, so this
      // cannot preempt a runaway. It marks the result as untrusted rather than
      // handing an agent a silent "clean".
      const overBudget = elapsed > MCP_SCAN_BUDGET_MS;
      return toolPayload({
        summary: {
          files_with_secrets: results.length,
          total_matches: matches.length,
          ...(overBudget ? { over_scan_budget: true } : {}),
        },
        ...(overBudget
          ? { over_budget: [{ file: fp, elapsed_ms: elapsed, budget_ms: MCP_SCAN_BUDGET_MS }] }
          : {}),
        json: JSON.parse(formatJson(results, { cwd: workspaceRoot, run })) as unknown,
        sarif: formatSarif(results, { cwd: workspaceRoot, run }),
      });
    },
  );

  server.registerTool(
    'scan_text',
    {
      title: 'Scan pasted text',
      description:
        'Scan arbitrary UTF-8 text (e.g. proposed AI edit). Optional virtual_path for SARIF artifact URI only.',
      inputSchema: {
        text: z.string().describe('UTF-8 content to scan'),
        virtual_path: z
          .string()
          .optional()
          .describe('Synthetic path label for SARIF (default: inline://snippet)'),
      },
    },
    async ({ text, virtual_path }) => {
      const bytes = Buffer.byteLength(text, 'utf8');
      if (bytes > MAX_SCAN_BYTES) {
        return toolPayload({ error: 'text_too_large', bytes, max_bytes: MAX_SCAN_BYTES });
      }
      const scanner = makeScanner(loadMcpConfig(workspaceRoot));
      const t0 = Date.now();
      const matches = scanner.scanContent(text);
      const label = virtual_path ?? 'inline://snippet';
      const results: FileScanResult[] = matches.length ? [{ file: label, matches }] : [];
      const run: JsonRunMetadata = {
        duration_ms: Date.now() - t0,
        files_scanned: 1,
        bytes_scanned: bytes,
        patterns_active: scanner.getActivePatternCount(),
      };
      return toolPayload({
        summary: { total_matches: matches.length },
        // virtual_path is a label, not a real path; skip relativization to preserve it verbatim.
        json: JSON.parse(formatJson(results, { cwd: null, run })) as unknown,
        sarif: formatSarif(results, { cwd: null, run }),
      });
    },
  );

  server.registerTool(
    'report_token_usage',
    {
      title: 'Estimate token usage',
      description:
        'Rough on-disk token estimate for paths (same heuristic as vault-guard tokens). Does not call cloud APIs.',
      inputSchema: {
        paths: z.array(z.string()).optional().describe('Files or directories to include (default: cwd)'),
      },
    },
    async ({ paths }) => {
      const targets = paths && paths.length > 0 ? paths : ['.'];
      let total = 0;
      const breakdown: Record<string, number> = {};
      // Real (symlink-resolved) directories already descended into. Shared
      // across all targets so an overlap between two targets is counted once,
      // and so a directory reachable by more than one path cannot recurse
      // without bound.
      const visited = new Set<string>();
      // Mirrors core's getAllFilesAsync: lstat every entry, never follow a
      // symlink, and gate directory descent on a realpath visited-set. Without
      // this the previous fs.statSync walk followed a symlinked directory out
      // of the workspace (the resolveWorkspacePath check only guards the
      // top-level target) and a symlink cycle could recurse without bound.
      const walkFile = (file: string): void => {
        try {
          const lst = fs.lstatSync(file);
          if (lst.isSymbolicLink()) return;
          if (lst.isFile()) {
            const n = tokenCounter.countTokensInFile(file);
            total += n;
            const ext = path.extname(file) || '(no-ext)';
            breakdown[ext] = (breakdown[ext] ?? 0) + n;
          } else if (lst.isDirectory()) {
            const real = fs.realpathSync(file);
            if (visited.has(real)) return;
            visited.add(real);
            const entries = fs.readdirSync(file, { withFileTypes: true });
            for (const e of entries) {
              if (e.name === 'node_modules' || e.name === '.git') continue;
              walkFile(path.join(file, e.name));
            }
          }
        } catch {
          /* skip */
        }
      };
      for (const t of targets) {
        const resolved = resolveWorkspacePath(workspaceRoot, t);
        if (!resolved.ok) {
          return toolPayload({ error: resolved.error, path: resolved.path });
        }
        // Resolve the validated top-level target through its own realpath so a
        // target that is itself a symlink (already confirmed by
        // resolveWorkspacePath to resolve INSIDE the workspace) is still
        // walked; the lstat guard above only rejects symlinks discovered
        // during the walk, which is what keeps the walk from escaping.
        let start = resolved.path;
        try {
          start = fs.realpathSync(resolved.path);
        } catch {
          /* missing path: walkFile's lstat will no-op */
        }
        walkFile(start);
      }
      const estCostAnthropic = tokenCounter.calculateCost('anthropic', total, 0);
      return toolPayload({
        total_tokens_estimated: total,
        breakdown,
        est_cost_usd_anthropic_input_only: Math.round(estCostAnthropic * 10_000) / 10_000,
      });
    },
  );

  server.registerTool(
    'record_session_event',
    {
      title: 'Record session / accuracy event',
      description:
        'Append an opt-in local telemetry row (e.g. accept/revert/secret_blocked). Stored under ~/.vault-guard/usage.sqlite only.',
      inputSchema: {
        event_type: z.string().describe('e.g. accept | reject | revert | secret_blocked | completion'),
        model: z.string().optional(),
        cwd: z.string().optional(),
        language: z.string().optional(),
        lines_accepted: z.number().int().optional(),
        lines_suggested: z.number().int().optional(),
        lines_reverted: z.number().int().optional(),
        extra: z.record(z.string(), z.any()).optional(),
      },
    },
    async args => {
      const store = getTelemetry();
      if (!store) {
        return toolPayload({ ok: false, telemetry: 'unavailable' });
      }
      store.recordSession({
        eventType: args.event_type,
        model: args.model,
        cwd: args.cwd,
        language: args.language,
        linesAccepted: args.lines_accepted,
        linesSuggested: args.lines_suggested,
        linesReverted: args.lines_reverted,
        extra: args.extra,
      });
      return toolPayload({ ok: true });
    },
  );

  return server;
}
