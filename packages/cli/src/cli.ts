import { Command } from 'commander';
import { scanCommand, OutputFormat } from './commands/scan';
import { installHookCommand } from './commands/install-hook';
import { tokensCommand } from './commands/tokens';
import { fixCommand } from './commands/fix';
import { checkCommand } from './commands/check';
import { statuslineCommand } from './commands/statusline';
import { suggestModelCommand } from './commands/suggest-model';
import { proxyCommand } from './commands/proxy';
import { dataStatusCommand, dataResetCommand, dataExportCommand } from './commands/data';
import { configValidateCommand } from './commands/config';
import { initCommand } from './commands/init';
import { readCliVersion } from './version';

function setExitCode(exitCode: number): void {
  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

export function buildCli(): Command {
  const program = new Command();

  program
    .name('vault-guard')
    .description('Security and optimization layer for AI-native coding')
    .version(readCliVersion());

  const configCmd = program.command('config').description('Inspect and validate Vault Guard configuration');

  configCmd
    .command('validate')
    .description('Validate the nearest .vault-guard.json (structure + scanner load)')
    .action(async () => {
      const exitCode = await configValidateCommand(process.cwd());
      setExitCode(exitCode);
    });

  // Scan command
  program
    .command('scan')
    .description('Scan files for secrets')
    .argument('[path]', 'Path to scan', '.')
    .option('-f, --format <format>', 'Output format: text | json | sarif', 'text')
    .option('--staged', 'Scan git staged files only (uses index vs HEAD)', false)
    .option(
      '--fail-on <severity>',
      'Minimum severity that fails the scan: critical | high | medium | low | none (default: medium, or fail_on in .vault-guard.json)',
    )
    .option(
      '--trust-base <ref>',
      'Pull-request mode: read .vault-guard.json, .vault-guard.local.json and the baseline from <ref> and scan the head tree. Exits 2 if <ref> cannot be read. Do not pass this from a pre-commit hook.',
    )
    .action(
      async (
        path: string,
        options: { format: string; staged?: boolean; failOn?: string; trustBase?: string },
      ) => {
        const format = (options.format as OutputFormat) ?? 'text';
        const exitCode = await scanCommand(
          path,
          format,
          Boolean(options.staged),
          options.failOn,
          options.trustBase,
        );
        setExitCode(exitCode);
      },
    );

  program
    .command('init')
    .description('Initialize Vault Guard in this repository (config, CI workflow, agent rules, hook)')
    .option('--dry-run', 'Print the file manifest and planned actions without writing', false)
    .option('--revert', 'Remove files recorded in .vault-guard/manifest.json', false)
    .option('--json', 'Machine-readable output', false)
    .option(
      '-m, --manager <manager>',
      'Hook integration when installing pre-commit: native | husky | lefthook | precommit',
      'native',
    )
    .option('--skip-hook', 'Do not install a pre-commit hook', false)
    .option('--skip-workflow', 'Do not create .github/workflows/vault-guard.yml', false)
    .option('--skip-config', 'Do not create .vault-guard.json', false)
    .option('--skip-agent-rules', 'Do not create .vault-guard/mcp-snippet.json or agent-rules.md', false)
    .action(
      async (options: {
        dryRun?: boolean;
        revert?: boolean;
        json?: boolean;
        manager: string;
        skipHook?: boolean;
        skipWorkflow?: boolean;
        skipConfig?: boolean;
        skipAgentRules?: boolean;
      }) => {
        const m = (options.manager ?? 'native').toLowerCase();
        if (!['native', 'husky', 'lefthook', 'precommit'].includes(m)) {
          console.error(`Unknown manager: ${options.manager}`);
          process.exitCode = 1;
          return;
        }
        const exitCode = await initCommand({
          dryRun: Boolean(options.dryRun),
          revert: Boolean(options.revert),
          json: Boolean(options.json),
          manager: m as 'native' | 'husky' | 'lefthook' | 'precommit',
          skipHook: Boolean(options.skipHook),
          skipWorkflow: Boolean(options.skipWorkflow),
          skipConfig: Boolean(options.skipConfig),
          skipAgentRules: Boolean(options.skipAgentRules),
        });
        setExitCode(exitCode);
      },
    );

  // Install-hook command
  program
    .command('install-hook')
    .description('Install pre-commit hook (runs vault-guard scan --staged)')
    .option(
      '-m, --manager <manager>',
      'Hook integration: native | husky | lefthook | precommit',
      'native',
    )
    .action(async (options: { manager: string }) => {
      const m = (options.manager ?? 'native').toLowerCase() as
        | 'native'
        | 'husky'
        | 'lefthook'
        | 'precommit';
      if (!['native', 'husky', 'lefthook', 'precommit'].includes(m)) {
        console.error(`Unknown manager: ${options.manager}`);
        process.exitCode = 1;
        return;
      }
      await installHookCommand(m);
    });

  // Tokens command
  program
    .command('tokens')
    .description('Show token usage')
    .action(async () => {
      await tokensCommand();
    });

  // Fix command
  program
    .command('fix')
    .description('Show remediation steps for secrets')
    .argument('[files...]', 'Files to check')
    .action(async (files: string[]) => {
      const exitCode = await fixCommand(files);
      setExitCode(exitCode);
    });

  // Check command
  program
    .command('check')
    .description('Scan files with config and baselines')
    .argument('[files...]', 'Files to check')
    .option(
      '--fail-on <severity>',
      'Minimum severity that fails the check: critical | high | medium | low | none (default: medium, or fail_on in .vault-guard.json)',
    )
    .option(
      '--trust-base <ref>',
      'Pull-request mode: read config and baseline from <ref> and check the head tree. Exits 2 if <ref> cannot be read.',
    )
    .action(async (files: string[], options: { failOn?: string; trustBase?: string }) => {
      const exitCode = await checkCommand(files, options.failOn, options.trustBase);
      setExitCode(exitCode);
    });

  program
    .command('statusline')
    .description('Emit status fields for editor statuslines (JSON)')
    .option('--json', 'Print machine-readable JSON (default)', true)
    .option('--human', 'Print human-readable summary instead of JSON')
    .action((options: { json?: boolean; human?: boolean }) => {
      const asJson = options.human ? false : options.json !== false;
      statuslineCommand(asJson);
    });

  program
    .command('suggest-model')
    .description('Heuristic model hint from local telemetry (opt-in)')
    .option('--json', 'Print JSON', false)
    .option('--cwd <dir>', 'Optional cwd context label')
    .option('--language <lang>', 'Optional language label (e.g. tsx)')
    .action((options: { json?: boolean; cwd?: string; language?: string }) => {
      suggestModelCommand({
        json: Boolean(options.json),
        cwd: options.cwd,
        language: options.language,
      });
    });

  program
    .command('proxy')
    .description('Opt-in local Anthropic HTTP forwarder with usage logging (MVP)')
    .requiredOption(
      '--listen <host:port>',
      'Bind address, e.g. 127.0.0.1:8765',
    )
    .option(
      '--allow-env-fallback',
      'Permit fallback to ANTHROPIC_API_KEY when caller omits x-api-key. ' +
        'Off by default -- see SECURITY.md before enabling.',
      false,
    )
    .option(
      '--allow-public',
      'Permit binding a non-loopback address. Off by default -- exposing this ' +
        'proxy on the network combined with --allow-env-fallback is a credit-card ' +
        'draining footgun.',
      false,
    )
    .option(
      '--max-rpm <n>',
      'Optional cap on forwarded POST /v1/messages requests per rolling 60s window (per process)',
    )
    .action(
      async (options: {
        listen: string;
        allowEnvFallback?: boolean;
        allowPublic?: boolean;
        maxRpm?: string;
      }) => {
        try {
          let maxRpm: number | undefined;
          if (options.maxRpm !== undefined && options.maxRpm !== '') {
            const n = Number(options.maxRpm);
            if (!Number.isFinite(n) || n < 1) {
              console.error('--max-rpm must be a positive number');
              process.exitCode = 1;
              return;
            }
            maxRpm = Math.floor(n);
          }
          const handle = await proxyCommand({
            listen: options.listen,
            allowEnvFallback: Boolean(options.allowEnvFallback),
            allowPublic: Boolean(options.allowPublic),
            maxRpm,
          });

          let signalled = false;
          const onSignal = (signal: NodeJS.Signals): void => {
            if (signalled) return;
            signalled = true;
            void handle
              .shutdown(signal)
              .catch(() => {
                /* shutdown is best-effort */
              })
              .finally(() => process.exit(0));
          };
          process.on('SIGINT', onSignal);
          process.on('SIGTERM', onSignal);

          await new Promise(() => {
            /* keep process alive until a signal triggers shutdown */
          });
        } catch (e) {
          console.error(String(e));
          process.exitCode = 1;
        }
      },
    );

  // `data` parent command -- inspects, exports, and resets the local
  // telemetry database at `~/.vault-guard/usage.sqlite`. No subcommand
  // shows help; this avoids an empty command landing.
  const dataCmd = program
    .command('data')
    .description('Inspect, export, or reset local telemetry (~/.vault-guard/usage.sqlite)');

  dataCmd
    .command('status')
    .description('Show a privacy-respecting summary of the local telemetry database')
    .option('--json', 'Print JSON', false)
    .action(async (options: { json?: boolean }) => {
      const exitCode = await dataStatusCommand({ json: Boolean(options.json) });
      setExitCode(exitCode);
    });

  dataCmd
    .command('reset')
    .description('Delete the local telemetry database and its WAL/SHM sidecars')
    .option('-y, --yes', 'Skip the interactive confirmation prompt', false)
    .option('--dry-run', 'Print what would be deleted without touching the filesystem', false)
    .option('--json', 'Print JSON', false)
    .action(async (options: { yes?: boolean; dryRun?: boolean; json?: boolean }) => {
      const exitCode = await dataResetCommand({
        yes: Boolean(options.yes),
        dryRun: Boolean(options.dryRun),
        json: Boolean(options.json),
      });
      setExitCode(exitCode);
    });

  dataCmd
    .command('export')
    .description('Dump usage_events and session_events to a local file')
    .requiredOption('-o, --output <file>', 'Output file path (will be created with mode 0600)')
    .option('--format <format>', 'Output format: json | jsonl', 'json')
    .action(async (options: { output: string; format?: string }) => {
      const fmt = options.format === 'jsonl' ? 'jsonl' : 'json';
      const exitCode = await dataExportCommand({ output: options.output, format: fmt });
      setExitCode(exitCode);
    });

  return program;
}
