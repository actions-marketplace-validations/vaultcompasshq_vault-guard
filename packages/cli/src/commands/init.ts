import * as fs from 'fs';
import * as path from 'path';
import { PreCommitHook, type HookManager } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import {
  MANAGED_FILE_PATHS,
  MANIFEST_RELATIVE_PATH,
  INIT_TEMPLATE_VERSION,
  buildManifestContent,
  templateContentForPath,
  type InitManifest,
  type ManagedFilePath,
} from '../init/templates';

export interface InitOptions {
  cwd?: string;
  dryRun?: boolean;
  revert?: boolean;
  json?: boolean;
  manager?: HookManager;
  skipHook?: boolean;
  skipWorkflow?: boolean;
  skipConfig?: boolean;
  skipAgentRules?: boolean;
}

export interface InitConflict {
  path: string;
  reason:
    | 'exists'
    | 'foreign_manifest'
    | 'manifest_mismatch'
    | 'not_a_git_repository'
    | 'foreign_hook';
}

export interface InitAdvisory {
  /** Detected manager that may already own pre-commit. */
  manager: 'husky' | 'lefthook' | 'precommit';
  path: string;
  guidance: string;
}

export interface InitPlannedAction {
  kind: 'create' | 'hook-install' | 'skip';
  path: string;
  detail?: string;
}

export interface InitResult {
  ok: boolean;
  dryRun: boolean;
  reverted: boolean;
  alreadyInitialized: boolean;
  actions: InitPlannedAction[];
  conflicts: InitConflict[];
  /** Non-blocking tips when other hook managers are present. */
  advisories: InitAdvisory[];
  hook?: { manager: string; path?: string; installed: boolean };
  manifestPath: string;
  mcpMergeHint: string;
}

const MCP_MERGE_HINT =
  'Merge .vault-guard/mcp-snippet.json into your editor MCP config (~/.cursor/mcp.json or Claude Desktop).';

function isGitRepo(cwd: string): boolean {
  return fs.existsSync(path.join(cwd, '.git'));
}

function readFileIfExists(filePath: string): string | undefined {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return undefined;
  }
}

function parseManifest(content: string): InitManifest | undefined {
  try {
    const parsed = JSON.parse(content) as InitManifest;
    if (parsed.initVersion !== '1' || !Array.isArray(parsed.files)) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

function managedContentPaths(options: InitOptions): ManagedFilePath[] {
  const skip = new Set<string>();
  if (options.skipConfig) skip.add('.vault-guard.json');
  if (options.skipWorkflow) skip.add('.github/workflows/vault-guard.yml');
  if (options.skipAgentRules) {
    skip.add('.vault-guard/mcp-snippet.json');
    skip.add('.vault-guard/agent-rules.md');
  }
  return MANAGED_FILE_PATHS.filter(
    (p): p is ManagedFilePath => p !== MANIFEST_RELATIVE_PATH && !skip.has(p),
  );
}

function hookRelativePath(cwd: string, hookPath: string): string {
  return path.relative(cwd, hookPath).split(path.sep).join('/');
}

function foreignHookConflict(
  cwd: string,
  manager: HookManager,
): InitConflict | undefined {
  const hook = new PreCommitHook();

  // Manager-specific paths first — lefthook/precommit do not use getPreCommitHookPath
  // (that helper still resolves the native hooks dir for non-husky managers).
  if (manager === 'lefthook') {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    if (!fs.existsSync(localPath)) return undefined;
    const content = readFileIfExists(localPath) ?? '';
    if (content.includes('vault-guard scan --staged')) return undefined;
    return { path: 'lefthook-local.yml', reason: 'foreign_hook' };
  }
  if (manager === 'precommit') {
    const configPath = path.join(cwd, '.pre-commit-config.yaml');
    if (!fs.existsSync(configPath)) return undefined;
    const content = readFileIfExists(configPath) ?? '';
    if (content.includes('vault-guard scan --staged')) return undefined;
    return { path: '.pre-commit-config.yaml', reason: 'foreign_hook' };
  }
  if (manager === 'husky') {
    const hookPath = hook.getPreCommitHookPath(cwd, 'husky');
    if (!fs.existsSync(hookPath)) return undefined;
    if (hook.isInstalled({ cwd, manager: 'husky' })) return undefined;
    const content = readFileIfExists(hookPath) ?? '';
    if (content.includes('vault-guard')) return undefined;
    return { path: hookRelativePath(cwd, hookPath), reason: 'foreign_hook' };
  }

  // native: POSIX hook and optional Windows companion
  const hookPath = hook.getPreCommitHookPath(cwd, 'native');
  if (fs.existsSync(hookPath) && !hook.isInstalled({ cwd, manager: 'native' })) {
    const content = readFileIfExists(hookPath) ?? '';
    if (content.trim().length > 0) {
      return { path: hookRelativePath(cwd, hookPath), reason: 'foreign_hook' };
    }
  }

  // The Windows .cmd companion is native-only and never written under
  // husky's generated hooks dir (see installNative's husky delegation).
  // getPreCommitCmdPath itself returns undefined there now, so a stray
  // file left inside .husky/_ can never be misread as a foreign hook --
  // no separate isHuskyGeneratedHooksDir guard needed here.
  const cmdPath = hook.getPreCommitCmdPath(cwd);
  if (cmdPath && fs.existsSync(cmdPath)) {
    const content = readFileIfExists(cmdPath) ?? '';
    const isOurs = content.includes('vault-guard') && content.includes('scan --staged');
    if (content.trim().length > 0 && !isOurs) {
      return { path: hookRelativePath(cwd, cmdPath), reason: 'foreign_hook' };
    }
  }

  return undefined;
}


function detectOtherHookManagers(cwd: string, selected: HookManager): InitAdvisory[] {
  const advisories: InitAdvisory[] = [];

  const huskyDir = path.join(cwd, '.husky');
  if (fs.existsSync(huskyDir) && selected !== 'husky') {
    advisories.push({
      manager: 'husky',
      path: '.husky/',
      guidance:
        'Husky detected. If core.hooksPath points at husky\'s generated directory, the default native manager already installs into the tracked pre-commit file automatically -- no --manager husky needed. Pass --manager husky only if you want vault-guard to manage that file directly regardless of core.hooksPath.',
    });
  }

  const lefthookYml = path.join(cwd, 'lefthook.yml');
  const lefthookLocal = path.join(cwd, 'lefthook-local.yml');
  if ((fs.existsSync(lefthookYml) || fs.existsSync(lefthookLocal)) && selected !== 'lefthook') {
    advisories.push({
      manager: 'lefthook',
      path: fs.existsSync(lefthookLocal) ? 'lefthook-local.yml' : 'lefthook.yml',
      guidance:
        'Lefthook detected. Prefer `vault-guard init --manager lefthook` (writes lefthook-local.yml) or merge `vault-guard scan --staged` under pre-commit.commands manually. Init never overwrites existing lefthook files.',
    });
  }

  const precommitCfg = path.join(cwd, '.pre-commit-config.yaml');
  if (fs.existsSync(precommitCfg) && selected !== 'precommit') {
    advisories.push({
      manager: 'precommit',
      path: '.pre-commit-config.yaml',
      guidance:
        'pre-commit framework config detected. Prefer `vault-guard init --manager precommit` only if the file is absent, or merge the local vault-guard hook into repos: yourself. Init never overwrites an existing .pre-commit-config.yaml.',
    });
  }

  return advisories;
}

/**
 * What changed in the 1.6.0 template, phrased for someone who initialised on an
 * earlier version. Their config is kept exactly as it is; this says what to
 * change by hand if they want the new default.
 */
const TEST_TREE_DEFAULT_NOTE =
  'The 1.6.0 default changed: test trees are now scanned instead of ignored, ' +
  'because an ignore is total and hid real keys committed to test files. Your ' +
  'existing config is kept as is and nothing was overwritten. To adopt the new ' +
  'default, remove "**/__tests__/**" from ignore.patterns in .vault-guard.json ' +
  '(keep fixtures/** and bench/fixtures/**).';

/**
 * The two 1.7.0 changes that can turn a previously green setup red, phrased for
 * someone whose repo was scaffolded by an earlier version. Neither is a finding;
 * both are things their existing files no longer say.
 */
const TRUST_BASE_UPGRADE_NOTE =
  'Two 1.7.0 changes affect a repo initialised earlier. First, a pull_request ' +
  'workflow now needs fetch-depth: 0 on actions/checkout, because pull-request ' +
  'mode reads the config and the baseline from the base branch and a shallow ' +
  'clone does not have it; without it the scan exits 2 instead of trusting the ' +
  'pull request. There is no input that turns pull-request mode off, because a ' +
  'same-repo pull_request event runs the workflow file from the pull request ' +
  'head, so an off switch would be settable by the pull request it judges; if ' +
  'you are not ready to change the checkout, stay pinned to ' +
  'vaultcompasshq/vault-guard@v1.6.0 until you are, knowing the trade: every ' +
  'tag before v1.7.1 installs the scanner from inside the checkout it scans, ' +
  'so a pull request can choose the program that judges it. Second, an unknown ' +
  'top-level key in .vault-guard.json now fails the run rather than being ' +
  'dropped in silence, so run "vault-guard config validate" once and remove ' +
  'whatever it names.';

function conflictGuidance(c: InitConflict): string {
  switch (c.reason) {
    case 'exists':
      if (c.path === '.vault-guard.json') {
        return `Your .vault-guard.json is kept as is; nothing was overwritten. ${TEST_TREE_DEFAULT_NOTE}`;
      }
      return 'File already exists with different content — edit manually or move it aside, then re-run init.';
    case 'foreign_manifest':
      return 'Existing .vault-guard/init-manifest.json is invalid or foreign — fix or remove it, then re-run.';
    case 'manifest_mismatch':
      return `This repo was initialised by an earlier vault-guard, so the manifest does not match the current templates. Nothing was overwritten. ${TEST_TREE_DEFAULT_NOTE} ${TRUST_BASE_UPGRADE_NOTE}`;
    case 'not_a_git_repository':
      return 'Run `git init` first, or pass `--skip-hook` to scaffold config/workflow without a hook.';
    case 'foreign_hook':
      if (c.path.includes('husky') || c.path.startsWith('.husky')) {
        return 'Existing Husky pre-commit has no vault-guard stanza. Append `vault-guard scan --staged` yourself, or use `install-hook --manager husky` after reviewing the file.';
      }
      if (c.path.includes('lefthook')) {
        return 'Add under pre-commit.commands:\n  vault-guard:\n    run: vault-guard scan --staged';
      }
      if (c.path.includes('pre-commit-config')) {
        return 'Merge a local vault-guard hook into repos: (see `vault-guard install-hook --manager precommit` error output for a snippet).';
      }
      return 'An existing pre-commit hook is present without vault-guard. Merge `vault-guard scan --staged` manually, or remove the foreign hook if unused.';
    default:
      return 'Resolve manually, then re-run vault-guard init.';
  }
}

function ensureParentDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

export function planInit(options: InitOptions = {}): InitResult {
  const cwd = options.cwd ?? process.cwd();
  const dryRun = Boolean(options.dryRun);
  const manager = options.manager ?? 'native';
  const actions: InitPlannedAction[] = [];
  const conflicts: InitConflict[] = [];
  const advisories = detectOtherHookManagers(cwd, manager);
  const trackedFiles: Array<{ path: string; action: 'created' }> = [];

  const manifestAbs = path.join(cwd, MANIFEST_RELATIVE_PATH);
  const manifestRaw = readFileIfExists(manifestAbs);
  const manifestParsed = manifestRaw ? parseManifest(manifestRaw) : undefined;

  if (manifestRaw && !manifestParsed) {
    conflicts.push({ path: MANIFEST_RELATIVE_PATH, reason: 'foreign_manifest' });
  }

  for (const rel of managedContentPaths(options)) {
    const abs = path.join(cwd, rel);
    const expected = templateContentForPath(rel);
    const current = readFileIfExists(abs);

    if (current === undefined) {
      actions.push({ kind: 'create', path: rel });
      trackedFiles.push({ path: rel, action: 'created' });
      continue;
    }

    if (current === expected) {
      actions.push({ kind: 'skip', path: rel, detail: 'content matches template' });
      trackedFiles.push({ path: rel, action: 'created' });
      continue;
    }

    conflicts.push({ path: rel, reason: 'exists' });
  }

  let hookState: InitResult['hook'];
  if (!options.skipHook) {
    if (!isGitRepo(cwd)) {
      conflicts.push({ path: '.git', reason: 'not_a_git_repository' });
    } else {
      const foreignHook = foreignHookConflict(cwd, manager);
      if (foreignHook) {
        conflicts.push(foreignHook);
      } else {
        const hook = new PreCommitHook();
        const hookPath = hook.getPreCommitHookPath(cwd, manager);
        // hookState.path stays ABSOLUTE (applyInit, hookMeta, and callers
        // of planInit's `hook` field all rely on that); only the actions
        // array entry is repo-relative, matching every 'create' action.
        if (hook.isInstalled({ cwd, manager })) {
          hookState = { manager, path: hookPath, installed: true };
          actions.push({
            kind: 'skip',
            path: hookRelativePath(cwd, hookPath),
            detail: 'hook already installed',
          });
        } else {
          hookState = { manager, path: hookPath, installed: false };
          actions.push({ kind: 'hook-install', path: hookRelativePath(cwd, hookPath), detail: manager });
        }
      }
    }
  }

  const hookMeta =
    hookState?.path && !options.skipHook
      ? { manager, path: hookRelativePath(cwd, hookState.path) }
      : undefined;

  function manifestMatchesState(manifest: InitManifest): boolean {
    if (manifest.templateVersion !== INIT_TEMPLATE_VERSION) return false;
    const expectedPaths = trackedFiles
      .map(f => f.path)
      .sort()
      .join('\0');
    const actualPaths = manifest.files
      .map(f => f.path)
      .sort()
      .join('\0');
    if (expectedPaths !== actualPaths) return false;
    if (hookMeta) {
      return manifest.hookManager === hookMeta.manager && manifest.hookPath === hookMeta.path;
    }
    return manifest.hookManager === undefined && manifest.hookPath === undefined;
  }

  if (manifestRaw === undefined && conflicts.length === 0) {
    actions.push({ kind: 'create', path: MANIFEST_RELATIVE_PATH });
  } else if (manifestParsed) {
    if (manifestMatchesState(manifestParsed)) {
      actions.push({ kind: 'skip', path: MANIFEST_RELATIVE_PATH, detail: 'manifest current' });
    } else if (conflicts.length === 0) {
      conflicts.push({ path: MANIFEST_RELATIVE_PATH, reason: 'manifest_mismatch' });
    }
  }

  const alreadyInitialized =
    conflicts.length === 0 &&
    actions.length > 0 &&
    actions.every(a => a.kind === 'skip');

  return {
    ok: conflicts.length === 0,
    dryRun,
    reverted: false,
    alreadyInitialized,
    actions,
    conflicts,
    advisories,
    hook: hookState,
    manifestPath: MANIFEST_RELATIVE_PATH,
    mcpMergeHint: MCP_MERGE_HINT,
  };
}

export function applyInit(plan: InitResult, options: InitOptions = {}): InitResult {
  if (!plan.ok || plan.dryRun) {
    return plan;
  }

  const cwd = options.cwd ?? process.cwd();
  const manager = options.manager ?? 'native';

  // Idempotent native refresh: backfill/update optional pre-commit.cmd even when
  // the repo is already fully initialized.
  if (
    plan.alreadyInitialized &&
    plan.hook &&
    !options.skipHook &&
    manager === 'native'
  ) {
    new PreCommitHook().install({ cwd, manager: 'native' });
    return plan;
  }

  if (plan.alreadyInitialized) {
    return plan;
  }

  const trackedFiles: Array<{ path: string; action: 'created' }> = [];
  const createdPaths: string[] = [];

  const rollbackCreatedFiles = (): void => {
    for (const rel of createdPaths.reverse()) {
      const abs = path.join(cwd, rel);
      try {
        if (fs.existsSync(abs)) fs.unlinkSync(abs);
      } catch {
        /* best effort */
      }
    }
  };

  if (plan.hook && !options.skipHook) {
    const hook = new PreCommitHook();
    // Always call install for native when planning a hook: first-time write, or
    // idempotent refresh of the optional pre-commit.cmd companion.
    if (!plan.hook.installed || manager === 'native') {
      const result = hook.install({ cwd, manager });
      if (!result.success && !plan.hook.installed) {
        return {
          ...plan,
          ok: false,
          actions: [
            ...plan.actions,
            {
              kind: 'skip',
              path: plan.hook.path ? hookRelativePath(cwd, plan.hook.path) : 'pre-commit',
              detail: `hook install failed: ${result.message}`,
            },
          ],
        };
      }
      if (result.success) {
        plan.hook = {
          manager,
          path: result.hookPath ?? plan.hook.path,
          installed: true,
        };
      }
    }
  }

  try {
    for (const action of plan.actions) {
      if (action.kind !== 'create' || action.path === MANIFEST_RELATIVE_PATH) continue;
      const abs = path.join(cwd, action.path);
      ensureParentDir(abs);
      fs.writeFileSync(abs, templateContentForPath(action.path as ManagedFilePath), {
        encoding: 'utf8',
        flag: 'wx',
      });
      trackedFiles.push({ path: action.path, action: 'created' });
      createdPaths.push(action.path);
    }
  } catch (error) {
    rollbackCreatedFiles();
    if (plan.hook?.installed && !options.skipHook) {
      new PreCommitHook().uninstall({ cwd, manager });
    }
    return {
      ...plan,
      ok: false,
      actions: [
        ...plan.actions,
        {
          kind: 'skip',
          path: 'init',
          detail: `file write failed: ${String(error)}`,
        },
      ],
    };
  }

  const hookMeta =
    plan.hook?.path && !options.skipHook
      ? { manager, path: hookRelativePath(cwd, plan.hook.path) }
      : undefined;

  const allTracked =
    trackedFiles.length > 0
      ? trackedFiles
      : managedContentPaths(options).map(p => ({ path: p, action: 'created' as const }));

  const manifestContent = buildManifestContent(allTracked, hookMeta);
  const manifestAbs = path.join(cwd, MANIFEST_RELATIVE_PATH);
  try {
    if (!fs.existsSync(manifestAbs)) {
      ensureParentDir(manifestAbs);
      fs.writeFileSync(manifestAbs, manifestContent, { encoding: 'utf8', flag: 'wx' });
    }
  } catch (error) {
    rollbackCreatedFiles();
    if (plan.hook?.installed && !options.skipHook) {
      new PreCommitHook().uninstall({ cwd, manager });
    }
    return {
      ...plan,
      ok: false,
      actions: [
        ...plan.actions,
        {
          kind: 'skip',
          path: MANIFEST_RELATIVE_PATH,
          detail: `manifest write failed: ${String(error)}`,
        },
      ],
    };
  }

  return { ...plan, ok: true };
}

export function revertInit(options: InitOptions = {}): InitResult {
  const cwd = options.cwd ?? process.cwd();
  const dryRun = Boolean(options.dryRun);
  const manifestAbs = path.join(cwd, MANIFEST_RELATIVE_PATH);
  const raw = readFileIfExists(manifestAbs);

  if (!raw) {
    return {
      ok: false,
      dryRun,
      reverted: false,
      alreadyInitialized: false,
      actions: [],
      advisories: [],
      conflicts: [{ path: MANIFEST_RELATIVE_PATH, reason: 'foreign_manifest' }],
      manifestPath: MANIFEST_RELATIVE_PATH,
      mcpMergeHint: MCP_MERGE_HINT,
    };
  }

  const manifest = parseManifest(raw);
  if (!manifest) {
    return {
      ok: false,
      dryRun,
      reverted: false,
      alreadyInitialized: false,
      actions: [],
      advisories: [],
      conflicts: [{ path: MANIFEST_RELATIVE_PATH, reason: 'foreign_manifest' }],
      manifestPath: MANIFEST_RELATIVE_PATH,
      mcpMergeHint: MCP_MERGE_HINT,
    };
  }

  const actions: InitPlannedAction[] = [];
  const filePaths = [...manifest.files.map(f => f.path)].reverse();

  for (const rel of filePaths) {
    actions.push({
      kind: 'skip',
      path: rel,
      detail: dryRun ? 'would remove file' : 'removed file',
    });
    if (!dryRun) {
      const abs = path.join(cwd, rel);
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
    }
  }

  if (manifest.hookManager) {
    actions.push({
      kind: 'hook-install',
      path: manifest.hookPath ?? 'pre-commit',
      detail: dryRun ? 'would uninstall hook' : 'uninstalled hook',
    });
    if (!dryRun) {
      new PreCommitHook().uninstall({
        cwd,
        manager: manifest.hookManager as HookManager,
      });
    }
  }

  actions.push({
    kind: 'skip',
    path: MANIFEST_RELATIVE_PATH,
    detail: dryRun ? 'would remove manifest' : 'removed manifest',
  });
  if (!dryRun && fs.existsSync(manifestAbs)) {
    fs.unlinkSync(manifestAbs);
    const vgDir = path.join(cwd, '.vault-guard');
    try {
      if (fs.existsSync(vgDir) && fs.readdirSync(vgDir).length === 0) {
        fs.rmdirSync(vgDir);
      }
    } catch {
      /* best effort */
    }
  }

  return {
    ok: true,
    dryRun,
    reverted: !dryRun,
    alreadyInitialized: false,
    actions,
    advisories: [],
    conflicts: [],
    manifestPath: MANIFEST_RELATIVE_PATH,
    mcpMergeHint: MCP_MERGE_HINT,
  };
}

function printHuman(result: InitResult, options: InitOptions): void {
  if (options.revert) {
    if (!result.ok) {
      console.error(chalk.red('❌ Revert failed:'), 'no valid init manifest found');
      return;
    }
    console.log(
      result.dryRun
        ? chalk.blue('🔍 Dry-run revert plan')
        : chalk.green.bold('✅ Reverted Vault Guard init artifacts'),
    );
    for (const a of result.actions) {
      console.log(chalk.gray(`   ${a.detail ?? a.path}`));
    }
    return;
  }

  if (result.conflicts.length > 0) {
    console.error(chalk.red.bold('❌ Init blocked — conflicts (no automatic overwrites):'));
    for (const c of result.conflicts) {
      console.error(chalk.white(`   ${c.path}`), chalk.gray(`(${c.reason})`));
      console.error(chalk.gray(`      → ${conflictGuidance(c)}`));
    }
    if (result.advisories.length > 0) {
      console.error(chalk.yellow('\nAlso noted:'));
      for (const a of result.advisories) {
        console.error(chalk.yellow(`   [${a.manager}] ${a.path}`));
        console.error(chalk.gray(`      ${a.guidance}`));
      }
    }
    console.error(chalk.gray('\nResolve manually, then re-run vault-guard init.'));
    return;
  }

  if (result.alreadyInitialized) {
    console.log(chalk.green('✅ Already initialized — no changes needed'));
    return;
  }

  if (result.dryRun) {
    console.log(chalk.blue('🔍 Dry-run — would apply:'));
  } else {
    console.log(chalk.green.bold('✅ Vault Guard initialized'));
  }

  for (const a of result.actions) {
    if (a.kind === 'create') {
      console.log(chalk.white(`   ${result.dryRun ? 'create' : 'created'} ${a.path}`));
    } else if (a.kind === 'hook-install') {
      console.log(
        chalk.white(`   ${result.dryRun ? 'install' : 'installed'} hook (${a.detail})`),
      );
    }
  }

  if (result.advisories.length > 0) {
    console.log(chalk.yellow('\nHook manager notes:'));
    for (const a of result.advisories) {
      console.log(chalk.yellow(`   [${a.manager}] ${a.path}`));
      console.log(chalk.gray(`      ${a.guidance}`));
    }
  }

  // Say this on first run, before the adopter hits it as a surprise blocked
  // commit. Vendor-anchored rules are NOT downgraded on a test path, so a
  // vendor-shaped value in a test blocks whether or not it is live -- the
  // scanner cannot tell a real key from a convincing fabricated one.
  console.log(
    chalk.yellow(
      '\nNote: test trees are scanned (they are not ignored by default since 1.6.0).',
    ),
  );
  console.log(
    chalk.gray(
      '      Fixture-shaped credentials are downgraded to "low", but a vendor-shaped\n' +
        '      token (sk-ant-, ghp_, AKIA, ...) in a test still blocks, live or not.\n' +
        '      Build fake tokens from fragments joined at runtime, or use placeholder\n' +
        '      words like EXAMPLE/test. See docs/RULES.md for the downgrade rules.',
    ),
  );

  console.log(chalk.gray(`\n${result.mcpMergeHint}`));
  console.log(chalk.gray(`Manifest: ${result.manifestPath}`));
}

export async function initCommand(options: InitOptions = {}): Promise<number> {
  if (options.revert) {
    const result = revertInit(options);
    if (options.json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      printHuman(result, options);
    }
    return result.ok ? 0 : 1;
  }

  const plan = planInit(options);
  const result = plan.dryRun ? plan : applyInit(plan, options);

  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    printHuman(result, options);
  }

  if (result.conflicts.length > 0) return 2;
  if (!result.ok) return 1;
  return 0;
}
