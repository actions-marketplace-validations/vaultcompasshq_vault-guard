import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { HookError } from '../errors';

export type HookManager = 'native' | 'husky' | 'lefthook' | 'precommit';

export interface InstallHookOptions {
  manager?: HookManager;
  /**
   * Working directory. MUST be the git repository root -- the directory
   * containing `.git` -- not a package subdirectory in a monorepo, even
   * one that owns its own `.husky`. `install()`/`uninstall()` refuse
   * outright when `.git` is not directly present (see the check at the
   * top of each), and core.hooksPath is resolved relative to the
   * worktree root regardless of where a nested `.husky` lives, so running
   * from anywhere else either fails fast or resolves the wrong hooks
   * directory entirely. Defaults to `process.cwd()`.
   */
  cwd?: string;
}

/**
 * Marks a hook file vault-guard wrote WHOLE, from a template -- as
 * opposed to a stanza vault-guard appended to a pre-existing (foreign)
 * hook it does not own. uninstallHusky uses this to decide whether it is
 * safe to delete the file outright: present means the whole file is
 * vault-guard's, so removing it entirely is correct; absent (even when
 * the file mentions "vault-guard" some other way) means the file
 * predates vault-guard or was never fully vault-guard's, so it must not
 * be deleted wholesale.
 */
const VAULT_GUARD_HOOK_HEADER = '# vault-guard pre-commit (installed by @vaultcompass/vault-guard)';

/**
 * Shell hook body for **native** Git hooks (`core.hooksPath` or `.git/hooks`).
 * Scans **staged files only** -- fast and matches what will actually be committed.
 */
const NATIVE_HOOK_SCRIPT = `#!/bin/sh
${VAULT_GUARD_HOOK_HEADER}
set -e

# Re-attach stdin for GUI git clients when possible.
# dash (Ubuntu /bin/sh) exits the whole shell on a failed \`exec </dev/tty\`
# even with \`|| true\` / \`set +e\` -- exit status 2. Probe in a subshell first;
# only \`exec\` in the current shell when that open succeeds. \`[ -r /dev/tty ]\`
# is not a usable guard: the node can exist and still fail open with ENXIO.
if [ ! -t 0 ]; then
  if (exec </dev/tty) 2>/dev/null; then
    exec </dev/tty
  fi
fi

if ! command -v vault-guard >/dev/null 2>&1; then
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi

echo "🔍 vault-guard: scanning staged files..."
# Capture the status rather than branching on \`if vault-guard ...\`: after a
# bare \`if\` with no else branch, \`$?\` is the IF STATEMENT's status (0), not
# the command's, so the exit code would be lost. \`|| status=$?\` also keeps
# \`set -e\` from aborting here, because the failure is handled.
status=0
vault-guard scan --staged || status=$?

if [ "$status" -eq 0 ]; then
  echo "✅ vault-guard: no secrets in staged files"
  exit 0
fi

echo ""
if [ "$status" -eq 2 ]; then
  # Exit 2 means vault-guard could not finish the scan, not that it found
  # something. Claiming secrets were detected would be false, and offering
  # --no-verify beside it would recommend skipping a check that never ran.
  echo "❌ COMMIT BLOCKED: vault-guard could not complete the scan"
  echo "   See the message above for what went unexamined. This commit has not been checked."
  exit 1
fi

echo "❌ COMMIT BLOCKED: secrets detected in staged files"
echo "💡 Fix or unstage, then retry. Emergency bypass (discouraged): git commit --no-verify"
exit 1
`;

/**
 * Optional `pre-commit.cmd` beside the POSIX hook. Git for Windows runs the
 * extensionless `pre-commit` via sh; a few clients may invoke `.cmd` directly.
 */
const NATIVE_HOOK_CMD = `@echo off
REM vault-guard pre-commit (installed by @vaultcompass/vault-guard)
where vault-guard >nul 2>&1
if errorlevel 1 (
  echo ❌ vault-guard: command not found ^(install: npm i -g @vaultcompass/vault-guard^)
  exit /b 1
)

echo 🔍 vault-guard: scanning staged files...
call vault-guard scan --staged
REM \`if errorlevel N\` is true for anything >= N, so 2 must be tested BEFORE
REM 1 or an incomplete scan would fall into the secrets-detected branch.
if errorlevel 2 (
  echo.
  echo ❌ COMMIT BLOCKED: vault-guard could not complete the scan
  echo    See the message above for what went unexamined. This commit has not been checked.
  exit /b 1
)
if errorlevel 1 (
  echo.
  echo ❌ COMMIT BLOCKED: secrets detected in staged files
  echo 💡 Fix or unstage, then retry. Emergency bypass ^(discouraged^): git commit --no-verify
  exit /b 1
)

echo ✅ vault-guard: no secrets in staged files
exit /b 0
`;

/** Husky-friendly hook (sources \`_/husky.sh\` when present). */
const HUSKY_HOOK_SCRIPT = `#!/usr/bin/env sh
${VAULT_GUARD_HOOK_HEADER}
if [ -f "$(dirname "$0")/_/husky.sh" ]; then
  . "$(dirname "$0")/_/husky.sh"
fi

if ! command -v vault-guard >/dev/null 2>&1; then
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi

echo "🔍 vault-guard: scanning staged files..."
status=0
vault-guard scan --staged || status=$?

if [ "$status" -eq 2 ]; then
  # Could not finish the scan, as opposed to finding something. No
  # --no-verify hint here: the check never ran, so bypassing it is not the
  # remedy. See the native template for the same reasoning.
  echo ""
  echo "❌ COMMIT BLOCKED: vault-guard could not complete the scan"
  echo "   See the message above for what went unexamined. This commit has not been checked."
  exit 1
fi

if [ "$status" -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: secrets detected in staged files"
  echo "💡 git commit --no-verify to bypass (discouraged)"
  exit 1
fi
echo "✅ vault-guard: no secrets in staged files"
`;

const LEFTHOOK_LOCAL = `# Merged by Lefthook with lefthook.yml -- added by vault-guard install-hook
pre-commit:
  commands:
    vault-guard:
      run: vault-guard scan --staged
`;

const PRE_COMMIT_CONFIG = `# See https://pre-commit.com
repos:
  - repo: local
    hooks:
      - id: vault-guard
        name: Vault Guard (staged files)
        entry: vault-guard scan --staged
        language: system
        pass_filenames: false
`;

export class PreCommitHook {
  /**
   * Resolve the directory where Git expects the \`pre-commit\` executable.
   * Honors \`core.hooksPath\` (local then global).
   *
   * A RELATIVE \`core.hooksPath\` resolves against the WORKING-TREE ROOT,
   * not against the .git directory. This resolved against the .git
   * directory until a review caught it: husky 9 sets exactly this shape
   * (core.hooksPath=.husky/_), so a repository using husky 9 had its hook
   * written to a path git never reads, reported as installed, and never
   * ran. Verified by driving a real commit rather than by re-reading the
   * documentation that was misread the first time: with
   * core.hooksPath=.husky/_ and an executable hook planted at BOTH
   * .husky/_/pre-commit and .git/.husky/_/pre-commit, a commit runs the
   * former. pre-commit-hook.test.ts pins it the same way.
   *
   * An ABSOLUTE \`core.hooksPath\` is used exactly as given, and no
   * \`core.hooksPath\` at all still resolves against the git directory
   * (never the working-tree root) -- both of those are unaffected by the
   * bug above and must stay that way: a linked worktree or a submodule
   * has its own git directory that is not its working-tree root, and that
   * is precisely where an unset \`core.hooksPath\` needs to keep pointing.
   */
  getEffectiveHooksDir(cwd: string): { hooksDir: string; viaHooksPath: boolean } {
    const gitDirAbs = this.resolveGitDir(cwd);
    if (!gitDirAbs) {
      return { hooksDir: path.join(cwd, '.git', 'hooks'), viaHooksPath: false };
    }

    let hooksPath = '';
    try {
      hooksPath = execSync('git config --get core.hooksPath', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
    } catch {
      hooksPath = '';
    }

    if (!hooksPath) {
      return { hooksDir: path.join(gitDirAbs, 'hooks'), viaHooksPath: false };
    }

    if (path.isAbsolute(hooksPath)) {
      return { hooksDir: hooksPath, viaHooksPath: true };
    }

    const worktreeRoot = this.resolveWorktreeRoot(cwd) ?? cwd;
    return { hooksDir: path.join(worktreeRoot, hooksPath), viaHooksPath: true };
  }

  /**
   * Whether the resolved hooks directory is husky 9's GENERATED,
   * gitignored directory (\`.husky/_\` by default) rather than a real
   * hooks directory. Husky's own prepare script rewrites this directory on
   * every \`pnpm install\`, so nothing vault-guard writes there survives;
   * the durable, tracked hook lives one directory up at
   * \`.husky/<hookname>\`.
   *
   * This is deliberately narrow: the ONLY signal that may trigger the
   * redirect is the directory SHAPE -- a resolved basename of \`_\` under a
   * directory literally named \`.husky\`. Two false-positive shapes were
   * caught by review before shipping and must never redirect:
   *  - core.hooksPath pointing at an unrelated directory (e.g. .githooks)
   *    that happens to contain a file literally named \`h\` -- an \`h\` file
   *    is not evidence of husky on its own, only the directory shape is;
   *  - a dispatcher-shaped pre-commit file (the same two-line shebang
   *    body husky 9 writes) sitting somewhere that is NOT \`.husky/_\`
   *    (e.g. plain \`.git/hooks/pre-commit\`) -- content shape alone is not
   *    evidence either, since a foreign hook can coincidentally look like
   *    this.
   * Neither the \`h\` shim nor dispatcher-shaped content is checked at all
   * here; they would only ever have been used to confirm a shape match,
   * never to trigger one on their own, and the shape check alone is both
   * necessary and sufficient for every case this fix needs to handle.
   */
  isHuskyGeneratedHooksDir(hooksDir: string): boolean {
    const base = path.basename(hooksDir);
    const parentBase = path.basename(path.dirname(hooksDir));
    return base === '_' && parentBase === '.husky';
  }

  /**
   * Where husky's own \`h\` shim actually resolves and executes the tracked
   * hook, given a husky-generated hooksDir (isHuskyGeneratedHooksDir(hooksDir)
   * must already be true). Husky computes this as the PARENT of the
   * generated \`_\` directory -- fixed relative to hooksDir, never a fixed
   * \`<cwd>/.husky\`, because core.hooksPath can point at a NESTED
   * \`.husky/_\` (e.g. \`packages/app/.husky/_\`, the ordinary shape for a
   * monorepo package that owns husky's "prepare" script but is not itself
   * the git root). In that case husky's shim genuinely runs
   * \`packages/app/.husky/<hookname>\`, not \`<cwd>/.husky/<hookname>\` --
   * proven wrong by independent review with a functional shim and a real
   * commit before this was fixed. getPreCommitHookPath, installNative,
   * uninstallNative, and getPreCommitCmdPath all resolve through this one
   * place so the redirect target can never drift between them.
   */
  private resolveHuskyDir(hooksDir: string): string {
    return path.dirname(hooksDir);
  }

  /** \`absPath\`, relative to \`cwd\`, with forward slashes on every platform. */
  private relFromCwd(cwd: string, absPath: string): string {
    return path.relative(cwd, absPath).split(path.sep).join('/');
  }

  /**
   * Absolute path to the \`pre-commit\` hook file for the given manager.
   *
   * For the \`native\` manager, when the resolved hooks directory is
   * husky 9's generated directory (see isHuskyGeneratedHooksDir), this
   * resolves to the TRACKED hook file husky's own \`h\` shim actually runs
   * -- see resolveHuskyDir -- because nothing written under the generated
   * directory survives husky's prepare script. See install()'s
   * husky-delegation in installNative for the write side of this.
   */
  getPreCommitHookPath(cwd: string, manager: HookManager = 'native'): string {
    if (manager === 'husky') {
      return path.join(cwd, '.husky', 'pre-commit');
    }
    const { hooksDir } = this.getEffectiveHooksDir(cwd);
    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      return path.join(this.resolveHuskyDir(hooksDir), 'pre-commit');
    }
    return path.join(hooksDir, 'pre-commit');
  }

  /**
   * Absolute path to the Windows \`pre-commit.cmd\` companion (native manager
   * only). \`undefined\` under a husky-generated hooks directory: the .cmd
   * companion is native-only and installNative's husky-redirect never
   * writes one there (see installNative), so there is no meaningful path
   * to report. Callers that used to guard this getter with their own
   * isHuskyGeneratedHooksDir check (the CLI's foreignHookConflict did)
   * can drop that guard now that it lives here instead.
   */
  getPreCommitCmdPath(cwd: string): string | undefined {
    const { hooksDir } = this.getEffectiveHooksDir(cwd);
    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      return undefined;
    }
    return path.join(hooksDir, 'pre-commit.cmd');
  }

  install(options: InstallHookOptions = {}): { success: boolean; message: string; hookPath?: string } {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';

    if (!fs.existsSync(path.join(cwd, '.git'))) {
      return { success: false, message: 'Not a git repository' };
    }

    switch (manager) {
      case 'native':
        return this.installNative(cwd);
      case 'husky':
        return this.installHusky(cwd);
      case 'lefthook':
        return this.installLefthook(cwd);
      case 'precommit':
        return this.installPreCommitFramework(cwd);
      default:
        return { success: false, message: `Unknown hook manager: ${String(manager)}` };
    }
  }

  uninstall(options: InstallHookOptions = {}): { success: boolean; message: string } {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';

    if (!fs.existsSync(path.join(cwd, '.git'))) {
      return { success: false, message: 'Not a git repository' };
    }

    switch (manager) {
      case 'native':
        return this.uninstallNative(cwd);
      case 'husky':
        return this.uninstallHusky(cwd);
      case 'lefthook':
        return this.uninstallLefthook(cwd);
      case 'precommit':
        return this.uninstallPreCommitFramework(cwd);
      default:
        return { success: false, message: `Unknown hook manager: ${String(manager)}` };
    }
  }

  isInstalled(options: InstallHookOptions = {}): boolean {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';
    const hookPath = this.getPreCommitHookPath(cwd, manager);

    if (!fs.existsSync(hookPath)) return false;
    const content = fs.readFileSync(hookPath, 'utf-8');
    return content.includes('vault-guard') && content.includes('scan --staged');
  }

  // -------------------------------------------------------------------------
  // native (Git hooks / core.hooksPath)
  // -------------------------------------------------------------------------

  /**
   * Write or refresh our `pre-commit.cmd`. Never overwrites a foreign file.
   * @returns whether our companion is present afterwards
   */
  private writeNativeCmdCompanion(hooksDir: string): boolean {
    const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
    if (fs.existsSync(cmdPath)) {
      const existing = fs.readFileSync(cmdPath, 'utf-8');
      const isOurs =
        existing.includes('vault-guard') && existing.includes('scan --staged');
      if (!isOurs) {
        return false;
      }
    }
    fs.writeFileSync(cmdPath, NATIVE_HOOK_CMD, { encoding: 'utf-8' });
    return true;
  }

  private removeNativeCmdCompanion(hooksDir: string): boolean {
    const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
    if (!fs.existsSync(cmdPath)) return false;
    const content = fs.readFileSync(cmdPath, 'utf-8');
    if (!content.includes('vault-guard') || !content.includes('scan --staged')) {
      return false;
    }
    fs.unlinkSync(cmdPath);
    return true;
  }

  private installNative(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const { hooksDir, viaHooksPath } = this.getEffectiveHooksDir(cwd);

    // core.hooksPath points at husky 9's generated, gitignored directory
    // (typically .husky/_, but see resolveHuskyDir for the nested case).
    // Writing there is pointless -- husky's prepare script rewrites it on
    // every `pnpm install` -- so install into the same tracked hook file
    // the husky manager uses, and say so. Never write under the generated
    // directory in this branch.
    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      const huskyDir = this.resolveHuskyDir(hooksDir);
      const result = this.installHusky(cwd, huskyDir);
      if (!result.success) {
        return result;
      }
      const relHookPath = this.relFromCwd(cwd, result.hookPath ?? path.join(huskyDir, 'pre-commit'));
      return {
        success: true,
        message: `Hooks are managed by husky; installing into ${relHookPath}. ${result.message}`,
        hookPath: result.hookPath,
      };
    }

    const hookPath = path.join(hooksDir, 'pre-commit');
    const cmdPath = path.join(hooksDir, 'pre-commit.cmd');

    try {
      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }

      if (fs.existsSync(hookPath)) {
        const existing = fs.readFileSync(hookPath, 'utf-8');
        if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
          // Refresh the Windows companion if missing or stale (never clobber foreign).
          const cmdOk = this.writeNativeCmdCompanion(hooksDir);
          return {
            success: true,
            message: cmdOk
              ? 'Hook already installed (POSIX + Windows .cmd companion)'
              : fs.existsSync(cmdPath)
                ? 'Hook already installed (left foreign pre-commit.cmd untouched)'
                : 'Hook already installed',
            hookPath,
          };
        }
      }

      fs.writeFileSync(hookPath, NATIVE_HOOK_SCRIPT, { mode: 0o755 });
      const cmdOk = this.writeNativeCmdCompanion(hooksDir);

      const hint = viaHooksPath
        ? `Installed to hooksPath: ${hooksDir}`
        : cmdOk
          ? 'Installed to .git/hooks/pre-commit (+ pre-commit.cmd)'
          : 'Installed to .git/hooks/pre-commit';

      return {
        success: true,
        message: `Pre-commit hook installed (${hint})`,
        hookPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to install hook: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallNative(cwd: string): { success: boolean; message: string } {
    const { hooksDir } = this.getEffectiveHooksDir(cwd);

    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      const huskyDir = this.resolveHuskyDir(hooksDir);
      const result = this.uninstallHusky(cwd, huskyDir);
      return {
        success: result.success,
        message: `Hooks are managed by husky; ${result.message}`,
      };
    }

    const hookPath = path.join(hooksDir, 'pre-commit');
    const cmdRemoved = this.removeNativeCmdCompanion(hooksDir);

    if (!fs.existsSync(hookPath)) {
      return {
        success: true,
        message: cmdRemoved
          ? 'Removed Windows pre-commit.cmd companion'
          : 'No hook to remove',
      };
    }

    const content = fs.readFileSync(hookPath, 'utf-8');
    if (!content.includes('vault-guard')) {
      return {
        success: true,
        message: cmdRemoved
          ? 'Removed Windows pre-commit.cmd companion'
          : 'No vault-guard hook to remove',
      };
    }

    try {
      fs.unlinkSync(hookPath);
      return {
        success: true,
        message: cmdRemoved
          ? 'Pre-commit hook and Windows .cmd companion removed'
          : 'Pre-commit hook removed',
      };
    } catch (error) {
      const hookError = new HookError(`Failed to remove hook: ${error}`, 'uninstall');
      return { success: false, message: hookError.message };
    }
  }

  // -------------------------------------------------------------------------
  // Husky -- .husky/pre-commit
  // -------------------------------------------------------------------------

  /**
   * @param huskyDir Directory holding the tracked hook. Defaults to
   *   \`<cwd>/.husky\`, correct for the explicit \`husky\` manager (it never
   *   consults core.hooksPath). installNative's redirect passes the
   *   ACTUAL directory resolveHuskyDir computed instead, which can be
   *   nested (e.g. \`packages/app/.husky\`) -- see resolveHuskyDir.
   */
  private installHusky(
    cwd: string,
    huskyDir: string = path.join(cwd, '.husky'),
  ): { success: boolean; message: string; hookPath?: string } {
    const hookPath = path.join(huskyDir, 'pre-commit');
    const relHookPath = this.relFromCwd(cwd, hookPath);

    try {
      if (!fs.existsSync(huskyDir)) {
        fs.mkdirSync(huskyDir, { recursive: true });
      }

      if (fs.existsSync(hookPath)) {
        const existing = fs.readFileSync(hookPath, 'utf-8');
        if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
          return { success: true, message: 'Husky hook already contains vault-guard', hookPath };
        }
        if (existing.includes('# --- vault-guard ---')) {
          return { success: true, message: 'Husky hook already contains vault-guard block', hookPath };
        }
        fs.appendFileSync(
          hookPath,
          `\n# --- vault-guard ---\nvault-guard scan --staged || {\n  echo "❌ vault-guard blocked commit"\n  exit 1\n}\n`,
          { encoding: 'utf-8' },
        );
        return { success: true, message: `Appended vault-guard to existing ${relHookPath}`, hookPath };
      }

      fs.writeFileSync(hookPath, HUSKY_HOOK_SCRIPT, { mode: 0o755 });
      return {
        success: true,
        message: `Created ${relHookPath} (run \`npx husky init\` first if _/husky.sh is missing)`,
        hookPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to install Husky hook: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  /**
   * @param huskyDir See installHusky.
   *
   * Fix for a defect the reviewer found while checking uninstall after
   * the redirect started routing every husky 9 repo through this
   * function (previously only reachable via the explicit `husky`
   * manager): when installHusky wrote the WHOLE file from
   * HUSKY_HOOK_SCRIPT (the fresh-install path -- what both the redirect
   * and a from-scratch \`--manager husky\` install take), there is no
   * "# --- vault-guard ---" appended-block marker to strip, so the old
   * logic here matched nothing, rewrote the file byte-identical, and
   * reported success:true with isInstalled still true. Distinguishing
   * the two shapes vault-guard itself ever produces -- the whole-file
   * header vs. the appended-stanza marker -- fixes this: a whole-file
   * hook is removed entirely; an appended stanza is stripped, keeping
   * the pre-existing foreign content; anything else that merely mentions
   * "vault-guard" in neither recognized shape is left untouched, with an
   * honest message and success only if it happens not to still read as
   * installed.
   */
  private uninstallHusky(
    cwd: string,
    huskyDir: string = path.join(cwd, '.husky'),
  ): { success: boolean; message: string } {
    const hookPath = path.join(huskyDir, 'pre-commit');
    const relHookPath = this.relFromCwd(cwd, hookPath);
    if (!fs.existsSync(hookPath)) {
      return { success: true, message: `No ${relHookPath} to remove` };
    }

    const content = fs.readFileSync(hookPath, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: `No vault-guard stanza in ${relHookPath}` };
    }

    // vault-guard wrote the ENTIRE file from HUSKY_HOOK_SCRIPT (whether
    // via a fresh --manager husky install or the native husky-redirect):
    // it is safe, and correct, to remove the file outright rather than
    // try to strip individual lines from a template vault-guard owns.
    if (content.includes(VAULT_GUARD_HOOK_HEADER)) {
      fs.unlinkSync(hookPath);
      return { success: true, message: `Removed ${relHookPath}` };
    }

    // vault-guard appended a stanza to a pre-existing (foreign) hook: strip
    // just that stanza, preserving whatever the file had before.
    if (content.includes('# --- vault-guard ---')) {
      const stripped = content.replace(/\n# --- vault-guard ---[\s\S]*$/m, '');
      if (stripped.trim().length === 0) {
        fs.unlinkSync(hookPath);
        return { success: true, message: `Removed ${relHookPath}` };
      }
      fs.writeFileSync(hookPath, stripped, { mode: 0o755 });
      const stillInstalled = stripped.includes('vault-guard') && stripped.includes('scan --staged');
      return {
        success: !stillInstalled,
        message: stillInstalled
          ? `Removed the appended stanza from ${relHookPath}, but it still references vault-guard -- review manually`
          : `Removed vault-guard stanza from ${relHookPath}`,
      };
    }

    // Mentions "vault-guard" somewhere, but in NEITHER shape vault-guard
    // itself ever writes (no whole-file header, no appended-stanza
    // marker) -- do not guess at what to remove from a file this code did
    // not write; leave it untouched and say so honestly. Report success
    // only if it does not still read as installed (isInstalled uses the
    // same two-substring check).
    const stillInstalled = content.includes('vault-guard') && content.includes('scan --staged');
    return {
      success: !stillInstalled,
      message: `${relHookPath} mentions vault-guard but does not match the shape this version writes; it may have been written by an older vault-guard, or by hand. Leaving it unchanged. Review and remove the vault-guard reference manually if needed.`,
    };
  }

  // -------------------------------------------------------------------------
  // Lefthook -- lefthook-local.yml (merged with lefthook.yml)
  // -------------------------------------------------------------------------

  private installLefthook(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    try {
      if (fs.existsSync(localPath)) {
        const existing = fs.readFileSync(localPath, 'utf-8');
        if (existing.includes('vault-guard scan --staged')) {
          return { success: true, message: 'lefthook-local.yml already configures vault-guard', hookPath: localPath };
        }
        return {
          success: false,
          message:
            'lefthook-local.yml already exists. Add under pre-commit.commands:\n' +
            '  vault-guard:\n    run: vault-guard scan --staged\n',
        };
      }
      fs.writeFileSync(localPath, LEFTHOOK_LOCAL, 'utf-8');
      return {
        success: true,
        message: 'Wrote lefthook-local.yml (merged by Lefthook with lefthook.yml). Run: lefthook install',
        hookPath: localPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to write lefthook-local.yml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallLefthook(cwd: string): { success: boolean; message: string } {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    if (!fs.existsSync(localPath)) {
      return { success: true, message: 'No lefthook-local.yml' };
    }
    const content = fs.readFileSync(localPath, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: 'lefthook-local.yml does not reference vault-guard' };
    }
    // Only remove the file if it is exactly what we wrote (avoid deleting user merges).
    if (content.replace(/\r\n/g, '\n').trim() !== LEFTHOOK_LOCAL.replace(/\r\n/g, '\n').trim()) {
      return {
        success: true,
        message: 'lefthook-local.yml was edited -- remove the vault-guard stanza manually',
      };
    }
    try {
      fs.unlinkSync(localPath);
      return { success: true, message: 'Removed lefthook-local.yml (vault-guard stub)' };
    } catch (error) {
      const hookError = new HookError(`Failed to remove lefthook-local.yml: ${error}`, 'uninstall');
      return { success: false, message: hookError.message };
    }
  }

  // -------------------------------------------------------------------------
  // pre-commit.com framework
  // -------------------------------------------------------------------------

  private installPreCommitFramework(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const cfg = path.join(cwd, '.pre-commit-config.yaml');
    if (fs.existsSync(cfg)) {
      const existing = fs.readFileSync(cfg, 'utf-8');
      if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
        return { success: true, message: '.pre-commit-config.yaml already includes vault-guard', hookPath: cfg };
      }
      return {
        success: false,
        message:
          '.pre-commit-config.yaml already exists. Merge manually:\n\n' +
          PRE_COMMIT_CONFIG +
          '\n(under your existing `repos:` list as an additional item, or combine with `repo: local`)',
      };
    }
    try {
      fs.writeFileSync(cfg, PRE_COMMIT_CONFIG, 'utf-8');
      return {
        success: true,
        message: 'Created .pre-commit-config.yaml -- run: pre-commit install',
        hookPath: cfg,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to write .pre-commit-config.yaml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallPreCommitFramework(cwd: string): { success: boolean; message: string } {
    const cfg = path.join(cwd, '.pre-commit-config.yaml');
    if (!fs.existsSync(cfg)) {
      return { success: true, message: 'No .pre-commit-config.yaml' };
    }
    const content = fs.readFileSync(cfg, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: '.pre-commit-config.yaml does not reference vault-guard' };
    }
    // Only delete if we created the minimal file (only our hook).
    if (content.includes('id: vault-guard') && content.split('\n').length < 25) {
      try {
        fs.unlinkSync(cfg);
        return { success: true, message: 'Removed .pre-commit-config.yaml (vault-guard-only stub)' };
      } catch (error) {
        const hookError = new HookError(`Failed to remove config: ${error}`, 'uninstall');
        return { success: false, message: hookError.message };
      }
    }
    return {
      success: true,
      message: 'Edit .pre-commit-config.yaml manually to remove the vault-guard hook entry',
    };
  }

  private resolveGitDir(cwd: string): string | null {
    try {
      const rel = execSync('git rev-parse --git-dir', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      return path.resolve(cwd, rel);
    } catch {
      return null;
    }
  }

  /**
   * The working-tree root, or null when it cannot be determined. Asked of
   * git rather than assumed to be \`cwd\`, so a relative \`core.hooksPath\`
   * resolves correctly when \`install\`/\`getEffectiveHooksDir\` is called
   * from a subdirectory of the repository.
   */
  private resolveWorktreeRoot(cwd: string): string | null {
    try {
      const rel = execSync('git rev-parse --show-toplevel', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      return path.resolve(cwd, rel);
    } catch {
      return null;
    }
  }
}
