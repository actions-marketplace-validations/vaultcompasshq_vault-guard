import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { PreCommitHook } from '@vaultcompass/vault-guard-core';
import {
  applyInit,
  initCommand,
  planInit,
  revertInit,
} from '../commands/init';
import {
  ACTION_TAG,
  UPLOAD_SARIF_SHA,
  MANIFEST_RELATIVE_PATH,
  defaultVaultGuardConfigJson,
  githubWorkflowYaml,
  templateContentForPath,
} from '../init/templates';
import { readCliVersion } from '../version';

function git(args: string[], cwd: string): void {
  const result = spawnSync('git', args, { cwd, stdio: 'ignore' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed in ${cwd}`);
  }
}

describe('vault-guard init', () => {
  let testDir: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    // fs.realpathSync.native canonicalizes the temp dir right away: on
    // Windows, mkdtempSync can hand back an 8.3 short-form path
    // (C:\Users\RUNNER~1\...) while product code resolves the same
    // directory to its long form (C:\Users\runneradmin\...) when building
    // hook paths. Canonicalizing testDir once here keeps every test in
    // this file comparing like with like instead of two spellings of the
    // same path.
    testDir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-init-')));
    git(['init', '-q'], testDir);
    git(['config', '--local', 'core.hooksPath', 'hooks'], testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('dry-run prints manifest without writing files', async () => {
    const code = await initCommand({ cwd: testDir, dryRun: true });
    expect(code).toBe(0);

    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(false);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(false);

    const plan = planInit({ cwd: testDir, dryRun: true });
    expect(plan.ok).toBe(true);
    expect(plan.actions.some(a => a.kind === 'create')).toBe(true);
    expect(plan.actions.some(a => a.path === '.vault-guard.json')).toBe(true);
  });

  it('default config scans test trees but keeps fixtures/bench ignored', () => {
    // Behaviour change: the init default no longer ignores `**/__tests__/**`,
    // so a real vendor-anchored key in a test file is scanned (and blocks)
    // rather than being skipped wholesale. `fixtures/**` and `bench/fixtures/**`
    // stay ignored because those trees hold deliberately-planted contiguous
    // credential fixtures that vendor rules never downgrade.
    const parsed = JSON.parse(defaultVaultGuardConfigJson()) as {
      ignore: { patterns: string[] };
    };
    expect(parsed.ignore.patterns).not.toContain('**/__tests__/**');
    expect(parsed.ignore.patterns).toContain('fixtures/**');
    expect(parsed.ignore.patterns).toContain('bench/fixtures/**');
  });

  it('creates managed files and manifest on first run', async () => {
    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(0);

    expect(fs.readFileSync(path.join(testDir, '.vault-guard.json'), 'utf8')).toBe(
      defaultVaultGuardConfigJson(),
    );
    expect(fs.existsSync(path.join(testDir, '.github/workflows/vault-guard.yml'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, '.vault-guard/mcp-snippet.json'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, '.vault-guard/agent-rules.md'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(true);

    const hook = new PreCommitHook();
    expect(hook.isInstalled({ cwd: testDir, manager: 'native' })).toBe(true);
  });

  it('is idempotent on second run', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);
    const manifestMtime = fs.statSync(path.join(testDir, MANIFEST_RELATIVE_PATH)).mtimeMs;

    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(0);

    const plan = planInit({ cwd: testDir });
    expect(plan.alreadyInitialized).toBe(true);
    expect(fs.statSync(path.join(testDir, MANIFEST_RELATIVE_PATH)).mtimeMs).toBe(manifestMtime);
  });

  it('conflicts when a managed file exists with foreign content', async () => {
    fs.writeFileSync(path.join(testDir, '.vault-guard.json'), '{"foreign": true}\n');

    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(2);

    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(false);
  });

  it('reverts manifest-tracked files and hook', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);
    expect(await initCommand({ cwd: testDir, revert: true })).toBe(0);

    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(false);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(false);

    const hook = new PreCommitHook();
    expect(hook.isInstalled({ cwd: testDir, manager: 'native' })).toBe(false);
  });

  it('revert dry-run does not delete files', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);
    expect(await initCommand({ cwd: testDir, revert: true, dryRun: true })).toBe(0);

    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(true);
  });

  it('emits JSON manifest in --json mode', async () => {
    const logs: string[] = [];
    const spy = jest.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      logs.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      return true;
    });

    try {
      const code = await initCommand({ cwd: testDir, dryRun: true, json: true });
      expect(code).toBe(0);
      const payload = JSON.parse(logs.join(''));
      expect(payload.ok).toBe(true);
      expect(payload.manifestPath).toBe(MANIFEST_RELATIVE_PATH);
      expect(Array.isArray(payload.actions)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('applyInit does not run when plan has conflicts', () => {
    fs.writeFileSync(path.join(testDir, '.vault-guard.json'), 'not-json\n');
    const plan = planInit({ cwd: testDir });
    expect(plan.ok).toBe(false);
    applyInit(plan, { cwd: testDir });
    expect(fs.existsSync(path.join(testDir, '.github/workflows/vault-guard.yml'))).toBe(false);
  });

  it('skip flags omit optional artifacts from the plan', () => {
    const plan = planInit({
      cwd: testDir,
      skipWorkflow: true,
      skipConfig: true,
      skipAgentRules: true,
      skipHook: true,
    });
    expect(plan.actions.map(a => a.path)).not.toContain('.vault-guard.json');
    expect(plan.actions.map(a => a.path)).not.toContain('.github/workflows/vault-guard.yml');
    expect(plan.actions.map(a => a.path)).not.toContain('.vault-guard/mcp-snippet.json');
  });

  it('hook-install action carries a repo-relative path, consistent with create actions', () => {
    // Review item 4 (cosmetic): the hook-install action used to carry the
    // ABSOLUTE hook path while every 'create' action carries a
    // repo-relative one (e.g. '.vault-guard.json') -- inconsistent within
    // the same actions array, and it leaks the host's temp-dir/home-dir
    // layout into --json output for no reason.
    const plan = planInit({ cwd: testDir });

    const hookInstallAction = plan.actions.find(a => a.kind === 'hook-install');
    expect(hookInstallAction).toBeDefined();
    expect(path.isAbsolute(hookInstallAction!.path)).toBe(false);
    expect(hookInstallAction!.path.startsWith(testDir)).toBe(false);

    const createAction = plan.actions.find(a => a.kind === 'create');
    expect(createAction).toBeDefined();
    expect(path.isAbsolute(createAction!.path)).toBe(false);
  });

  it('the already-installed hook skip action also carries a repo-relative path', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);

    const plan = planInit({ cwd: testDir });
    expect(plan.alreadyInitialized).toBe(true);

    const hookSkipAction = plan.actions.find(
      a => a.kind === 'skip' && a.detail === 'hook already installed',
    );
    expect(hookSkipAction).toBeDefined();
    expect(path.isAbsolute(hookSkipAction!.path)).toBe(false);
    expect(hookSkipAction!.path.startsWith(testDir)).toBe(false);
  });

  it('revertInit fails without manifest', () => {
    const result = revertInit({ cwd: testDir });
    expect(result.ok).toBe(false);
  });

  it('reports not_a_git_repository when hook required outside git', async () => {
    const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-init-nogit-'));
    try {
      const code = await initCommand({ cwd: nonGit, skipHook: false });
      expect(code).toBe(2);
    } finally {
      fs.rmSync(nonGit, { recursive: true, force: true });
    }
  });

  it('allows file-only init outside git when hook skipped', async () => {
    const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-init-nogit-'));
    try {
      const code = await initCommand({ cwd: nonGit, skipHook: true });
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(nonGit, '.vault-guard.json'))).toBe(true);
    } finally {
      fs.rmSync(nonGit, { recursive: true, force: true });
    }
  });

  it('conflicts when a foreign pre-commit hook already exists', async () => {
    const hook = new PreCommitHook();
    const hookPath = hook.getPreCommitHookPath(testDir, 'native');
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, '#!/bin/sh\necho custom-hook\n', { mode: 0o755 });

    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(2);
    expect(fs.readFileSync(hookPath, 'utf8')).toContain('custom-hook');
    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(false);
  });

  it('conflict dry-run still exits 2', async () => {
    const workflowPath = path.join(testDir, '.github/workflows/vault-guard.yml');
    fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
    fs.writeFileSync(
      workflowPath,
      templateContentForPath('.github/workflows/vault-guard.yml').replace('main', 'develop'),
    );
    const code = await initCommand({ cwd: testDir, dryRun: true });
    expect(code).toBe(2);
  });

  it('advises when husky is present but native manager is selected', () => {
    fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
    const plan = planInit({ cwd: testDir, manager: 'native' });
    expect(plan.advisories.some(a => a.manager === 'husky')).toBe(true);
    expect(plan.advisories.find(a => a.manager === 'husky')?.guidance).toMatch(/husky/i);
  });

  it('the husky advisory no longer claims native hooks may not run: that was the bug this branch fixed', () => {
    // The native manager now detects husky's generated hooksPath shape
    // and installs into the tracked file automatically -- the old
    // guidance describing that as a limitation is exactly the bug this
    // branch fixes, and would mislead a user who already has the fix.
    fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
    const plan = planInit({ cwd: testDir, manager: 'native' });
    const guidance = plan.advisories.find(a => a.manager === 'husky')?.guidance;
    expect(guidance).toBeDefined();
    expect(guidance).not.toMatch(/may not run/i);
    expect(guidance).toMatch(/automatic/i);
  });

  it('does not advise husky when manager is husky', () => {
    fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
    const plan = planInit({ cwd: testDir, manager: 'husky', skipHook: true });
    expect(plan.advisories.some(a => a.manager === 'husky')).toBe(false);
  });

  it('advises when lefthook.yml exists under native manager', () => {
    fs.writeFileSync(path.join(testDir, 'lefthook.yml'), 'pre-commit:\n  commands: {}\n');
    const plan = planInit({ cwd: testDir, manager: 'native' });
    expect(plan.advisories.some(a => a.manager === 'lefthook')).toBe(true);
  });

  it('conflicts on foreign lefthook-local.yml when manager is lefthook', () => {
    fs.writeFileSync(path.join(testDir, 'lefthook-local.yml'), 'pre-commit:\n  commands:\n    other:\n      run: echo hi\n');
    const plan = planInit({ cwd: testDir, manager: 'lefthook', skipConfig: true, skipWorkflow: true, skipAgentRules: true });
    expect(plan.ok).toBe(false);
    expect(plan.conflicts.some(c => c.path === 'lefthook-local.yml' && c.reason === 'foreign_hook')).toBe(true);
  });

  it('pins the workflow template to the Action tag, which is not the package version', () => {
    const yaml = githubWorkflowYaml();
    const match = yaml.match(/uses: vaultcompasshq\/vault-guard@(\S+)/);
    expect(match).not.toBeNull();
    const pin = (match as RegExpMatchArray)[1];

    // Shape guard first: this must always look like a real semver tag, not e.g.
    // an empty string or "vundefined".
    expect(pin).toMatch(/^v\d+\.\d+\.\d+$/);

    // Then the actual pin, which comes from ACTION_TAG and DELIBERATELY not
    // from readCliVersion().
    //
    // This test used to assert `v${readCliVersion()}`, and 1.7.1 is where that
    // became wrong: an action-only release moves the tag and leaves the
    // packages alone, so the derived pin would have scaffolded `@v1.7.0` — the
    // action that installs its scanner from inside the tree it scans — into
    // every repository that ran `vault-guard init` after the release. The tag
    // says which version of the workflow step; the package version says which
    // scanner. They are allowed to differ and here they do.
    expect(pin).toBe(ACTION_TAG);
    // A real tag is at or ahead of the packages, never behind: behind means
    // somebody derived it from the package version again, or bumped the
    // packages and forgot to move the tag.
    const order = (a: number[], b: number[]): number =>
      a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
    const tagParts = pin.slice(1).split('.').map(Number);
    const pkgParts = readCliVersion().split('.').map(Number);
    expect([pin, readCliVersion(), order(tagParts, pkgParts) >= 0]).toEqual([
      pin,
      readCliVersion(),
      true,
    ]);
  });

  it('keeps ACTION_TAG in step with the newest CHANGELOG release', () => {
    // The staleness this cannot otherwise catch: a SECOND action-only release
    // moves the tag and the CHANGELOG, and nothing makes anybody open
    // templates.ts. The scaffold would then keep handing new repositories the
    // previous Action — which for 1.7.1 specifically means the one that
    // installs its scanner from inside the tree it scans.
    //
    // The newest `## [X.Y.Z]` heading is the release this working tree
    // describes; `## [Unreleased]` is skipped because it is not a release.
    const changelog = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', '..', 'CHANGELOG.md'),
      'utf-8',
    );
    const newest = changelog.match(/^## \[(\d+\.\d+\.\d+)\]/m);
    expect(newest).not.toBeNull();
    expect(ACTION_TAG).toBe(`v${(newest as RegExpMatchArray)[1]}`);
  });

  it('scaffolds the guarded upload shape, with the uploader pinned to a SHA', () => {
    // The generated workflow has to be the shape the docs tell people to write.
    // A bare `if: always()` upload fails the job on the empty file a
    // could-not-run scan leaves behind, with a SARIF parse error sitting on top
    // of the real message — the exact confusion the non-empty `results-file`
    // output was added to remove.
    const yaml = githubWorkflowYaml();
    expect(yaml).toContain('id: vault-guard');
    expect(yaml).toContain("if: always() && steps.vault-guard.outputs.results-file != ''");
    expect(yaml).toContain('sarif_file: ${{ steps.vault-guard.outputs.results-file }}');

    // And the uploader is pinned to a commit, not to `v3`. It runs in the
    // consumer's repository with the consumer's `security-events: write`, so a
    // mutable tag there is the same bet the `version` input stopped taking.
    const uses = yaml.match(/uses:\s*(\S+)/g) ?? [];
    expect(uses.length).toBeGreaterThan(0);
    for (const entry of uses) {
      const ref = entry.replace(/^uses:\s*/, '');
      // The action's own tag is a release tag by design; everything else is a
      // third-party action and must be a full SHA.
      if (ref.startsWith('vaultcompasshq/vault-guard@')) continue;
      expect([ref, /@[0-9a-f]{40}$/.test(ref)]).toEqual([ref, true]);
    }
  });

  it('scaffolds the permissions the upload step needs, and no more', () => {
    // The generated workflow uploads SARIF, and the default GITHUB_TOKEN is
    // read-only: without this block the upload fails with a 403 that says
    // nothing about the scan, on the first run, in every repository that ran
    // init. Narrow on purpose too -- this job reads code and writes one
    // code-scanning log.
    const yaml = githubWorkflowYaml();
    expect(yaml).toContain('permissions:');
    expect(yaml).toContain('contents: read');
    expect(yaml).toContain('security-events: write');
    expect(yaml).not.toContain('permissions: write-all');
  });

  it('pins the uploader to the same SHA this repository pins', () => {
    // Two spellings of one decision drift. ci.yml is where this repository
    // decided which upload-sarif commit it trusts; the scaffold hands that same
    // commit to every consumer, so it reads the value rather than carrying a
    // second copy of it that nobody diffs.
    const ci = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', '..', '.github', 'workflows', 'ci.yml'),
      'utf-8',
    );
    const pinned = ci.match(/github\/codeql-action\/upload-sarif@([0-9a-f]{40})/);
    expect(pinned).not.toBeNull();
    expect(UPLOAD_SARIF_SHA).toBe((pinned as RegExpMatchArray)[1]);
    expect(githubWorkflowYaml()).toContain(
      `github/codeql-action/upload-sarif@${UPLOAD_SARIF_SHA}`,
    );
  });

  it('scaffolds no `version` input, because the Action tag carries the scanner pin', () => {
    // `version: latest` was in this template and is now REFUSED by the action:
    // a dist-tag hands the choice of scanner to the registry on the morning of
    // the run. A generated workflow that fails on its first run is worse than
    // the thing it was generated for, so the input is gone rather than pinned
    // to a number that would then be a second pin to keep in step with the tag.
    const yaml = githubWorkflowYaml();
    expect(yaml).not.toMatch(/^\s*version:\s*latest\s*$/m);
    expect(yaml).not.toMatch(/^\s*version:\s/m);
  });

  describe('husky-generated hooks dir (husky 9)', () => {
    // Same husky 9 shape as the core package's fixture: core.hooksPath is
    // the generated, gitignored .husky/_ directory; the tracked hook lives
    // one directory up at .husky/<hookname>.
    function buildHusky9Layout(dir: string, options: { absoluteHooksPath?: boolean } = {}): void {
      const genDir = path.join(dir, '.husky', '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, '.gitignore'), '*\n');
      fs.writeFileSync(
        path.join(genDir, 'h'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/../pre-commit"\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(genDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        { mode: 0o755 },
      );
      // Absolute core.hooksPath is used exactly as given (no
      // git-rev-parse-based worktree-root resolution), so a test that
      // compares the RELATIVE conflict path string stays clean even on a
      // host (macOS) where the OS temp dir is itself behind a symlink;
      // see the "false positives" describe block above for the same
      // workaround and why it is needed.
      const hooksPathValue = options.absoluteHooksPath ? genDir : '.husky/_';
      git(['config', '--local', 'core.hooksPath', hooksPathValue], dir);
    }

    it('bare init lands the vault-guard stanza in .husky/pre-commit, not .husky/_', async () => {
      buildHusky9Layout(testDir);

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(code).toBe(0);

      const trackedPath = path.join(testDir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);
      expect(fs.readFileSync(trackedPath, 'utf-8')).toContain('scan --staged');
    });

    it('never writes under .husky/_ during init', async () => {
      buildHusky9Layout(testDir);
      const before = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();

      await initCommand({ cwd: testDir, skipConfig: true, skipWorkflow: true, skipAgentRules: true });

      const after = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();
      expect(after).toEqual(before);
    });

    it('bare init reports already installed when .husky/pre-commit already has the vault-guard stanza', () => {
      buildHusky9Layout(testDir);
      fs.writeFileSync(
        path.join(testDir, '.husky', 'pre-commit'),
        '#!/usr/bin/env sh\nvault-guard scan --staged\n',
        { mode: 0o755 },
      );

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });

      expect(plan.ok).toBe(true);
      expect(plan.hook?.installed).toBe(true);
      // realpathSync normalizes macOS's /var -> /private/var symlink:
      // plan.hook.path is the ABSOLUTE hook path (unlike conflict paths,
      // never relativized), resolved against git's own (symlink-resolved)
      // worktree root for this relative core.hooksPath.
      expect(plan.hook?.path).toBe(path.join(fs.realpathSync(testDir), '.husky', 'pre-commit'));
    });

    it('names .husky/pre-commit as the conflict when a foreign tracked hook already exists there', async () => {
      buildHusky9Layout(testDir, { absoluteHooksPath: true });
      fs.writeFileSync(
        path.join(testDir, '.husky', 'pre-commit'),
        '#!/usr/bin/env sh\necho custom-hook\n',
        { mode: 0o755 },
      );

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(code).toBe(2);

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(
        plan.conflicts.some(c => c.path === '.husky/pre-commit' && c.reason === 'foreign_hook'),
      ).toBe(true);
    });

    it('dry-run reports the tracked .husky/pre-commit path, not the generated dir', () => {
      buildHusky9Layout(testDir);

      const plan = planInit({
        cwd: testDir,
        dryRun: true,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });

      expect(plan.hook?.path).toBe(path.join(fs.realpathSync(testDir), '.husky', 'pre-commit'));
    });
  });

  describe('husky 9 with a nested core.hooksPath (monorepo package not at git root)', () => {
    // BLOCKING finding from independent review: the ordinary monorepo
    // shape has the package that owns husky's "prepare" script somewhere
    // other than the git root, e.g. packages/app. core.hooksPath (set
    // repo-wide, from the root) then points at "packages/app/.husky/_",
    // nested below cwd, and husky's own `h` shim resolves the tracked
    // hook it actually executes as the PARENT of that generated `_`
    // directory: packages/app/.husky/pre-commit, never
    // <cwd>/.husky/pre-commit. init must name and target the nested
    // path, never a fixed <cwd>/.husky/pre-commit.
    const subdir = 'packages/app';

    function buildNestedHusky9Layout(
      rootDir: string,
      options: { absoluteHooksPath?: boolean } = {},
    ): void {
      const genDir = path.join(rootDir, subdir, '.husky', '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, '.gitignore'), '*\n');
      fs.writeFileSync(
        path.join(genDir, 'h'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/../pre-commit"\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(genDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        { mode: 0o755 },
      );
      // Absolute core.hooksPath is used exactly as given (no
      // git-rev-parse-based worktree-root resolution), so a test that
      // compares the RELATIVE conflict path string stays clean even on a
      // host (macOS) where the OS temp dir is itself behind a symlink.
      const hooksPathValue = options.absoluteHooksPath ? genDir : `${subdir}/.husky/_`;
      git(['config', '--local', 'core.hooksPath', hooksPathValue], rootDir);
    }

    it('bare init lands the vault-guard stanza at the nested tracked hook, not <cwd>/.husky', async () => {
      buildNestedHusky9Layout(testDir);

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(code).toBe(0);

      const trackedPath = path.join(testDir, subdir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);
      expect(fs.readFileSync(trackedPath, 'utf-8')).toContain('scan --staged');
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);
    });

    it('names the nested tracked hook, not <cwd>/.husky/pre-commit, as the conflict when a foreign hook already exists there', async () => {
      buildNestedHusky9Layout(testDir, { absoluteHooksPath: true });
      const trackedPath = path.join(testDir, subdir, '.husky', 'pre-commit');
      fs.writeFileSync(trackedPath, '#!/usr/bin/env sh\necho custom-hook\n', { mode: 0o755 });

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(code).toBe(2);

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(
        plan.conflicts.some(
          c => c.path === `${subdir}/.husky/pre-commit` && c.reason === 'foreign_hook',
        ),
      ).toBe(true);
      expect(plan.conflicts.every(c => c.path !== '.husky/pre-commit')).toBe(true);
    });
  });

  describe('false positives that must not redirect to .husky/pre-commit', () => {
    // Amendment: only directory shape (basename `_` under a directory
    // named `.husky`) may trigger the redirect. These two shapes each
    // defeat the old (now removed) h-shim / dispatcher-content signals
    // while failing the shape check -- init must refuse the foreign hook
    // at its REAL location, never redirect it to .husky/pre-commit, and
    // never create a .husky directory.

    it('refuses a foreign hook at .githooks/pre-commit, the real location, when an unrelated file named h sits beside it', async () => {
      const hooksDirAbs = path.join(testDir, '.githooks');
      fs.mkdirSync(hooksDirAbs, { recursive: true });
      fs.writeFileSync(path.join(hooksDirAbs, 'h'), '#!/usr/bin/env sh\necho unrelated\n');
      fs.writeFileSync(path.join(hooksDirAbs, 'pre-commit'), '#!/bin/sh\necho custom-hook\n', {
        mode: 0o755,
      });
      // Absolute core.hooksPath is used exactly as given (no
      // git-rev-parse-based worktree-root resolution), so the printed
      // relative conflict path stays a clean .githooks/pre-commit even on
      // a host (macOS) where the OS temp dir is itself behind a symlink.
      git(['config', '--local', 'core.hooksPath', hooksDirAbs], testDir);

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });

      expect(code).toBe(2);
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(
        plan.conflicts.some(c => c.path === '.githooks/pre-commit' && c.reason === 'foreign_hook'),
      ).toBe(true);
      expect(plan.conflicts.every(c => c.path !== '.husky/pre-commit')).toBe(true);
    });

    it('refuses a dispatcher-shaped foreign hook at .git/hooks/pre-commit, the real default location, with no core.hooksPath set', async () => {
      git(['config', '--local', '--unset', 'core.hooksPath'], testDir);
      const hooksDirAbs = new PreCommitHook().getEffectiveHooksDir(testDir).hooksDir;
      fs.mkdirSync(hooksDirAbs, { recursive: true });
      fs.writeFileSync(
        path.join(hooksDirAbs, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        { mode: 0o755 },
      );

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });

      expect(code).toBe(2);
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(
        plan.conflicts.some(
          c => c.path === '.git/hooks/pre-commit' && c.reason === 'foreign_hook',
        ),
      ).toBe(true);
    });
  });

  it('conflicts on foreign pre-commit.cmd for native manager', () => {
    // The beforeEach hook sets a RELATIVE core.hooksPath ("hooks"), which
    // resolves against the working-tree root, not .git -- so the foreign
    // file has to be planted where install() will actually look, not at
    // the old (and wrong) .git/hooks assumption.
    const hooksDir = new PreCommitHook().getEffectiveHooksDir(testDir).hooksDir;
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(path.join(hooksDir, 'pre-commit.cmd'), '@echo off\necho other\n');
    const plan = planInit({
      cwd: testDir,
      manager: 'native',
      skipConfig: true,
      skipWorkflow: true,
      skipAgentRules: true,
    });
    expect(plan.ok).toBe(false);
    expect(plan.conflicts.some(c => c.path.endsWith('pre-commit.cmd') && c.reason === 'foreign_hook')).toBe(
      true,
    );
  });

});
