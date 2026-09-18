// Runs action.yml's REAL "Validate inputs" step, and reads the file for the
// shapes a behavioural test cannot see.
//
// Two kinds of assertion live here, and the second is what keeps the first
// honest:
//
//   1. Behavioural: the step accepts and rejects the right values, exercised by
//      running it under the real bash with the step's own `env:` mapping.
//   2. Textual: action.yml actually contains the idioms that behaviour was
//      written against -- the install step, the absolute binary, the
//      working-directory on both steps -- and does not contain the shapes known
//      to break them. Without these, a step could be deleted outright and the
//      behavioural half would keep passing against whatever was left.
//
// The original regression this file inherits: a bash `=~` pattern written
// `{1,256}` fails to COMPILE on macOS, where the BSD regex engine sets
// RE_DUP_MAX to 255. A pattern that fails to compile does not match, so every
// path input -- including the default `.` -- was rejected, and the action was
// unusable on macOS while passing perfectly on the ubuntu runners CI used.
// scripts/test-action-path-validation.sh runs the same guards on a macOS runner,
// where that asymmetry is visible.

import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

interface StepContext {
  inputs: Record<string, string>;
  runnerTemp: string;
  workspace: string;
}

interface ActionFile {
  text: string;
  hasStep(stepName: string): boolean;
  extractRunScript(stepName: string): string;
  extractStepEnv(stepName: string): Record<string, string>;
  extractStepWorkingDirectory(stepName: string): string;
  evaluateStepEnv(stepName: string, ctx: StepContext): Record<string, string>;
  cwdForStep(stepName: string, ctx: StepContext): string;
}

const REPO_ROOT = path.join(__dirname, '..', '..', '..', '..', '..');

// Honours the same override as action-run-script.test.ts. Without it, a mutation
// run would point the behavioural suite at a weakened copy while every textual
// guard in THIS file kept reading the real action.yml and reporting green, which
// is a false negative in exactly the situation the override exists to
// investigate.
const ACTION_PATH = process.env.VG_ACTION_FILE ?? path.join(REPO_ROOT, 'action.yml');

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { loadAction } = require(path.join(REPO_ROOT, 'scripts', 'lib', 'action-steps.cjs')) as {
  loadAction: (actionPath: string) => ActionFile;
};

const action = loadAction(ACTION_PATH);
const actionYml = action.text;

const INSTALL_STEP = 'Install vault-guard outside the workspace';
const RUN_STEP = 'Run vault-guard';

const DEFAULT_INPUTS: Record<string, string> = {
  version: '1.7.0',
  path: '.',
  format: 'sarif',
  'sarif-output': 'vault-guard-results.sarif',
  'trust-base': 'auto',
};

// The variables come from the step's own `env:` mapping in action.yml, never
// from a table written here: a harness that injects a variable the step does not
// declare is testing a program that does not exist.
function runValidateWith(
  inputs: Record<string, string>,
  extraEnv: Record<string, string> = {},
): { status: number; stdout: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'vault-guard-action-validate-'));
  const scriptFile = path.join(dir, 'validate.sh');
  writeFileSync(scriptFile, action.extractRunScript('Validate inputs'));
  const ctx: StepContext = {
    inputs: { ...DEFAULT_INPUTS, ...inputs },
    runnerTemp: dir,
    workspace: dir,
  };
  try {
    const stdout = execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: process.env.PATH ?? '',
        ...action.evaluateStepEnv('Validate inputs', ctx),
        ...extraEnv,
      },
    });
    return { status: 0, stdout };
  } catch (err) {
    const e = err as { status?: number; stdout?: string };
    return { status: typeof e.status === 'number' ? e.status : -1, stdout: e.stdout ?? '' };
  }
}

describe('action.yml "Validate inputs", version', () => {
  it('takes an exact version and refuses a dist-tag or a path', () => {
    // `latest` used to be the DEFAULT here. It is refused now: a tag hands the
    // choice of scanner to the registry on the morning of the run. `.`, `..` and
    // `payload.tgz` are the sharper half -- npm reads those as a PATH rather
    // than a version, which on a run that started inside the checkout was one
    // committed file away from the tree choosing its own scanner.
    expect(runValidateWith({ version: '1.7.0' }).status).toBe(0);
    expect(runValidateWith({ version: '10.20.30' }).status).toBe(0);
    for (const bad of [
      'latest',
      'next',
      'beta',
      '1.7',
      '^1.7.0',
      '1.7.0-rc.1',
      '.',
      '..',
      'payload.tgz',
      '-1.7.0',
    ]) {
      const run = runValidateWith({ version: bad });
      expect([bad, run.status]).not.toEqual([bad, 0]);
      expect(run.stdout).toContain('must be an exact version');
    }
  });

  it('refuses a version with a leading zero, which npm reads as a tag', () => {
    // `01.7.0` is not semver, so npm falls back to treating the spec as a
    // dist-tag: the exact family this input claims to refuse.
    for (const bad of ['01.7.0', '00.0.0', '1.7.00', '1.07.0']) {
      expect([bad, runValidateWith({ version: bad }).status]).not.toEqual([bad, 0]);
    }
  });

  it('tells someone pinned to `latest` what to do instead', () => {
    // A refusal with no alternative in it is a wall. This is the migration the
    // breaking change forces, so the message has to carry the answer.
    expect(runValidateWith({ version: 'latest' }).stdout).toContain('REMOVE the input');
  });

  it('defaults to the scanner version this repository publishes', () => {
    // The action tag and the scanner version are two numbers and are allowed to
    // differ -- an action-only release moves the tag and leaves the scanner
    // alone -- but the DEFAULT is always the scanner the tag shipped with, and
    // this repository's packages are that scanner. Bumping the packages without
    // bumping this default would ship an action that installs a version nobody
    // is publishing any more; turning this red is how that gets noticed in the
    // PR that bumps it.
    const defaultAt = /default:\s*(\S+)\s*\n\s*path:/.exec(actionYml);
    expect(defaultAt).not.toBeNull();
    const cliVersion = JSON.parse(
      readFileSync(path.join(REPO_ROOT, 'packages', 'cli', 'package.json'), 'utf-8'),
    ).version;
    expect((defaultAt as RegExpExecArray)[1]).toBe(cliVersion);
  });

  it('refuses a scanner too old for the flags this action tag passes', () => {
    // The `version` input exists so a consumer can pin a scanner OTHER than the
    // one this tag shipped with, which makes version skew a supported
    // configuration. The run step passes `--trust-base` unconditionally, and
    // that flag arrived in scanner 1.7.0, so every older pin produces an
    // unsupported argument vector. Commander answers an unknown option with
    // exit 1, the findings code, so the shape validation passing here is what
    // turns a stale pin into an accusation of carrying secrets.
    //
    // The message has to carry BOTH numbers. "Unsupported version" without them
    // sends the reader to the changelog to work out which two values disagree.
    const run = runValidateWith({ version: '1.4.1' });
    expect(run.status).not.toBe(0);
    expect(run.stdout).toContain('1.4.1');
    expect(run.stdout).toContain('1.7.0');
    expect(run.stdout).toContain('--trust-base');
  });

  it('compares the floor numerically, not as text', () => {
    // `1.10.0` sorts BELOW `1.7.0` as a string and above it as a version, so a
    // lexicographic comparison here would refuse a scanner newer than the one
    // the floor is protecting. The low side is the same check from the other
    // direction: 1.6.9 is one patch under the floor and must still be refused.
    for (const tooOld of ['0.9.9', '1.6.0', '1.6.9', '1.4.1']) {
      expect([tooOld, runValidateWith({ version: tooOld }).status]).not.toEqual([tooOld, 0]);
    }
    for (const ok of ['1.7.0', '1.7.1', '1.8.0', '1.10.0', '2.0.0', '10.0.0']) {
      expect([ok, runValidateWith({ version: ok }).status]).toEqual([ok, 0]);
    }
  });

  it('never defaults to a scanner version it would then refuse', () => {
    // Two numbers in one file that have to move together: raising the floor
    // without raising the default would make the action refuse its own default
    // and fail every run that did not set the input.
    const defaultAt = /default:\s*(\S+)\s*\n\s*path:/.exec(actionYml);
    expect(defaultAt).not.toBeNull();
    const defaultVersion = (defaultAt as RegExpExecArray)[1];
    expect([defaultVersion, runValidateWith({ version: defaultVersion }).status]).toEqual([
      defaultVersion,
      0,
    ]);
  });
});

describe('action.yml "Validate inputs", paths', () => {
  it('accepts the paths a consumer actually passes', () => {
    // "." is the default and is the value the RE_DUP_MAX bug rejected, so it is
    // the single most load-bearing case in this file.
    for (const value of ['.', './src', 'packages/cli', 'vault-guard-results.sarif', 'a'.repeat(256)]) {
      expect([value, runValidateWith({ path: value }).status]).toEqual([value, 0]);
    }
  });

  it('rejects traversal, absolute paths, and shell-hostile characters', () => {
    for (const value of [
      '',
      '..',
      '../etc',
      'a/../../b',
      '/etc/passwd',
      'has space',
      'semi;colon',
      'back`tick',
      '$(subshell)',
      'quote"mark',
      'a'.repeat(257),
    ]) {
      expect([value, runValidateWith({ path: value }).status]).not.toEqual([value, 0]);
    }
  });

  it('refuses a path or a results target that begins with a dash', () => {
    // Not about escaping the workspace: a value beginning with `-` is read as an
    // OPTION by whichever command it reaches.
    expect(runValidateWith({ path: '-rf' }).stdout).toContain('must not begin with a dash');
    expect(runValidateWith({ 'sarif-output': '-rf' }).stdout).toContain('must not begin with a dash');
  });

  it('refuses every spelling of .github/ that reaches the same directory', () => {
    // That directory holds the workflow file and the CODEOWNERS entry that
    // decide how this gate runs. The guard compares strings, so every second
    // name for the directory has to be normalised away first: a `./` prefix, an
    // interior `/./`, a doubled slash, and -- because a macOS runner's
    // filesystem is case-insensitive -- a different case.
    for (const spelling of [
      '.github/workflows/out.sarif',
      './.github/workflows/out.sarif',
      './/.github/out.sarif',
      '.github/./out.sarif',
      '.GitHub/workflows/out.sarif',
      '.GITHUB/out.sarif',
      './.GitHub/out.sarif',
      // Trailing slashes are normalised away too, so `.github/` is not a second
      // name that reaches the same directory unchecked.
      '.github/out.sarif/',
      './/.github/out.sarif//',
    ]) {
      const run = runValidateWith({ 'sarif-output': spelling });
      expect([spelling, run.status]).not.toEqual([spelling, 0]);
      expect(run.stdout).toContain('must not write under .github/');
    }
    // And a path that merely starts with the same letters is not caught.
    expect(runValidateWith({ 'sarif-output': '.githubbed/out.sarif' }).status).toBe(0);
    expect(runValidateWith({ 'sarif-output': 'out.sarif' }).status).toBe(0);
  });

  it('refuses a results target that names a directory rather than a file', () => {
    // `.`, `./` and `.//` all normalise to nothing or to a single dot, and
    // every one of them is a directory. The redirect would fail deep inside the
    // run step with a shell error, rather than here with the name of the
    // workflow input that caused it.
    for (const value of ['.', './', './/', './/./']) {
      const run = runValidateWith({ 'sarif-output': value });
      expect([value, run.status]).not.toEqual([value, 0]);
      expect(run.stdout).toContain('must name a file');
    }
    // A trailing slash on a real filename is a stray character, not a
    // directory: accepted here and stripped in the run step, where `test -L`
    // would otherwise follow the symlink it is meant to catch.
    expect(runValidateWith({ 'sarif-output': 'out.sarif/' }).status).toBe(0);
  });

  it('accepts a `./` prefix, which is ordinary Actions style', () => {
    // Closing the `./.github/` bypass by refusing any value containing `./`
    // would break `path: ./src`, which every earlier release accepted, and a
    // security upgrade that turns a green check red is one people back out of.
    // The guard normalises instead of refusing.
    expect(runValidateWith({ path: './src' }).status).toBe(0);
    expect(runValidateWith({ 'sarif-output': './out.sarif' }).status).toBe(0);
  });
});

describe('action.yml "Validate inputs", format and trust-base', () => {
  it('takes the three formats and nothing else', () => {
    for (const value of ['text', 'json', 'sarif']) {
      expect([value, runValidateWith({ format: value }).status]).toEqual([value, 0]);
    }
    for (const value of ['', 'yaml', 'SARIF', 'sarif;id']) {
      expect([value, runValidateWith({ format: value }).status]).not.toEqual([value, 0]);
    }
  });

  it('accepts auto and a real ref', () => {
    for (const value of ['auto', 'origin/main', 'HEAD~1', 'v1.2.3^']) {
      expect([value, runValidateWith({ 'trust-base': value }).status]).toEqual([value, 0]);
    }
  });

  it('refuses `off` however it is capitalised, naming what to do instead', () => {
    // Pull-request mode is the floor, not a knob: on a same-repo pull_request
    // event the workflow file runs from the pull request's own head, so an
    // opt-out input would be settable by the very pull request whose control
    // inputs it governs. A value refused as `off` and accepted as `Off` would be
    // an opt-out with a shift key in front of it.
    for (const spelling of ['off', 'Off', 'OFF', 'oFf']) {
      const run = runValidateWith({ 'trust-base': spelling });
      expect([spelling, run.status]).not.toEqual([spelling, 0]);
      expect(run.stdout).toContain('was removed');
    }
    const run = runValidateWith({ 'trust-base': 'off' });
    expect(run.stdout).toContain('v1.6.0');
    expect(run.stdout).toContain('fetch-depth: 0');
  });

  it('refuses a ref that could be read as a git option', () => {
    expect(runValidateWith({ 'trust-base': '--upload-pack=touch' }).status).not.toBe(0);
    expect(runValidateWith({ 'trust-base': '-rf' }).stdout).toContain('must not begin with a dash');
    expect(runValidateWith({ 'trust-base': 'origin/$(id)' }).status).not.toBe(0);
    expect(runValidateWith({ 'trust-base': 'a'.repeat(201) }).status).not.toBe(0);
  });

  it('refuses a base ref the runner handed it that is not ref-shaped', () => {
    // `auto` turns GITHUB_BASE_REF into part of a command line without anyone
    // having typed it, so it is checked even though GitHub sets it from the
    // pull request's TARGET branch.
    expect(runValidateWith({}, { GITHUB_BASE_REF: 'main' }).status).toBe(0);
    expect(runValidateWith({}, { GITHUB_BASE_REF: 'main;id' }).status).not.toBe(0);
  });
});

describe('action.yml text guards', () => {
  it('does not reintroduce the {1,256} path regex', () => {
    // On Linux this pattern "works", which is exactly why a behavioural test on
    // an ubuntu runner would never notice it coming back.
    expect(actionYml).not.toMatch(/\[A-Za-z0-9\._\/-\]\{1,256\}/);
    expect(actionYml).not.toMatch(/=~[^\n]*\{1,\s*256\}/);
  });

  it('uses the portable charset-plus-length idiom the tests above exercise', () => {
    expect(actionYml).toContain('=~ ^[A-Za-z0-9._/-]+$');
    expect(actionYml).toContain('> 256');
  });

  it('validates both path-shaped inputs, not just one', () => {
    expect(actionYml).toContain('validate_path "path"');
    expect(actionYml).toContain('validate_path "sarif-output"');
  });

  it('uses no bash 4 only syntax, because macOS ships bash 3.2', () => {
    // `${x,,}` and `${x^^}` are bash 4.0 case expansions and are a SYNTAX ERROR
    // on bash 3.2, which is what macOS ships: the whole step would fail to parse
    // on the one platform whose case-insensitive filesystem made the
    // case-folding necessary. Same family as the `{1,256}` regex above, and
    // equally invisible from an ubuntu runner.
    //
    // Comment lines are skipped, because the comment at the normalise_path
    // helper names `${x,,}` to say why it is not used, and a guard that forbade
    // the spelling anywhere would be satisfied by deleting the explanation.
    const code = actionYml.split('\n').filter((line) => !line.trim().startsWith('#'));
    for (const line of code) {
      expect([line, /\$\{[A-Za-z_][A-Za-z0-9_]*,,\}/.test(line)]).toEqual([line, false]);
      expect([line, /\$\{[A-Za-z_][A-Za-z0-9_]*\^\^\}/.test(line)]).toEqual([line, false]);
      expect([line, /^\s*(mapfile|readarray|declare -A|local -A)\b/.test(line)]).toEqual([
        line,
        false,
      ]);
    }
  });

  it('installs the scanner from outside the tree it scans', () => {
    // The boundary, stated as file contents rather than behaviour, because the
    // behavioural half cannot see a step that is not there: a review of the
    // sibling repo deleted the entire install step from a copy of its action and
    // every behavioural test still passed.
    expect(action.hasStep(INSTALL_STEP)).toBe(true);
    const install = action.extractRunScript(INSTALL_STEP);
    expect(install).toContain(
      'npm install -g --ignore-scripts "@vaultcompass/vault-guard@${VG_VERSION}"',
    );
    expect(action.extractStepEnv(INSTALL_STEP).npm_config_prefix).toContain('${{ runner.temp }}');
  });

  it('never installs without --ignore-scripts, and verifies before handing over', () => {
    // Stated as text for the same reason as the guard above: the behavioural
    // tests run against a STUBBED npm, so they can prove the action ASKS for
    // both, and nothing about what a real npm does when asked. These two lines
    // are the ask.
    const install = action.extractRunScript(INSTALL_STEP);
    // COMMENTS STRIPPED FIRST. The ordering claim is about the CODE, and this
    // step now explains at length why the verification exists, naming the
    // command well above the line that runs it. Matching raw text made the
    // explanation look like an earlier invocation and turned the file red for
    // documenting itself, which is how an explanation gets deleted.
    const code = install
      .split('\n')
      .filter((line) => !line.trim().startsWith('#'))
      .join('\n');
    const installAt = code.indexOf('npm install -g');
    const auditAt = code.indexOf('npm audit signatures');
    expect([installAt, auditAt].every((i) => i !== -1)).toBe(true);
    expect(auditAt).toBeGreaterThan(installAt);
    // No install anywhere in the step that skips the flag.
    for (const line of code.split('\n')) {
      if (line.trim().startsWith('npm install')) {
        expect([line, line.includes('--ignore-scripts')]).toEqual([line, true]);
      }
    }
  });

  it('never runs npx, and never resolves the scanner by bare name', () => {
    // npx is how the tree under judgment used to choose its own scanner: in
    // non-global mode it reads project config from its cwd, and a copy already
    // in the head's node_modules satisfies the spec and runs without contacting
    // a registry at all.
    //
    // Matched as an INVOCATION rather than as the word, because the comments in
    // this file necessarily name npx to explain why it is gone, and a guard that
    // forbade the word would be satisfied by deleting the explanation.
    expect(actionYml).not.toMatch(/^\s*npx\b/m);
    expect(actionYml).not.toMatch(/npx\s+--yes/);
    const run = action.extractRunScript(RUN_STEP);
    expect(run).toContain('"${VG_BIN}"');
    expect(action.extractStepEnv(RUN_STEP).VG_BIN).toContain('${{ runner.temp }}');
  });

  it('declares a working directory outside the checkout on both shell steps', () => {
    // A composite step with no working-directory runs at the workspace root,
    // which is the head's own tree.
    for (const step of [INSTALL_STEP, RUN_STEP]) {
      expect([step, action.extractStepWorkingDirectory(step)]).toEqual([
        step,
        '${{ runner.temp }}',
      ]);
    }
  });

  it('passes the scan root as an absolute, resolved path built from the workspace', () => {
    // `pwd -P` rather than string concatenation: vault-guard resolves the
    // pull-request file set against its own process cwd, which node reports
    // with symlinks resolved, and a logical target against a resolved cwd puts
    // every file in the head tree outside the scan target. The run then scans
    // zero files and reports a clean result over nothing.
    const run = action.extractRunScript(RUN_STEP);
    expect(run).toContain('SCAN_ROOT="$(cd "${ROOT}/${VG_PATH}" && pwd -P)"');
    expect(run).toContain('ARGS=(scan "${SCAN_ROOT}"');
    expect(run).toContain('ROOT_REAL');
  });

  it('guards the results target against a symlink before creating anything', () => {
    const run = action.extractRunScript(RUN_STEP);
    const symlinkAt = run.indexOf('-L "${CURSOR}"');
    const mkdirAt = run.indexOf('mkdir -p "$(dirname "${OUT}")"');
    expect(symlinkAt).toBeGreaterThan(-1);
    expect(mkdirAt).toBeGreaterThan(symlinkAt);
  });

  it('does not pass a bare -- between the program and the command', () => {
    // That separator is forwarded into vault-guard's argv; Commander then treats
    // it as end-of-options and ignores `--format`, so text banners land in the
    // SARIF file and the upload fails.
    expect(actionYml).not.toMatch(/VG_BIN[^\n]*--\s+scan/);
  });

  it('keeps the trust-base ref one argv element, with the bash 3.2 empty-array guard', () => {
    // A string built with `TRUST_ARGS="--trust-base ${ref}"` would word-split at
    // the first space. And with `set -u`, bash 3.2 treats a bare empty-array
    // expansion as an unbound variable and aborts the step, so the `+` form is
    // required rather than stylistic.
    const run = action.extractRunScript(RUN_STEP);
    expect(run).toContain('TRUST_ARGS=(');
    const invocation = run.split('\n').find((l) => l.includes('"${VG_BIN}"'));
    expect(invocation).toBeDefined();
    expect(invocation).toContain('TRUST_ARGS[@]+');
  });

  it('offers no `off` value back in any message, and carries no branch for it', () => {
    // The charset refusal went on printing "Allowed: auto | off | ..." after the
    // value was removed, so a typo was told to use the one value refused by name
    // two checks earlier.
    expect(actionYml).not.toMatch(/auto \| off/);
    expect(actionYml).not.toMatch(/"\$\{VG_TRUST_BASE\}" != "off"/);
  });

  it('every input reaching a shell is passed through env, never interpolated', () => {
    // `${{ inputs.x }}` is substituted into the script text before bash parses
    // it, so a hostile value interpolated directly cannot be quoted out of.
    const interpolations = actionYml.match(/\$\{\{\s*inputs\.[^}]*\}\}/g) ?? [];
    expect(interpolations.length).toBeGreaterThan(0);
    for (const line of actionYml.split('\n')) {
      if (!/\$\{\{\s*inputs\./.test(line)) continue;
      // A comment explaining the rule is not a violation of it.
      if (line.trim().startsWith('#')) continue;
      expect([line.trim(), /^([A-Za-z0-9_-]+:|if:)\s/.test(line.trim())]).toEqual([
        line.trim(),
        true,
      ]);
    }
  });

  it('never interpolates the base ref into a run body', () => {
    expect(actionYml).not.toMatch(/\$\{\{[^}]*base_ref/i);
  });

  it('pins every third-party action to a full commit sha', () => {
    // A tag is mutable, and this action runs inside other people's repositories
    // with their permissions.
    const uses = actionYml.match(/uses:\s*(\S+)/g) ?? [];
    expect(uses.length).toBeGreaterThan(0);
    for (const entry of uses) {
      expect([entry, /@[0-9a-f]{40}$/.test(entry.replace(/^uses:\s*/, ''))]).toEqual([entry, true]);
    }
  });
});
