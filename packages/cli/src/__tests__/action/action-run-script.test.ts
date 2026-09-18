// Executes action.yml's own install and run steps, under the exact bash
// invocation GitHub Actions uses for a composite `shell: bash` step:
//
//   bash --noprofile --norc -eo pipefail {0}
//
// WHAT THIS FILE IS FOR. The action used to run
// `npx --yes "@vaultcompass/vault-guard@${VG_VERSION}"` from inside the
// checkout, which put the choice of PROGRAM inside the tree under judgment by
// two routes: a committed `.npmrc` repoints the registry npx fetches from, and
// a copy already in the head's `node_modules` wins outright, with the version
// pin degraded to a satisfaction check on a package the head wrote. The scanner
// is a control input, and a gate that reads its config from the base branch and
// then runs a binary the head chose has moved the decision rather than removed
// it.
//
// Every fact this file asserts is read out of action.yml: the script, the step's
// `env:` mapping, and the step's `working-directory:`. A harness with its own
// table of variables, or its own idea of a step's cwd, asserts a property of
// itself -- the two lines that carry the whole boundary are "which directory is
// npm started in" and "which prefix does it install under", and a harness that
// supplies those cannot see them go missing.
//
// npm IS STUBBED HERE, which bounds what this file can prove: that the action no
// longer ASKS npm to run from inside the checkout. What real npm does when it is
// asked to is a decision of the real client, and bench/action-install.cjs is
// what pins that, with two local registries and a real install.

import { execFileSync } from 'child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'fs';
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

// Overridable so a mutation run can point the whole suite at a deliberately
// weakened copy and watch which assertions go red. Nothing in CI sets it, and
// the default is the real file. A test that cannot be made to fail on demand is
// a test nobody has checked.
const ACTION_PATH = process.env.VG_ACTION_FILE ?? path.join(REPO_ROOT, 'action.yml');

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { loadAction } = require(path.join(REPO_ROOT, 'scripts', 'lib', 'action-steps.cjs')) as {
  loadAction: (actionPath: string) => ActionFile;
};

const action = loadAction(ACTION_PATH);

const INSTALL_STEP = 'Install vault-guard outside the workspace';
const RUN_STEP = 'Run vault-guard';

const DEFAULT_INPUTS: Record<string, string> = {
  version: '1.7.0',
  path: '.',
  format: 'sarif',
  'sarif-output': 'vault-guard-results.sarif',
  'trust-base': 'auto',
};

interface Runner {
  dir: string;
  workspace: string;
  runnerTemp: string;
  ctx: StepContext;
  env: Record<string, string>;
  plantedRecord: string;
  npxRecord: string;
  npmRecord: string;
  pathDir: string;
  cwdRecord?: string;
}

// A runner: a checkout, a runner temp, and (for the run step) the scanner where
// the install step would have left it.
//
// The planted files are the attack the install boundary exists to close, and the
// head's own node_modules/.bin goes FIRST on PATH, which is the ordering a
// workflow with an earlier install step actually produces. Without that
// ordering, "the planted copy never ran" would hold for the uninteresting reason
// that nothing could have reached it.
function makeRunner(inputs: Record<string, string> = {}, npmVersion = '10.9.2'): Runner {
  const dir = mkdtempSync(path.join(tmpdir(), 'vault-guard-action-'));
  const workspace = path.join(dir, 'workspace');
  const runnerTemp = path.join(dir, 'runner-temp');
  mkdirSync(workspace, { recursive: true });
  mkdirSync(runnerTemp, { recursive: true });

  const ctx: StepContext = { inputs: { ...DEFAULT_INPUTS, ...inputs }, runnerTemp, workspace };
  const env = action.evaluateStepEnv(RUN_STEP, ctx);

  // The scan root has to exist, because the run step chdirs into it. A `path`
  // input naming a subdirectory is a real shape (`path: packages/cli`), and a
  // fixture without that directory would fail the step for a reason that has
  // nothing to do with what the case is about.
  mkdirSync(path.join(workspace, ctx.inputs.path), { recursive: true });

  const plantedRecord = path.join(dir, 'planted.txt');
  const npxRecord = path.join(dir, 'npx.txt');
  const npmRecord = path.join(dir, 'npm.txt');
  mkdirSync(path.join(workspace, 'node_modules/.bin'), { recursive: true });
  writeFileSync(
    path.join(workspace, 'node_modules/.bin/vault-guard'),
    `#!/bin/sh\necho PLANTED >> ${JSON.stringify(plantedRecord)}\necho 'PLANTED node_modules COPY RAN'\nexit 0\n`,
  );
  chmodSync(path.join(workspace, 'node_modules/.bin/vault-guard'), 0o755);
  writeFileSync(path.join(workspace, '.npmrc'), 'registry=http://127.0.0.1:9/\n');

  const pathDir = path.join(dir, 'path-bin');
  mkdirSync(pathDir, { recursive: true });
  writeFileSync(path.join(pathDir, 'npx'), `#!/bin/sh\necho NPX >> ${JSON.stringify(npxRecord)}\nexit 0\n`);
  chmodSync(path.join(pathDir, 'npx'), 0o755);

  // npm records its argv AND the directory it was started in. The second one is
  // the point: npm started inside the checkout reads the head's `.npmrc`,
  // package.json and lockfile, and no assertion about the run step can see that,
  // because by then the install has already happened.
  // The stub also CREATES `<prefix>/lib`, because a real global install does
  // and the step verifies the installed tree from inside it. A stub that
  // recorded the argv without laying the directory down would make the
  // verification step abort on a missing cwd, which is the harness failing
  // rather than the action -- and would hide whether the action verifies at
  // all.
  writeFileSync(
    path.join(pathDir, 'npm'),
    `#!/bin/sh\nprintf 'cwd=%s\\n' "$(pwd -P)" >> ${JSON.stringify(npmRecord)}\n` +
      `printf 'argv=%s\\n' "$*" >> ${JSON.stringify(npmRecord)}\n` +
      `printf 'prefix=%s\\n' "\${npm_config_prefix:-unset}" >> ${JSON.stringify(npmRecord)}\n` +
      // A real npm answers `--version`, and the step now reads it: below
      // 10.6.0 the verification calls a clean install tampered with. Written
      // with `%b` so a test can hand it MULTIPLE lines and reproduce a client
      // printing an upgrade notice above its version, the shape that defeated
      // two earlier versions of the floor.
      `case "$1" in --version) printf '%b\\n' "${npmVersion}" ;; ` +
      'install) mkdir -p "${npm_config_prefix}/lib" ;; esac\n' +
      'exit 0\n',
  );
  chmodSync(path.join(pathDir, 'npm'), 0o755);

  return { dir, workspace, runnerTemp, ctx, env, plantedRecord, npxRecord, npmRecord, pathDir };
}

// The scanner the install step would have left behind, at the absolute path
// action.yml says to call, writing a document and recording its own cwd.
function installStubScanner(
  runner: Runner,
  { exitCode = 0, body = '{"version":"2.1.0","runs":[]}', echoArgs = false } = {},
): Runner {
  const target = runner.env.VG_BIN;
  if (!target || !target.startsWith('/')) {
    throw new Error(`action.yml did not give the run step an absolute VG_BIN (got ${target})`);
  }
  mkdirSync(path.dirname(target), { recursive: true });
  const cwdRecord = path.join(runner.dir, 'scanner-cwd.txt');
  writeFileSync(
    target,
    `#!/bin/sh\npwd -P >> ${JSON.stringify(cwdRecord)}\n` +
      (echoArgs ? 'echo "$@"\n' : `echo '${body}'\n`) +
      `exit ${exitCode}\n`,
  );
  chmodSync(target, 0o755);
  runner.cwdRecord = cwdRecord;
  return runner;
}

function stepEnvironment(runner: Runner, stepName: string, extraEnv: Record<string, string>) {
  return {
    PATH: `${path.join(runner.workspace, 'node_modules/.bin')}:${runner.pathDir}:${process.env.PATH ?? ''}`,
    GITHUB_WORKSPACE: runner.workspace,
    ...action.evaluateStepEnv(stepName, runner.ctx),
    ...extraEnv,
  };
}

interface RunResult {
  status: number;
  stdout: string;
  runner: Runner;
  outputs: string;
  sarifPath: string;
  plantedRan: boolean;
  npxRan: boolean;
  scannerCwd: string;
}

function runStep(
  exitCode: number,
  extraEnv: Record<string, string> = {},
  inputs: Record<string, string> = {},
): RunResult {
  const runner = makeRunner(inputs);
  installStubScanner(runner, { exitCode });
  return runStepFor(runner, extraEnv);
}

// The same execution against a runner the caller has already shaped, for the
// cases that have to mutate the checkout (a symlinked scan root, a missing one)
// after the fixture is built.
function runStepFor(runner: Runner, extraEnv: Record<string, string> = {}): RunResult {
  const outputFile = path.join(runner.dir, 'github-output');
  writeFileSync(outputFile, '');
  const scriptFile = path.join(runner.dir, 'step.sh');
  writeFileSync(scriptFile, action.extractRunScript(RUN_STEP));

  let status = 0;
  let stdout = '';
  try {
    stdout = execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: action.cwdForStep(RUN_STEP, runner.ctx),
      env: stepEnvironment(runner, RUN_STEP, { GITHUB_OUTPUT: outputFile, ...extraEnv }),
    });
  } catch (err) {
    const e = err as { status?: number; stdout?: string };
    status = typeof e.status === 'number' ? e.status : -1;
    stdout = e.stdout ?? '';
  }

  return {
    status,
    stdout,
    runner,
    outputs: readFileSync(outputFile, 'utf-8'),
    sarifPath: path.join(runner.workspace, runner.ctx.inputs['sarif-output']),
    plantedRan: existsSync(runner.plantedRecord),
    npxRan: existsSync(runner.npxRecord),
    scannerCwd:
      runner.cwdRecord !== undefined && existsSync(runner.cwdRecord)
        ? readFileSync(runner.cwdRecord, 'utf-8').trim()
        : '',
  };
}

// The argument vector the step actually builds, read back from the file the stub
// scanner writes. Proven as executed rather than by matching the YAML.
function argvFor(
  inputs: Record<string, string> = {},
  extraEnv: Record<string, string> = {},
): string {
  const runner = makeRunner(inputs);
  installStubScanner(runner, { echoArgs: true });

  const outputFile = path.join(runner.dir, 'github-output');
  writeFileSync(outputFile, '');
  const scriptFile = path.join(runner.dir, 'step.sh');
  writeFileSync(scriptFile, action.extractRunScript(RUN_STEP));

  execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: action.cwdForStep(RUN_STEP, runner.ctx),
    env: stepEnvironment(runner, RUN_STEP, { GITHUB_OUTPUT: outputFile, ...extraEnv }),
  });

  return readFileSync(path.join(runner.workspace, runner.ctx.inputs['sarif-output']), 'utf-8');
}

describe('action.yml "Install vault-guard outside the workspace"', () => {
  function runInstall(inputs: Record<string, string> = {}): {
    runner: Runner;
    status: number;
    record: string;
  } {
    const runner = makeRunner(inputs);
    const scriptFile = path.join(runner.dir, 'install.sh');
    writeFileSync(scriptFile, action.extractRunScript(INSTALL_STEP));
    let status = 0;
    try {
      execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: action.cwdForStep(INSTALL_STEP, runner.ctx),
        env: stepEnvironment(runner, INSTALL_STEP, {}),
      });
    } catch (err) {
      const e = err as { status?: number };
      status = typeof e.status === 'number' ? e.status : -1;
    }
    const record = existsSync(runner.npmRecord) ? readFileSync(runner.npmRecord, 'utf-8') : '';
    return { runner, status, record };
  }

  it('installs the pinned version globally, and nothing else', () => {
    const run = runInstall();
    expect(run.status).toBe(0);
    expect(run.record).toContain(
      'argv=install -g --ignore-scripts @vaultcompass/vault-guard@1.7.0',
    );
  });

  it('installs the version the input asked for, not a hardcoded one', () => {
    expect(runInstall({ version: '1.6.0' }).record).toContain(
      'argv=install -g --ignore-scripts @vaultcompass/vault-guard@1.6.0',
    );
  });

  it('starts npm outside the checkout, so a committed .npmrc is never its cwd', () => {
    // The head's `.npmrc` sits in the workspace. npm started there reads it and
    // fetches from whatever registry it names. This is the assertion that makes
    // the whole boundary real; everything else follows from it.
    const run = runInstall();
    const cwdLine = run.record.split('\n').find((l) => l.startsWith('cwd='));
    expect(cwdLine).toBeDefined();
    expect(cwdLine).toContain(path.basename(run.runner.runnerTemp));
    expect(cwdLine).not.toContain(`${path.sep}workspace`);
  });

  it('installs under a prefix in the runner temp, not into the checkout', () => {
    const run = runInstall();
    const prefixLine = run.record.split('\n').find((l) => l.startsWith('prefix='));
    expect(prefixLine).toBeDefined();
    expect(prefixLine).not.toBe('prefix=unset');
    expect(prefixLine).toContain(path.basename(run.runner.runnerTemp));
    expect(prefixLine).not.toContain(`${path.sep}workspace`);
  });

  // Runs the install step with a stub npm that answers `--version` however the
  // caller asks, and reports whether the step got as far as installing.
  function runInstallWithNpm(npmVersion: string): { status: number; record: string } {
    const runner = makeRunner({}, npmVersion);
    const scriptFile = path.join(runner.dir, 'install.sh');
    writeFileSync(scriptFile, action.extractRunScript(INSTALL_STEP));
    let status = 0;
    try {
      execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: action.cwdForStep(INSTALL_STEP, runner.ctx),
        env: stepEnvironment(runner, INSTALL_STEP, {}),
      });
    } catch (err) {
      const e = err as { status?: number };
      status = typeof e.status === 'number' ? e.status : -1;
    }
    return {
      status,
      record: existsSync(runner.npmRecord) ? readFileSync(runner.npmRecord, 'utf-8') : '',
    };
  }

  it('refuses an npm too old to verify, rather than calling a clean install tampered with', () => {
    // `npm audit signatures` is not version-stable. Below 10.6.0 it fails on a
    // CLEAN install of these very packages: on 10.5.0 it says "Someone might
    // have tampered with these packages", naming ours; on 10.2.4 it is
    // EEXPIREDSIGNATUREKEY. Both false, both alarming.
    //
    // THE SETUP-NODE STEP DOES NOT COVER THIS, which is why the check exists
    // here at all. `node-version: '22'` is a major-only spec and Node 22.0.0
    // ships npm 10.5.1, inside the failing band.
    for (const old of ['8.19.4', '9.9.4', '10.2.4', '10.5.0', '10.5.1']) {
      const run = runInstallWithNpm(old);
      expect([old, run.status]).not.toEqual([old, 0]);
      // And it must not have installed anything with a client it cannot use.
      expect([old, run.record.includes('argv=install')]).toEqual([old, false]);
    }
  });

  it('accepts the first npm that actually verifies, and newer', () => {
    // The floor must not be too high either: 10.6.0 is the first version
    // measured to pass, so refusing it would break consumers for nothing.
    for (const ok of ['10.6.0', '10.9.2', '11.0.0']) {
      expect([ok, runInstallWithNpm(ok).status]).toEqual([ok, 0]);
    }
  });

  it('still reads the version when npm prints a notice above it', () => {
    // The shape that defeated two earlier versions of this floor. A per-line
    // shape check passed, then the arithmetic read the WHOLE string, errored,
    // the `if` read false, and the floor was skipped on a client it exists to
    // refuse.
    const old = runInstallWithNpm('npm notice a new version is available\\n10.5.0');
    expect(old.status).not.toBe(0);
    expect(old.record.includes('argv=install')).toBe(false);

    // The same shape must not refuse a client that is fine.
    expect(runInstallWithNpm('npm notice a new version is available\\n10.9.2').status).toBe(0);
  });

  it('refuses rather than assumes when it cannot read a version at all', () => {
    // A guard that fails open when it cannot see is not a guard.
    for (const unreadable of ['', 'not a version']) {
      const run = runInstallWithNpm(unreadable);
      expect([unreadable, run.status]).not.toEqual([unreadable, 0]);
      expect([unreadable, run.record.includes('argv=install')]).toEqual([unreadable, false]);
    }
  });

  it('never lets an installed package run its own install scripts', () => {
    // The scanner is a control input, and this step runs on a runner holding
    // the job's token. Without `--ignore-scripts` every package in the
    // resolved tree gets arbitrary code execution there on every run, which is
    // a strange amount of trust for the tool whose whole job is deciding
    // whether this repository can be trusted.
    //
    // It costs nothing here. `better-sqlite3` is the only native dependency,
    // it is an OPTIONAL dependency of the telemetry package, and the store
    // degrades when its bindings are missing -- `store-unavailable.test.ts`
    // covers exactly the "an --ignore-scripts install" case by name. Verified
    // against the real registry too: a global install with the flag scans a
    // clean tree to the same 627 bytes and the same exit 0 as one without it.
    const run = runInstall();
    const argvLine = run.record.split('\n').find((l) => l.startsWith('argv=install'));
    expect(argvLine).toBeDefined();
    expect(argvLine).toContain('--ignore-scripts');
  });

  it('checks the registry still serves every name and version it installed', () => {
    // Deliberately NOT titled "verifies what it installed". `npm audit
    // signatures` refetches manifests from the registry and checks the
    // signatures served back; it hashes nothing on disk, so a tampered install
    // passes it. Measured: appending a payload to the installed binary and
    // re-running the command exits 0. The honest claim is the title.
    const run = runInstall();
    expect(run.record).toContain('argv=audit signatures');
  });

  it('declares the scanner as a dependency, or the audit silently skips it', () => {
    // THE BUG THIS EXISTS FOR, found in review of the first version of this
    // step. `npm audit signatures` audits the tree's EDGES OUT. A global
    // install leaves `<prefix>/lib` with a `node_modules` and no manifest, so
    // the root declares nothing, the package just installed is on the far end
    // of no edge, and the audit covers its dependencies while skipping the
    // scanner -- the one package the check exists for.
    //
    // Measured on a real install: 13 added, 12 audited without this file; 13
    // audited and 5 attestations with it. The first version of this step
    // recorded that 12 as evidence the check worked.
    const runner = makeRunner();
    const scriptFile = path.join(runner.dir, 'install.sh');
    writeFileSync(scriptFile, action.extractRunScript(INSTALL_STEP));
    execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: action.cwdForStep(INSTALL_STEP, runner.ctx),
      env: stepEnvironment(runner, INSTALL_STEP, {}),
    });

    const manifestPath = path.join(runner.runnerTemp, 'vault-guard-action', 'lib', 'package.json');
    expect(existsSync(manifestPath)).toBe(true);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    // The declared version has to be the one being installed, or the audit
    // checks a different package than the one that landed.
    expect(manifest.dependencies['@vaultcompass/vault-guard']).toBe(runner.ctx.inputs.version);
  });

  it('verifies AFTER installing, never before', () => {
    // Ordering is the whole control. A verification that ran before the
    // install would be checking a tree that does not exist yet, and one that
    // ran after the scan would be an audit note rather than a gate.
    const run = runInstall();
    const lines = run.record.split('\n');
    const installAt = lines.findIndex((l) => l.startsWith('argv=install'));
    const auditAt = lines.findIndex((l) => l.startsWith('argv=audit signatures'));
    expect([installAt, auditAt].every((i) => i !== -1)).toBe(true);
    expect(auditAt).toBeGreaterThan(installAt);
  });

  it('the binary the run step calls is the one this step installs', () => {
    // The two steps agree by construction rather than by coincidence: the prefix
    // here and VG_BIN there both derive from runner.temp, and a change to one
    // that forgot the other would leave the run step calling a path nothing
    // wrote.
    const run = runInstall();
    const prefix = (run.record.split('\n').find((l) => l.startsWith('prefix=')) ?? '').slice(
      'prefix='.length,
    );
    expect(run.runner.env.VG_BIN).toBe(path.join(prefix, 'bin', 'vault-guard'));
  });
});

describe('action.yml runs the installed scanner and nothing else', () => {
  it("the head's copy is somewhere a bare-name resolution would reach it", () => {
    // Negative control. If this fails, "the planted copy never ran" below stops
    // being evidence and starts passing for the uninteresting reason that
    // nothing could have run it.
    const runner = makeRunner();
    const probe = execFileSync('vault-guard', [], {
      encoding: 'utf-8',
      cwd: runner.runnerTemp,
      env: { PATH: `${path.join(runner.workspace, 'node_modules/.bin')}:${process.env.PATH ?? ''}` },
    });
    expect(probe).toContain('PLANTED');
    expect(existsSync(runner.plantedRecord)).toBe(true);
  });

  it('ignores a node_modules copy and an .npmrc the head committed', () => {
    // The two redirects this boundary closes. The head controls both:
    // node_modules content comes from its package.json and lockfile, and a
    // committed `.npmrc` repoints the registry npm fetches from.
    const run = runStep(0);
    // The planted copy first, so a step that took the wrong binary fails with a
    // message naming the attack rather than one about a stub not being run.
    expect(run.plantedRan).toBe(false);
    expect(run.npxRan).toBe(false);
    expect(run.status).toBe(0);
    expect(run.outputs).toContain('exit_code=0');
  });

  it('declares a working directory outside the checkout on both steps', () => {
    // THE ISOLATION ASSERTION, and it is declarative on purpose.
    //
    // For the install step it is load-bearing and also proven behaviourally
    // above: npm started at the workspace root reads the head's `.npmrc`. For
    // the run step it is defence in depth -- the script chdirs to the scan root
    // itself, because vault-guard anchors its config, its trust base and every
    // path it reports at its own process cwd -- but a step that STARTS in the
    // head's tree is one edit away from doing something there, and the absence
    // of `working-directory` is invisible to every behavioural assertion in this
    // file. Deleting the key from either step turns this red, which is the
    // point: the harness reads the cwd from the step rather than supplying one.
    for (const step of [INSTALL_STEP, RUN_STEP]) {
      const runner = makeRunner();
      const declared = action.extractStepWorkingDirectory(step);
      expect([step, declared]).not.toEqual([step, '']);
      const resolved = action.cwdForStep(step, runner.ctx);
      expect([step, resolved]).toEqual([step, runner.runnerTemp]);
      expect([step, resolved.startsWith(runner.workspace)]).toEqual([step, false]);
    }
  });

  it('points the scanner at the scan root, which is where vault-guard reads its config', () => {
    // The other half of the same decision. vault-guard resolves the config, the
    // trust base and every reported path from its process cwd, so the step
    // chdirs there deliberately after starting outside the checkout. Run from
    // the runner temp instead, a pull-request scan would fail to resolve
    // `origin/<base>` and exit 2 on every run, blaming a fetch-depth the caller
    // already set.
    // Compared through realpath on both sides: `pwd -P` resolves symlinks, and
    // on macOS the system temp directory is one (`/var` -> `/private/var`).
    const run = runStep(0);
    expect(run.scannerCwd).toBe(realpathSync(run.runner.workspace));
  });

  it('scans the path the input asked for, not just the workspace root', () => {
    const argv = argvFor({ path: 'packages/cli', 'sarif-output': 'args.txt' });
    expect(argv).toContain(`${path.sep}workspace${path.sep}packages${path.sep}cli`);
  });

  it('scans an absolute path, so the scan root survives the move', () => {
    const argv = argvFor({ 'sarif-output': 'args.txt' });
    expect(argv.split(/\s+/).some((a) => a.startsWith('/'))).toBe(true);
  });

  it('passes the format input through to the scanner', () => {
    expect(argvFor({ 'sarif-output': 'args.txt' })).toContain('--format sarif');
    expect(argvFor({ format: 'text', 'sarif-output': 'args.txt' })).toContain('--format text');
  });

  it('passes --trust-base on a pull_request event and nowhere else', () => {
    // GITHUB_BASE_REF is set by GitHub on, and only on, a pull_request event, so
    // it is what decides the default. The origin/ prefix is part of what this
    // asserts: a bare "main" would not resolve after a detached-HEAD checkout.
    const invoke = (env: Record<string, string>, inputs: Record<string, string> = {}) =>
      argvFor({ 'sarif-output': 'args.txt', ...inputs }, env);

    expect(invoke({})).not.toContain('--trust-base');
    expect(invoke({ GITHUB_BASE_REF: 'main' })).toContain('--trust-base origin/main');
    expect(invoke({ GITHUB_BASE_REF: 'main' }, { 'trust-base': 'origin/release' })).toContain(
      '--trust-base origin/release',
    );
  });

  it('refuses a scan path that resolves outside the workspace through a symlink', () => {
    // The validate step's rules constrain the STRING -- no `..`, no leading
    // slash -- and the head controls the directories those names point at. A
    // `src` symlink would otherwise put the runner's own filesystem into a
    // document the caller uploads.
    const runner = makeRunner({ path: 'src' });
    installStubScanner(runner, {});
    const outside = path.join(runner.dir, 'outside-the-workspace');
    mkdirSync(outside, { recursive: true });
    // makeRunner created the scan root as a real directory; replace it.
    rmSync(path.join(runner.workspace, 'src'), { recursive: true, force: true });
    symlinkSync(outside, path.join(runner.workspace, 'src'));

    const run = runStepFor(runner);
    expect(run.status).not.toBe(0);
    expect(run.stdout).toContain('resolves outside the workspace');
  });

  it('fails rather than scanning the wrong directory when the path does not exist', () => {
    const runner = makeRunner({ path: 'src' });
    installStubScanner(runner, {});
    rmSync(path.join(runner.workspace, 'src'), { recursive: true, force: true });

    const run = runStepFor(runner);
    expect(run.status).not.toBe(0);
    expect(run.stdout).toContain('does not name a directory in the checkout');
    // And nothing was scanned: the step stopped before the scanner was called.
    expect(run.scannerCwd).toBe('');
  });

  it('refuses a results target that resolves through a symlink at any depth', () => {
    // The head controls the filename and every directory on the way to it. A
    // guard that checked only the leaf and its immediate parent is walked past
    // with one more level of nesting.
    for (const [target, linkAt] of [
      ['out.sarif', 'out.sarif'],
      ['reports/out.sarif', 'reports'],
      ['reports/sub/out.sarif', 'reports'],
      ['a/b/c/out.sarif', 'a'],
      // A TRAILING SLASH on the final component. `test -L` FOLLOWS the link
      // when the path it is given ends in a slash, so this spelling walked
      // straight past the guard: `dirname` then returned the workspace, the
      // loop ended having checked nothing, and the write went through the link.
      ['out.sarif/', 'out.sarif'],
    ]) {
      const runner = makeRunner({ 'sarif-output': target });
      installStubScanner(runner, {});
      const outside = path.join(runner.dir, 'outside-the-workspace');
      mkdirSync(outside, { recursive: true });
      const linkPath = path.join(runner.workspace, linkAt);
      mkdirSync(path.dirname(linkPath), { recursive: true });
      symlinkSync(outside, linkPath);

      const outputFile = path.join(runner.dir, 'github-output');
      writeFileSync(outputFile, '');
      const scriptFile = path.join(runner.dir, 'step.sh');
      writeFileSync(scriptFile, action.extractRunScript(RUN_STEP));
      let status = 0;
      try {
        execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
          encoding: 'utf-8',
          stdio: ['ignore', 'pipe', 'pipe'],
          cwd: action.cwdForStep(RUN_STEP, runner.ctx),
          env: stepEnvironment(runner, RUN_STEP, { GITHUB_OUTPUT: outputFile }),
        });
      } catch (err) {
        const e = err as { status?: number };
        status = typeof e.status === 'number' ? e.status : -1;
      }
      expect([target, status]).not.toEqual([target, 0]);
      // And nothing was written through the link, including by `mkdir -p`, which
      // runs after the check rather than before it.
      expect([target, readdirSync(outside)]).toEqual([target, []]);
    }
  });
});

describe('action.yml "Run vault-guard", under GitHub bash flags', () => {
  it('records the outputs when vault-guard exits 0', () => {
    const run = runStep(0);
    expect(run.outputs).toContain('exit_code=0');
    expect(run.outputs).toMatch(/results_file=.*vault-guard-results\.sarif/);
    expect(existsSync(run.sarifPath)).toBe(true);
  });

  it('records the outputs when vault-guard exits 1, the case a stray errexit breaks', () => {
    // GitHub invokes a composite bash step with errexit already on, so a script
    // that let it stand would abort at the scan the moment vault-guard exited
    // non-zero -- the entire interesting case -- and never reach the status
    // capture. The outputs would be empty and the findings would never be
    // uploaded.
    const run = runStep(1);
    expect(run.outputs).toContain('exit_code=1');
    expect(run.outputs).toMatch(/results_file=.*vault-guard-results\.sarif/);
    expect(run.status).toBe(1);
  });

  it('re-raises exit 2 as exit 2, in different words from findings', () => {
    // 2 means vault-guard could not establish something it needed, which is a
    // different fact from "there are findings" and must not be reported as one.
    const run = runStep(2, {}, {});
    expect(run.outputs).toContain('exit_code=2');
    expect(run.status).toBe(2);
  });

  it('treats any other code as could not run, never as findings', () => {
    // 126 and 127 are what the SHELL produces when a binary is missing or not
    // executable, which is exactly what a failed install looks like from here.
    // Reporting those as findings would invent a verdict.
    for (const code of [3, 126, 127]) {
      const run = runStep(code);
      expect([code, run.status]).toEqual([code, 2]);
      expect(run.stdout).toContain('did not produce a result');
    }
  });

  it('publishes the MAPPED exit code, not the raw shell status', () => {
    // The binary is never installed here, so the shell answers 127. A caller
    // reading `exit-code` is doing so precisely to tell a verdict from a
    // failure to reach one, and the output documents three values: publishing
    // the raw 127 would hand them a fourth the contract says cannot happen.
    //
    // It also proves the absolute path does not fall back to PATH: the head's
    // planted copy is first on PATH and answers to the same name, and a step
    // that resolved by name would have run it and exited 0.
    const runner = makeRunner();
    const run = runStepFor(runner);
    expect(run.status).toBe(2);
    expect(run.outputs).toContain('exit_code=2');
    expect(run.outputs).not.toContain('exit_code=127');
    expect(run.plantedRan).toBe(false);
    expect(run.stdout).toContain('did not produce a result');
  });

  it('publishes no results file when the scan wrote nothing', () => {
    // vault-guard exits before writing any document when it could not run, and
    // `tee` has already created the target, so the file exists and is empty.
    // Handing that to upload-sarif fails the job with a parse error that buries
    // the real cause.
    const runner = makeRunner();
    installStubScanner(runner, { exitCode: 2, body: '' });
    // An empty body: `echo ''` still writes a newline, so the stub is rewritten
    // to print nothing at all.
    writeFileSync(runner.env.VG_BIN, '#!/bin/sh\nexit 2\n');
    chmodSync(runner.env.VG_BIN, 0o755);

    const outputFile = path.join(runner.dir, 'github-output');
    writeFileSync(outputFile, '');
    const scriptFile = path.join(runner.dir, 'step.sh');
    writeFileSync(scriptFile, action.extractRunScript(RUN_STEP));
    try {
      execFileSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', scriptFile], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: action.cwdForStep(RUN_STEP, runner.ctx),
        env: stepEnvironment(runner, RUN_STEP, { GITHUB_OUTPUT: outputFile }),
      });
    } catch {
      // Exit 2 is the point of the case.
    }
    const outputs = readFileSync(outputFile, 'utf-8');
    expect(outputs).toContain('results_file=\n');
    expect(outputs).toContain('exit_code=2');
  });

  it('writes only what the scanner printed, with no shell noise', () => {
    const run = runStep(1);
    expect(() => JSON.parse(readFileSync(run.sarifPath, 'utf-8'))).not.toThrow();
  });

  // A stub that exits with `code` having written nothing to stdout. Commander
  // writes its argument errors to STDERR, which is why the report the step tees
  // is empty in exactly this case, and why a stub that echoed something to
  // stdout would be testing a different program.
  function runStepWritingNothing(code: number): RunResult {
    const runner = makeRunner();
    installStubScanner(runner);
    writeFileSync(runner.env.VG_BIN, `#!/bin/sh\necho 'boom' >&2\nexit ${code}\n`);
    chmodSync(runner.env.VG_BIN, 0o755);
    return runStepFor(runner);
  }

  it('reports a CLI argument failure as could not run, never as findings', () => {
    // Commander exits 1 on an unknown option, and 1 is also the findings code.
    // An action that reads the number alone tells a repository it is carrying
    // secrets when the scanner never got past parsing its own argv. The
    // realistic way in is version skew: a `version` input older than the flags
    // this tag passes, which is how this was found.
    //
    // The disproof is already in hand by this point in the step -- findings
    // would have produced a report, and there is no report.
    const run = runStepWritingNothing(1);
    expect(run.status).toBe(2);
    expect(run.outputs).toContain('exit_code=2');
    expect(run.stdout).toContain('did not produce a result');
    expect(run.stdout).not.toContain('found secrets');
  });

  it('never reports a clean result from a scan that wrote nothing', () => {
    // The same inference as the case above, on the arm where getting it wrong
    // fails OPEN: an exit 0 with no report is not a clean scan, it is a scan
    // that did not happen, and calling it clean passes a pull request that
    // nothing looked at.
    const run = runStepWritingNothing(0);
    expect(run.status).toBe(2);
    expect(run.outputs).toContain('exit_code=2');
    expect(run.stdout).toContain('did not produce a result');
  });

  it('names the trust base when the scanner itself says it could not run', () => {
    // The scanner's reachable exit-2 paths write to stderr and no report, so
    // they land in the no-report branch too. Left there, the generic message
    // would tell someone whose actual problem is a missing `fetch-depth: 0` --
    // the one failure the Action docs single out -- to go and check their
    // `version` input instead. A status of 2 is the scanner reporting
    // could-not-run itself and needs no inference from what it wrote.
    const run = runStepWritingNothing(2);
    expect(run.status).toBe(2);
    expect(run.outputs).toContain('exit_code=2');
    expect(run.stdout).toContain('unresolvable trust base');
    expect(run.stdout).not.toContain('check the `version` input');
  });

  it('still calls a report with findings in it findings', () => {
    // The guard above keys on the REPORT rather than on the exit code, so this
    // is the assertion that keeps it from swallowing the case the gate exists
    // for.
    const run = runStep(1);
    expect(run.status).toBe(1);
    expect(run.outputs).toContain('exit_code=1');
    expect(run.stdout).toContain('found secrets');
  });
});
