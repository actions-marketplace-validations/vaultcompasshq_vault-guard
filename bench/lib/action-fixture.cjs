// The two halves of the world the action's install step runs in: the packages
// the LEGITIMATE registry serves, and the hostile checkout the head controls.
//
// Nothing here is stubbed. The legitimate tarballs are this worktree's own
// packages/core, packages/telemetry and packages/cli, packed the same way a
// publish packs them, so the binary that ends up running really is the scanner
// this repository builds. The hostile checkout is a real git repository
// carrying a real `.npmrc` and a real node_modules copy, because both attack
// routes are decisions npm makes about files on disk and a fixture that only
// described them would prove nothing.

const { execFileSync } = require('child_process');
const {
  accessSync,
  chmodSync,
  constants: fsConstants,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} = require('fs');
const path = require('path');

const { readTarballEntry } = require('./tarball.cjs');

// The directories a step is allowed to find a program in, beyond the ones this
// harness builds for it. Deliberately the base system ones and nothing else.
const SYSTEM_PATH_DIRS = ['/usr/bin', '/bin', '/usr/sbin', '/sbin'];

// Hooks and a template directory are the two things a git repository can carry
// that run code on this machine. The fixture below is built by this file, so
// neither is a live risk here; they are disabled anyway because the harness
// should not depend on the machine's git configuration to be reproducible.
const GIT_FLAGS = [
  '-c',
  'core.hooksPath=',
  '-c',
  'commit.gpgsign=false',
  '-c',
  'user.name=vault-guard action dogfood',
  '-c',
  'user.email=dogfood@example.invalid',
];

function git(cwd, args) {
  execFileSync('git', [...GIT_FLAGS, ...args], {
    cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, GIT_TEMPLATE_DIR: '', GIT_CONFIG_NOSYSTEM: '1' },
  });
}

function readManifestFromTarball(tarballPath) {
  const entry = readTarballEntry(readFileSync(tarballPath), 'package/package.json');
  if (!entry) {
    throw new Error(`${tarballPath} has no package/package.json`);
  }
  return JSON.parse(entry.toString('utf8'));
}

// npm and pnpm both name a pack file `<name with @ dropped and / replaced by a
// dash>-<version>.tgz`. Computed rather than globbed: two of the packages here
// are `@vaultcompass/vault-guard` at the same version -- the real one and the
// hostile stand-in -- and a glob that matched the wrong one would pass this
// harness while proving the opposite of what it claims.
function packFileName(name, version) {
  return `${name.replace('@', '').replace('/', '-')}-${version}.tgz`;
}

function packageEntry(dir, name, version) {
  const tarballPath = path.join(dir, packFileName(name, version));
  if (!existsSync(tarballPath)) {
    throw new Error(
      `pack did not produce ${packFileName(name, version)} in ${dir}; found ${readdirSync(dir).join(', ')}`,
    );
  }
  const manifest = readManifestFromTarball(tarballPath);
  if (manifest.name !== name || manifest.version !== version) {
    throw new Error(`${tarballPath} carries ${manifest.name}@${manifest.version}, not ${name}@${version}`);
  }
  return { name, version, manifest, tarball: readFileSync(tarballPath) };
}

function manifestAt(dir) {
  return JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'));
}

// Every third-party package the scanner needs at runtime, found the way node
// finds them rather than by a list written here: a list would go stale the next
// time a dependency is added, and the failure would be an install error in the
// middle of a security harness rather than a missing entry anybody could see.
//
// optionalDependencies are deliberately NOT followed. `better-sqlite3` is one,
// it is a native module, and building it from a local registry would be a
// node-gyp run in the middle of this harness for a code path the scan never
// takes. npm is expected to fail soft on it, and the recorded baseline is what
// pins that expectation: if npm ever starts failing hard, the install status in
// the baseline changes and the harness says so.
//
// Resolved by walking `node_modules` upward rather than with
// `require.resolve('<name>/package.json')`: a package with an `exports` map does
// not have to export its own manifest, and commander does not, so the tidy
// spelling throws ERR_PACKAGE_PATH_NOT_EXPORTED on the first dependency it
// meets. The walk also lands on pnpm's real directories, which is where a
// transitive dependency's own siblings live.
//
// REALPATH'D, because pnpm links a dependency into its dependent's node_modules
// and keeps the real directory in the store. Walking up from the LINK stays in
// the dependent's tree, where a transitive dependency's siblings are not; the
// walk has to continue from the store directory that actually holds them.
function resolvePackageDir(name, fromDir) {
  let current = fromDir;
  for (;;) {
    const candidate = path.join(current, 'node_modules', name);
    if (existsSync(path.join(candidate, 'package.json'))) return realpathSync(candidate);
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function resolveRuntimeClosure(entryDirs) {
  const found = new Map();
  const queue = entryDirs.map((dir) => ({ dir, deps: manifestAt(dir).dependencies ?? {} }));

  while (queue.length > 0) {
    const { dir, deps } = queue.shift();
    for (const name of Object.keys(deps)) {
      // The workspace packages are packed explicitly by the caller; a
      // `workspace:*` spec is not something to resolve here.
      if (name.startsWith('@vaultcompass/')) continue;
      const depDir = resolvePackageDir(name, dir);
      if (depDir === null) {
        throw new Error(
          `${name} is not installed under ${dir}; run pnpm install --frozen-lockfile first`,
        );
      }
      if (found.has(depDir)) continue;
      found.set(depDir, manifestAt(depDir));
      queue.push({ dir: depDir, deps: manifestAt(depDir).dependencies ?? {} });
    }
  }
  return [...found.keys()];
}

// The scanner as the registry would serve it, plus its dependency closure.
//
// PACKED, NOT LINKED. `npm install -g` resolves a spec against a registry and
// unpacks a tarball; handing it a directory would exercise a different code path
// from the one a runner takes, and the code path is the thing under test. pnpm
// pack rewrites the `workspace:*` dependencies to exact version pins exactly as
// `pnpm publish` would.
//
// THE DEPENDENCY CLOSURE IS SERVED TOO, because the harness must not touch the
// network: chalk, commander, ignore and whatever they pull are packed from the
// copies already installed in this worktree.
function packRealPackages({ repoRoot, workDir }) {
  const packDir = path.join(workDir, 'real-packs');
  mkdirSync(packDir, { recursive: true });

  const cliSrc = path.join(repoRoot, 'packages', 'cli');
  const coreSrc = path.join(repoRoot, 'packages', 'core');
  const telemetrySrc = path.join(repoRoot, 'packages', 'telemetry');
  if (!existsSync(path.join(cliSrc, 'dist', 'cli-entry.js'))) {
    throw new Error(
      `no built CLI at ${path.join(cliSrc, 'dist', 'cli-entry.js')}; run pnpm build first`,
    );
  }

  for (const dir of [coreSrc, telemetrySrc, cliSrc]) {
    execFileSync('pnpm', ['--dir', dir, 'pack', '--pack-destination', packDir], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }

  const cli = packageEntry(packDir, manifestAt(cliSrc).name, manifestAt(cliSrc).version);
  const core = packageEntry(packDir, manifestAt(coreSrc).name, manifestAt(coreSrc).version);
  const telemetry = packageEntry(
    packDir,
    manifestAt(telemetrySrc).name,
    manifestAt(telemetrySrc).version,
  );

  const deps = [];
  for (const from of resolveRuntimeClosure([cliSrc, coreSrc, telemetrySrc])) {
    // --ignore-scripts because these are third-party packages and this is
    // packing them, not installing them.
    execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', packDir, from], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const depManifest = manifestAt(from);
    deps.push(packageEntry(packDir, depManifest.name, depManifest.version));
  }

  return { cli, core, telemetry, deps, all: [cli, core, telemetry, ...deps] };
}

// Writes the marker, then prints an empty but VALID SARIF log and exits 0.
//
// Valid matters. An unparseable body would fail the caller's upload step and
// draw attention; an empty run list is a green check with nothing in it, which
// is the outcome an attacker wants and the outcome this harness has to be able
// to see. It names itself `vault-guard` in the tool driver, because an attacker
// would: a log announcing itself as something else is one a reviewer notices.
// So the discriminator is never the name -- it is that the real scanner reports
// its own run metadata and a rule catalogue, and a stand-in faking a clean run
// emits neither.
function hostileScript(markerPath, marker) {
  return [
    '#!/bin/sh',
    `printf '%s\\n' ${JSON.stringify(marker)} >> ${JSON.stringify(markerPath)}`,
    `echo '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0","runs":[{"tool":{"driver":{"name":"vault-guard","rules":[]}},"results":[]}]}'`,
    'exit 0',
    '',
  ].join('\n');
}

// The scanner the ATTACKER would rather run. Same name, same exact version, so
// the pin in the workflow file is satisfied either way and the only thing that
// decides which one runs is where npm looked.
function buildHostilePackage({ workDir, name, version, markerPath, marker }) {
  // A pack directory of its own. This package deliberately carries the same
  // name and the same exact version as the real one, so its tarball has the
  // same filename, and one directory holding both would hand whichever of them
  // was written second to every caller.
  const packDir = path.join(workDir, 'hostile-packs');
  mkdirSync(packDir, { recursive: true });
  const dir = path.join(workDir, 'hostile-package');
  mkdirSync(dir, { recursive: true });

  writeFileSync(
    path.join(dir, 'package.json'),
    `${JSON.stringify(
      {
        name,
        version,
        description: 'stand-in for a scanner the tree under judgment chose for itself',
        bin: { 'vault-guard': 'vault-guard.sh' },
        files: ['vault-guard.sh'],
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(path.join(dir, 'vault-guard.sh'), hostileScript(markerPath, marker));
  chmodSync(path.join(dir, 'vault-guard.sh'), 0o755);

  execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', packDir, dir], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return packageEntry(packDir, name, version);
}

// The credential the head commits, assembled at RUNTIME from fragments.
//
// Written this way on purpose, and the repository's own agent rules say to: a
// contiguous vendor-anchored key in a tracked file is a finding, and this file
// is tracked. vault-guard scans its own repository in CI and at commit time, so
// a fixture secret spelled out here would block the commit that added the
// harness -- correctly. Joined at runtime it is a secret to the scanner reading
// the FIXTURE and not to the scanner reading this file, which is exactly the
// distinction the directive exists for.
// The body is chunked rather than written as one string for the same reason,
// and the chunks are deliberately not a repeated character: a run of identical
// or sequential characters is what the scanner's own placeholder and
// sequential-run rules exist to downgrade, so a lazier fixture would be
// reported at `low`, sail under the default gate, and the real scanner would
// exit 0 -- the same exit code as the attacker's stand-in, and the harness
// would have nothing to tell them apart by.
function fixtureSecretLine() {
  const value =
    ['sk', 'ant', 'api03'].join('-') +
    '-' +
    ['7Kd2Lp', '9Qw4Zx', '3Vb6Nm', '1Tr8Hs', '5Yj0Gf'].join('');
  return `export const client = createClient({ apiKey: '${value}' });\n`;
}

// The checkout GITHUB_WORKSPACE points at: a real git repository whose head
// commit adds a file carrying a vendor-anchored credential, with the base branch
// present as `origin/main` so pull-request mode can resolve it.
//
// PULL_REQUEST IS THE RUN THAT MATTERS. The head of a pull request is written by
// somebody who is not trusted yet, which is the whole reason the scanner has to
// come from outside the tree. So the fixture is shaped like one: two commits, a
// remote-tracking ref at the base, and GITHUB_BASE_REF set, which is what makes
// the run step pass `--trust-base origin/main`.
//
// The head commit is what makes the real scanner exit 1. That is the
// load-bearing half of this fixture: a hostile scanner exits 0, so the recorded
// gate result is the difference between a red check and a green one rather than
// a detail in a log.
function buildCheckout({ dir, version, evilRegistryOrigin, npmrcKey = 'global', planted }) {
  mkdirSync(dir, { recursive: true });

  writeFileSync(
    path.join(dir, 'package.json'),
    `${JSON.stringify(
      { name: 'vault-guard-action-dogfood-fixture', version: '1.0.0', private: true },
      null,
      2,
    )}\n`,
  );
  mkdirSync(path.join(dir, 'src'), { recursive: true });
  writeFileSync(path.join(dir, 'src', 'clean.ts'), 'export const greeting = "hello world";\n');

  git(dir, ['init', '-q', '-b', 'main']);
  git(dir, ['add', 'package.json', 'src/clean.ts']);
  git(dir, ['commit', '-q', '-m', 'base']);
  // The base branch as actions/checkout leaves it: a remote-tracking ref, not a
  // local branch. A bare "main" would not resolve on a detached-HEAD checkout,
  // which is why the run step prefixes origin/.
  git(dir, ['update-ref', 'refs/remotes/origin/main', 'HEAD']);

  writeFileSync(path.join(dir, 'src', 'client.ts'), fixtureSecretLine());
  git(dir, ['add', 'src/client.ts']);
  git(dir, ['commit', '-q', '-m', 'head']);

  // ROUTE ONE: a committed `.npmrc` repoints the registry.
  //
  // TWO KEYS DO THIS, and the harness runs both. `registry=` is the global one
  // and the simplest form an attacker would commit; `@vaultcompass:registry=` is
  // scope-specific, takes precedence over the global key for this package alone,
  // and is the quieter of the two because every other install in the workflow
  // keeps working normally. Neither may reach the scanner.
  writeFileSync(
    path.join(dir, '.npmrc'),
    npmrcKey === 'scoped'
      ? `@vaultcompass:registry=${evilRegistryOrigin}/\n`
      : `registry=${evilRegistryOrigin}/\n`,
  );

  // ROUTE TWO: a copy already in node_modules wins outright. `npx pkg@version`
  // in a tree whose node_modules already satisfies that spec runs the local copy
  // and never contacts a registry at all, so the version pin stops being a
  // choice of program and becomes a satisfaction check on a package the head
  // wrote. Any workflow with an install step before the gate produces this.
  if (planted) {
    const pkgDir = path.join(dir, 'node_modules', '@vaultcompass', 'vault-guard');
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      path.join(pkgDir, 'package.json'),
      `${JSON.stringify(
        { name: '@vaultcompass/vault-guard', version, bin: { 'vault-guard': 'vault-guard.sh' } },
        null,
        2,
      )}\n`,
    );
    writeFileSync(path.join(pkgDir, 'vault-guard.sh'), hostileScript(planted.markerPath, planted.marker));
    chmodSync(path.join(pkgDir, 'vault-guard.sh'), 0o755);

    const binDir = path.join(dir, 'node_modules', '.bin');
    mkdirSync(binDir, { recursive: true });
    writeFileSync(path.join(binDir, 'vault-guard'), hostileScript(planted.markerPath, planted.marker));
    chmodSync(path.join(binDir, 'vault-guard'), 0o755);
  }

  return dir;
}

// The first directory on `searchPath` holding an executable file called `name`,
// or null. Pure path arithmetic and a stat, so the harness can ask the question
// about a PATH it has not run anything with yet.
function resolveOnPath(name, searchPath) {
  for (const dir of searchPath.split(path.delimiter)) {
    if (dir.length === 0) continue;
    const candidate = path.join(dir, name);
    try {
      if (!statSync(candidate).isFile()) continue;
      accessSync(candidate, fsConstants.X_OK);
      return candidate;
    } catch {
      // Not there, or not executable. Next.
    }
  }
  return null;
}

// A PATH the harness controls, holding exactly the programs a step needs.
//
// THIS IS NOT TIDINESS, IT IS THE DIFFERENCE BETWEEN A RESULT AND A FICTION. A
// machine with `@vaultcompass/vault-guard` installed globally at the very
// version the fixture pins hands `npm exec pkg@version` a binary that already
// satisfies the spec, so npx reads the hostile packument, finds the operator's
// copy good enough, and runs THAT -- and the harness records a clean,
// real-scanner run for the vulnerable action. The attack has not failed; the
// harness has stopped being able to see it, and the honest-looking result is the
// bug.
//
// So the inherited PATH is thrown away. Each tool a step needs is wrapped by a
// one-line script that execs the real absolute path, which keeps npm and npx
// working out of a node installation whose bin directory this PATH never
// contains. Anything else a step reaches for comes from the base system
// directories or does not resolve at all.
function buildToolBin({ dir, tools, sourcePath = process.env.PATH ?? '' }) {
  mkdirSync(dir, { recursive: true });
  const resolved = {};
  for (const tool of tools) {
    const target = resolveOnPath(tool, sourcePath);
    if (target === null) {
      throw new Error(`${tool} is not on PATH, so the harness cannot give a step a way to run it`);
    }
    const wrapper = path.join(dir, tool);
    writeFileSync(wrapper, `#!/bin/sh\nexec ${JSON.stringify(target)} "$@"\n`);
    chmodSync(wrapper, 0o755);
    resolved[tool] = target;
  }
  return { dir, resolved };
}

// The PATH a step actually runs with, and the ordering is the adversarial one:
// the CHECKOUT'S OWN node_modules/.bin comes first, which is what a workflow
// with an install step before the gate produces. Without that ordering, "the
// planted copy never ran" would hold for the uninteresting reason that nothing
// could have reached it.
function stepPath({ workspace, toolBinDir }) {
  return [path.join(workspace, 'node_modules', '.bin'), toolBinDir, ...SYSTEM_PATH_DIRS].join(
    path.delimiter,
  );
}

// The RUNNER's own npm configuration, which is a different file from the one in
// the checkout and is the whole point of the distinction. A real runner reads a
// user-level ~/.npmrc that the pull request cannot write; the checkout gets a
// project-level `.npmrc` that it can. Pointing this one at the legitimate server
// and the other at the hostile one is what makes "which registry answered" a
// readable answer rather than a coincidence.
//
// `prefix` is the second half of the isolation, and PATH alone does not get it.
// `npm exec pkg@version` will run a binary it finds in the GLOBAL bin directory
// when the package behind it satisfies the spec, and it finds that directory
// from npm's own `prefix` config rather than by searching PATH. Left at the
// default it is the node installation's own prefix, so on a developer machine
// with the scanner installed globally the vulnerable action would come out
// looking clean. The install step's own `npm_config_prefix` still wins over
// this, because an environment variable beats a user config file.
//
// audit, fund and the update notifier are turned off because each of them
// reaches for a host this harness does not run, and a hang or a stray 404 in the
// request log would be noise in the recorded result. All of it is runner
// configuration, not action configuration: the install step's command line is
// taken from action.yml unchanged.
function buildRunnerHome({ dir, legitRegistryOrigin, npmPrefix }) {
  mkdirSync(dir, { recursive: true });
  mkdirSync(npmPrefix, { recursive: true });
  writeFileSync(
    path.join(dir, '.npmrc'),
    [
      `registry=${legitRegistryOrigin}/`,
      `prefix=${npmPrefix}`,
      'audit=false',
      'fund=false',
      'update-notifier=false',
      'progress=false',
      '',
    ].join('\n'),
  );
  return dir;
}

module.exports = {
  SYSTEM_PATH_DIRS,
  buildCheckout,
  buildHostilePackage,
  buildRunnerHome,
  buildToolBin,
  packRealPackages,
  resolveOnPath,
  stepPath,
};
