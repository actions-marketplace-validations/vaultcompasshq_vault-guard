// Tests for the release-kind decision: given a pushed tag and the version
// every published package carries, is this a package release (publish
// everything) or an action-only release (publish nothing, move the tag,
// cut a Release)?
//
// Ported from dep-guard's scripts/tests/release-kind.test.mjs, generalised
// from two packages (core, cli) to vault-guard's four
// (vault-guard-core, vault-guard, vault-guard-mcp, vault-guard-telemetry --
// vault-guard-vscode is Marketplace-only and is never part of this check).
//
// Run under jest.release-kind.config.mjs (see the "test:release-kind"
// script in package.json), not under any package's own ts-jest config --
// these are plain ESM files with no build step ahead of them, matching
// how .github/workflows/release.yml runs scripts/classify-release-tag.mjs
// before "pnpm install". No import from '@jest/globals': describe/it/expect
// are ambient jest globals here, the same way every other test file in
// this repository uses them (via @types/jest for the TypeScript suites;
// this file has no types package equivalent, so eslint.config.mjs declares
// them as globals for scripts/tests/**/*.test.mjs instead).
//
// Everything here runs offline. The registry lookup is injected -- as a
// function at the library level, as an executable at the script level
// (VG_NPM_BIN) -- so no test in this file can pass or fail because of what
// npmjs.com happened to answer.

import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  EXACT_SEMVER,
  classifyRelease,
  compareExactSemver,
  parseExactSemver,
  readActionVersionDefault,
} from '../lib/release-kind.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'classify-release-tag.mjs');

const CORE_NAME = '@vaultcompass/vault-guard-core';
const CLI_NAME = '@vaultcompass/vault-guard';
const MCP_NAME = '@vaultcompass/vault-guard-mcp';
const TELEMETRY_NAME = '@vaultcompass/vault-guard-telemetry';
const PACKAGE_NAMES = [CORE_NAME, CLI_NAME, MCP_NAME, TELEMETRY_NAME];

// The four packages at a single version, one of them optionally overridden
// by name -- used to build a lockstep break without repeating all four.
function packagesAt(version, overrides = {}) {
  return PACKAGE_NAMES.map((name) => ({ name, version: overrides[name] ?? version }));
}

// A stand-in action.yml whose description block deliberately contains the
// string "default:" and a version-shaped number in prose, the same trap
// the real file's version input description has (it names an example
// version and uses the word "default" in prose). A parser that just
// grepped for the first "default:" after "version:" would read the prose
// and be wrong in the direction that matters: it would compare the tag
// against a number nobody ships.
function actionYmlWith(defaultVersion) {
  return [
    'name: Vault Guard',
    'inputs:',
    '  version:',
    '    description: |',
    '      npm dist-tag or semver for @vaultcompass/vault-guard, such as `1.7.0`.',
    '      The default: below is the scanner version this action tag shipped with.',
    '    required: false',
    `    default: ${defaultVersion}`,
    '  path:',
    '    description: Path to scan',
    '    required: false',
    '    default: .',
    'runs:',
    '  using: composite',
    '',
  ].join('\n');
}

// A CHANGELOG.md in this repository's own style: "## [1.7.0] - 2026-09-06".
function changelogWith(...versions) {
  return [
    '# Changelog',
    '',
    ...versions.flatMap((version) => [`## [${version}] - 2026-09-13`, '', '- Something changed.', '']),
  ].join('\n');
}

function registryStub(publishedSpecs) {
  const published = new Set(publishedSpecs);
  const calls = [];
  const lookup = (name, version) => {
    calls.push(`${name}@${version}`);
    return published.has(`${name}@${version}`) ? version : null;
  };
  lookup.calls = calls;
  return lookup;
}

// The happy action-only case, spelled out once: all four packages at 1.7.0
// and all four live on the registry at exactly that version, action.yml's
// default at 1.7.0, a CHANGELOG entry for 1.8.0, tag v1.8.0.
function actionOnlyInputs(overrides = {}) {
  return {
    tagName: 'v1.8.0',
    refDescription: 'tag v1.8.0',
    packages: packagesAt('1.7.0'),
    actionYmlText: actionYmlWith('1.7.0'),
    changelogText: changelogWith('1.8.0', '1.7.0'),
    publishedVersion: registryStub(PACKAGE_NAMES.map((name) => `${name}@1.7.0`)),
    ...overrides,
  };
}

describe('parseExactSemver', () => {
  it('accepts an exact three-part version with no leading zeros', () => {
    expect(parseExactSemver('1.7.0')).toEqual([1, 7, 0]);
    expect(parseExactSemver('10.20.30')).toEqual([10, 20, 30]);
  });

  it('rejects prerelease and build suffixes, leading zeros, and short forms', () => {
    for (const bad of ['1.7.1-rc.1', '1.7.1+build.5', '01.2.3', '1.7.00', '1.7', 'v1.7.1', '', 'latest']) {
      expect(parseExactSemver(bad)).toBeNull();
    }
  });

  it('does not admit action.yml\'s dist-tag values, since a release tag is never one', () => {
    // action.yml's own `version` input accepts `latest`, `next` and `beta`
    // for consumers who want to float -- a release tag is never any of
    // those, and EXACT_SEMVER is deliberately stricter than that input's
    // own charset for exactly this reason.
    for (const distTag of ['latest', 'next', 'beta']) {
      expect(EXACT_SEMVER.test(distTag)).toBe(false);
    }
  });
});

describe('compareExactSemver', () => {
  it('orders by number, not by string', () => {
    // The string comparison bash would have done reads "1.9.0" as greater
    // than "1.10.0". This is the one place that difference decides whether
    // a tag is a forward move or a mistake.
    expect(compareExactSemver([1, 10, 0], [1, 9, 0])).toBeGreaterThan(0);
    expect(compareExactSemver([1, 7, 1], [1, 7, 0])).toBeGreaterThan(0);
    expect(compareExactSemver([1, 7, 0], [1, 7, 1])).toBeLessThan(0);
    expect(compareExactSemver([2, 0, 0], [1, 99, 99])).toBeGreaterThan(0);
    expect(compareExactSemver([1, 7, 0], [1, 7, 0])).toBe(0);
  });
});

describe('readActionVersionDefault', () => {
  it('reads the version input default, not a version-shaped string in its prose', () => {
    expect(readActionVersionDefault(actionYmlWith('1.7.0'))).toBe('1.7.0');
  });

  it('is not confused by a later input that also has a default', () => {
    expect(readActionVersionDefault(actionYmlWith('1.2.3'))).toBe('1.2.3');
  });

  it('throws when there is no version input to read', () => {
    const yml = ['inputs:', '  path:', '    default: .', ''].join('\n');
    expect(() => readActionVersionDefault(yml)).toThrow(/version/i);
  });

  it('throws when the version input has no default', () => {
    const yml = ['inputs:', '  version:', '    required: true', '  path:', '    default: .', ''].join('\n');
    expect(() => readActionVersionDefault(yml)).toThrow(/default/i);
  });

  it('throws when there is no inputs block at all', () => {
    const yml = ['name: Vault Guard', 'runs:', '  using: composite', ''].join('\n');
    expect(() => readActionVersionDefault(yml)).toThrow(/inputs/i);
  });

  it('reads the version input, not a same-named key in another top-level block', () => {
    // "version" is a plausible key outside inputs -- an outputs block is
    // the obvious one -- and putting it FIRST is what catches a reader
    // that takes the first "  version:" in the file. The number it would
    // pick up here is not what the action installs, so the check it feeds
    // would be comparing the tag against nothing meaningful.
    const yml = [
      'name: Vault Guard',
      'outputs:',
      '  version:',
      '    description: The version that ran',
      '    default: 9.9.9',
      'inputs:',
      '  version:',
      '    description: The version to install',
      '    required: false',
      '    default: 1.7.0',
      'runs:',
      '  using: composite',
      '',
    ].join('\n');
    expect(readActionVersionDefault(yml)).toBe('1.7.0');
  });

  it('throws rather than choosing when the version input has two defaults', () => {
    // YAML would resolve a duplicate key silently by taking the last one.
    // A release gate does not get to answer a question the file gives two
    // answers to.
    const yml = [
      'inputs:',
      '  version:',
      '    required: false',
      '    default: 1.7.0',
      '    default: 1.8.0',
      '  path:',
      '    default: .',
      'runs:',
      '  using: composite',
      '',
    ].join('\n');
    expect(() => readActionVersionDefault(yml)).toThrow(/two|2 `default:`|ambiguous/i);
  });

  // The real action.yml's `version` input currently defaults to a dist-tag
  // (`latest`), not an exact package version -- a separate, concurrent
  // change is moving it to exact-versions-only, at which point this
  // default becomes an exact package version. Asserting the SHAPE (a
  // parseable, non-empty default) rather than the literal value, or the
  // EXACT_SEMVER shape that value does not have yet, is what keeps this
  // canary honest through that migration without needing an edit in lockstep
  // with it: the parser has to keep reading whatever the real file
  // currently says, whichever of the two shapes that is.
  it('reads the real action.yml and finds a non-empty version default', () => {
    const real = readActionVersionDefault(readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
    expect(typeof real).toBe('string');
    expect(real.length).toBeGreaterThan(0);
  });
});

// The other half of that canary. The CHANGELOG condition is a pattern
// match against a heading style nothing enforces, so the way it breaks is
// silent: somebody reformats the headings, every test above keeps passing
// against its own synthetic changelog, and the next action-only tag is
// refused at tag time for a release that was perfectly fine. Reading the
// real file here moves that discovery to the pull request that reformats
// it.
describe('the real CHANGELOG.md', () => {
  it('carries a heading the action-only check can find for the current package version', () => {
    const version = JSON.parse(
      readFileSync(path.join(ROOT, 'packages', 'core', 'package.json'), 'utf8')
    ).version;
    const changelog = readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');

    // The same pattern classifyRelease builds, against the version the
    // packages actually carry rather than a number written down here.
    expect(changelog).toMatch(new RegExp(`^##\\s*\\[${version.replace(/\./g, '\\.')}\\]`, 'm'));
  });
});

describe('classifyRelease', () => {
  it('requires at least one package', () => {
    expect(() =>
      classifyRelease({
        tagName: null,
        refDescription: 'branch main (not a tag push)',
        packages: [],
        actionYmlText: actionYmlWith('1.7.0'),
        changelogText: changelogWith('1.7.0'),
        publishedVersion: registryStub([]),
      })
    ).toThrow(/at least one package/i);
  });

  it('calls a tag that equals v plus the package version a package release', () => {
    const publishedVersion = registryStub([]);
    const result = classifyRelease({
      ...actionOnlyInputs(),
      tagName: 'v1.7.0',
      refDescription: 'tag v1.7.0',
      publishedVersion,
    });

    expect(result.actionOnly).toBe(false);
    expect(result.scannerVersion).toBe('1.7.0');
    // The package path must behave exactly as it did before this feature
    // existed, which includes touching the registry not at all: a package
    // release publishes a version that is by definition NOT on the
    // registry yet.
    expect(publishedVersion.calls).toEqual([]);
  });

  it('calls a greater tag with every package published and the action default in step an action-only release', () => {
    const inputs = actionOnlyInputs();
    const result = classifyRelease(inputs);

    expect(result.actionOnly).toBe(true);
    // The Release body names the scanner the tag installs; it is the
    // published package version, never the tag.
    expect(result.scannerVersion).toBe('1.7.0');
    expect([...inputs.publishedVersion.calls].sort()).toEqual(
      PACKAGE_NAMES.map((name) => `${name}@1.7.0`).sort()
    );
  });

  it('fails when the tag is below the package version', () => {
    expect(() =>
      classifyRelease(actionOnlyInputs({ tagName: 'v1.6.9', refDescription: 'tag v1.6.9' }))
    ).toThrow(/greater/i);
  });

  it('fails when the tag is numerically below the package version but above it as a string', () => {
    // 1.9.0 sorts after 1.10.0 as text. If the comparison were textual
    // this tag would be accepted as a forward move onto an older line.
    expect(() =>
      classifyRelease(
        actionOnlyInputs({
          tagName: 'v1.9.0',
          refDescription: 'tag v1.9.0',
          packages: packagesAt('1.10.0'),
          actionYmlText: actionYmlWith('1.10.0'),
          publishedVersion: registryStub(PACKAGE_NAMES.map((name) => `${name}@1.10.0`)),
        })
      )
    ).toThrow(/greater/i);
  });

  it('fails on a tag with a prerelease suffix', () => {
    expect(() =>
      classifyRelease(actionOnlyInputs({ tagName: 'v1.8.0-rc.1', refDescription: 'tag v1.8.0-rc.1' }))
    ).toThrow(/exact semver/i);
  });

  it('fails on a tag with a build suffix', () => {
    expect(() =>
      classifyRelease(actionOnlyInputs({ tagName: 'v1.8.0+build.5', refDescription: 'tag v1.8.0+build.5' }))
    ).toThrow(/exact semver/i);
  });

  it('fails on a tag with a leading-zero component', () => {
    expect(() =>
      classifyRelease(actionOnlyInputs({ tagName: 'v1.08.0', refDescription: 'tag v1.08.0' }))
    ).toThrow(/exact semver/i);
  });

  it('fails on a tag that does not begin with v', () => {
    expect(() =>
      classifyRelease(actionOnlyInputs({ tagName: '1.8.0', refDescription: 'tag 1.8.0' }))
    ).toThrow(/exact semver/i);
  });

  it('fails naming whichever package is not on the registry at the package version', () => {
    for (const missing of PACKAGE_NAMES) {
      const published = registryStub(
        PACKAGE_NAMES.filter((name) => name !== missing).map((name) => `${name}@1.7.0`)
      );
      expect(() => classifyRelease(actionOnlyInputs({ publishedVersion: published }))).toThrow(
        new RegExp(missing.replace(/[/@]/g, '\\$&'))
      );
    }
  });

  it('fails when the registry answers with a different version than it was asked for', () => {
    const publishedVersion = () => '1.5.0';
    expect(() => classifyRelease(actionOnlyInputs({ publishedVersion }))).toThrow(/registry/i);
  });

  it("fails when action.yml's version default is not the package version", () => {
    // The tag is allowed to move without the scanner. The default is not:
    // an action-only tag ships the scanner that is already published, so a
    // moved default means the scanner changed and this is a package
    // release that forgot to bump its packages.
    expect(() =>
      classifyRelease(actionOnlyInputs({ actionYmlText: actionYmlWith('1.8.0') }))
    ).toThrow(/action\.yml/i);
  });

  it('fails a PACKAGE release whose action.yml default is not the version being published', () => {
    // The symmetric half of the action-only default check, and the one
    // that closes the split in the direction nobody chooses on purpose:
    // publishing 1.9.0 under tag v1.9.0 while the action that tag ships
    // still installs 1.7.0.
    expect(() =>
      classifyRelease(
        actionOnlyInputs({
          tagName: 'v1.9.0',
          refDescription: 'tag v1.9.0',
          packages: packagesAt('1.9.0'),
          actionYmlText: actionYmlWith('1.7.0'),
        })
      )
    ).toThrow(/different scanner than it publishes/i);
  });

  it('accepts a package release whose action.yml default matches', () => {
    const result = classifyRelease(
      actionOnlyInputs({
        tagName: 'v1.9.0',
        refDescription: 'tag v1.9.0',
        packages: packagesAt('1.9.0'),
        actionYmlText: actionYmlWith('1.9.0'),
      })
    );
    expect(result).toEqual({ actionOnly: false, scannerVersion: '1.9.0' });
  });

  it('skips the default check for a prerelease package version, which the action cannot be pinned to', () => {
    // action.yml refuses a prerelease pin outright, so there is no value
    // its default could carry that would equal 1.9.0-rc.1. Requiring one
    // would make a prerelease package release impossible rather than safe.
    const result = classifyRelease(
      actionOnlyInputs({
        tagName: 'v1.9.0-rc.1',
        refDescription: 'tag v1.9.0-rc.1',
        packages: packagesAt('1.9.0-rc.1'),
        actionYmlText: actionYmlWith('1.7.0'),
      })
    );
    expect(result).toEqual({ actionOnly: false, scannerVersion: '1.9.0-rc.1' });
  });

  it('checks the action.yml default on a dispatch run too', () => {
    // A dispatch run publishes and cuts a Release tagged v plus the
    // package version, so the same split is reachable without a tag push.
    expect(() =>
      classifyRelease(
        actionOnlyInputs({
          tagName: null,
          refDescription: 'branch main (not a tag push)',
          actionYmlText: actionYmlWith('1.6.0'),
        })
      )
    ).toThrow(/different scanner than it publishes/i);
  });

  it('fails an action-only tag with no CHANGELOG entry for its version', () => {
    // The stray-tag case every other condition lets through: packages
    // left at 1.7.0 and "v1.8.0" pushed in the belief that they had moved.
    // Exact semver, greater, published, default in step -- and nobody
    // wrote it down, because nobody decided to release it.
    expect(() =>
      classifyRelease(
        actionOnlyInputs({
          changelogText: changelogWith('1.7.0'),
        })
      )
    ).toThrow(/CHANGELOG\.md/);
  });

  it('accepts an action-only tag whose version has a CHANGELOG entry', () => {
    const result = classifyRelease(actionOnlyInputs());
    expect(result.actionOnly).toBe(true);
  });

  it('fails an action-only tag when CHANGELOG.md could not be read at all', () => {
    expect(() => classifyRelease(actionOnlyInputs({ changelogText: null }))).toThrow(/CHANGELOG\.md/);
  });

  it('checks the CHANGELOG before it touches the registry', () => {
    // Local, on the tagged commit's own tree, and free. A stray tag should
    // not cost a registry round trip to reject.
    const publishedVersion = registryStub(PACKAGE_NAMES.map((name) => `${name}@1.7.0`));
    expect(() =>
      classifyRelease(
        actionOnlyInputs({
          changelogText: changelogWith('1.7.0'),
          publishedVersion,
        })
      )
    ).toThrow(/CHANGELOG\.md/);
    expect(publishedVersion.calls).toEqual([]);
  });

  it('fails when packages disagree, before anything else is considered', () => {
    const publishedVersion = registryStub([]);
    expect(() =>
      classifyRelease(
        actionOnlyInputs({ packages: packagesAt('1.7.0', { [TELEMETRY_NAME]: '1.6.0' }), publishedVersion })
      )
    ).toThrow(/lockstep/i);
    expect(publishedVersion.calls).toEqual([]);
  });

  it('never consults the registry when there is no tag at all', () => {
    // workflow_dispatch: there is no tag to classify, and a dispatch run
    // is a package release and publishes a version that should not be
    // there yet.
    const publishedVersion = registryStub([]);
    const result = classifyRelease({
      ...actionOnlyInputs(),
      tagName: null,
      refDescription: 'branch main (not a tag push)',
      publishedVersion,
    });
    expect(result.actionOnly).toBe(false);
    expect(publishedVersion.calls).toEqual([]);

    expect(() =>
      classifyRelease({
        ...actionOnlyInputs(),
        tagName: null,
        refDescription: 'branch main (not a tag push)',
        packages: packagesAt('1.7.0', { [CLI_NAME]: '1.6.0' }),
      })
    ).toThrow(/lockstep/i);
  });

  it('fails legibly when the package version itself is not exact semver and the tag differs', () => {
    expect(() =>
      classifyRelease(
        actionOnlyInputs({
          packages: packagesAt('1.7.0-rc.1'),
          actionYmlText: actionYmlWith('1.7.0'),
        })
      )
    ).toThrow(/package version/i);
  });

  it('names the ref in every failure message', () => {
    // The whole point of failing here rather than at publish time is that
    // a human reads the message at tag time. A message that does not name
    // the tag makes them go look it up.
    expect(() =>
      classifyRelease(actionOnlyInputs({ tagName: 'v1.6.9', refDescription: 'tag v1.6.9' }))
    ).toThrow(/tag v1\.6\.9/);
  });
});

// The workflow half. The library above can be perfectly correct while
// .github/workflows/release.yml ignores its answer, and the failure that
// would produce is the expensive one: a publish on a tag that was supposed
// to publish nothing, or a Release page announcing a publish that did not
// happen. Nothing here re-tests the decision -- it tests that the decision
// is wired to the steps it is supposed to govern.
//
// Textual rather than through a YAML parser on purpose: this repository
// has no YAML dependency in scripts/, and the release job's decision step
// runs before `pnpm install` precisely so it depends on nothing.
describe('.github/workflows/release.yml wiring', () => {
  // VG_RELEASE_WORKFLOW points this suite at a mutated copy, the same idea
  // as VG_NPM_BIN for the registry: a guard nobody has watched fail is a
  // guard nobody knows works. Used to confirm that dropping the gate from
  // "Publish to npm" turns this file red, which is not something that can
  // be tried on the real file.
  const workflow = readFileSync(
    process.env.VG_RELEASE_WORKFLOW ?? path.join(ROOT, '.github', 'workflows', 'release.yml'),
    'utf8'
  );
  // Spelled positively, and asserted as this exact string. "!= 'true'" is
  // the same thing right up until the output is empty or missing, at
  // which point it publishes on a run that decided nothing.
  const GATE = "steps.kind.outputs.action_only == 'false'";

  // The release job's steps sit at four spaces; the smoke job's at six, so
  // this reads only the first job.
  //
  // A step is identified by its name, or by "uses:<value>" when it has no
  // name -- a step written "- uses: actions/checkout@..." with no name is
  // valid YAML and perfectly ordinary, and a parser that only knew
  // "- name:" would not see it at all. That blindness is exactly what an
  // exact-list assertion must not have: an unnamed publish-side step would
  // then be invisible to every check below rather than caught by them.
  function parseSteps(text) {
    const lines = text.split('\n');
    const steps = [];
    let current = null;
    for (const line of lines) {
      const nameMatch = /^ {4}- name: (.*)$/.exec(line);
      const usesMatch = /^ {4}- uses: (.*)$/.exec(line);
      if (nameMatch !== null || usesMatch !== null) {
        current = {
          name: nameMatch === null ? null : nameMatch[1].trim(),
          uses: usesMatch === null ? null : usesMatch[1].trim(),
          if: null,
        };
        current.id = current.name ?? `uses:${current.uses}`;
        steps.push(current);
        continue;
      }
      if (current !== null) {
        const ifMatch = /^ {6}if: (.*)$/.exec(line);
        if (ifMatch !== null) {
          current.if = ifMatch[1].trim();
        }
        const usesLater = /^ {6}uses: (.*)$/.exec(line);
        if (usesLater !== null && current.uses === null) {
          current.uses = usesLater[1].trim();
        }
        if (/^ {2}\S/.test(line)) {
          current = null;
        }
      }
    }
    return steps;
  }

  const releaseJobSteps = () => parseSteps(workflow);

  // Every step that exists to protect or perform a publish, in the order
  // the workflow runs them. The code gates (install, build, docs-drift,
  // tests, the release-kind suite, the private-names check, the CHANGELOG
  // assertion) are NOT here: they run on both kinds of release, because
  // this workflow never learns whether ci.yml ran on the exact commit that
  // got tagged, and an action-only release's payload is exactly what those
  // gates cover.
  const GATED_STEPS = [
    'Verify publish hygiene (no source maps or test artifacts in tarballs)',
    'Upgrade npm for OIDC trusted publishing',
    'Publish to npm',
  ];

  // Every step from the decision to the end of the release job, gated or
  // not, in order. The set assertion below cannot see a NEW ungated step
  // -- that is what this list is for: inserting anything after the
  // decision, named or unnamed, fails until somebody states which side of
  // the gate it belongs on.
  //
  // It runs to the LAST step rather than stopping at tag resolution,
  // because the steps after that point are the ones that publish a claim:
  // a second publish step slipped in between "Resolve release tag" and
  // "Create GitHub Release" would be past a window that ended earlier, and
  // would run on an action-only release.
  const STEPS_AFTER_DECISION = [
    'Install dependencies',
    'Build packages',
    'Regenerate docs/RULES.md and check for drift',
    'Run tests with coverage',
    'Run release-kind tests',
    'Check for private portfolio references',
    'Assert CHANGELOG.md documents this version',
    ...GATED_STEPS,
    'Resolve release tag',
    'Create GitHub Release',
    'Create GitHub Release (action-only)',
  ];

  it('gates exactly the publish-side steps on the decision step output', () => {
    const gated = releaseJobSteps()
      .filter((step) => step.if === GATE)
      .map((step) => step.id);
    // "Create GitHub Release" carries the same gate and is asserted
    // separately below, with the body claim it guards.
    expect(gated.sort()).toEqual([...GATED_STEPS, 'Create GitHub Release'].sort());
  });

  it('runs the code gates on both kinds of release', () => {
    const ungated = [
      'Install dependencies',
      'Build packages',
      'Regenerate docs/RULES.md and check for drift',
      'Run tests with coverage',
      'Run release-kind tests',
      'Check for private portfolio references',
      'Assert CHANGELOG.md documents this version',
    ];
    for (const name of ungated) {
      const step = releaseJobSteps().find((s) => s.id === name);
      expect(step).toBeDefined();
      expect(step.if).toBeNull();
    }
  });

  it('accounts for every step after the decision, to the end of the job, in order', () => {
    const ids = releaseJobSteps().map((step) => step.id);
    const from = ids.indexOf('Decide the release kind, and refuse a tag that is neither');
    expect(from).toBeGreaterThan(-1);
    expect(ids.slice(from + 1)).toEqual(STEPS_AFTER_DECISION);
  });

  it('leaves tag resolution ungated, since both kinds of release cut a Release', () => {
    const resolve = releaseJobSteps().find((step) => step.id === 'Resolve release tag');
    expect(resolve).toBeDefined();
    expect(resolve.if).toBeNull();
  });

  it('claims a publish only on the path that performs one', () => {
    // "Published ... to npm" must live in exactly one Release body, and
    // that body's step must carry the same gate as the publish step. An
    // action-only release that announced a publish would be sending
    // people to look for a version that does not exist.
    const publishClaims = workflow.match(/Published `@vaultcompass\/vault-guard`/g) ?? [];
    expect(publishClaims).toHaveLength(1);

    const release = releaseJobSteps().find((step) => step.id === 'Create GitHub Release');
    expect(release.if).toBe(GATE);

    const actionOnlyRelease = releaseJobSteps().find(
      (step) => step.id === 'Create GitHub Release (action-only)'
    );
    expect(actionOnlyRelease.if).toBe("steps.kind.outputs.action_only == 'true'");
    expect(workflow).toContain('Nothing was published to npm by this release.');
    expect(workflow).toContain('CHANGELOG.md');
  });

  it('skips the published-CLI smoke job when nothing was published', () => {
    // Positive spelling here too: an empty output means no run decided
    // anything, and the smoke job's whole premise is that a publish
    // happened.
    expect(workflow).toContain("if: needs.release.outputs.action_only == 'false'");
    expect(workflow).toContain('action_only: ${{ steps.kind.outputs.action_only }}');
  });

  it('never gates anything on the negative spelling', () => {
    // The one assertion that would catch a well-meaning edit back to
    // "!= 'true'", which reads identically and fails open.
    expect(workflow).not.toContain("action_only != 'true'");
    expect(workflow).not.toContain("action_only != 'false'");
  });

  it('passes the changelog to the decision script on both invocations', () => {
    const invocations = workflow.match(/node scripts\/classify-release-tag\.mjs/g) ?? [];
    expect(invocations).toHaveLength(2);
    const changelogArgs = workflow.match(/--changelog CHANGELOG\.md/g) ?? [];
    expect(changelogArgs).toHaveLength(2);
  });

  it('passes all four published packages to the decision script', () => {
    for (const dir of ['core', 'cli', 'mcp', 'telemetry']) {
      expect(workflow).toContain(`require('./packages/${dir}/package.json').name`);
      expect(workflow).toContain(`require('./packages/${dir}/package.json').version`);
    }
    const packageFlags = workflow.match(/--package "/g) ?? [];
    // Four packages, two invocations (tag push and workflow_dispatch).
    expect(packageFlags).toHaveLength(8);
  });

  it('calls the decision script from a step with the id the conditions read', () => {
    expect(workflow).toMatch(/^ {4}- name: Decide the release kind[^\n]*\n {6}id: kind$/m);
    expect(workflow).toContain('node scripts/classify-release-tag.mjs');
  });
});

// The script half: argument handling, the real spawn of an npm-shaped
// executable, and the GITHUB_OUTPUT contract the workflow's later steps
// read. VG_NPM_BIN points at a stub here, so this never reaches the
// network -- and the stub records what it was asked, so "the package path
// does not consult the registry" is proven against the real spawn path and
// not only against the injected function above.
describe('classify-release-tag.mjs', () => {
  function makeNpmStub(publishedSpecs) {
    const dir = mkdtempSync(path.join(tmpdir(), 'vg-npm-stub-'));
    const bin = path.join(dir, 'npm-stub.mjs');
    const log = path.join(dir, 'calls.log');
    const source = [
      '#!/usr/bin/env node',
      "import { appendFileSync } from 'node:fs';",
      `const published = ${JSON.stringify(publishedSpecs)};`,
      // Logs the working directory it was started in as well as its
      // arguments: where npm runs decides which .npmrc it reads, and that
      // decides what "already published" means.
      `appendFileSync(${JSON.stringify(log)}, 'cwd=' + process.cwd() + ' argv=' + process.argv.slice(2).join(' ') + '\\n');`,
      "const spec = process.argv[3] ?? '';",
      'if (!published.includes(spec)) {',
      "  process.stderr.write('npm error code E404\\n');",
      '  process.exit(1);',
      '}',
      "process.stdout.write(spec.slice(spec.lastIndexOf('@') + 1) + '\\n');",
      '',
    ].join('\n');
    writeFileSync(bin, source);
    chmodSync(bin, 0o755);
    writeFileSync(log, '');
    return { bin, log, dir };
  }

  function run(args, env) {
    const outFile = path.join(mkdtempSync(path.join(tmpdir(), 'vg-gh-out-')), 'output.txt');
    // Actions creates this file before the step runs and the script only
    // ever appends, so the harness creates it too. Reading it back has to
    // work on the failure paths as well: "the run failed AND wrote no
    // action_only=true" is one of the things being asserted.
    writeFileSync(outFile, '');
    const result = spawnSync(process.execPath, [SCRIPT, ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, GITHUB_OUTPUT: outFile, ...env },
    });
    return { ...result, outputs: readFileSync(outFile, 'utf8') };
  }

  const baseArgs = (tag) => [
    ...(tag === null ? [] : ['--tag', tag]),
    '--package',
    `${CORE_NAME}=1.7.0`,
    '--package',
    `${CLI_NAME}=1.7.0`,
    '--package',
    `${MCP_NAME}=1.7.0`,
    '--package',
    `${TELEMETRY_NAME}=1.7.0`,
  ];

  function withActionYml(defaultVersion) {
    const dir = mkdtempSync(path.join(tmpdir(), 'vg-action-yml-'));
    const file = path.join(dir, 'action.yml');
    writeFileSync(file, actionYmlWith(defaultVersion));
    return file;
  }

  function withChangelog(...versions) {
    const dir = mkdtempSync(path.join(tmpdir(), 'vg-changelog-'));
    const file = path.join(dir, 'CHANGELOG.md');
    writeFileSync(file, changelogWith(...versions));
    return file;
  }

  // The files every case below needs unless it is testing one of them: an
  // action.yml whose default matches the package version, and a CHANGELOG
  // carrying an entry for the action-only tag these tests push.
  const files = (actionDefault = '1.7.0', changelogVersions = ['1.8.0', '1.7.0']) => [
    '--action-yml',
    withActionYml(actionDefault),
    '--changelog',
    withChangelog(...changelogVersions),
  ];

  it('reports action_only=true and the scanner version for a valid action-only tag', () => {
    const stub = makeNpmStub(PACKAGE_NAMES.map((name) => `${name}@1.7.0`));
    const result = run([...baseArgs('v1.8.0'), ...files()], {
      VG_NPM_BIN: stub.bin,
    });

    expect(result.status).toBe(0);
    expect(result.outputs).toContain('action_only=true');
    expect(result.outputs).toContain('scanner_version=1.7.0');
    expect(readFileSync(stub.log, 'utf8')).toContain(`view ${CORE_NAME}@1.7.0 version`);
  });

  it('asks the public registry, from a directory this repository does not control', () => {
    // npm reads .npmrc from its working directory upward, so running the
    // lookup at the repository root would let a checked-in or generated
    // .npmrc decide what "already published" means -- the one question
    // standing between a tag and a Release page claiming a published
    // version. Hence a temp directory, and an explicit --registry.
    const stub = makeNpmStub(PACKAGE_NAMES.map((name) => `${name}@1.7.0`));
    const result = run([...baseArgs('v1.8.0'), ...files()], { VG_NPM_BIN: stub.bin });
    expect(result.status).toBe(0);

    const log = readFileSync(stub.log, 'utf8');
    const cwds = [...log.matchAll(/^cwd=(.*?) argv=/gm)].map((m) => m[1]);
    expect(cwds.length).toBeGreaterThan(0);
    for (const cwd of cwds) {
      expect(cwd).not.toBe(ROOT);
      expect(cwd.startsWith(ROOT)).toBe(false);
    }
    expect(log).toContain('--registry=https://registry.npmjs.org');
  });

  it('runs the lookup in RUNNER_TEMP when the runner provides one', () => {
    const runnerTemp = mkdtempSync(path.join(tmpdir(), 'vg-runner-temp-'));
    const stub = makeNpmStub(PACKAGE_NAMES.map((name) => `${name}@1.7.0`));
    const result = run([...baseArgs('v1.8.0'), ...files()], {
      VG_NPM_BIN: stub.bin,
      RUNNER_TEMP: runnerTemp,
    });

    expect(result.status).toBe(0);
    // realpath: the OS temp dir resolves through a symlink on macOS, so
    // the child reports the resolved path for the value handed in here.
    expect(readFileSync(stub.log, 'utf8')).toContain(`cwd=${realpathSync(runnerTemp)} `);
  });

  it('refuses an action-only tag whose version has no CHANGELOG entry', () => {
    const stub = makeNpmStub(PACKAGE_NAMES.map((name) => `${name}@1.7.0`));
    const result = run([...baseArgs('v1.8.0'), ...files('1.7.0', ['1.7.0'])], {
      VG_NPM_BIN: stub.bin,
    });

    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain('CHANGELOG.md');
    expect(result.outputs).not.toContain('action_only=true');
  });

  it('reports action_only=false for a package-release tag and never runs npm', () => {
    const stub = makeNpmStub([]);
    const result = run([...baseArgs('v1.7.0'), ...files()], {
      VG_NPM_BIN: stub.bin,
    });

    expect(result.status).toBe(0);
    expect(result.outputs).toContain('action_only=false');
    expect(readFileSync(stub.log, 'utf8')).toBe('');
  });

  it('refuses a package-release tag whose action.yml default is a different version', () => {
    const stub = makeNpmStub([]);
    const result = run([...baseArgs('v1.7.0'), ...files('1.6.0')], { VG_NPM_BIN: stub.bin });

    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain('different scanner than it publishes');
    expect(readFileSync(stub.log, 'utf8')).toBe('');
  });

  it('exits 1 with a workflow error annotation when the packages are not published', () => {
    const stub = makeNpmStub([]);
    const result = run([...baseArgs('v1.8.0'), ...files()], {
      VG_NPM_BIN: stub.bin,
    });

    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain('::error::');
    expect(result.stdout + result.stderr).toContain(CORE_NAME);
    expect(result.outputs).not.toContain('action_only=true');
  });

  it('exits 1 when no --package is given', () => {
    const result = run(['--tag', 'v1.8.0'], {});
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toMatch(/--package/);
  });

  it('exits 1 when a --package value is not name=version', () => {
    const result = run(['--tag', 'v1.8.0', '--package', 'not-a-valid-value'], {});
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toMatch(/name=version/);
  });

  it('treats an npm lookup that fails for any reason as not published', () => {
    // Fail closed. A registry outage blocks an action-only tag; it must
    // never be read as "published, go ahead".
    const dir = mkdtempSync(path.join(tmpdir(), 'vg-npm-broken-'));
    const bin = path.join(dir, 'npm-broken');
    writeFileSync(bin, '#!/bin/sh\nexit 7\n');
    chmodSync(bin, 0o755);

    const result = run([...baseArgs('v1.8.0'), ...files()], {
      VG_NPM_BIN: bin,
    });
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain('::error::');
  });
});
