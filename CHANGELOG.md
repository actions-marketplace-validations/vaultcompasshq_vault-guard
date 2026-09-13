# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.7.1] - 2026-09-13

**An action-only release. The tag moves; the npm packages do not.** Nothing in
the scanner changed, so `@vaultcompass/vault-guard` and the other three packages
stay at 1.7.0 on npm, and the Action's `version` default stays `1.7.0`, which is
the scanner this Action tag installs and was tested against.

That makes the Action tag and the scanner version two different numbers for the
first time, and it is deliberate rather than an oversight:
`vaultcompasshq/vault-guard@v1.7.1` installs
`@vaultcompass/vault-guard@1.7.0`. Publishing an identical scanner as 1.8.0 so
the two strings matched would burn a version number on a change that touches no
scanning code, through a trusted-publisher path that is a one-way door.

**Pinning `vaultcompasshq/vault-guard@v1.7.0` gets the OLD Action**, the one
that installs the scanner from inside the checkout. Move to `@v1.7.1`.

### Upgrading

1. **Delete `version: latest` from your workflow.** The input takes an exact
   version now and a dist-tag is refused, with a message saying to remove the
   input. The default is the scanner this tag shipped with, which is the pin you
   want. `vault-guard init` no longer scaffolds the input at all.
2. **Guard a chained `upload-sarif` on the `results-file` output being
   non-empty.** It is empty now when the scan wrote no document, which is what
   exit 2 looks like. Previously the output named a zero-byte file and the
   upload failed with a SARIF parse error sitting on top of the real message.

### Security

- **The Action installs the scanner from outside the tree it scans.** It ran
  `npx --yes "@vaultcompass/vault-guard@${VG_VERSION}"` from inside the
  checkout, which put the choice of program inside the tree under judgment by
  two routes. An `.npmrc` committed by the head repoints the registry npx
  fetches from. A copy of the package already in the head's `node_modules`,
  from the workflow's own earlier install step, is what npx runs, with the
  version pin acting only as a satisfaction check on a package the head wrote.
  Either one lets a pull request choose the program that scans it, and the
  second needs no registry at all. On a `pull_request` run that checkout is the
  untrusted head, so this was the gate reading its config from the base branch
  and then running a binary the head chose. The package is now installed
  globally into a prefix under the runner temp, with npm started from the
  runner temp rather than from the workspace, and called by absolute path.

  Both routes are exercised against real npm by `bench/action-install.cjs`,
  which runs the Action's own steps with two local registries, and records the
  pre-fix Action from tag `v1.7.0` as a negative control: the attack has to be
  visible there or the harness is not measuring anything.

- **The scan path is absolute and resolved.** The step no longer starts inside
  the checkout, so the scan root is built from `GITHUB_WORKSPACE` and passed
  whole. It is resolved with `pwd -P`, because vault-guard resolves the
  pull-request file set against its own process cwd: a logical path against a
  resolved cwd puts every file in the head tree outside the scan target, and
  the run scans zero files and reports a clean result over nothing. A `path`
  input that resolves outside the workspace through a symlink is refused.

### Changed

- **`version` takes an exact version only, and defaults to the scanner version
  the Action shipped with.** It accepted dist-tags and defaulted to `latest`. A
  tag hands the choice of scanner to the registry on the morning of the run.
  The old `[0-9A-Za-z.+-]{1,64}` charset also accepted values npm reads as a
  PATH rather than a version, `.`, `..` and `payload.tgz` among them, and
  values that are not semver at all such as `01.7.0`, which npm falls back to
  treating as a dist-tag. **A workflow relying on the old `latest` default must
  remove the input.**
- **Only 0, 1 and 2 are verdicts.** Any other exit code from the run step,
  including the 126 and 127 the shell produces when a binary is missing or not
  executable, is reported as could-not-run and re-raised as 2 rather than
  passed through as if the scanner had produced it.
- **`results-file` is published only when the run wrote something**, and a new
  `exit-code` output carries vault-guard's own code.
- **Input validation.** No value may begin with a dash, rather than only the
  ref: a path or a ref starting with `-` is read as an option by whichever
  command it reaches. `trust-base: off` is refused in any capitalisation, so an
  opt-out with a shift key in front of it is not an opt-out either.
- **`sarif-output` may not resolve under `.github/`**, which holds the workflow
  file and the CODEOWNERS entry that decide how this gate runs. Compared after
  normalising `./` segments, doubled slashes and case to a fixed point, so
  `./.github/x` and `.GitHub/x` are refused too. A `./` prefix stays legal on
  every input.
- **`sarif-output` may not resolve through a symlink**, at the file or at any
  directory on the way to it, checked before the containing directories are
  created rather than after. The head controls those, and a symlink there sends
  the write outside the workspace.
- **`sarif-output` must name a file.** A value that normalises to nothing or to
  a single dot (`.`, `./`) is a directory, and is refused with the input's name
  rather than left to fail as a shell redirect error deep in the run step. A
  trailing slash is normalised away everywhere, because `test -L` follows a
  symlink when the path ends in one, so `out.sarif/` walked past the symlink
  guard that `out.sarif` does not.
- **`vault-guard init` scaffolds `@v1.7.1`, no `version` input, and the guarded
  upload shape** — the scan step carries an `id`, and the `upload-sarif` step is
  gated on its `results-file` output being non-empty and pinned to a full commit
  SHA rather than the mutable `v3` tag. The template's Action pin used to be
  derived from the CLI package version, which would have scaffolded the pre-fix
  Action into every repository initialised after this release.

## [1.7.0] - 2026-09-06

Minor bump on all four packages. **The rule: on a pull-request run, every
control input comes from the base ref and the head tree is the thing scanned.**
A new flag, new report lines and a new JSON field, so this is a minor rather
than a patch.

### Upgrading

Two things can turn a green run red on upgrade, and neither is a secret the
scanner found.

1. **An unknown top-level key in `.vault-guard.json` now fails the run.** The
   schema check used to run only in `vault-guard config validate`, an opt-in
   command, so through 1.6.0 an unrecognised key was silently dropped and the
   scan carried on. `$schema`, `comment` and `version` are realistic keys that
   were tolerated and are now refused, with the validation message and exit 1
   on a plain `scan`. Run `vault-guard config validate` once after upgrading
   and delete or rename whatever it names. This is deliberate: a check the gate
   does not run is documentation, not a control, and a config whose
   `severity_overrides` were quietly dropped is a gate nobody knew was open.
2. **A `pull_request` workflow needs `fetch-depth: 0` on `actions/checkout`.**
   The Action now passes `--trust-base origin/$GITHUB_BASE_REF` on pull-request
   events by default, and the base branch has to exist locally for that ref to
   resolve. A shallow clone exits 2 with a message naming the ref, rather than
   falling back to trusting the pull request. There is deliberately no input
   that turns pull-request mode off: on a same-repo `pull_request` event GitHub
   runs the workflow file from the pull request head, so an off switch would be
   settable by the pull request it judges. If you are not ready to change the
   checkout, stay pinned to `vaultcompasshq/vault-guard@v1.6.0` until you are.
   That is a decision a maintainer makes on a protected branch, which is what a
   switch in a PR-controlled file is not.

### Added

- **`--trust-base <ref>` on `scan` and `check`.** Pull-request mode.
  `.vault-guard.json`, `.vault-guard.local.json` (at every level between the
  scan directory and the repository root) and `.vault-guard.baseline.json` are
  read from `<ref>` with `git ls-tree` and `git show`, and the head tree is what
  gets scanned. A control input the head changed never takes effect for the run
  and is reported on one line: `config changed in this pull request`, or
  `baseline changed in this pull request`, with a short parenthetical when it is
  cheap to compute (`2 patterns added to ignore, fail_on lowered`,
  `1 baseline entry added`). A control input that exists only in the head is
  `config added in this pull request`, and the run uses the defaults it would
  have used with no config at all. Reads only: no checkout switch, no worktree,
  and nothing written into the repository. Fails closed, exit 2, when the ref
  will not resolve; a missing base is never a reason to fall back to trusting
  the head. A pre-commit hook never passes it.
- **A `trust-base` input on the composite Action**, defaulting to `auto`, which
  passes `--trust-base origin/$GITHUB_BASE_REF` on exactly the pull-request
  events. The ref reaches the CLI through the step's `env` block and a bash
  array, never through a `${{ }}` expression substituted into a `run` body. Any
  other value is used as the ref. There is deliberately no value that turns
  pull-request mode off, and `off` is refused by name: base-ref judging is the
  floor rather than a knob, and on a same-repo `pull_request` event the workflow
  file runs from the pull request head, so an off switch on this input would sit
  on the untrusted side of the boundary it disables. The only change this input
  accepts is a tightening.
- **A `trustBase` block in the JSON output**, naming the ref, every proposed
  control-input change, and how the head changed each control file's type or
  mode. SARIF carries one `toolExecutionNotification` per proposal, because a
  proposal is a statement about the run's configuration rather than a finding
  with a file to point at.
- **A distinct count for an inline ignore directive that hid a critical
  vendor-anchored finding**, beside the existing total, in text (when non-zero)
  and in JSON as `run.inline_suppressed_critical_vendor` (always). Inline
  directives are content rather than configuration, so they stay honoured; a
  directive over a generic fixture assignment and a directive on the same line
  as a provider-issued key are not the same event, and one total let the second
  hide inside the first.
- **`init`'s generated workflow now sets `fetch-depth: 0`** on `actions/checkout`,
  which pull-request mode requires. Template version 3.

### Security

- **A pull request could turn the scanner off in the same commit that carried
  what the scanner exists to catch.** Every control input was read from the tree
  under judgment. Measured on a scratch repository with a committed config and
  baseline on the base branch, each of the following, added in the same commit
  as a provider-shaped key, turned exit 1 into exit 0 with no line of output
  saying anything had been muted:
  `ignore: {"paths": ["**"]}` in `.vault-guard.json`; a `severity_overrides`
  entry setting the matching rule to `off`; `"fail_on": "none"`; a
  `.vault-guard.local.json` swapped in for the committed `.vault-guard.json`
  (the swap is what makes it bite: the two filenames are tried in order within a
  directory, so a local file added *beside* an existing `.vault-guard.json`
  never wins); a `.vault-guard.baseline.json` rewritten to carry the fingerprint
  of the finding being added; a `.gitignore` covering the file the key was
  committed in; and the key committed under a directory named `vendor`. All
  seven now report the change and block, verified before and after, and each
  has its old behaviour pinned by a test so it cannot come back unnoticed.
- **The pull-request file set is the HEAD tree, not the index.** It was
  `git ls-files`, which reports the index, and the index is the wrong side of
  the boundary in both directions: `git rm --cached src/leak.ts` dropped a
  committed key out of the scan while leaving the file on disk and in HEAD, and
  a staged but uncommitted file was scanned even though the pull request had not
  proposed it. It is now `git ls-tree -r HEAD`, whose records also carry the
  mode, so a symlink or a submodule gitlink never enters the list at all. In CI
  the index and HEAD agree; locally the first of those was a mute costing one
  command, with the file left exactly where it was.
- **Descendant `.gitignore` files cannot mute a committed file in pull-request
  mode.** The file set there is the HEAD tree filtered the way the walk filters,
  not a filesystem walk filtered by the gitignore tester. The tester is
  unchanged for untracked working-tree scans, which have no flag.
- **The vendored-directory names are anchored to the scan root in pull-request
  mode**, so a committed `src/vendor/` is scanned while a root `node_modules` is
  still skipped, and the run prints how many directories it skipped, in yellow
  when that number is not zero. Anchoring is safe there precisely because the
  set is the HEAD tree.
- **A pull-request run now says how many files it skipped by extension or name.**
  `.min.js`, `.bundle.js`, `.lock`, `.map`, `.log` and the lockfile names are
  skipped on the name alone, so a key committed as `src/leak.min.js` exited 0
  with no count and no line anywhere in the output. What is skipped is
  deliberately unchanged; the silence is not. The count prints beside the
  vendored-directory count and is carried in JSON as `run.type_filtered_files`.
- **A scan target outside the repository the base ref lives in is refused**,
  exit 2. Pull-request mode resolves the base from the run's anchor, which for a
  directory scan is the process cwd, so a target in another checkout had no
  files in common with it: the intersection that makes the mode safe
  became an intersection with nothing, and the run printed "no secrets found"
  over zero files scanned. Found by running the built CLI against another
  checkout by absolute path. Refused rather than re-anchored, because
  re-anchoring would move the config search, the output paths and the baseline
  fingerprints with it.
- **A trust base beginning with a dash is refused**, because git would read it
  as an option rather than as a revision.
- **A trust base that resolves to the commit being scanned is refused**, exit 2,
  even though it names a real commit. `--trust-base HEAD` would put the boundary
  back exactly where it started while the report said pull-request mode was on.
  The realistic way in is `--trust-base ${{ github.sha }}`, because on a
  `pull_request` event with the default `actions/checkout` that SHA is the merge
  commit, which is HEAD. The comparison is on resolved commits, so an alias, a
  tag or a raw SHA naming the head commit is refused alike.
- **A trust base whose TREE equals the head's is refused too**, exit 2, even
  when it is a different commit. What GitHub publishes as `refs/pull/N/merge` is
  a merge commit whose tree, when the base has not moved since the fork, *is*
  the head branch's tree. Merging the base into the branch changes the head's
  tree, so a pull request that does that is judged normally.
- **Both sides of the base-versus-head comparison are read through git**, so a
  config the head replaced with a symlink is compared as the link target string
  it is rather than as the file it points at. Without that, a link whose target
  held the base config's exact bytes read as no change at all, which is the
  first half of a two-step: land the link, then edit the link target in a later
  pull request where the config path never appears in the diff. Shape changes
  (symlink, not a regular file, removed, mode) are reported separately from
  content changes, and a control input that is not a regular file AT THE BASE
  is exit 2, because that is the state the run's decisions were supposed to rest
  on.

### Changed

- **Config schema validation now runs on every load**, not only in
  `vault-guard config validate`. An unknown top-level key was silently dropped
  and a mistyped `severity_overrides` value was carried into the scanner as-is,
  so a check the gate did not run was documentation rather than a control. This
  is a hardening OUTSIDE pull-request mode as well: a config that parsed as JSON
  but failed the schema used to scan and now exits 1 with the validation
  message, on every path that loads a config (the CLI, the MCP server, the
  editor extension). A base-ref config that fails validation is exit 2, because
  in that case nothing was scanned at all.
- **Exit 2 now also means an unreadable trust base**, in addition to a git
  failure and an unreadable staged file. It has always meant could-not-run.

### Documentation

- **The workflow that passes `--trust-base` has to be put on the protected side
  deliberately.** For a same-repo `pull_request` event GitHub runs the workflow
  file from the pull request head, so the job is as editable as any other file
  in the branch unless the check is required by name in branch protection or the
  gate lives in a reusable workflow on a protected ref. No flag can detect a job
  a pull request deleted. Both the README and the Action doc now say so.
- **Requiring a human to approve a config or baseline change is described as
  repository configuration, not as a feature**: a `CODEOWNERS` entry for those
  paths plus required code-owner review. There is deliberately no in-repo knob,
  because a knob that can relax the gate and lives in the file the pull request
  controls is the vulnerability wearing a settings label. Base-ref judgment is
  the floor; a human approval can only make the gate stricter.

## [1.6.0] - 2026-09-05

A security release. Every built-in pattern was swept for ReDoS and timed at two
input sizes (measured, not read off source); six that grew quadratically were
bounded. A post-hoc per-file scan budget was added, and the init default was
changed so test trees are scanned rather than ignored.

### Security

- **Six built-in patterns backtracked quadratically.** Each was measured before
  and after against an adversarial input. Doubling the input roughly quadrupled
  the time in every case, which is a real ReDoS reachable inside an ordinary
  file, not a theoretical shape. Measured at 200k characters, unbounded then
  bounded:

  | rule | cause | 200k before | 200k after |
  |---|---|---|---|
  | `gcp-oauth` | `[0-9]+` before `-`, one start per digit | 16,563 ms | 38 ms |
  | `jwt-token` | segment repeat before `.`, one start per `eyJ` | 7,083 ms | 0.33 ms |
  | `postgresql-url` | `[^@\s]+` contains the `:` that ends the previous class | 1,462 ms | 9.2 ms |
  | `mysql-url` | same shape | 2,217 ms | 10.6 ms |
  | `mongodb-url` | same shape | 1,848 ms | 8.5 ms |
  | `redis-url` | same shape | 2,289 ms | 10.1 ms |

  Fixes: `gcp-oauth`'s numeric prefix is bounded to `{1,64}`; each DSN component
  is bounded (user/password/host 256, port 8 digits, path 1024); each JWT
  segment is bounded to `{1,4096}` and the `eyJ` prefix is token-boundary
  anchored, since the bound alone still scales with the bound while the
  lookbehind removes the start offsets entirely. Detection is unchanged for a
  real client id, a real three-segment JWT (including one with a 1k+ char
  payload), and every DSN shape. The remaining 53 rules measured linear.
- **`ssh-private-key` had an ambiguous repeat.** The space that must follow the
  key-type words was also a member of the repeated class `[A-Z0-9 ]+`. This
  shape measured linear already, so this is hardening rather than a fix: the
  space is now lifted out of the class while the same headers still match
  (PKCS#8, RSA, EC, DSA, OPENSSH, ENCRYPTED).
- **Per-file scan budget (post-hoc, defense in depth).** This is **not** an
  execution-time bound. Node's regex engine is **synchronous** and cannot be
  interrupted, so the budget compares elapsed time *after* a file's scan has
  already returned: it cannot abandon or preempt a runaway scan, which still
  runs to completion. What it does is refuse to trust that result. An
  over-budget file is treated as unscannable, so on the staged path the run
  fails closed (exit 2, no success line) through the same incomplete-scan path
  an unreadable file uses, and on a directory scan it is reported with a
  `file.scan_timeout` diagnostic while scanning continues. The regex bounds are
  what bound time; this catches the case where a future edit reintroduces a
  runaway shape. Applied to the CLI directory and staged paths and to the MCP
  `scan_file` / `scan_workspace` tools.

### Added

- **A checked-in ReDoS timing sweep** (`pnpm redos:sweep`, see
  [`docs/REDOS_SWEEP.md`](docs/REDOS_SWEEP.md)). It times every built-in rule
  against adversarial input at two sizes, compares growth, and diffs a recorded
  baseline. Its `--self-test` replays the six pre-1.6.0 quadratic forms and
  requires the harness to flag all six, because a clean sweep is only meaningful
  if the harness can detect a dirty one. That self-test earned its place
  immediately: an early version of the sweep stopped parsing at the parenthesis
  in `postgres(?:ql)?` and reported three of the four DSN rules clean while they
  were quadratic. Deliberately **not** a CI gate, because timing on shared
  runners is noisy and a flaky security gate gets disabled. A pass means
  measured linear on the inputs the harness constructs, not a proof.

### Fixed

- **OpenPGP private key headers were never detected.** A real header ends
  `-----BEGIN PGP PRIVATE KEY BLOCK-----`, and the rule required
  `PRIVATE KEY-----`, so it matched neither the old nor the newly bounded form.
  The test that claimed coverage manufactured its own pass by deleting
  " BLOCK" from the header before scanning, so the gap was invisible. The rule
  now accepts the optional ` BLOCK` suffix (a fixed literal, measured to add no
  backtracking) and the test asserts the real header.

### Changed

- **`init` no longer ignores test trees.** The generated `.vault-guard.json`
  used to write `**/__tests__/**` into `ignore.patterns`, which is what let a
  vendor-anchored key committed to a test file slip past the hook entirely: an
  ignore is total, so the scanner never looked. Test trees are now scanned. The
  sequential-run and test-context downgrades keep the low-precision rules
  (generic assignments, DSNs, JWTs, PEM headers) at `low` in a test path, but
  **vendor-anchored patterns are not downgraded in test files at all**. The
  practical consequence, which is the point of the change and also its cost: a
  vendor-shaped value in a test blocks whether or not it is live, because the
  scanner cannot tell a real `sk-ant-`/`ghp_`/`AKIA` string from a convincing
  fabricated one. Fabricate test tokens as fragments joined at runtime, or use
  the documented placeholder words. `fixtures/**` and `bench/fixtures/**` stay
  ignored because those directories hold deliberately-planted, contiguous
  credential fixtures. This changes the default for new adopters only; existing
  users keep their committed config, and `init` now prints a one-line note
  saying so.

## [1.5.0] - 2026-09-05

A security and reporting release: three fail-closed hardening fixes and a new
suppression-visibility field. No detection severity changes.

### Security

- **`git show :<path>` could be steered onto a different blob.** git's
  `:<path>` revision syntax also accepts the `:<stage>:<path>` form, so a
  staged file whose repo-relative path began `0:`, `1:`, `2:` or `3:` was read
  as a stage reference to a different, shorter path. Staged beside a clean file
  of that shorter name, the scanner read the clean neighbour while recording
  the finding against the crafted name, letting a real staged secret through
  under a clean result. `readGitIndexFile` now resolves the staged blob by
  object id (`git ls-files -s`, then `git cat-file blob`), keeping
  attacker-controlled path text out of git's revision grammar entirely.
- **The MCP `report_token_usage` walk followed symlinks out of the
  workspace.** It walked with `fs.statSync`, which follows symlinks, skipped
  only `node_modules` and `.git`, and kept no visited set, so a symlinked
  directory inside the workspace pointing outside was followed out of it and a
  cycle could recurse without bound. The walk now mirrors the core walker:
  `lstat` every entry, never follow a symlink, and gate directory descent on a
  realpath visited-set.
- **MCP `scan_file` and `scan_text` had no input size cap.** Both now refuse an
  input larger than the same 10 MB bound `scan_workspace` already enforces per
  file, rather than reading an arbitrarily large blob into the host process.
- **The VS Code extension let a repository choose the binary it executes.**
  `vaultGuard.executable` is read from configuration and spawned, and the
  contributed property declared no scope, so a workspace `.vscode/settings.json`
  could set the executable path. The property is now `"scope": "machine"`, so a
  workspace cannot set it.

### Added

- **Suppression visibility.** A suppression is the user's decision and must be
  visible. The text summary now prints a `Suppressed:` line every run (even at
  zero), and JSON and SARIF carry `run.baseline_suppressed` and a new
  `run.inline_suppressed` field (emitted even at zero) counting findings hidden
  by inline `vault-guard: ignore-line` / `ignore-next-line` directives, with a
  `suppression.inline` diagnostic naming the suppressed line numbers. What is or
  is not suppressed is unchanged; only its visibility.

## [1.4.7] - 2026-09-05

Three false-positive classes found by scanning a public Rust monorepo.
That scan produced 30 findings, 20 of them blocking, and every one was a
test fixture, a hand-typed placeholder, or a Sentry DSN that is public by
design. The same scan now reports 23 findings, all at `low`, and exits 0.

### Fixed

- **Rust test files were not recognised as test files.**
  `TEST_FILE_PATTERNS` covered JS/TS, Go and Python but not Rust. Cargo
  has no separate directory for unit tests, so a crate keeps them beside
  its source as `src/auth/auth_tests.rs`, and every throwaway token in
  one kept its full severity even though the rules involved
  (`api-key-generic`, `jwt-token`, `bearer-token`, `ssh-private-key`)
  were already on the test-path downgrade list. `*_tests.rs` and
  `*_test.rs` now downgrade the same way `*_test.go` does.
- **Inline `#[cfg(test)]` modules were invisible.** Rust's dominant
  unit-test convention puts the tests in the same file as the production
  code, which no path heuristic can see. A new content-side signal
  locates in-file test regions and grants a match inside one the same
  downgrade a test path grants, for the same rule set. It is a
  line-based heuristic, not a parser. A column-0 `cfg` attribute opens a
  region when its predicate is true under `cargo test` and it introduces
  a `mod` or `fn`; the region runs to end of file, closing early at a
  negated-test attribute, at the next top-level item without such an
  attribute, or at a column-0 macro invocation such as
  `lazy_static! { … }`. The predicate is read structurally, not by
  substring: `test` counts only outside any `not(`, so
  `#[cfg(all(not(test), feature = "prod"))]` is a closer and never an
  opener, and string literals are skipped, so a feature named `test`,
  `test-utils` or `testing` is not the `test` predicate. The finder is a
  per-language registry; Rust is the only implementation.

  Three blind spots remain, and only the first is safe. An **indented**
  attribute is ignored, so a test item nested inside an `impl` keeps its
  full severity. A column-0 `#[cfg(test)]` written inside a raw string or
  a block comment opens a region that does not exist, and production code
  resuming in a shape not on the closer list leaves a region open over
  it. **Both of those demote real code**, and the fix for both is the
  same one this design does not attempt: parse Rust rather than scan
  lines.
- **Alphabet-run placeholders defeated the entropy gate.** Shannon
  entropy counts character frequencies and throws the order away, so a
  strict run such as `abcdefghijklmnopqrstuvwxyz0123456789` scores at
  the top of the range for its length and walked straight through. No
  threshold fixes that: order is the signal, and entropy does not look
  at order. A new check ahead of the entropy gate drops any value where
  at least 75% of its characters sit inside runs of three or more
  consecutive code points, ascending or descending. A value that is half
  run and half random scores 50% and survives, because a real credential
  can carry an incidental run. Values under 12 characters are never
  checked, since coverage says nothing at that length.

  **Rules whose value is human-chosen are exempt**, because for those a
  run is a *weak* secret and not a fake one, and suppressing it destroys
  the finding rather than demoting it. The exempt list is
  `password-in-code` plus the four connection-string rules
  (`postgresql-url`, `mysql-url`, `mongodb-url`, `redis-url`), whose
  secret is the password component of the DSN. `password-in-code`
  matters most: its minimum capture is 12 characters, the same as this
  check's minimum value length, so ordinary weak passwords sat exactly on
  the boundary.

### Changed

- The sequential-run check applies to vendor-anchored patterns as well,
  unlike the entropy gate, which those patterns never consult. That is
  where it earns its keep: `ghp_abcdefghij…` and `AKIAABCDEFGH…`
  are how a fake key gets typed by hand, and five of the eight criticals
  in that public-repo scan were exactly this. It is safe there for the
  same reason it is useful: a real provider key comes from a random
  source and cannot be the alphabet. **If your repository carries a
  counting or alphabet-run placeholder under a real vendor prefix, that
  finding now disappears rather than blocking.**
- Both test-context changes are severity downgrades, never suppressions,
  and neither touches vendor-anchored provider keys. A real provider key
  is a real key even in a test file.

### Notes

- `bench/README.md` records a limitation the corpus has always had: the
  harness counts a file as detected at any severity, so a false positive
  fixed by a *downgrade* cannot be guarded as a clean fixture there. A
  `maxSeverity` label is the way to close that and is deferred on cost.
  The two Rust classes are parked as TP fixtures that guard against the
  downgrade silently becoming a suppression, and the behaviour itself is
  covered by unit tests.

## [1.4.6] - 2026-09-03

### Fixed

- **Staged scan depended on repository config and working directory.**
  With git's `diff.relative` set, git prints staged paths relative to
  the process working directory and omits every staged path outside it.
  The gate assumed repository-root-relative paths and resolved them
  against the working directory instead. From a subdirectory that meant
  files staged above it were silently absent from the scan, with no
  error and no diagnostic. The staged diff now always runs at the
  worktree root with `diff.relative` and `core.quotePath` forced off.
- **An unreadable staged file no longer passes as a clean run.** A file
  the scanner could not read used to produce a warning while the run
  still reported success. It is now fatal: exit 2, every unreadable
  file named, and findings from the files that did read still shown.
  `run.unscannable_files` carries the list in JSON and SARIF. Directory
  scans are unchanged and keep diagnosing without failing, since a
  directory walk is open-ended discovery rather than a closed list git
  itself declared.
- **A staged submodule pointer no longer blocks a commit.** A submodule
  bump has no blob for the gate to read; it is now ignored at the diff
  instead of being treated as an unreadable file.
- **Paths in text, JSON and SARIF output are anchored at the repository
  root**, regardless of the directory a staged scan is run from.
- **The installed pre-commit and pre-push hooks now say the scan could
  not complete on exit 2**, and offer no bypass hint, rather than
  describing the failure as secrets detected.

### Changed

- A staged scan that finds a secret and also hits an unreadable file
  now exits 2 rather than 1. Gate on any non-zero exit code, not on 1
  alone.

Left for a follow-up: a scan run directly against an explicit,
unreadable file target still exits 0.

## [1.4.5] - 2026-09-03

### Fixed

- **SARIF output leaked local filesystem layout.** `artifactLocation.uri`
  was relativized against the working directory, so scanning a target
  outside it emitted absolute paths; it is now relativized against the
  scan root instead. Diagnostic notifications carried the same absolute
  paths into `tool.driver.notifications` and are sanitized the same way.
  In-checkout scans are unchanged.

## [1.4.4] - 2026-09-03

### Fixed

- **Husky-managed repositories.** husky 9 points `core.hooksPath` at
  `.husky/_`, a generated directory it rewrites on every install. Init
  wrote the hook there and reported success, and the next install
  removed it. When the hooks directory is named `_` under `.husky`,
  install, uninstall, and detection now use that `.husky` directory's
  own tracked hook, including a nested husky directory. husky 8 and
  repositories without husky are unchanged.
- **Uninstall reported success without removing anything.** A hook
  written whole from the husky template had no stanza marker to strip,
  so uninstall rewrote it unchanged and said it succeeded. The template
  now carries a header line; uninstall removes a whole-file hook, strips
  only an appended stanza, leaves anything else alone with an honest
  message, and reports success only when the hook is really gone. A hook
  written by an older release is left in place and named as such.

## [1.4.3] - 2026-09-02

### Fixed

- **Hook install location with a relative `core.hooksPath`.** The path
  was resolved against the `.git` directory; git resolves it against the
  working-tree root. With husky 9's `core.hooksPath=.husky/_`, init wrote
  the hook where git never looks and reported success, so the gate never
  ran. Found by running the umbrella installer against a real clone. The
  test now installs the hook and drives a real commit that must be
  refused.

## [1.4.2] - 2026-09-02

### Fixed

- **SARIF output.** Results now carry `partialFingerprints` (the same
  positional fingerprint the JSON output emits), and `artifactLocation.uri`
  is relative to the scan root with forward slashes for files under it.
  Uploads to code scanning no longer leak the local filesystem layout.
- **Init workflow template pin.** `vault-guard init` wrote a workflow
  pinned to `@v1.2.0` for three releases. The pin is now derived from the
  installed CLI version, and the README and Action docs were brought to
  the current release at the same time.
- **Windows install.** `better-sqlite3` is now an optional dependency of
  the telemetry package. When the native binding cannot be built or
  loaded, every command still runs; telemetry degrades to a no-op store,
  and the proxy and MCP server say once that usage is not being recorded.
- **Integrator guidance.** Tools consuming the JSON output should gate on
  `run.blocking_matches`, which honours the configured threshold, not on
  `summary.secrets`. The docs now say so.

### Security

- Overrides bumped for `fast-uri` (four advisories) and `qs` (two
  advisories) reached through the MCP SDK dependency chain.

## [1.4.1] - 2026-08-11

### Fixed

- **GitHub Action SARIF upload.** The composite action invoked
  `npx … -- scan …`. npx forwards that `--` into the CLI argv; Commander
  treats it as end-of-options and ignores `--format`, so `tee` wrote text
  banners (`🔍 Scanning…`) into the SARIF file and `upload-sarif` failed
  with invalid JSON. The action no longer inserts that separator, and the
  CLI drops a single leading `--` if a wrapper still passes one.

## [1.4.0] - 2026-08-11

Two things drove this release: the AI provider rules had quietly fallen two
years behind, and the commit gate blocked on findings the scanner itself had
already decided were not worth blocking. Both were found by pointing Vault
Guard at real code instead of its own fixtures.

### Fixed

- **GitHub Action path validation on macOS.** `validate_path` used bash
  `=~` with `{1,256}`, which fails to compile where `RE_DUP_MAX` is 255
  (macOS/BSD). Every path — including the default `.` — was rejected as
  invalid even with no secrets present. Charset is now checked with `+`
  plus an explicit length guard; CI runs the self-test on `macos-latest`.

- **Native pre-commit hook on dash.** Failed `exec </dev/tty` aborted the
  whole hook under Ubuntu `/bin/sh` (exit 2) even with `|| true`. Probe in a
  subshell before re-attaching stdin in the current shell.

### Changed

- The scan gate now defaults to `--fail-on medium`, where before any match at
  all exited 1. That old behaviour cancelled out the scanner's own severity
  downgrades: `path-severity.ts` drops generic findings to `low` inside
  `__tests__/`, `docs/` and `*.example` files, and then the commit was blocked
  anyway. Scanning three real-world repositories turned up 26 findings, every
  one we inspected a false positive, and all three exited non-zero.

  Findings under the threshold are still reported in text, JSON and SARIF.
  They just no longer break the build. Put back the old behaviour with
  `--fail-on low`, or `"fail_on": "low"` in `.vault-guard.json`.

  `scan` and `check` both take `--fail-on critical|high|medium|low|none`, and
  the JSON `run` block now carries `fail_on` and `blocking_matches`. If you
  gate a build on our output, read `blocking_matches` rather than
  `summary.secrets`.

- `better-sqlite3` moved to ^13.0.2. The 12.x line has no prebuild for Node 25
  and will not compile against its V8 headers, so telemetry, the `data`
  commands and `vault-guard proxy` were all broken there despite `engines`
  claiming `>=22`.

- CI runs Node 22, 24 and 25 instead of 22 alone. Nothing exercised the upper
  half of our own supported range, which is why the breakage above went
  unnoticed.

### Added

Rules for the AI providers people actually wire up today: Groq, OpenRouter,
xAI, Perplexity, Mistral, DeepSeek, Together, Fireworks and LangSmith. The AI
set had not moved past Anthropic, OpenAI, HuggingFace and Replicate, which is
an awkward gap for a tool that pitches itself at AI-assisted coding.

Also added, since agents wire these up constantly: Supabase (personal access
token and secret key), Vercel Blob, PlanetScale, Doppler, Databricks,
Cloudflare API tokens, Notion, Airtable and Figma.

Sentry DSNs are detected at `low`. A DSN is meant to ship inside a client
bundle, so it is worth surfacing but not worth failing a build over, same call
we already made for GCP OAuth client IDs.

### Fixed

- **PKCS#8 private keys were never detected.** The rule required an algorithm
  name between `BEGIN` and `PRIVATE KEY`, so `-----BEGIN PRIVATE KEY-----`
  slipped straight through. That is the default OpenSSL output and the form
  embedded in GCP service-account JSON, and the CLI would happily print
  "No secrets found" over a file that was nothing but a private key. Found by
  scanning a public repo that gitleaks flagged and we did not.

- Hyphenated placeholders. `your_api_key` was suppressed but
  `your-anthropic-api-key` fired as `api-key-generic` at `high`, which shows up
  all over `.env.example` files and READMEs.

- Unquoted variable references. The generic assignment rules capture whatever
  follows `:` or `=`, so `'x-api-key': scheduledIngestApiKey` was reported as a
  leaked key. Unquoted values that break into word-shaped segments are now read
  as code references. Quoted literals and every vendor-anchored rule are
  untouched.

- Password hashes. bcrypt, argon2, sha-crypt and Django/Passlib digests no
  longer count as `password-in-code`. A hash is the safe-at-rest form of a
  credential, and seed data is full of them. This was the single largest source
  of noise in the dogfood run.

- Bare PEM headers. UI code keeps `-----BEGIN RSA PRIVATE KEY-----` around as a
  label or an input placeholder. A header with no base64 body after it cannot
  leak key material, so it no longer fires. Note this is a small deliberate
  reduction in recall.

- Translation catalogues. A key like `tfa_secret` puts a translated label where
  the generic rules expect a value, so a German 2FA label read as a
  29-character secret. Files under `locales/`, `i18n/`, `lang/` and friends now
  get the same downgrade as docs and tests.

- `test-data` and `test_data` directories are recognised alongside `testdata`.

- Upgrading users get a one-time heads-up about the new default. When a run
  passes only because the implicit `medium` gate spared findings that earlier
  versions would have blocked, a note on stderr says so and points at
  `fail_on`. Choosing any threshold explicitly, via flag or config, silences
  it permanently.

- Text output contradicted itself once the gate had a threshold. A run whose
  findings all sat below it printed "BLOCKED: Found 1 secret", listed the
  finding, printed "Commit blocked", and then exited 0. The headline now
  reflects whether the run actually fails. Low-severity findings are also no
  longer marked with a green checkmark, which read as "this file is clean".

- Every known advisory in the dependency tree is resolved. `pnpm audit` went
  from 5 high and 4 moderate to zero, via overrides on `fast-uri`,
  `brace-expansion`, `hono` and `@hono/node-server`. The `pnpm audit
  --audit-level high` CI gate was already failing on `main` before this
  release.

- The pre-commit hook printed `/dev/tty: Device not configured` on every commit
  made without a controlling terminal. A failed `exec <` is reported by the
  shell itself, so a `2>/dev/null` on the redirect never suppressed it. The
  redirect now sits inside a group whose stderr is discarded. Testing
  `[ -r /dev/tty ]` first is not a fix: the device node passes the permission
  check and the open still fails with ENXIO.

- **A benchmark fixture was passing on the wrong rule.** The Groq fixture
  carried a 48-character key where the real format is 52, so the `groq` rule
  never fired and `api-key-generic` matched the surrounding assignment instead.
  The corpus reported a clean 100% while the rule under test did nothing. Every
  positive fixture now pins the rule id it must fire, and the harness fails the
  run if a different rule matches. Caught by driving the MCP server directly
  rather than trusting the corpus.

- **The benchmark scored gitleaks at a flat 0% recall, and that was our bug.**
  `bench/run.cjs` passed `--report-format json` with no `--report-path`.
  Gitleaks writes its report to a file, so stdout held only the banner,
  `JSON.parse` failed, and every file recorded zero findings. Run properly it
  scores 91.7% precision and 57.9% recall on this corpus. The harness and
  `bench/README.md` now also state outright that the corpus is a regression
  suite grown from our own fixed false positives, that its score is not a
  generalization metric, and that any cross-tool comparison on it is played at
  home.

### Dogfood

Scanned roughly 82,000 files across sixteen public repositories. Findings that
would block a commit at the new default dropped from 267 to 30, and the 30 that
remain are genuine by shape: committed `.env` files, PEM key files, a
service-account blob in a README, and JWT signing secrets in compose files.

### Documentation

`README.md` covers the gate and the wider rule set. It also now says plainly
that Clerk secret keys get reported under the `stripe` rule id, because both
vendors use `sk_live_` / `sk_test_` and nothing in the key body separates them.
The id stays as it is since baseline fingerprints include it.

## [1.2.3] - 2026-07-16

### Fixed

- **Nested `.gitignore` files are now honored when scanning from an ancestor
  directory.** `vault-guard scan .` previously only merged `.gitignore` rules
  found by walking *up* from the scan root to the git root, so a `.gitignore`
  nested below the scan root (a common pattern in monorepos, e.g. a
  per-package `target/` or `dist/` ignore) was silently skipped. On one real
  repo this meant scanning 9,186 files / 1.7GB of compiled build artifacts
  instead of the 469 files git actually tracks, producing 9 critical false
  positives on binary artifacts. Fixed by discovering `.gitignore` files
  below the scan root as well as above it.
- **`gcp-oauth` downgraded from critical to low severity.** The pattern
  matches GCP OAuth 2.0 client IDs, which are public identifiers safe for
  client-side embedding (only the paired client secret is sensitive). This
  is consistent with the project's existing policy of not treating public
  identifiers as secrets.

## [1.1.2] - 2026-07-07

### Fixed

- **Structured output flush.** Large `scan --format json` and `scan --format sarif`
  runs no longer truncate stdout when findings force a non-zero exit. CLI commands
  set `process.exitCode` instead of calling `process.exit(1)` immediately, so
  Node can drain stdout before the process ends.

## [1.1.1] - 2026-07-06

### Changed

- **MCP workspace sandboxing.** `scan_file`, `scan_workspace`, and
  `report_token_usage` now reject paths outside the MCP server workspace,
  including traversal and symlink escapes. `scan_workspace` also honors
  `.vault-guard.json` ignore paths/patterns.
- **Accurate reported locations.** Scanner matches now separate line-relative
  `column` from absolute `offset`, so CLI text, SARIF, and editor diagnostics
  point at the correct column on multi-line files. Existing baselines remain
  compatible because fingerprints continue to use the absolute position.
  JSON integrators should treat `matches[].column` as a 0-based line-relative
  column and `matches[].offset` as the 0-based absolute UTF-16 offset.
- **`vault-guard check` parity.** `check` now delegates to the normal scan path,
  so config, baselines, and diagnostics apply consistently with
  `vault-guard scan`.
- **GitHub Action reliability.** The composite action now runs Node 22 and
  emits `results-file` even when the scanner exits non-zero due to findings.
- Document OpenAI pattern trade-off: pre-watermark bare `sk-<N>` keys intentionally
  not matched (comment in `secret-scanner.ts`; rides next release train).

### Fixed

- Pin MCP's transitive `hono` dependency to a patched version so
  `pnpm audit --audit-level high` passes.
- Harden `scripts/check-pack.cjs` to use a temporary npm cache and show the real
  npm error when pack fails.

### Removed

- Removed the tracked internal `docs/plans/` audit-remediation note; local plans
  should stay out of the public repo.

## [1.1.0] - 2026-06-11

### Fixed

- **Streaming proxy telemetry records real tokens and cost.** The stream path now
  tees a bounded copy of the Anthropic SSE body (1 MB cap) and parses
  `message_start` / `message_delta` usage events via `proxy-sse.ts`. Cost is
  auto-computed by `TelemetryStore` when `estCostUsd` is omitted. Overflow uses
  source `proxy-stream-overflow`. Fixes the High-severity audit finding where
  streaming always logged `inputTokens: 0, outputTokens: 0`.
- **OpenAI key detection broadened for current formats.** Replaced fixed
  `sk-[48]` with `T3BlbkFJ` watermark rules: `openai-project`, `openai-svcacct`,
  `openai-admin`, and legacy `openai` (token-boundary + watermark). Recall tests
  and bench fixtures added; corpus 25 → 29 files, precision/recall 100%.

### Added

- **Release train:** `@changesets/cli`, lockstep versioning for all four published
  packages, `pnpm version-packages` / `pnpm release:next`, `CONTRIBUTING.md`
  cadence policy (one minor every 2–4 weeks).
- `.vault-guard.json` — ignore `fixtures/**`, `bench/fixtures/**`, `**/__tests__/**`
  for pre-commit scans.

## [1.0.6] - 2026-06-11

### Fixed (publish hygiene)

- **Source maps no longer ship to npm.** `sourceMap` and `declarationMap` are now
  `false` in the published tsconfigs (`core`, `cli`, `telemetry`); `declaration`
  (`.d.ts`) is kept. This removes ~half the files from each tarball (e.g. CLI
  74 -> 34, core 94 -> 48) and stops shipping `.map` artifacts from a tool whose
  own docs warn about source-map leaks. (The maps did not embed source text, but
  shipping them at all is sloppy and pure bloat.)
- **Test code no longer ships in the CLI tarball.** `proxy-test-helpers.ts` was
  not named `*.test.ts`, so the old `exclude` missed it and it landed in
  `dist/__tests__/`. The build now excludes `**/__tests__/**` entirely; tests
  still run via `ts-jest` independently of the build.

### Added

- **`scripts/check-pack.cjs` publish-hygiene gate.** Runs `npm pack --dry-run`
  for every publishable package and fails if any source map, `__tests__`
  directory, test helper, or test file would be published. Wired into CI and as
  a required gate in the release workflow before publish (`pnpm check:pack`).

## [1.0.5] - 2026-06-11

### Fixed (false positives)

- **`resend-api` no longer matches `re_<identifier>` substrings.** A long Go test
  name (e.g. `...stateStore_reconfigureLeadingToMigrationOfLocalState`) produced a
  `re_<camelCase>` run that satisfied the old `re_[a-zA-Z0-9]{32,}` rule and was
  flagged `critical`. The rule is now anchored to a token boundary and
  entropy-gated (`minEntropy: 3.5`), so only standalone high-entropy `re_` tokens
  match. Surfaced by the OSS corpus scan against terraform.

### Added

- Bench fixtures locking the fix: a standalone Resend key (TP) and a Go test-name
  false-positive guard (FP).

## [1.0.4] - 2026-06-11

### Fixed

- **MCP server no longer crashes when `better-sqlite3` is unavailable.** Telemetry
  is now lazily constructed and degrades gracefully: if the native binding cannot
  load (common under `npx`, `--ignore-scripts`, or a Node ABI mismatch), the
  `scan_workspace`/`scan_file`/`scan_text` tools stay fully functional and only
  `record_session_event` returns `{ ok: false, telemetry: "unavailable" }`.

### Added

- MCP integration tests (in-memory client/server) covering tool registration,
  `scan_text` detection, telemetry-unavailable degradation, and session recording.

## [1.0.3] - 2026-06-11

### Added

- Package READMEs for `@vaultcompass/vault-guard`, `@vaultcompass/vault-guard-core`,
  `@vaultcompass/vault-guard-mcp`, and `@vaultcompass/vault-guard-telemetry` (npm
  getting-started docs).

## [1.0.2] - 2026-06-07

### Fixed (false positives)

- **`.env.<env>.example` templates** (e.g. `.env.production.example`, `.env.staging.example`)
  are now treated as fixture paths; fixes false positives on multi-env `.example` templates.
- **All markdown documentation** (`README.md`, `CLAUDE.md`, `*GUIDE*.md`, any `.md`/`.mdx`)
  is recognized as a documentation path; generic patterns downgrade to `low`, vendor
  patterns in docs downgrade to `low`, and common placeholders are suppressed.
- **Template-redacted keys** (`sk-XXXX…`, `replace-with-*`) suppressed globally.
- **`secret:ENV_VAR_NAME` in CI workflows**: ALL_CAPS env-var names no longer match
  `secret-generic`.
- **Python triple-quoted docstring examples** (Ansible `EXAMPLES = r"""…"""`) suppress
  generic assignment patterns such as `password-in-code`.
- **CodeQL ReDoS findings in `doc-context.ts`**: removed polynomial filename regex
  (redundant with all-`.md` detection) and replaced `your_*_key` placeholder matching
  with a bounded string scan.
- **`scripts/gen-rules-doc.cjs`**: escape backslashes in generated `docs/RULES.md` table
  cells (CodeQL incomplete-sanitization alert).

### Added

- Bench fixtures for `.env.production.example` templates and README placeholder keys.

### Changed

- Consolidated path parsing and severity downgrade ID lists into shared utils.
- Removed tracked `todos-local.md`; use gitignored `TODO.local.md` for private notes.
- **`docs/GITHUB_BRANCH_PROTECTION.md`**: required checks now `test (22.x)`, `lint`, and
  `CodeQL` (drop obsolete `test (20.x)`).

## [1.0.1] - 2026-06-02

### Fixed (false positives)

- **Expanded test/fixture path detection for path-aware severity downgrades.** Go
  `*_test.go`, Python `test_*.py` / `*_test.py`, `examples/` (and
  `example`/`samples`/`sample`), Celery-style `t/unit/` and `t/integration/`
  trees, directory segments ending in `test` (`caddytest/`, `integrationtest/`
 ; excluding `contest/` and `latest/`), and `.env.example` / `.env.sample`
  templates are now treated as test/fixture paths. Generic patterns, DSNs, and
  SSH/JWT shapes downgrade to `low` instead of `high`/`critical` in these
  locations. Addresses OSS sweep noise on Terraform, Celery, Caddy, Strapi, and
  Gatsby example configs.
- **Documentation-site false positives.** Algolia search-only keys (32-char hex)
  and similar `api-key-generic` matches in `docs/`, `website/`, and doc config
  files (`algolia.js`, `docusaurus.config.js`) are suppressed. Generic patterns
  in documentation paths downgrade to `low` severity.
- **Docstring demo passwords.** Pydantic-style documentation literals such as
  `password='IAmSensitive'` are suppressed via the aggressive placeholder tier.

### Added

- Bench fixtures for Algolia docs config and docstring demo passwords.
- CLI startup warning when Node.js is below 22.

## [1.0.0] - 2026-06-05

### Fixed

- **`config.ignore.paths` / `config.ignore.patterns` now actually work.** These
  fields were declared in the config schema and type but were never consumed by
  the scan pipeline; a silent no-op since the feature was first added. Both
  fields now accept gitignore-style glob patterns and are applied uniformly to
  directory scans (`vault-guard scan <path>`) and staged-file scans
  (`vault-guard scan --staged`). Patterns are matched relative to the scanned
  root so that e.g. `packages/**/__tests__/**` works as expected from the repo
  root. `buildConfigIgnoreFilter` is exported from
  `@vaultcompass/vault-guard-core` for use in custom tooling.
- Added repo-root `.vault-guard.json` so `vault-guard` dogfoods its own ignore
  config on this repo (excludes `packages/**/__tests__/**` and `fixtures/**`
  from scans, preventing the pre-commit hook from blocking on synthetic test
  fixtures).

### Fixed (false positives)

- **Placeholder / example-value suppression.** Matched values that are obvious
  documentation samples or test fixtures are now dropped. A *standard* tier
  (markers such as `EXAMPLE`, `changeme`, `your_token_here`, plus pure
  character-repetition padding) applies to every pattern; this suppresses
  AWS's documented `AKIAIOSFODNN7EXAMPLE` key, for example. An *aggressive* tier
  (`test`, `sample`, `password`, …) applies only to the low-precision generic /
  password-assignment patterns so vendor-anchored keys keep full recall.
  Exposed as `isPlaceholderSecret()` from `@vaultcompass/vault-guard-core`.
- **Vendored / generated trees skipped by default.** File discovery now ignores
  `.yarn`, `vendor`, `.venv`/`venv`, `__pycache__`, `.mypy_cache`,
  `.pytest_cache`, `.gradle`, and `.svelte-kit` directories, plus minified /
  bundled single-file artifacts (`*.min.{js,mjs,cjs,css}`, `*.bundle.{js,mjs,cjs}`,
  `*.map`, `.pnp.cjs`, `.pnp.loader.mjs`). These are never hand-authored and were
  a major false-positive source (broad key shapes occur by chance inside large
  minified blobs). On a real `strapi` checkout this cut findings from 72 to 20
  with no loss of true positives.
- **Local / dev / example connection strings no longer flagged.** Database and
  Redis DSN patterns (`postgresql-url`, `mysql-url`, `mongodb-url`, `redis-url`)
  now suppress matches whose host is local/non-routable (`localhost`,
  `127.0.0.1`, a bare docker-compose service name like `mysql`, or a reserved
  TLD such as `.local`/`.test`), or whose password is an obvious
  placeholder/default (`pass`, `PASSWORD`, `root:root`, `${DB_PASSWORD}`, …).
  A real remote host with a real password is still flagged. This was the single
  largest real-world FP source: on a `prisma` checkout it cut findings from
  **147 (146 critical)** to **4**, all `low`. Exposed as
  `isNonSecretConnectionString()`.
- **Canonical jwt.io sample token suppressed.** The ubiquitous RFC 7519 / jwt.io
  example JWT (decodes to `sub: "1234567890"`, `name: "John Doe"`,
  `iat: 1516239022`) that appears in countless API docs is no longer reported.
  Real JWTs are unaffected. Exposed as `isSampleJwt()`.
- **Path-aware severity for credential-shaped strings in test/fixture paths.**
  Findings from generic-assignment, connection-string, and key/token patterns
  (`password-in-code`, `postgresql-url`, `ssh-private-key`, `jwt-token`, …) are
  downgraded to `low` severity (not suppressed) when the file lives in a test
  or fixture path (`__tests__/`, `tests/`, `*.test.ts`, `fixtures/`, `spec/`,
  …). Hard vendor-anchored API-key patterns (Anthropic, AWS, Stripe, GitHub, …)
  keep full severity everywhere. Previously this only applied to files over
  10 MB; it now applies on the normal scan path too. Exposed as
  `applyPathAwareSeverity()` / `isTestFilePath()`.
- **`password-in-code` no longer fires on compound identifiers.** A negative
  lookbehind prevents matching when `password` is the suffix of a larger key
  name (e.g. `email-reset-password: "…"` in i18n files). Only standalone
  `password = …` / `password: …` assignments match.
- **Generic-assignment patterns no longer flag function-call results.** The
  generic assignment patterns (`secret-generic`, `api-key-generic`,
  `password-in-code`) stop their value capture at `(`, so an unquoted value
  immediately followed by `(` is a callee identifier, not a literal secret.
  These are now suppressed (e.g. Django's
  `csrf_secret = _add_new_csrf_cookie(request)` was reported as a `high`
  hardcoded secret. The heuristic is scoped to those three patterns only;
  vendor- and context-anchored detectors (including the critical
  `aws-secret-context`) are explicitly excluded and keep full recall. Verified
  on Django/Flask/Gin/Caddy checkouts: cleared all remaining Python
  `secret-generic` false positives with no loss of recall.

### Added

- **`bench/` precision/recall harness.** A labeled fixture corpus (real-world
  true positives + false-positive candidates) plus `node bench/run.cjs`
  (`pnpm bench`) reporting Precision / Recall / F1 / Grade, with an optional
  `--gitleaks` side-by-side. Current score on the corpus: **100% / 100% / A**.

### Changed (BREAKING)

- **`engines.node` raised to `>=20.0.0`** on all publishable packages and the
  workspace root. CI matrix narrowed to Node **20.x / 22.x**. Reason:
  `better-sqlite3@12` (telemetry store) stopped shipping prebuilt binaries for
  Node 18 on Linux x64, leaving CI / installs broken without a build toolchain.

### Fixed

- **CI green again.** `pnpm/action-setup@v6` errors when both `with: version`
  and `package.json` `packageManager` are set; dropped `with.version: 9` from
  every workflow step. Also corrected a malformed
  `softprops/action-gh-release` SHA comment in `release.yml`.

### Added

- **`engines.npm` / `engines.pnpm`** (`>=9`) on all publishable packages
  (`@vaultcompass/vault-guard-core`, `@vaultcompass/vault-guard`,
  `@vaultcompass/vault-guard-mcp`, `@vaultcompass/vault-guard-telemetry`)
  alongside existing `engines.node` (`>=18`).
- **Release workflow smoke job**: after a tag publish, installs
  `@vaultcompass/vault-guard@<version>` from the public registry (with retry),
  runs `vault-guard scan` on `fixtures/release-smoke/`, and asserts a non-zero
  exit and `summary.secrets > 0` in JSON output.
- **Telemetry `cwd` privacy**: `usage_events.cwd` and `session_events.cwd`
  now store **HMAC-SHA256** digests (hex) using a per-machine key in
  `~/.vault-guard/salt` (mode `0600`). One-time migration rewrites legacy
  plaintext paths when the SQLite `user_version` pragma is below `2`.
- **Telemetry retention**: deletes rows older than **`VG_TELEMETRY_RETENTION_DAYS`**
  (default **90**; set to **`0`** to disable). Purge is throttled to at most
  once per hour per process; tests can set **`VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE=1`**
  to disable the throttle.
- **`ignore` (npm) for `.gitignore` handling** in `@vaultcompass/vault-guard-core`
 ; replaces the hand-rolled regex compiler in `file-utils.ts`. Nested
  ignore files are merged relative to the Git work tree (or filesystem root
  when no `.git/` is present). Cache entries are LRU-bounded and invalidated
  when any contributing `.gitignore` mtime changes; `clearGitignoreCache()` is
  exported for tests and long-lived hosts.
- **`scanTextFileAsync` / `scanTextFileSync`**: async scans stream UTF-8
  line-by-line when a file exceeds the size threshold so multi‑MB text files
  are not fully buffered (multi-line secrets may be missed in streaming mode).
  CLI and MCP use the async helper; sync returns empty matches for oversized
  files with a `file.too_large` diagnostic.
- **`SecretScanner.mergeChunkedMatches`**: dedupe helper for streamed scans.
- **`vault-guard data` command group** for managing the local telemetry
  database at `~/.vault-guard/usage.sqlite`:
  - `data status`; privacy-respecting summary (file path/size, row counts,
    distinct-value *counts*; never raw `cwd` strings). `--json` for
    machine-readable output.
  - `data reset`; deletes the SQLite database and its WAL/SHM/journal
    sidecars. Interactive `y/N` prompt by default; `--yes` for
    non-interactive use; `--dry-run` to preview. Refuses to proceed when
    stdin is not a TTY and `--yes` was not passed.
  - `data export`; dumps `usage_events` and `session_events` to a JSON or
    JSONL file with mode `0o600` (user-only).
- **Scan run metadata**: JSON and SARIF include optional `run` (`duration_ms`,
  `files_scanned`, `bytes_scanned`, `patterns_active`, `diagnostics_count`,
  optional `baseline_suppressed`); SARIF mirrors this under
  `runs[0].properties.vault_guard_run`. MCP scan tools emit the same fields.
- **`SecretScanner#getActivePatternCount()`**: reports how many built-in +
  extra patterns are active after `severity_overrides` / rejections.
- **Baseline file**: optional `.vault-guard.baseline.json` (version `1`,
  `fingerprints[]`) discovered with the same directory walk as config; JSON
  output includes a per-match **`fingerprint`** (SHA-256 of path + rule +
  span; no raw secret) for populating the baseline.
- **`vault-guard config validate`**: structural validation plus
  `SecretScanner` construction (fails if any `extra_patterns` are rejected).
- **`schemas/vault-guard-config.json`**: JSON Schema for `.vault-guard.json`.
- **`docs/PRODUCT_SCOPE.md`**: in-scope vs out-of-scope; README links and
  “compose with Gitleaks / TruffleHog” guidance.
- **`vault-guard proxy --max-rpm`**: optional rolling 60s cap; returns HTTP 429
  when exceeded.
- **CLI integration tests (`json-output`)**: contract coverage for `--format json`:
  invoking the built `packages/cli/dist/cli-entry.js`, stdout must be a single
  parseable JSON object for `fixtures/release-smoke/` (findings) and for a clean
  temporary directory (no findings).

### Documentation

- **README**: scripting / CI: stable JSON via `node packages/cli/dist/cli-entry.js`,
  `pnpm exec` variant, avoiding mixed global vs workspace CLI versions, and
  guidance when many matches remain after manual audits (baseline / ignore).

### Security

- **`action.yml` input validation.** All four GitHub Action inputs
  (`version`, `path`, `format`, `sarif-output`) are now passed through
  `env:` (which the shell expands at runtime) instead of `${{ ... }}`
  template substitution (which happens before the shell parses, defeating
  any amount of quoting). A dedicated validation step regex-checks each
  value before the `npx` invocation, rejects path-traversal (`..`) and
  absolute paths, and `--` separates `npx`'s flags from package args.
  Tracked threat: shell injection / npm dist-tag injection via attacker-
  controlled workflow inputs.
- **`DiagnosticBus`**: every previously silent `catch {}` in the scanner, file
  walker, git helpers, and config loader now emits a typed diagnostic
  (`config.parse_error`, `file.too_large`, `fs.permission_denied`,
  `git.staged_files_failed`, `pattern.redos_unsafe`, …). Diagnostics surface in
  JSON output (`diagnostics[]`) and SARIF (tool/driver `notifications`), so a
  swallowed permission error or a corrupt `.vault-guard.json` no longer
  produces a misleading "✅ no secrets found".
- **Heuristic ReDoS gate on user-supplied `extra_patterns`**: length cap,
  quantifier-density cap, and shape checks for `(…[*+]…)[*+]` and
  `(.|.)[*+]`. Rejected patterns surface as `pattern.redos_unsafe` /
  `pattern.too_long` diagnostics rather than being silently dropped.
  `extra_patterns_unsafe: true` opts out of the heuristic; the length cap
  always applies as a memory-use backstop. Tracked threat: catastrophic
  backtracking from a malicious in-repo `.vault-guard.json`.
- **Pre-commit fails closed on git failure.** `getGitStagedFilePaths` now
  throws `GitError` instead of returning `[]` when `git diff --cached` fails.
  The pre-commit path catches it, exits **2**, and prints the failing command
  so a broken git environment can't masquerade as a clean commit.
- **Telemetry native bindings load lazily and degrade gracefully.**
  `better-sqlite3` is loaded with `createRequire` on first use; missing or
  ABI-mismatched bindings throw `TelemetryUnavailableError`. `statusline` and
  `suggest-model` catch this and exit cleanly; `proxy` lets it propagate
  (it is the primary writer and should fail loudly).
- **WAL checkpoint on proxy shutdown.** SIGINT/SIGTERM now triggers
  `wal_checkpoint(TRUNCATE)` before closing the SQLite handle, so usage rows
  written just before shutdown survive without WAL recovery surprises.

- **Tighter secret redaction in all output formats.** Matched values are now redacted
  to a 4-character prefix + length tag (e.g. `sk-a…(37c)`) instead of a 12-character
  prefix. The longer prefix could leak meaningful entropy for some vendor formats.
- **SARIF output no longer embeds the redacted value in the rule message.** The
  `region` (line, startColumn, endColumn) plus `ruleId` are sufficient for reviewers,
  and removing the value shrinks the leak surface when SARIF is uploaded to GitHub
  Code Scanning, attached to PRs, or shared in support tickets.
- **JSON and SARIF outputs now emit cwd-relative file paths** (paths outside the
  scan root remain absolute). Avoids leaking the developer's home directory and OS
  username when output is shared.
- Text output reformatted as `path:line:col` so editors auto-link to the exact
  location (iTerm2, Windows Terminal, VS Code, JetBrains all recognise this form).

### Added

- **`docs/RULES.md`**: generated from `BUILTIN_PATTERNS` via
  `scripts/gen-rules-doc.cjs`. CI fails if the file drifts from the source.
- **`docs/PRIVACY.md`** and **`docs/THREAT_MODEL.md`**: what
  `~/.vault-guard/usage.sqlite` actually stores, and the per-component
  threat model for CLI / proxy / MCP boundaries.
- `.github/dependabot.yml`; weekly npm + GitHub Actions updates, grouped
  by `@types/*`, eslint, and jest.
- `.gitattributes`; repo-wide `text=auto eol=lf` to keep Windows
  contributors from accidentally committing CRLF source files.
- Coverage thresholds in every package's `jest.config.js`, with
  `pnpm test:coverage` wired through `--workspace-concurrency=1` (proxy
  integration tests bind real ports).

- `@vaultcompass/vault-guard-mcp`; stdio MCP server (`scan_workspace`, `scan_file`, `scan_text`, `report_token_usage`, `record_session_event`); plus **`vault-guard statusline`** and VS Code extension package **`vault-guard-vscode`** (inline diagnostics, status bar, allow-list snippet command). See **`docs/MCP.md`**.
- `@vaultcompass/vault-guard-telemetry`; local `~/.vault-guard/usage.sqlite` store, **`vault-guard suggest-model`** heuristic, and **`vault-guard proxy --listen`** (Anthropic `/v1/messages` forwarder MVP with `usage` logging for non-stream JSON).
- `SecretScanner.scanContent()` and shared **`formatJson` / `formatSarif`** in `@vaultcompass/vault-guard-core`.
- **`vault-guard scan --staged`**: scans only git-indexed (staged) files.
- Pre-commit hook respects `core.hooksPath` (local + global), installs `vault-guard scan --staged` with `set -e`, TTY re-attach, and `--no-verify` hint; optional **`--manager`** `native` | `husky` | `lefthook` | `precommit`.
- Git utilities in core: `getGitStagedFilePaths`, `isInsideGitWorkTree`.
- Repo hygiene: `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Dependabot, CodeQL and OpenSSF Scorecard workflows, issue + PR templates.
- Distribution: root **`action.yml`** composite action, **`docker/`** image recipe, **`packaging/homebrew/README.md`**, **`docs/GITHUB_ACTION.md`**.

### Removed

- **`vault-guard monitor`** subcommand. The implementation was a stub that
  printed placeholder text; it has been removed from the CLI surface,
  command index, and tests rather than left as a misleading entry point.
  `vault-guard statusline --json` covers the live-status use case.

### Changed

- **CI / release:** `pnpm` **9** in workflows (matches lockfile v9); `pnpm/action-setup`, CodeQL, Scorecard, and `action-gh-release` pinned to commit SHAs; release job grants **`id-token: write`** for npm provenance; CI has **`workflow_dispatch`** and default **`permissions: contents: read`**.
- Root **`packageManager`**: `pnpm@9.15.9`; engines require **`pnpm >= 9`**.
- **`vault-guard proxy`:** max request/response buffer sizes; stderr warning when bind host is not loopback; **SECURITY.md** documents proxy threat model.
- Workspace root package renamed to `@vaultcompass/vault-guard-monorepo` (avoids clashing with the published CLI package name).
- CI builds before tests; lint failures fail the job; `pnpm audit` uses `--audit-level high`.
- GitHub Releases use `softprops/action-gh-release` with generated notes.
- CI / release workflows pin **`actions/checkout`**, **`actions/setup-node`**, and **`pnpm/action-setup`** to full commit SHAs. npm publish sets **`NPM_CONFIG_PROVENANCE=true`**.
- CLI `--version` reads from `packages/cli/package.json`.
- npm publish metadata: `files`, `publishConfig.access`, `repository`, `engines` on publishable packages.

### Fixed

- Tests build Stripe/Twilio-shaped strings via **template concatenation** so GitHub push protection does not block commits that contained contiguous `sk_live_*` / `sk_test_*` / `AC…` literals in fixtures.
- Jest resolves `@vaultcompass/vault-guard-core` from source in the CLI package so tests run without a prior `core` build.

## [0.1.0] - 2026-04-11

Initial development baseline (secret scan, pre-commit hook, token helpers).
