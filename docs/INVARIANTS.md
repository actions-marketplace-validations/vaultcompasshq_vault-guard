# Invariants

Cross-cutting properties this repository is supposed to hold, with the reason
each one exists and the thing that enforces it. An audit reads this file instead
of re-deriving a list from memory, and every new architectural decision appends
to it.

**This file is a claim, not a fact.** It was started during the 1.7.1
action-only release and currently covers the composite Action and the two
version numbers around it; it is not yet a complete list of this repository's
invariants, and saying so is more useful than implying coverage it does not
have. Every entry below names what enforces it, so a reader can check the claim
against the code rather than trusting the prose. An entry written in the same
change as the fix it describes deserves the most scrutiny, and these were.

---

## The scanner is itself a control input, and comes from outside the tree

Pull-request mode draws a line between a SUBJECT (the head tree) and a CONTROL
INPUT (`.vault-guard.json`, `.vault-guard.local.json`, the baseline), and reads
the control inputs from the base ref. That list was incomplete, and the missing
entry is the largest one: **the program doing the scanning**. A gate that reads
its config from the base branch and then runs a binary the head chose has moved
the decision, not removed it.

Through `@v1.7.0` the Action ran `npx --yes "@vaultcompass/vault-guard@${VG_VERSION}"`
with the checkout as its working directory. Two routes followed from that, and
both are decisions real npm makes about files the head controls:

- **A committed `.npmrc` repoints the registry.** npx in non-global mode reads
  project config from its cwd, and `--yes` means no prompt. A pull request
  adding one root file chooses which registry the scanner is fetched from.
  Both the global `registry=` key and the scope-specific
  `@vaultcompass:registry=` key do it; the second is quieter, because every
  other install in the workflow keeps working normally.
- **An installed copy wins outright.** `npx pkg@version` run in a tree whose
  `node_modules` already satisfies that spec runs the local copy and never
  contacts a registry. The version pin degrades from a choice of program to a
  satisfaction check on a package the head wrote, and any workflow with an
  install step before the gate hands that over.

**The rule: install the scanner from the registry into a prefix under the runner
temp, start npm from the runner temp, and call the result by absolute path.**
Not "install outside and run wherever": a composite step with no
`working-directory` runs at the workspace root, so npm would still start with
the head's `.npmrc`, manifest and lockfile under its cwd. Global mode is
documented not to read project config, which is a property of a version of npm
rather than of this repository, and is not what the boundary should rest on.

**Enforced by:** `packages/cli/src/__tests__/action/action-run-script.test.ts`
(runs both steps with npm stubbed, recording npm's argv, cwd and prefix),
`packages/cli/src/__tests__/action/action-path-validation.test.ts` (the steps
exist at all, and neither runs npx), and `bench/action-install.cjs` (real npm,
two local registries, both routes mounted).

`scripts/test-action-path-validation.sh` also runs on a macOS runner, where the
jest suites do not, and what it carries is two different things. Its grep guards
read the real `action.yml`, and its per-step checks ask the real file through
`scripts/extract-action-step.cjs`, so neither can drift. Its `validate_path`,
`validate_version` and `validate_trust_base` functions are **hand copies** of
the ones in `action.yml`, kept there because the point is to run those idioms
under bash 3.2, and a copy can drift from its original: read a green run of that
file as "these idioms are portable", not as "action.yml still contains them".
The grep guards beside them are what keep the second claim true.

**What this does NOT cover**, and the comment in `action.yml` says so: a pull
request can edit the workflow file, because a `pull_request` run uses the
workflow as it is in the merge commit. Branch protection on the base branch with
review required for `.github/workflows/**` is the control for that, and nothing
the action does substitutes for it. The absolute binary path is likewise not
total: the shim starts with `#!/usr/bin/env node`, so the interpreter is still a
PATH lookup a cooperating workflow can influence.

## The scanner is installed without scripts, and verified before it is trusted

Two properties of the same step, and both follow from the scanner being a
CONTROL INPUT rather than an ordinary dependency.

`--ignore-scripts`, because this step runs on a runner holding the job's token.
Without it every package in the resolved tree gets arbitrary code execution
there on every run, which is a strange amount of trust to extend from the tool
whose job is deciding whether this repository can be trusted. It costs nothing
here: the only native dependency is `better-sqlite3`, it is an OPTIONAL
dependency of the telemetry package, and the store degrades when its bindings
are missing.

`npm audit signatures` after the install. **Read the next paragraphs before
relying on it**, because the obvious summary of this command is wrong and the
first version of this entry asserted three things it does not do.

WHAT IT DOES. It asks the registry for each name and version in the tree and
checks the registry signature served back. Every name and version, the scanner
included, has to be one npmjs currently serves with a valid signature. That
catches an unpublished, replaced or unsigned package at the moment of install,
and it fails closed under `set -eu`.

WHAT IT DOES NOT DO, each measured rather than reasoned. It does not read the
installed files: `pacote` refetches the manifest instead of hashing anything on
disk, so a tampered install is invisible — appending a payload to the installed
binary and re-running the command exits 0. It does not defeat a compromised
registry, which signs what it serves. And a MISSING attestation is not a
failure, only a missing or invalid signature is, so it does not require
provenance despite these packages publishing it.

THE ROOT MANIFEST IS LOAD-BEARING. `npm audit signatures` audits the tree's
EDGES OUT, and a global install leaves `<prefix>/lib` with a `node_modules` and
no manifest, so the root declares nothing and the installed package sits on the
far end of no edge. Without a manifest the audit covers the dependencies and
SKIPS THE SCANNER, the one package the check exists for. Measured: 13 packages
installed, 12 audited without it, 13 audited and 5 attestations with it. The
first version of this step shipped without the manifest and recorded that 12 as
evidence the check worked — the numbers disproved the claim in the same sentence
that made it, which is the failure this file exists to catch.

KNOWN CONSEQUENCE OF FAILING CLOSED: a consumer whose runner points npm at a
mirror or proxy that does not serve `/-/npm/v1/keys` installs fine and then
fails here with `EMISSINGSIGNATUREKEY`, and a sigstore or TUF outage does the
same to everyone at once. Written down in `docs/GITHUB_ACTION.md` rather than
left to be discovered from a red required check.

**Enforced by:** `action-run-script.test.ts` (the argv carries the flag, the
manifest is written declaring the version being installed, the audit is
recorded, and the audit comes after the install), the text guards in
`action-path-validation.test.ts`, and `scripts/test-action-path-validation.sh`,
which refuses ANY `npm install` line in the file lacking the flag. The jest
suites run against a STUBBED npm, so they prove the action ASKS and say nothing
about what a real npm does when asked — and that gap is precisely what hid the
missing manifest, since the stub laid down an empty `lib` where the real command
would have reported 12 of 13. Verified by hand against the registry at 1.7.0:
two global installs of `@vaultcompass/vault-guard@1.7.0`, one with
`--ignore-scripts` and one without, scanning the same clean tree, produce
byte-identical output apart from the `scannedAt` timestamp, both exiting 0. An
earlier version of this paragraph cited a byte count without naming the tree or
the flags, which nobody could reproduce.

## The scan path is absolute AND resolved, and that is one decision with two halves

The run step starts in the runner temp, so the scan root is built from
`GITHUB_WORKSPACE` rather than passed as a relative `.`.

It is then resolved with `pwd -P` before being handed over, because vault-guard
anchors a directory scan at its own process cwd: node reports that cwd with
symlinks resolved, while bash's `cd` keeps the logical path. Hand the scanner a
logical `/var/...` target while its cwd reads `/private/var/...` and every file
in the head tree falls outside the target by `path.relative`, so the run scans
**zero files and reports a clean result over nothing**. That is a green check
that scanned nothing, which is the worst failure shape a gate has.

It would be silent on a Linux runner, whose workspace path is canonical already.
It was found by `bench/action-install.cjs` on a macOS temp directory, where
`/var` is a symlink, before the release shipped.

The step then chdirs into that scan root, which is deliberate and separate from
where npm ran: vault-guard loads its config, resolves the trust base and
computes every reported path from its cwd, so a scanner left in the runner temp
would fail to resolve `origin/<base>` and exit 2 on every pull-request run,
blaming a `fetch-depth` the caller already set.

**Enforced by:** the `SCAN_ROOT` guards in
`packages/cli/src/__tests__/action/action-path-validation.test.ts` and
`scripts/test-action-path-validation.sh`, and by the `filesScanned` field
recorded per case in `bench/baseline.action-install.json` — a run that scans
nothing shows up there as a number, not as a passing test.

## The output path is checked as a path, not as a string

`sarif-output` names a file the action WRITES, into a tree the head controls, so
the string rules are not the whole check. It may not resolve under `.github/`,
which holds the workflow file and the CODEOWNERS entry that decide how this gate
runs, and it may not resolve through a symlink at the file or at any directory
on the way to it — checked before `mkdir -p`, so a refused run has not already
created directories through the link.

Every guard here compares strings, so every SECOND NAME for the same file has to
be normalised away first, to a fixed point: a `./` prefix, an interior `/./`, a
doubled slash, a different case (macOS filesystems are case-insensitive), and a
**trailing slash**. That last one is not only cosmetic: `test -L` FOLLOWS a
symlink when the path it is given ends in a slash, so `out.sarif/` and
`out.sarif` name the same file and only the first walked past the symlink guard,
after which `dirname` returned the workspace and the loop ended having checked
nothing. A value that normalises to nothing or to a single dot names a
directory, and is refused with the input's name rather than left to fail as a
shell redirect error deep in the run step.

**Enforced by:** the `.github/`, symlink and directory cases in both action test
files, including the trailing-slash spellings; the symlink case is proven by
planting a real link and asserting nothing was written through it.

## Only 0, 1 and 2 are verdicts, in the step's exit AND in its output

126 and 127 are what the SHELL produces when a binary is missing or not
executable, which is exactly what a failed install looks like from the run step.
They are re-raised as 2, could-not-run, because reporting them as 1 would invent
findings nobody found.

The `exit-code` OUTPUT carries the mapped code too, not the raw status. A caller
reads that output precisely to tell a verdict from a failure to reach one, and
publishing a 127 the documented contract says cannot happen is the same bug one
layer out. `results-file` is published only when the run wrote something, so a
chained `upload-sarif` can be guarded on one expression instead of failing on an
empty file with a parse error that buries the real message.

**Enforced by:** the exit-code cases in `action-run-script.test.ts`, including
one that never installs the binary at all and asserts the output reads 2.

## A verdict requires a report, and the exit code alone is not one

The status says what the scanner decided. Whether it wrote anything says whether
it got far enough to decide. When the report is empty the status must not be
read as a verdict at all, and both arms of reading it anyway are wrong, in
opposite directions.

Exit 1 with no report is not findings. Commander exits 1 on an unknown option
and writes the message to STDERR, so the teed report stays empty, and 1 is also
the findings code. That is a live failure rather than a theoretical one: a
consumer pinning a `version` older than the flags this tag passes had a
repository told it was carrying secrets by a scanner that never parsed its own
argv. Findings would have produced findings.

Exit 0 with no report is not a clean scan. Same inference on the arm that fails
OPEN: a clean scan prints its report, so nothing written means the scan did not
happen, and calling that clean passes a pull request nothing looked at.

Both are re-raised as 2 with a message that says no report was written and names
the version skew as the usual cause. This is deliberately keyed on the REPORT
and not on a list of known-bad exit codes: the failure that produced this rule
landed on 1, the most ordinary code there is, which is why the wildcard arm that
had exactly the right words for it never fired.

**Enforced by:** `action-run-script.test.ts`, which drives a stub that writes to
stderr only and exits 0 and 1 in turn, alongside a case asserting a report WITH
findings in it is still reported as findings.

Verified against the real binary at scanner 1.7.0: a clean scan writes 627 bytes
and exits 0, the `fixtures/release-smoke` leak writes 1830 bytes and exits 1,
and an UNKNOWN OPTION writes zero bytes to stdout, its message to stderr, and
exits 1. That last one is a stand-in for the reported failure rather than a
reproduction of it: it runs a made-up flag against a current scanner, not
`--trust-base` against an old one, which is a different way into the same
Commander code path at `lib/command.js:2010`, where `error()` computes
`config.exitCode || 1`. Nobody has run an old scanner here, and this entry
should not be read as saying otherwise.

## The `version` input takes an exact version only

It defaults to the SCANNER version the Action tag shipped with, which is a
different number from the tag whenever an action-only release happens.

A dist-tag hands the choice of program to the registry on the morning of the
run. A charset check is not enough on its own: npm's specifier parser reads a
value beginning with `.` or ending in `.tgz` as a local path, so `.`, `..` and
`payload.tgz` resolve against a directory instead of the registry, and a value
that is not valid semver at all — `01.7.0`, `1.7.00` — falls back to being
treated as a dist-tag. The refusal message names the migration (`REMOVE the
input`), because `latest` used to be the default and a refusal with no
alternative in it is a wall.

**Enforced by:** the version cases in both action test files, and the SHAPE half
of the contract in `scripts/test-action-path-validation.sh`. That script checks
a hand-copied regex rather than the step itself, so it can run on the macOS
runner's bash 3.2. The copy has already cost once: it kept asserting `0.0.0` was
accepted, and stayed green, after the action started refusing it.

## The `version` input is checked for CAPABILITY, not only for shape

Passing the semver pattern proves the input names a version. It says nothing
about whether that version understands the arguments this tag is about to hand
it, and the input exists precisely so a consumer can pin a scanner OTHER than
the one the tag shipped with. Version skew is therefore a supported
configuration that can produce an unsupported argument vector.

The step declares the oldest scanner this tag can drive and refuses anything
below it, naming both numbers and the flag that set the floor. The floor is a
property of THE FLAGS THIS TAG PASSES rather than of the tag number: raise it in
the same commit that starts passing a newer flag. Today it is 1.7.0, set by
`--trust-base`.

The comparison is component by component and never textual, because `1.10.0`
sorts below `1.7.0` as a string and above it as a version, so a lexicographic
check would refuse the newer scanner the floor exists to keep.

**Enforced by:** the floor cases in `action-path-validation.test.ts`, which
include `1.10.0` on the accepted side and `1.6.9` on the refused side, plus a
case asserting the action never defaults to a version it would itself refuse.

## On a pull request, `version` may not pin BACKWARD

The floor above is flag compatibility, and it is not the control for version
choice: it admits everything at or above 1.7.0. On a same-repo `pull_request`
event GitHub runs the workflow file from the HEAD, so `version:` is written by
the pull request being judged. Once a second version exists, that is a bypass
with an innocent shape — deleting a security step reads as deleting a security
step, while `version: 1.7.0` reads as version management.

So on a pull-request event the step refuses a version BELOW the scanner this
action tag ships, and accepts anything at or above it. Pinning FORWARD stays
allowed, which is the direction the input exists for. That rests on an
ASSUMPTION the rule does not enforce: that a newer scanner is at least as
strict. Nothing bounds a forward pin, so a version ahead of the tag scanner is
accepted whatever its rules turn out to be.

Four properties, each load-bearing:

- `VG_TAG_SCANNER_*` is a SEPARATE constant from `VG_MIN_*`. They hold the same
  number today and mean different things: the floor is the oldest scanner that
  understands this tag's flags, this is the tested scanner the tag ships. One
  constant serving both is how raising one silently raises the other.
- The comparison is against that hardcoded constant, never against anything
  derived from an input. `inputs.version` looks identical whether a consumer
  pinned the current version or the default supplied it, so the step cannot tell
  a pin from a default; the constant is the only source of truth. It is
  trustworthy because `action.yml` comes from the ref the consumer's workflow
  names, not from the pull request's tree.
- The event test is `GITHUB_BASE_REF` being non-empty, the same one the run step
  uses to decide whether to pass `--trust-base` under `auto`, rather than a
  second detector to keep in step. It rests on a PLATFORM GUARANTEE worth
  recording, because a same-repo pull request's author writes the workflow file
  and the obvious bypass is therefore `env: GITHUB_BASE_REF: ""` at job level:
  GitHub documents that the default `GITHUB_*` and `RUNNER_*` variables cannot
  be overwritten and that such an assignment is ignored
  (https://docs.github.com/en/actions/reference/workflows-and-actions/variables).
  The Validate inputs step also DECLARES `GITHUB_BASE_REF: ${{ github.base_ref }}`
  in its own `env:` mapping, the same spelling the run step uses. A step-level
  entry wins over a job-level one, and `github.base_ref` is read out of the
  event payload rather than out of anything a workflow author writes, so the
  value cannot come from the workflow file either way. The declared form is
  defense in depth and is stronger than a bare read of the runner default,
  because its value comes from the event payload rather than from anything a
  workflow author can write, but it is not absolute immunity: a job-level
  `env: BASH_ENV: <a file>` that runs `unset GITHUB_BASE_REF` would still
  defeat it, because BASH_ENV is sourced before the step script runs and is
  not itself one of the GITHUB_*/RUNNER_* variables the no-overwrite guarantee
  covers. The platform no-overwrite guarantee above remains a second, separate
  line of defence, and neither form is depended on as the sole control.
- Written accept-only-if, not refuse-if, for the same reason as the npm floor:
  `[` returns 2 on a malformed comparison and an `if` reads 2 as false, so a
  refuse-if shape turns an arithmetic error into permission.

**What this does NOT cover, stated because the obvious summary is wider than the
rule.** It closes pinning backward on a SAME-REPO pull request, and nothing
else.

- Not forks, and on forks the rule costs something rather than merely doing
  nothing. A fork's `pull_request` run uses the BASE repository's workflow file,
  so a fork author never writes the `version:` that judges them and there is no
  hole there to close. But `GITHUB_BASE_REF` IS set on a fork pull request, so
  the check fires anyway and judges the base repository's own trusted workflow
  file. Once a newer scanner ships, a maintainer's deliberate backward pin in
  that base workflow fails EVERY fork pull-request run: a pure false refusal, on
  a pin nobody untrusted wrote. The remedy is the same as for any consumer,
  which is to remove the `version:` input.
- Not a pull request that deletes the step, moves the `uses:` pin to an older
  action tag, or edits the job away. Those are workflow-file edits, and the
  control is branch protection with required review on `.github/workflows/**`.
  Nothing in `action.yml` can substitute for it.
- Not push events. The rule fires exactly where `GITHUB_BASE_REF` is set, which
  is `pull_request` and `pull_request_target`; push runs are out of scope and
  the flag floor remains their only version gate. Read that as scope, not as
  safety: a push to an UNPROTECTED feature branch runs that branch's own
  workflow file, written by the same author, with `GITHUB_BASE_REF` empty, so it
  is as author-controlled as a pull request and the rule does not cover it.
- It costs consumers nothing today, because the tag scanner equals the only
  published version. It starts costing something the first time two versions
  exist.

**Enforced by:** the `pinning the scanner backward on a pull request` cases in
`action-path-validation.test.ts`. Because the two floors are the same number
today, no real input lands between them, so the behavioural cases drive the real
step text with the tag-scanner constant advanced one minor version — the action
as it will be the day a 1.8.0 scanner ships — and assert the replacement matched,
so deleting the constant turns them red. Plus a drift case tying
`VG_TAG_SCANNER_*`, the `version` input's default and
`packages/cli/package.json` to one number, a case proving the flag floor answers
first for a version below BOTH, and the bash 3.2 mirror in
`scripts/test-action-path-validation.sh`, which also asserts every constant it
hand-copied still equals the one in `action.yml`.

## The Action tag and the scanner version are two numbers, and both get bumped

1.7.1 is the first release where they came apart: the tag moved, the four npm
packages stayed at 1.7.0. They are allowed to differ, and an action-only release
is the normal reason — publishing an identical scanner purely to keep two
strings matching burns a version through a one-way trusted-publisher path. What
is not allowed is a document telling a reader to pin one number while an example
next to it pins the other.

**The rule: when either number moves, grep for BOTH.** The places that carry one
or the other, as of 1.7.1:

- `action.yml`, the `version` input's `default:` — the SCANNER version
- `action.yml`, `VG_TAG_SCANNER_MAJOR/MINOR/PATCH` — the SCANNER version again,
  as the constant the pull-request rule above compares against. It moves with
  the published packages, unlike `VG_MIN_*` next to it, which moves only when
  this tag starts passing a newer flag
- `scripts/test-action-path-validation.sh`, `TAG_SCANNER_*` and `MIN_*` — the
  bash 3.2 hand copy of both, which that script now checks against `action.yml`
  rather than trusting
- `action.yml`, the `version` input's description, which names an example
- `packages/*/package.json` (four packages) — the scanner version
- `docs/GITHUB_ACTION.md`, the inputs table's `version` default — the scanner
- `README.md`, the `uses: vaultcompasshq/vault-guard@vX.Y.Z` example — the TAG
- `README.md`, the prose about which scanner a tag installs — both numbers
- `docs/GITHUB_ACTION.md`, every `uses:` example — the tag
- `packages/cli/src/init/templates.ts`, `ACTION_TAG` — the tag that
  `vault-guard init` scaffolds into a generated workflow
- `CHANGELOG.md`, the release heading and any migration line naming a tag
- `bench/action-install.cjs`, `PRE_FIX_REF` — the tag the negative control reads
  its vulnerable `action.yml` out of, which must stay the release BEFORE the fix
- `packages/cli/src/init/templates.ts`, `UPLOAD_SARIF_SHA` and
  `.github/workflows/ci.yml`'s `upload-sarif@` pin — one decision about which
  third-party commit this project trusts, spelled in two files: the scaffold
  hands it to every consumer's repository, where it runs with that repository's
  `security-events: write`. `init.test.ts` reads the workflow and asserts the
  constant matches, so bumping one and not the other goes red rather than
  shipping a consumer a commit nobody here chose
- `bench/baseline.action-install.json`, `scannerVersion` and the case ids —
  the recorded run embeds both numbers, so a scanner bump or a new `PRE_FIX_REF`
  makes the baseline stale and `--compare` says so rather than a human noticing

The init template's pin used to be `v${readCliVersion()}`, derived from the CLI
package version. An action-only release is exactly where that breaks: it would
have scaffolded `@v1.7.0`, the pre-fix Action, into every repository
initialised after the release. It is a constant now.

**Enforced by:** `init.test.ts`, which asserts three things about that constant:
the generated workflow pins it rather than anything derived from the package
version; it is not BEHIND the package version by semver ordering (equal is legal
— a package release moves both numbers together); and it equals `v` plus the
newest `## [X.Y.Z]` heading in `CHANGELOG.md`, which is what catches a second
action-only release that moved the tag and the changelog and forgot the
scaffold. Plus the `defaults to the scanner version this repository publishes`
case in `action-path-validation.test.ts`, which ties the `version` input's
default to `packages/cli/package.json`. The rest of the list is a grep, not a
gate.

## Testing the Action derives every step's environment and cwd from action.yml

A harness with its own table of environment variables, or its own idea of a
step's working directory, asserts a property of the harness. The two lines that
carry the whole install boundary are "which directory is npm started in" and
"which prefix does it install under", and a harness that supplies those cannot
see them go missing.

The jest suites, `bench/action-install.cjs` and the shell script's own per-step
checks (through `scripts/extract-action-step.cjs`) all read the step script, the
step's `env:` mapping and its `working-directory:` out of `action.yml` through
one shared parser, `scripts/lib/action-steps.cjs`. A second copy of that parser
would drift, and the drift would be invisible: every caller would keep passing,
each against its own idea of what the file says.

That extends to values a harness might be tempted to know for itself. The
dogfood harness reads the install PREFIX out of the install step's `env:`
mapping rather than rebuilding `<runner temp>/vault-guard-action`: hardcoded,
the record would go on reporting an install under the runner prefix even after
`action.yml` moved it into the workspace, which is the one claim that record
exists to carry.

`VG_ACTION_FILE` points both suites at a mutated copy, so any of this can be
made to fail on demand. Both files honour it; one of them not honouring it would
produce a green run against a weakened file. Verified in this change by deleting
the install step from a copy of `action.yml` (8 tests red) and by removing
`working-directory` from the run step (2 tests red).

## action.yml must parse and behave on bash 3.2

macOS ships bash 3.2, and GitHub's macOS runners do too. Two bug classes here are
invisible from Linux, where the broken spelling works:

- a `=~` pattern with `{1,256}` fails to COMPILE on the BSD regex engine
  (`RE_DUP_MAX` is 255), and a pattern that fails to compile does not match, so
  every path input including the default `.` was rejected;
- `${x,,}` and `${x^^}` are bash 4.0 case expansions and are a SYNTAX ERROR on
  3.2, so a step using one fails to parse entirely. The `.github/` comparison
  needs case folding precisely because macOS filesystems are case-insensitive,
  which is what makes this the likeliest place to reach for one. `tr` instead.

**Enforced by:** `scripts/test-action-path-validation.sh`, which the
`action-path-validation` CI job runs on `macos-latest` as well as
`ubuntu-latest`. It extracts each step's run script through
`scripts/extract-action-step.cjs` and runs `"${BASH}" -n` over it, so on the
macOS runner the whole file is parsed by the bash version the claim is about.

`"${BASH}"`, never a bare `bash`. A bare name is a PATH lookup, and on a machine
with Homebrew bash ahead of `/bin` the check ran under bash 5 while the script
itself ran under 3.2 — the one guard against bash 4 syntax performed by a bash
that accepts it. A review demonstrated it with a `;&` case fallthrough, which is
legal in 4.0, a syntax error in 3.2, and passed the gate. That is
the enforcement; the textual guards against `${x,,}` and `${x^^}` here and in
`action-path-validation.test.ts` are a faster, narrower net that only ever
catches the idioms already on the list, and they name the bug when they fire.
