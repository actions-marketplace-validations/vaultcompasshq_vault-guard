#!/usr/bin/env bash
# Self-test for action.yml input validation, run on BOTH ubuntu and macOS.
#
# The reason it runs on two platforms: macOS ships bash 3.2, and the two bugs
# this file exists for are both invisible from Linux. A `=~` pattern with
# `{1,256}` fails to COMPILE on the BSD regex engine (RE_DUP_MAX=255), so every
# path including the default `.` was rejected while ubuntu CI stayed green. A
# `${x,,}` case expansion is a bash 4.0 feature and a SYNTAX ERROR on 3.2, so
# the whole step would fail to parse. Keep every idiom here portable.
#
# The jest suites under packages/cli/src/__tests__/action/ run the REAL step
# scripts out of action.yml with npm stubbed, and bench/action-install.cjs runs
# them against real npm. This file is the portability gate and the grep guards.
set -euo pipefail

# Anchored to this script rather than to the caller's cwd. The grep guards
# below check the real action.yml, and a run from anywhere else used to check
# whatever action.yml happened to sit in the current directory, which is a
# guard that passes without having looked at the file it names.
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION_YML="$(cd "${SCRIPTS_DIR}/.." && pwd)/action.yml"

INSTALL_STEP="Install vault-guard outside the workspace"
RUN_STEP="Run vault-guard"

# For the `bash -n` syntax checks below. Removed on exit, including on the
# `exit 1` paths, so a failed run does not leave a directory behind.
SYNTAX_DIR="$(mktemp -d)"
trap 'rm -rf "${SYNTAX_DIR}"' EXIT

# node reads action.yml through the same parser the jest suites and the dogfood
# harness use. Every GitHub-hosted runner image ships node, so a missing one is
# a broken environment rather than a reason to quietly skip the strongest checks
# in this file.
if ! command -v node >/dev/null 2>&1; then
  printf 'node is required: this script asks action.yml about its own steps rather than grepping for them\n' >&2
  exit 1
fi

validate_path() {
  local value="$1"
  if [[ ! "${value}" =~ ^[A-Za-z0-9._/-]+$ ]] || (( ${#value} > 256 )); then
    return 1
  fi
  if [[ "${value}" == *".."* ]]; then
    return 1
  fi
  if [[ "${value}" == /* ]]; then
    return 1
  fi
  if [[ "${value}" == -* ]]; then
    return 1
  fi
  return 0
}

assert_ok() {
  local value="$1"
  if ! validate_path "${value}"; then
    printf 'expected OK for %q\n' "${value}" >&2
    exit 1
  fi
}

assert_bad() {
  local value="$1"
  if validate_path "${value}"; then
    printf 'expected reject for %q\n' "${value}" >&2
    exit 1
  fi
}

# The failing consumer default that dogfooded the bug.
assert_ok "."
assert_ok "./src"
assert_ok "vault-guard-results.sarif"
assert_ok "$(printf 'a%.0s' {1..256})"

assert_bad ""
assert_bad ".."
assert_bad "../etc"
assert_bad "/etc/passwd"
assert_bad "has space"
assert_bad "semi;colon"
assert_bad "-rf"
assert_bad "$(printf 'a%.0s' {1..257})"

# Guard: the old pattern must not be reintroduced. On macOS it fails to
# compile; on Linux it "works" and would hide the regression from ubuntu CI.
if grep -nE '\[A-Za-z0-9\._/-\]\{1,256\}' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml still contains {1,256} path regex (breaks macOS RE_DUP_MAX)\n' >&2
  exit 1
fi

# Guard: no bash 4 only syntax anywhere outside a comment. `${x,,}` and
# `${x^^}` parse on the ubuntu runner and are a syntax error on this one, which
# is the same asymmetry as the regex above. Comments are skipped because the
# comment at normalise_path names `${x,,}` to explain why it is not used.
if grep -vE '^[[:space:]]*#' "${ACTION_YML}" | grep -nE '\$\{[A-Za-z_][A-Za-z0-9_]*(,,|\^\^)\}' >/dev/null; then
  printf 'action.yml uses a bash 4 case expansion; macOS runners ship bash 3.2\n' >&2
  exit 1
fi

# --- version ----------------------------------------------------------------
#
# EXACT VERSIONS ONLY. A dist-tag hands the choice of scanner to the registry on
# the morning of the run, and a value npm reads as a PATH rather than a version
# (`.`, `..`, anything ending in `.tgz`) was, on a step that ran from inside the
# checkout, one committed file away from the tree choosing its own scanner.

# The floor below is the second half of the contract: shape is not capability.
# The action passes `--trust-base` on pull-request runs, that flag arrived in
# scanner 1.7.0, and an older scanner answers an unknown option with exit 1,
# which is also its findings code. Kept in step with the `VG_MIN_*` values in
# action.yml.
#
# This IS a hand-copied check rather than the real step, deliberately, so it can
# run on the macOS runner's bash 3.2 where the jest harness does not reach. That
# copy is also the hazard: it sat green while asserting the OPPOSITE of the
# shipped action for `0.0.0` until the floor was mirrored here.
MIN_MAJOR=1
MIN_MINOR=7
MIN_PATCH=0

validate_version() {
  local value="$1"
  if [[ ! "${value}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    return 1
  fi
  local major="${BASH_REMATCH[1]}"
  local minor="${BASH_REMATCH[2]}"
  local patch="${BASH_REMATCH[3]}"
  # Component by component, never textual: `1.10.0` sorts below `1.7.0` as a
  # string and above it as a version.
  if (( major < MIN_MAJOR )); then
    return 1
  elif (( major == MIN_MAJOR )); then
    if (( minor < MIN_MINOR )); then
      return 1
    elif (( minor == MIN_MINOR )) && (( patch < MIN_PATCH )); then
      return 1
    fi
  fi
  return 0
}

assert_version_ok() {
  if ! validate_version "$1"; then
    printf 'expected OK for version %q\n' "$1" >&2
    exit 1
  fi
}

assert_version_bad() {
  if validate_version "$1"; then
    printf 'expected reject for version %q\n' "$1" >&2
    exit 1
  fi
}

assert_version_ok "1.7.0"
assert_version_ok "10.20.30"
# `1.10.0` is the one a textual comparison gets wrong, and this is the only
# place the floor is exercised on bash 3.2.
assert_version_ok "1.10.0"
assert_version_ok "1.7.1"
assert_version_ok "2.0.0"

# Below the floor. `0.0.0` USED to be asserted OK here, and stayed green after
# the action started refusing it, because this check is a copy rather than the
# step itself.
assert_version_bad "0.0.0"
assert_version_bad "1.6.9"
assert_version_bad "1.6.0"
assert_version_bad "0.9.9"

assert_version_bad ""
assert_version_bad "latest"
assert_version_bad "next"
assert_version_bad "beta"
assert_version_bad "1.7"
assert_version_bad "^1.7.0"
assert_version_bad "1.7.0-rc.1"
assert_version_bad "."
assert_version_bad ".."
assert_version_bad "payload.tgz"
assert_version_bad "-1.7.0"
# Not semver, so npm does not read it as a version at all and falls back to
# treating the spec as a dist-tag: the family this check exists to refuse.
assert_version_bad "01.7.0"
assert_version_bad "1.7.00"

# --- pinning the scanner backward on a pull request --------------------------
#
# THE THIRD half of the contract, and a different rule from the floor above. On
# a same-repo `pull_request` event GitHub runs the workflow file from the HEAD,
# so `version:` is written by the pull request being judged. The floor admits
# anything at or above 1.7.0, so the day a newer scanner ships with new rules, a
# pull request can pin back to an older one, clear the floor, and be judged by
# the rules it chose. On that one event the action refuses a version BELOW the
# scanner the tag ships. Forward stays allowed: a newer scanner is not a weaker
# one.
#
# TAG_SCANNER is a SEPARATE constant from MIN_* on purpose, in this file as in
# action.yml. Same number today, different meanings: MIN_* is flag
# compatibility, TAG_SCANNER is the tested scanner this tag ships.
TAG_SCANNER_MAJOR=1
TAG_SCANNER_MINOR=7
TAG_SCANNER_PATCH=0

# Guard: every constant copied into this file still equals the one in
# action.yml. This is the direct answer to the hazard named above -- a copy that
# drifts asserts the opposite of the shipped action and stays green while it does
# it, which has already happened here once.
assert_action_constant() {
  local name="$1"
  local expected="$2"
  local found
  found="$(grep -oE "^[[:space:]]*${name}=[0-9]+" "${ACTION_YML}" | head -n 1 | grep -oE '[0-9]+$' || true)"
  if [[ "${found}" != "${expected}" ]]; then
    printf 'action.yml has %s=%s and this file has %s; the hand copy has drifted\n' \
      "${name}" "${found:-<missing>}" "${expected}" >&2
    exit 1
  fi
}

assert_action_constant "VG_MIN_MAJOR" "${MIN_MAJOR}"
assert_action_constant "VG_MIN_MINOR" "${MIN_MINOR}"
assert_action_constant "VG_MIN_PATCH" "${MIN_PATCH}"
assert_action_constant "VG_TAG_SCANNER_MAJOR" "${TAG_SCANNER_MAJOR}"
assert_action_constant "VG_TAG_SCANNER_MINOR" "${TAG_SCANNER_MINOR}"
assert_action_constant "VG_TAG_SCANNER_PATCH" "${TAG_SCANNER_PATCH}"

# Takes the floor as arguments rather than reading a constant, so the cases
# below can exercise the comparison against a HYPOTHETICAL future tag scanner.
# Today the two floors are the same number and no real input lands between them,
# so a test that only used TAG_SCANNER could not show the rule doing anything.
#
# Accept-only-if, like the action: `[` returns 2 on a malformed comparison and
# an `if` reads 2 as false, so a refuse-if shape turns an arithmetic error into
# permission.
version_at_least() {
  local value="$1"
  local want_major="$2"
  local want_minor="$3"
  local want_patch="$4"
  if [[ ! "${value}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    return 1
  fi
  local major="${BASH_REMATCH[1]}"
  local minor="${BASH_REMATCH[2]}"
  local patch="${BASH_REMATCH[3]}"
  local ok=0
  if (( major > want_major )); then
    ok=1
  elif (( major == want_major )); then
    if (( minor > want_minor )); then
      ok=1
    elif (( minor == want_minor )) && (( patch >= want_patch )); then
      ok=1
    fi
  fi
  (( ok == 1 ))
}

# What the action does on a pull-request event: the flag floor first, then this.
validate_version_pull_request() {
  if ! validate_version "$1"; then
    return 1
  fi
  version_at_least "$1" "${TAG_SCANNER_MAJOR}" "${TAG_SCANNER_MINOR}" "${TAG_SCANNER_PATCH}"
}

assert_pr_version_ok() {
  if ! validate_version_pull_request "$1"; then
    printf 'expected OK on a pull request for version %q\n' "$1" >&2
    exit 1
  fi
}

assert_pr_version_bad() {
  if validate_version_pull_request "$1"; then
    printf 'expected reject on a pull request for version %q\n' "$1" >&2
    exit 1
  fi
}

# Forward, and the scanner the tag ships. `1.10.0` is again the case a textual
# comparison gets wrong, and here it would refuse the one direction this rule
# deliberately leaves open.
assert_pr_version_ok "1.7.0"
assert_pr_version_ok "1.7.1"
assert_pr_version_ok "1.8.0"
assert_pr_version_ok "1.10.0"
assert_pr_version_ok "2.0.0"
assert_pr_version_ok "10.20.30"

# Backward, and the shapes the first check already refuses.
assert_pr_version_bad "1.6.9"
assert_pr_version_bad "1.6.0"
assert_pr_version_bad "0.9.9"
assert_pr_version_bad "latest"
assert_pr_version_bad ""

# The rule with a FUTURE tag scanner, which is the only way to see it act today:
# with a 1.8.0 scanner shipped, `1.7.0` still clears the flag floor -- so a push
# takes it -- and is refused on a pull request.
assert_version_ok "1.7.0"
if version_at_least "1.7.0" 1 8 0; then
  printf 'a version below a 1.8.0 tag scanner was accepted on a pull request\n' >&2
  exit 1
fi
if ! version_at_least "1.8.0" 1 8 0; then
  printf 'the tag scanner itself was refused on a pull request\n' >&2
  exit 1
fi
if ! version_at_least "1.10.0" 1 8 0; then
  printf 'a pull-request pin ahead of the tag scanner was refused; the comparison is textual\n' >&2
  exit 1
fi

# Guard: the action gates this on GITHUB_BASE_REF, which is the same event test
# the run step uses for `--trust-base`. A rule that fired on every event would
# break push builds that pin an older scanner on purpose.
if ! grep -n 'n "${GITHUB_BASE_REF:-}"' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer tests for a pull-request event with GITHUB_BASE_REF\n' >&2
  exit 1
fi

# Guard: accept-only-if, not refuse-if. The flag has to start at 0 so an
# arithmetic error refuses rather than permits.
if ! grep -n 'VG_PR_SCANNER_OK=0' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer starts the pull-request scanner check closed\n' >&2
  exit 1
fi

# Guard: the refusal message has to carry the migration, because `latest` used
# to be the default and every workflow that spelled it out has to change.
if ! grep -n 'REMOVE the input' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer tells a workflow pinned to `latest` what to do instead\n' >&2
  exit 1
fi

# --- where the scanner comes from -------------------------------------------
#
# The vulnerability this replaced: `npx --yes "@vaultcompass/vault-guard@..."`
# run with the checkout as its working directory. A committed `.npmrc` repoints
# the registry npx fetches from, and a copy already in the head's node_modules
# wins outright with the version pin degraded to a satisfaction check on a
# package the head wrote.

# Guard: npx must not come back, as an invocation. Matched at the start of a
# line rather than as the word, because the comments necessarily name npx to
# say why it is gone.
if grep -nE '^[[:space:]]*npx\b' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml runs npx again; the scanner must be installed outside the checkout\n' >&2
  exit 1
fi

# Guard: the install step, its global install, and its prefix under the runner
# temp. All three: an install step that installed into the workspace would
# satisfy a check for the step alone.
if ! grep -n 'name: Install vault-guard outside the workspace' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml has no install step; the scanner would come from inside the tree it scans\n' >&2
  exit 1
fi
if ! grep -n 'npm install -g --ignore-scripts "@vaultcompass/vault-guard@\${VG_VERSION}"' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer installs the pinned scanner globally with --ignore-scripts\n' >&2
  exit 1
fi
# The install runs on a runner holding the job's token, so no install in this
# file may omit --ignore-scripts, and what arrives has to be verified before it
# is trusted to render a verdict. Both are checked here as well as in the jest
# suites because those run against a STUBBED npm: they prove the action asks,
# and this proves the ask is still written down.
if grep -nE '^[[:space:]]*npm install' "${ACTION_YML}" | grep -v -- '--ignore-scripts' >/dev/null; then
  printf 'action.yml has an npm install without --ignore-scripts; the scanner is a control input and this step holds the job token\n' >&2
  exit 1
fi
if ! grep -n 'npm audit signatures' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer verifies the provenance of what it installed\n' >&2
  exit 1
fi
if ! grep -nE 'npm_config_prefix: \$\{\{ runner\.temp \}\}/vault-guard-action' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer installs under a prefix in the runner temp\n' >&2
  exit 1
fi

# Guard: BOTH shell steps start outside the checkout. A composite step with no
# working-directory runs at the workspace root, which is the head's own tree, so
# npm would start with the pull request's .npmrc, manifest and lockfile under
# its cwd.
#
# Asked of each STEP BY NAME, through the same parser the jest suites and the
# dogfood harness use, rather than by counting occurrences in the file. A count
# of exactly two is a guard that goes red the day somebody gives the validate
# step a working-directory, which is a harmless change, and it cannot say WHICH
# steps the two belong to, which is the only thing it was ever asked.
assert_step_workdir() {
  local step="$1"
  local declared
  if ! declared="$(node "${SCRIPTS_DIR}/extract-action-step.cjs" "${ACTION_YML}" "${step}" working-directory)"; then
    printf 'action.yml has no step named %s\n' "${step}" >&2
    exit 1
  fi
  if [[ "${declared}" != '${{ runner.temp }}' ]]; then
    printf 'step %s must declare working-directory: ${{ runner.temp }}, found %q\n' "${step}" "${declared}" >&2
    exit 1
  fi
}

assert_step_workdir "${INSTALL_STEP}"
assert_step_workdir "${RUN_STEP}"

# Guard: every step script PARSES under the bash running this file.
#
# This is what makes the bash 3.2 claim real. The grep above catches the two
# bash 4 idioms somebody is most likely to reach for, and a grep can only ever
# catch the ones already on the list; `bash -n` catches whatever is actually
# there. On a macOS runner the bash running this file is 3.2, which is the
# version the claim is about, so this check is worth most exactly where the
# behavioural suites do not run.
#
# "${BASH}" -n, NEVER a bare `bash -n`. A bare name is a PATH lookup, and a
# machine with Homebrew bash ahead of /bin on PATH parses the file with bash 5
# while this script itself runs under 3.2 -- so the one check that exists to
# catch bash 4 syntax is performed by a bash that accepts it. A review proved
# that with a `;&` case fallthrough: legal in 4.0, a syntax error in 3.2, and
# the gate passed under /bin/bash. ${BASH} is the interpreter running this
# script, so the parse and the claim are about the same program, and the failure
# message prints that interpreter's own version rather than some other one's.
assert_step_parses() {
  local step="$1"
  local script="${SYNTAX_DIR}/step.sh"
  if ! node "${SCRIPTS_DIR}/extract-action-step.cjs" "${ACTION_YML}" "${step}" run > "${script}"; then
    printf 'action.yml has no step named %s\n' "${step}" >&2
    exit 1
  fi
  if ! "${BASH}" -n "${script}"; then
    printf 'the run script of step %s does not parse under %s (bash %s)\n' "${step}" "${BASH}" "${BASH_VERSION}" >&2
    exit 1
  fi
}

assert_step_parses "Validate inputs"
assert_step_parses "${INSTALL_STEP}"
assert_step_parses "${RUN_STEP}"

# Guard: the scanner is called by ABSOLUTE path. A bare name would be resolved
# against PATH, and a workflow that put the checkout's node_modules/.bin on PATH
# would hand the head's copy back the resolution the install step took away.
if ! grep -nE 'VG_BIN: \$\{\{ runner\.temp \}\}/vault-guard-action/bin/vault-guard' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer calls the installed scanner by absolute path\n' >&2
  exit 1
fi

# Guard: the scan path must be absolute too, and the two halves are
# inseparable. The step starts in the runner temp, so a relative `.` would
# resolve against the wrong directory entirely.
#
# And RESOLVED, with `pwd -P`. vault-guard resolves the pull-request file set
# against its own process cwd, which node reports with symlinks resolved, while
# bash `cd` keeps the logical path: a logical target against a resolved cwd puts
# every file in the head tree outside the scan target, and the run scans zero
# files and reports a clean result over nothing. Silent on a Linux runner, whose
# workspace path is canonical already, which is why it is pinned here rather
# than left to a behavioural test on ubuntu.
if ! grep -n 'SCAN_ROOT="$(cd "${ROOT}/${VG_PATH}" && pwd -P)"' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer builds an absolute, resolved scan root from GITHUB_WORKSPACE\n' >&2
  exit 1
fi

# Guard: and the resolved scan root has to still be inside the checkout, which
# the string rules cannot decide. The head controls the directories its path
# names point at, so a committed symlink is a second name for somewhere else.
if ! grep -n 'resolves outside the workspace, through a symlink' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer checks that the resolved scan root is inside the workspace\n' >&2
  exit 1
fi

# Guard: no bare `--` before `scan`. That separator is forwarded into
# vault-guard argv; Commander then ignores `--format` and the action writes text
# banners into the SARIF file.
if grep -nE 'VG_BIN[^\n]*--[[:space:]]+scan' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml passes a bare `--` before `scan` (breaks --format / SARIF upload)\n' >&2
  exit 1
fi

# --- sarif-output -----------------------------------------------------------

# Guard: the output path may not land under .github/, which holds the workflow
# file and the CODEOWNERS entry that decide how this gate runs.
if ! grep -n 'must not write under .github/' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer refuses a sarif-output under .github/\n' >&2
  exit 1
fi

# Guard: and may not resolve through a symlink, checked BEFORE the containing
# directories are created rather than after.
if ! grep -n 'resolves through a symlink' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer refuses a sarif-output that resolves through a symlink\n' >&2
  exit 1
fi
symlink_line="$(grep -n -- '-L "${CURSOR}"' "${ACTION_YML}" | head -1 | cut -d: -f1)"
mkdir_line="$(grep -n 'mkdir -p "$(dirname "${OUT}")"' "${ACTION_YML}" | head -1 | cut -d: -f1)"
if [[ -z "${symlink_line}" || -z "${mkdir_line}" || "${symlink_line}" -gt "${mkdir_line}" ]]; then
  printf 'the symlink guard must run before mkdir -p, or a refused run has already created directories through the link\n' >&2
  exit 1
fi

# --- trust-base -------------------------------------------------------------
#
# Same checks as the path ones above, for the same reason: the value reaches a
# command line, and this file is where a regression in it gets noticed on both
# Linux and macOS bash.

validate_trust_base() {
  local value="$1"
  # `off` is refused BY NAME rather than falling through to the ref charset,
  # which it would otherwise pass and be used as a branch called "off". It was
  # accepted before 1.7.0 shipped and was removed because a same-repo
  # pull_request event runs the workflow file from the pull request head, so an
  # off switch here sits on the untrusted side of the boundary it turns off.
  # Matched in any capitalisation: a value refused as `off` and accepted as
  # `Off` is an opt-out with a shift key in front of it.
  case "${value}" in
    [Oo][Ff][Ff]) return 1 ;;
  esac
  if [[ "${value}" == "auto" ]]; then
    return 0
  fi
  if [[ ! "${value}" =~ ^[A-Za-z0-9._/@^~-]+$ ]] || (( ${#value} > 200 )); then
    return 1
  fi
  if [[ "${value}" == -* ]]; then
    return 1
  fi
  return 0
}

assert_trust_ok() {
  if ! validate_trust_base "$1"; then
    printf 'expected OK for trust-base %q\n' "$1" >&2
    exit 1
  fi
}

assert_trust_bad() {
  if validate_trust_base "$1"; then
    printf 'expected reject for trust-base %q\n' "$1" >&2
    exit 1
  fi
}

assert_trust_ok "auto"
assert_trust_ok "origin/main"
assert_trust_ok "HEAD~1"
assert_trust_ok "v1.2.3^"

assert_trust_bad ""
assert_trust_bad "off"
assert_trust_bad "Off"
assert_trust_bad "OFF"
assert_trust_bad "-rf"
assert_trust_bad 'HEAD^{commit}'
assert_trust_bad 'origin/$(id)'
assert_trust_bad 'origin/main; rm -rf /'
assert_trust_bad 'origin/`id`'
assert_trust_bad "$(printf 'a%.0s' {1..201})"

# Guard: `trust-base: off` must be refused by name, with an error that says it
# was removed. Base-ref judging is the floor and not a knob: on a same-repo
# pull_request event the workflow file runs from the pull request head, so any
# off switch here is settable by the pull request it is meant to judge. Without
# this guard `off` reads as an ordinary ref, passes the charset check, and the
# scan fails later with a confusing "does not resolve to a commit".
if ! grep -n 'trust-base: off` was removed' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer refuses `trust-base: off` by name with a removal message\n' >&2
  exit 1
fi

# Guard: and no other message may offer `off` back. The charset refusal went on
# printing "Allowed: auto | off | ..." after the value was removed, so a typo
# was told to use the one value refused by name two checks earlier.
if grep -nE 'auto \| off' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml still offers `off` as an allowed trust-base value in an error message\n' >&2
  exit 1
fi

# Guard: and the argv builder must not carry a branch for it either, which is
# where the switch actually lived.
if grep -nE '"\$\{VG_TRUST_BASE\}" != "off"' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml still treats `off` as a trust-base keyword in the argv builder\n' >&2
  exit 1
fi

# Guard: the ref must reach the scanner as a bash ARRAY element, so a branch
# name with a space stays one argv entry. A string built with
# `TRUST_ARGS="--trust-base ${ref}"` would word-split at the first space.
if ! grep -nE 'TRUST_ARGS=\(' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer builds the trust-base args as an array\n' >&2
  exit 1
fi

# Guard: `set -u` plus bash 3.2 (macOS runners) aborts on a bare empty-array
# expansion, so the `+` form is required rather than stylistic. Checked on the
# invocation line itself, not anywhere in the file: an earlier version of this
# guard grepped the whole document and was satisfied by the COMMENT explaining
# the idiom, which is a guard that passes whatever the code says.
scan_line="$(grep '"${VG_BIN}" "${ARGS\[@\]}"' "${ACTION_YML}" || true)"
if [[ -z "${scan_line}" ]]; then
  printf 'action.yml no longer invokes the installed scanner with its argv array\n' >&2
  exit 1
fi
if [[ "${scan_line}" != *'TRUST_ARGS[@]+'* ]]; then
  printf 'the scan line expands TRUST_ARGS without the ${a[@]+...} guard (breaks bash 3.2 + set -u)\n' >&2
  exit 1
fi

# Guard: the base ref must never be interpolated into a run body as a GitHub
# expression. That substitution happens before the shell parses the script, so
# no amount of quoting downstream helps.
if grep -nE '\$\{\{[^}]*base_ref' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml interpolates base_ref into a run body (command injection)\n' >&2
  exit 1
fi

# Names the interpreter, not just the version: the whole point of the syntax
# check above is which bash did the parsing, so the green line has to say.
printf 'action path validation OK (%s, %s, bash %s)\n' "$(uname -s)" "${BASH}" "${BASH_VERSION}"
