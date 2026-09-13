# Vault Guard Benchmark

Precision / recall / F1 harness for the `vault-guard` secret scanner, measured against a labeled fixture corpus.

Two harnesses live in this directory and they measure different things.
`bench/run.cjs` is the detection benchmark described below. `bench/action-install.cjs`
is the Action's install-boundary dogfood harness, described at the end of this
file: it measures whether the tree being scanned can choose the program that
scans it, which is a security property rather than a precision one.

## Read this before quoting a number

**This is a regression suite, not a generalization benchmark.** Nearly every
fixture under `fixtures/clean/` was added in reaction to a specific false
positive that was then fixed. A perfect score therefore means "no known bug
came back" and says nothing about accuracy on code the scanner has never seen.

Two consequences, both learned the hard way in the 1.4.0 audit:

1. **Do not publish the score as a headline accuracy metric.** Scanning real
   third-party repositories found both a missing-coverage class and two
   false-positive classes while this corpus read 100% / Grade A.
2. **Do not read the `--gitleaks` comparison as a fair head-to-head.** The
   corpus is chosen to exercise Vault Guard's rules and suppressions, which is
   home-field advantage and systematically understates any other tool. (Before
   1.4.0 the harness also passed `--report-format json` with no
   `--report-path`, so gitleaks' findings were never parsed at all and it was
   scored at a flat 0% recall. That was a harness bug, not a result.)

The right use of this harness is a CI gate against regressions
(`node bench/run.cjs --assert`), plus a place to park every real-world false
positive you find so it can never come back.

## Run

```bash
# Build first so the harness uses the local binary
pnpm build

# Basic run (Vault Guard only)
node bench/run.cjs

# Verbose: show per-file TP/FP/FN/TN
node bench/run.cjs --verbose

# CI gate: exit non-zero if precision/recall fall below floors
node bench/run.cjs --assert
node bench/run.cjs --assert --min-precision 1.0 --min-recall 0.95

# Side-by-side with Gitleaks (must be installed: brew install gitleaks)
node bench/run.cjs --gitleaks --verbose
```

Or via the monorepo root:

```bash
pnpm bench
```

## Fixture corpus

| Directory | Purpose |
|---|---|
| `fixtures/secrets/` | Files that **should** trigger at least one finding (TP candidates); **gitignored, generated at runtime** |
| `fixtures/clean/` | Files that **should not** trigger any findings (FP candidates); committed |

`fixtures/secrets/` is gitignored because committing contiguous secret-shaped strings (even synthetic ones) is blocked by GitHub push protection and vault-guard's own pre-commit hook. Instead, `generate-fixtures.cjs` stores each secret as joined string fragments and writes the files at runtime. `run.cjs` calls the generator automatically before scanning.

Each fixture is registered in `labels.json` with `shouldDetect: true/false` and a short note.

## Metrics

| Metric | Formula |
|---|---|
| Precision | TP / (TP + FP); "when it flags, is it right?" |
| Recall | TP / (TP + FN); "does it catch all the real ones?" |
| F1 | 2 × P × R / (P + R); harmonic mean |

**Grades:** A ≥ 90% F1 + Precision · B ≥ 80% · C ≥ 70% · D ≥ 55% · F < 55%

The grade is an internal health signal for this corpus only. It is not a
product claim, and it does not belong in the README, release notes, or any
comparison table.

## Adding fixtures

**TP fixtures (must trigger):** add an entry to `generate-fixtures.cjs`; store the value as joined fragments (`['sk_live_', 'AbCd…'].join('')`) then add the file to `labels.json`.

**FP fixtures (must not trigger):** create the file under `fixtures/clean/`, then add to `labels.json`:

```json
"fixtures/clean/my-fixture.ts": { "shouldDetect": false, "note": "Why this should stay clean" }
```

## Notes

- The harness measures **file-level** detection (did any finding occur in a file expected to contain a secret?), not individual-finding accuracy. This matches the primary user-facing guarantee: "no secrets slip through undetected."
- **This harness cannot express "downgraded, not suppressed."** It counts a
  file as detected when any finding occurs, **at any severity**. A false
  positive fixed by a severity *downgrade* therefore still reads as a
  detection, so it can never be a `clean/` fixture and the corpus has no way to
  tell a `critical` from a `low`. Adding a `maxSeverity` label to
  `labels.json`, asserted next to `rule`, is the way to close this; it is
  deferred on cost, not on principle. One wrinkle to handle when it lands:
  every path under `bench/` contains the segment `fixtures`, which the
  path-aware downgrade already matches, so a `maxSeverity` assertion here would
  pass on the path rule alone and would not isolate a content-based downgrade.
  That part is a layout convention rather than anything structural, and staging
  fixtures under a neutral directory before scanning would settle it. Until
  then, downgrade fixes (the Rust `*_tests.rs` and inline `#[cfg(test)]`
  classes added in 1.4.7, and `caddytest/key.pem` before them) are parked here
  as TP fixtures that guard against the downgrade silently becoming a
  suppression, and the behaviour itself is covered by unit tests in
  `packages/core`. Suppression fixes (the 1.4.7 sequential-run class) are
  guarded properly, as `clean/` fixtures, because suppression is
  path-independent.
- `fixtures/clean/test-passwords.ts` is a `.ts` file in a non-test path to stress the generic `password-in-code` pattern. The path-aware severity downgrade applies only to files inside `__tests__/`, `tests/`, `fixtures/`, etc.), not this benchmark's `clean/` directory. If this file triggers, that is a FP the scanner needs to address.

---

# The Action install-boundary harness (`bench/action-install.cjs`)

```bash
pnpm build
pnpm bench:action-install                     # compare against the baseline
pnpm bench:action-install:update-baseline     # re-record it
node bench/action-install.cjs --json --keep   # the full record, work dirs kept
```

**What it measures.** The Action's own install and run steps, extracted from
`action.yml` and executed against REAL npm, with a checkout that mounts both
attacks the install boundary exists to close: a committed `.npmrc` repointing
the registry, and a copy of the scanner already sitting in the head's
`node_modules`. It records which program ended up doing the scanning.

**Why it is not a unit test.** The jest suites under
`packages/cli/src/__tests__/action/` run the same step scripts under the same
shell flags with npm stubbed, which proves the action no longer ASKS npm to run
from inside the checkout. Both attack routes are decisions the real npm client
makes about files on disk, and a stub does whatever the stub says.

**No network.** Two registries run on 127.0.0.1 on ephemeral ports for the life
of the run. The legitimate one serves this worktree's own packages, packed the
way a publish packs them, plus their dependency closure. The hostile one serves
a stand-in at the same name and the same exact version whose bin writes a marker
and exits 0 with an empty SARIF log.

**The negative control is the point.** Each run also executes the PRE-FIX action
from tag `v1.7.0`, read out of git rather than committed, and the baseline
records the attack succeeding there: the planted copy runs, the hostile registry
is contacted, and the gate goes from red to green. A harness that reports the
current action clean proves nothing on its own — it has to be shown catching the
attack on the action that had it. `--compare` fails just as loudly when a
`v1.7.0` case stops showing the attack as when a `current` case starts.

The fixture's head commit carries a vendor-anchored credential assembled from
fragments at runtime, so the real scanner exits 1 and a stand-in faking a clean
run exits 0. That difference is the whole measurement; a fixture the real
scanner did not object to would make every case look identical.
