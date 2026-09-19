# FINDINGS

This is a durable, append-by-PR record of what vault-guard actually did when
run against real code: this repo's own code, other Vault & Compass repos, or
public artifacts. A gate result that only lives in a terminal scroll or a
closed pull request evaporates; this file is the place it lands instead, so
false-positive and false-negative classes accumulate across runs instead of
being rediscovered by the next person who hits them.

A run that found nothing still gets a row. "It caught nothing" is itself a
datum: it is the only way to tell whether the scanner is blind on that input
or the base rate of real secrets in it is genuinely low. Log the clean run,
not just the interesting one.

## Format

One row per run. Append new rows at the bottom, in chronological order. Do
not edit or delete existing rows; if a verdict turns out to be wrong on
later review, append a new row that corrects it and say which row it
corrects.

Verdict is one of: true positive, false positive, true negative, false
negative, could-not-run.

| Date | What was scanned (repo/artifact + version) | What the gate said | Verdict | Follow-up |
|---|---|---|---|---|
| 2026-01-01 (EXAMPLE) | example-app (git SHA abc1234) + vault-guard 1.7.0, vault-guard scan --staged | 1 finding: critical, rule aws-secret-key, config/prod.env:12 | true positive | none |
| 2026-09-16 | A repository whose CI pinned the Action at v1.7.1 driving a scanner pinned at 1.4.1 (which predates --trust-base) | Commander (the CLI's argument parser) exited 1 on the unknown --trust-base option with nothing written; the Action's run step read that bare exit 1 as "vault-guard found secrets at or above the gate" | false positive | Fixed in v1.7.2: the run step now requires a written report before it reads the exit code as a verdict; exit 1 with nothing written is reported as could-not-run instead. See CHANGELOG.md, [1.7.2] - 2026-09-16. |

## How to add an entry

Open a pull request that appends one row to the table above. Any seat may
open it, human or agent. Keep the table chronological. A clean run (true
negative) and a run the scanner could not complete (could-not-run) are both
worth recording, not just the runs that found something.
