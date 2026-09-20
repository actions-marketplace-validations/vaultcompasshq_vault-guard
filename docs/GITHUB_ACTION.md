# GitHub Action (`action.yml`)

The composite action in the **repository root** installs the published
`@vaultcompass/vault-guard` CLI into a prefix under the runner temp, after Node
22 is installed, and runs it from there by absolute path.

## Requirements

1. **`actions/checkout`** of your repository **before** this action (the action
   does not check out your code; it only installs Node and the scanner).
2. A **published** `@vaultcompass/vault-guard` at the exact version the
   `version` input names (default `1.8.0`, the scanner this Action tag shipped
   with).

## The Action tag and the scanner version are two numbers

`vaultcompasshq/vault-guard@v1.8.0` installs `@vaultcompass/vault-guard@1.8.0`:
this is a package release, so the tag and the scanner move together. They are
still allowed to differ -- `vaultcompasshq/vault-guard@v1.7.4` installed
`@vaultcompass/vault-guard@1.7.0`; 1.7.1 through 1.7.4 were all action-only
releases that changed the Action and nothing in the scanner, so there was no
new scanner to publish.
Read the tag as "which version of the workflow step", not as "which version of
the scanner", and leave `version` out so there is one pin to bump rather than
two that can disagree.

## Where the scanner comes from

**The scanner is a control input, and it comes from outside the tree it
scans.** Through `@v1.7.0` this action ran `npx` with the checkout as its
working directory, which handed the choice of program to the tree under
judgment by two routes:

- a **committed `.npmrc`** repoints the registry npx fetches from (either the
  global `registry=` key or the scope-specific `@vaultcompass:registry=` one);
- a **copy already in the head's `node_modules`**, which any workflow with an
  install step before the gate produces, wins outright: `npx pkg@version` in a
  tree that already satisfies the spec runs the local copy and never contacts a
  registry at all, so the version pin degrades into a satisfaction check on a
  package the head wrote.

On a `pull_request` run that checkout is the untrusted head. Since `@v1.7.1` the
package is installed globally into a prefix under `RUNNER_TEMP`, with npm
started from the runner temp rather than from the workspace, and the resulting
binary is called by absolute path. The step then chdirs into the scan root,
because vault-guard reads its config, resolves the trust base and reports every
path relative to its own process cwd.

The install also passes `--ignore-scripts`, so nothing in the resolved tree runs
code on the runner at install time, and the step then runs `npm audit
signatures` over what it installed.

**What that verification proves, and what it does not.** It asks the registry
for each name and version in the tree — the scanner included — and checks the
registry signature served back, so an unpublished, replaced or unsigned package
fails the step. It does **not** read the installed files: npm refetches manifests
rather than hashing anything on disk, so it will not detect a tampered install.
It does **not** defeat a compromised registry, which signs what it serves. And a
**missing** attestation is not a failure, only a missing or invalid signature is,
so it does not require provenance even though these packages publish it.

> **Two ways this step fails closed, both on purpose.**
>
> **It needs npm 10.5.2 or newer.** `npm audit signatures` is not
> version-stable: below 10.5.2 it fails on a *clean, untampered* install of
> these packages, because the client's own bundled keys and TUF root are stale.
> On npm 10.5.0 it reports "Someone might have tampered with these packages
> since they were published on the registry!", naming ours. The Action refuses
> up front and names the npm it found, so a stale client is reported as a stale
> client rather than as a supply-chain incident.
>
> This Action installs its own Node 22, and **that is not on its own
> sufficient**: `node-version` is a major-only spec and **Node 22.0.0 ships npm
> 10.5.1**, one patch below the floor, and `setup-node` satisfies a major from
> the runner's tool cache when it can. The floor is enforced rather than
> assumed. Node 20.13.0 and later, and 22.1.0 and later, carry a usable npm.
>
> **It needs a registry that serves `/-/npm/v1/keys`.** If your runner points
> npm at a mirror or a proxy that does not — via `actions/setup-node`'s
> `registry-url:`, a corporate `~/.npmrc`, or `npm_config_registry` — the
> install will succeed and this step will then fail with
> `EMISSINGSIGNATUREKEY`. A sigstore or TUF outage has the same effect.
>
> If either blocks you, pin to `@v1.7.2`, which does not verify.

**What this does not cover.** A `pull_request` run uses the workflow file as it
is in the merge commit, so a pull request can edit or delete this step like any
other CI step. Branch protection on the base branch, with review required for
`.github/workflows/**`, is the control for that, and nothing the action does
substitutes for it. The boundary here is against the TREE choosing its own
judge.

## Inputs

| Input           | Default                     | Description |
|----------------|-----------------------------|-------------|
| `version`      | `1.8.0`                     | **Exact** version of `@vaultcompass/vault-guard`, validated against `^(0\|[1-9][0-9]*)\.(0\|[1-9][0-9]*)\.(0\|[1-9][0-9]*)$`. A dist-tag (`latest`, `next`, `beta`), a range, a prerelease, or a leading zero is refused, and so is anything below **1.7.0**, the oldest scanner this Action tag can drive. **On a pull request it may not go below the scanner this Action tag ships** (`1.8.0` today); pinning forward is still allowed there. The default is the scanner this Action tag shipped with; leaving the input out is the recommended shape. |
| `path`         | `.`                         | Subdirectory to scan, relative to workspace root. Must not begin with `-`, contain `..`, or resolve outside the workspace through a symlink. |
| `format`       | `sarif`                     | `sarif`, `json`, or `text`. |
| `sarif-output` | `vault-guard-results.sarif` | Output file path **under** `GITHUB_WORKSPACE`. May not resolve under `.github/`, and may not resolve through a symlink at the file or at any directory on the way to it. |
| `trust-base`   | `auto`                      | Pull-request mode. `auto` passes `--trust-base origin/$GITHUB_BASE_REF` when that variable is set; any other value is used as the ref. There is deliberately no value that turns it off. |

### `version: latest` is refused

It used to be the default. Two reasons it is gone. A dist-tag means the program
judging a pull request is whichever one the registry served that morning, rather
than one decided in the workflow file and reviewable there. And npm's specifier
parser reads `@scope/name@<value>` as a PATH when the value begins with a dot or
ends in `.tgz`, so the old charset accepted `.`, `..` and `payload.tgz` — which,
on a step that ran from inside the checkout, was one committed file away from
the tree handing over its own scanner. **Remove the input** rather than pinning
it: the default is already the right pin.

### A `version` below 1.7.0 is refused too

Shape is not capability. Passing the semver pattern proves the input names a
version; it says nothing about whether that version understands the arguments
this Action tag hands it. The scan passes `--trust-base`, which the scanner
added in 1.7.0, and an older scanner answers an unknown option with exit 1, the
same code it uses for findings.

So the Action declares the oldest scanner it can drive and refuses anything
below it at input validation, naming both numbers. The floor tracks THE FLAGS
THE TAG PASSES, not the tag number, and it moves in whichever release starts
passing a newer flag.

This is the shape that produced the bug: a repository whose workflow pinned
`version: 1.4.1` while Dependabot moved only the Action SHA got told it was
carrying secrets, from a scan that stopped at argument parsing. **Remove the
input.** A `version:` Dependabot does not move is a second pin in a place no
automation looks.

### On a pull request, `version` may not pin backward

The floor above is about flag compatibility, so it admits everything at or above
1.7.0 — it is not the control for which scanner judges a pull request. On a
same-repo `pull_request` event GitHub runs the workflow file from the head, so
`version:` is written by the pull request being judged. Before 1.8.0 shipped,
exactly one published version cleared the floor, so nothing could be chosen;
now that a 1.8.0 scanner exists with new rules, `version: 1.7.0` still clears
the flag floor but is refused by the check below, so a pull request cannot pin
back to it and be judged by the older rules it picked for itself. That would
have read like version management in a diff, which is what makes it worse than
deleting the step outright.

**So on a pull-request event the Action refuses a `version` below the scanner
the tag ships, and accepts anything at or above it.** Pinning forward is still
allowed there, on an assumption the rule does not enforce: that a newer scanner
is at least as strict. Nothing bounds a forward pin. The comparison is against a
constant in `action.yml`, which comes from the ref your workflow's `uses:` names
rather than from the pull request's tree.

The rule fires exactly where `GITHUB_BASE_REF` is set, which is `pull_request`
and `pull_request_target`. Push runs are out of scope, and the flag floor stays
their only version gate. That is a statement of scope, not a safety argument: a
push to an unprotected branch runs that branch's own workflow file, written by
the same author, so it is as author-controlled as a pull request and is not
covered.

The refusal names both numbers and the fix, which is to **remove the `version`
input**.

**What it does not cover, and what it costs on forks.** A fork's `pull_request`
run uses the base repository's workflow file, so a fork author never writes the
`version:` that judges them and there is no hole there to close. The rule still
fires on that run: `GITHUB_BASE_REF` is set on a fork pull request too, so the
check runs and judges your own trusted workflow file. Once a newer scanner
exists, a backward pin you deliberately wrote in the base workflow will fail
every fork pull request, which is a refusal on a pin nobody untrusted wrote. If
you need that pin, remove the `version:` input or raise it.

It also does not stop a pull request deleting the step, or moving the `uses:`
pin to an older Action tag. Those are workflow-file edits, and the control is
branch protection with required review on `.github/workflows/**`. See
[GITHUB_BRANCH_PROTECTION.md](./GITHUB_BRANCH_PROTECTION.md).

## Pull requests

**On a pull-request run every control input comes from the base ref, and the
head tree is what gets scanned.** `.vault-guard.json`,
`.vault-guard.local.json` and `.vault-guard.baseline.json` are read from the
base with `git show`; a version of them that the pull request changed is
reported as a proposal and is not applied. Without this a pull request could
turn the scanner off in the same commit that carried the secret.

`auto` fires on exactly the pull-request events, because `GITHUB_BASE_REF` is
set only there. The ref reaches the CLI through the step's `env` block and a
bash array, never by substituting a `${{ }}` expression into a `run` body:
expressions are textual substitution performed before the shell parses the
script, which is how a crafted branch name would become a command.

**There is no `trust-base` value that turns pull-request mode off**, and that is
a decision rather than an omission. On a same-repo `pull_request` event GitHub
runs the workflow file from the pull request head, so an off switch on this
input would be settable by the pull request it exists to judge: the boundary
would ship with its own off switch, sitting on the untrusted side. Base-ref
judging is the floor. The only kind of change this input accepts is a tightening
(an explicit ref), and the human-approval tightening lives in repository
settings, where a pull request cannot write it. `trust-base: off` was accepted
in a pre-release build and is now refused by name, with an error saying so.

If you are not ready to add `fetch-depth: 0` to your checkout, stay pinned to
`vaultcompasshq/vault-guard@v1.6.0` until you are. That is a deliberate choice a
maintainer makes on a protected branch, which is exactly what an off switch in a
PR-controlled file is not.

**What pinning back costs, stated plainly:** every tag before `@v1.7.1`,
`@v1.6.0` included, installs the scanner with `npx` from inside the checkout, so
a pull request can choose the program that scans it — with a committed `.npmrc`
or a copy in its own `node_modules`. See [Where the scanner comes
from](#where-the-scanner-comes-from). Adding `fetch-depth: 0` is a one-line
change to a workflow file and gives up nothing; pinning back gives up that
boundary for as long as it lasts.

Two requirements on the calling workflow, and neither can be met from inside
this action:

1. **`fetch-depth: 0` on `actions/checkout`.** The base branch has to exist
   locally for the base ref to resolve. Without it the scan exits 2 with a line
   naming the ref and saying to fetch the base. It does not fall back to
   trusting the pull request.

2. **The workflow file has to be protected deliberately.** On a same-repo
   `pull_request` event GitHub runs the workflow from the pull request head, so
   the job running this gate is as editable as any other file in the branch, and
   no flag can detect a job the pull request deleted. Make the check required by
   name in branch protection, or put the gate in a reusable workflow on a
   protected ref and call it. See
   [GITHUB_BRANCH_PROTECTION.md](./GITHUB_BRANCH_PROTECTION.md).

Requiring a human to approve a change to the config or the baseline is
repository configuration rather than an action input: a `CODEOWNERS` entry for
those paths plus required code-owner review. There is no in-repo knob for it on
purpose, because a knob that can relax the gate and lives in the file the pull
request controls is not a control at all.

```yaml
on: pull_request

jobs:
  secrets:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Needed only if you chain upload-sarif, and needed explicitly: the
      # default token is read-only, so the upload 403s without it.
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - uses: vaultcompasshq/vault-guard@v1.8.0
        with:
          format: sarif
```

## Output

| Output          | Description |
|----------------|-------------|
| `results-file` | Absolute path to the written SARIF/JSON file, or **empty** when the run wrote nothing at all. |
| `exit-code`    | The verdict: 0 clean, 1 secrets at or above the gate, 2 could not run. Usually vault-guard's own exit code, but see the remap below: a scan that wrote no report is **2** whatever it exited. |

**A verdict requires a report.** The exit code says what the scanner decided;
whether it wrote anything says whether it got far enough to decide. When the
report is empty the status is not read as a verdict at all, and the run is
reported as could-not-run (**2**). That covers exits of 0 and 1 too, not only
unexpected codes. Exit 1 with no report is not findings, because findings would
have produced findings, and the realistic cause is a scanner that refused an
argument (see the version floor above). Exit 1 is also what the CLI's argument
parser returns for an unknown option, writing to stderr, which leaves nothing in
the report. Exit 0 with no report is not a clean scan either: a clean scan
prints its report, so nothing written means the scan did not happen.

Only 0, 1 and 2 are verdicts. Anything else the step sees — including the 126
and 127 the shell produces when a binary is missing or not executable — is
reported as could-not-run and re-raised as **2**, because a failed install is
not a clean scan and must not be reported as findings either.

## Example: fail the job on secrets

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
- uses: vaultcompasshq/vault-guard@v1.8.0
  id: vg
  with:
    format: text
    sarif-output: vault-guard.txt
```

When `vault-guard` exits non-zero, the step fails and the job turns red. No
extra wiring required.

## SARIF upload

Use `format: sarif` and pipe output is already written to disk by the action
step (`tee`). Chain `github/codeql-action/upload-sarif` as in the root
`README.md` example.

### Exit 2 leaves the SARIF file empty, and `results-file` empty with it

Exit 2 means the run could not establish something it needed and scanned
nothing: a base ref it cannot read, a base config that fails validation, a
staged file it cannot read. There is deliberately no SARIF document in that
case, because a document reporting zero results would be a claim the run did
not earn. The action still `tee`s stdout, so the file exists and is **empty**.

An `upload-sarif` step with a bare `if: always()` then fails on that empty file,
and its error is the one people read first, sitting on top of the real message
further up the log. Since `@v1.7.1` the action publishes `results-file` **only
when the file has content**, so the guard is one expression rather than a step
of its own:

```yaml
    permissions:
      contents: read
      # The upload needs this explicitly; the default token is read-only and
      # the step fails with a 403 that says nothing about the scan.
      security-events: write
    steps:
      - uses: vaultcompasshq/vault-guard@v1.8.0
        id: vg
        with:
          format: sarif
      # Pinned to a commit, not to `v3`: this runs in your repository with the
      # permission above. Same SHA `vault-guard init` scaffolds.
      - uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9 # v4.37.0
        if: always() && steps.vg.outputs.results-file != ''
        with:
          sarif_file: ${{ steps.vg.outputs.results-file }}
```

On `@v1.7.0` and earlier the output always named the file, empty or not, and the
check had to be a shell step of its own reading `-s "${SARIF_FILE}"` — with the
path passed through `env` rather than substituted into the `run` body, for the
same reason the base ref is.
