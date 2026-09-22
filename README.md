# Vault Guard

Vault Guard reads the text of the files you point it at, and reports the
credentials it finds in them, before a commit lands or before an agent's
proposed edit is applied.

<!-- guardrails-family: shared block, keep it identical in dep-guard, vault-guard, intent-guard and conductor -->
The Vault & Compass guardrails are three gates over an AI-assisted coding
session: [dep-guard](https://www.npmjs.com/package/@vaultcompass/dep-guard)
checks what comes in (hallucinated package names, typosquats, tampered
lockfile entries),
[vault-guard](https://www.npmjs.com/package/@vaultcompass/vault-guard) checks
what goes out (credentials about to be committed), and
[intent-guard](https://www.npmjs.com/package/@vaultcompass/intent-guard)
checks the change against what was approved (drift from a frozen intent
contract, and change budgets). Each one installs, configures and runs on its
own;
[conductor](https://www.npmjs.com/package/@vaultcompass/conductor) is the
optional umbrella that runs them from one policy file, one hook and one
report.
<!-- /guardrails-family -->

```bash
npm install -g @vaultcompass/vault-guard
```

---

## Why

A pasted key arrives as an ordinary edit. It is a few characters in a
config file or a test fixture, it does not look different from the lines
around it, and nobody reads a generated diff closely enough to spot it.
Vault Guard sits at the three points a credential passes through on its way
into a repository: the edit an agent proposes (an MCP server exposes
`scan_text`, `scan_file` and `scan_workspace`, so a client can ask before
applying), the staged diff (a pre-commit hook running `vault-guard scan
--staged`), and the checkout in CI (a GitHub Action that writes SARIF for
code scanning).

It catches credentials that have a shape it can recognise: vendor key
formats, database connection URLs, SSH private keys, JWTs, and generic
`api_key` or `secret` assignments whose value clears an entropy gate. The
vendors are listed under [What it detects](#what-it-detects) and the rules
with their severities are in [docs/RULES.md](./docs/RULES.md).

It does not read Git history. A key that was committed months ago and
deleted since is invisible to a working-tree scan, and finding it is
Gitleaks' or TruffleHog's job rather than this tool's; that boundary is
deliberate and [docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md) records it
as such. It does not check whether a key it found still works, does not
look inside dependency trees or published tarballs, and does not judge
whether a package is malicious. The miss it will make most often is a
credential with no distinctive prefix or format, held in a plainly named
variable, at an entropy the generic rules let through.

---

## Quickstart

### 0. One-command setup (recommended)

From your repository root:

```bash
vault-guard init
```

Creates `.vault-guard.json`, a GitHub Actions workflow, local agent guardrail files under
`.vault-guard/`, and a pre-commit hook. Preview changes first:

```bash
vault-guard init --dry-run
```

Init never overwrites existing files: resolve conflicts manually. To undo:

```bash
vault-guard init --revert
```

Merge `.vault-guard/mcp-snippet.json` into your editor MCP config (see step 1).

### 1. Protect your AI editor (MCP)

Add to your MCP config (`~/.cursor/mcp.json`, `claude_desktop_config.json`, etc.):

```json
{
  "mcpServers": {
    "vault-guard": {
      "command": "npx",
      "args": ["-y", "@vaultcompass/vault-guard-mcp"]
    }
  }
}
```

Vault Guard exposes `scan_text`, `scan_file`, and `scan_workspace` tools. Your AI agent can call them before applying any edit that touches secrets.

See **[docs/MCP.md](./docs/MCP.md)** for the full tool reference.

### 2. Block secrets at commit time

```bash
vault-guard install-hook
```

Installs a hook that runs `vault-guard scan --staged` before every commit. Honors `core.hooksPath` (including globally-configured hook paths). When husky 9 already owns `core.hooksPath` (its generated `.husky/_` directory), the default `native` manager detects this automatically and installs into the same tracked `pre-commit` file husky's own shim runs -- no `--manager husky` needed. This also works when the package that owns husky's `.husky` is a monorepo subdirectory rather than the repo root (`core.hooksPath` like `packages/app/.husky/_`): the tracked hook lands at `packages/app/.husky/pre-commit`, matching where husky actually runs it. **Run `install-hook` (and `init`) from the git repository root, never from a package subdirectory** -- they refuse outright otherwise. Supports all major managers:

```bash
vault-guard install-hook --manager native     # default: Git hooks / hooksPath
vault-guard install-hook --manager husky      # .husky/pre-commit
vault-guard install-hook --manager lefthook   # lefthook-local.yml
vault-guard install-hook --manager precommit  # .pre-commit-config.yaml (only if absent)
```

**Windows:** `scan`, `check`, MCP, and CI workflows are supported on Windows,
by calling the CLI. **The composite Action is Linux and macOS only**: it
installs the scanner globally and adds `<prefix>/bin` to `PATH`, which is where
npm puts the shims on those platforms and not where it puts them on Windows. On
a `windows-latest` runner, run the CLI directly rather than
`uses: vaultcompasshq/vault-guard@…`.
Native hook install writes a POSIX `pre-commit` script (Git for Windows runs it
via `sh`, same as Git Bash) plus an optional `pre-commit.cmd` for clients that
call `.cmd` hooks directly. `git.exe` does not use the `.cmd` file.
Husky/Lefthook/pre-commit managers still use their own runners. CI runs
`pnpm test:windows` (core + CLI unit tests, excluding hook/proxy integration).

Emergency bypass (discouraged): `git commit --no-verify`.

### 3. Scan a repo or file

```bash
vault-guard scan .
vault-guard scan --staged          # staged files only (fast, for CI / hooks)
vault-guard check src/api.ts       # single file

# Pull-request mode: config and baseline come from the base ref, the head tree
# is what gets scanned. See "Pull requests" under CI below. Never in a hook.
vault-guard scan . --trust-base origin/main
vault-guard check --trust-base origin/main
```

**Machine-readable output** (SARIF for GitHub Code Scanning, or JSON):

```bash
vault-guard scan . --format sarif
vault-guard scan . --format json
```

### What fails the build

Findings at or above the **`--fail-on` threshold** produce exit code 1. Everything
below it is still reported (text, JSON, SARIF) but does not break the gate.

Exit code **2** means vault-guard could not complete the scan and is refusing to
call the result clean: `git diff --cached` failed, `--staged` reached a staged
file it could not read, or `--trust-base` named a ref whose control inputs it
could not read. On exit 2 no JSON or SARIF document is written at all, because a
document reporting zero findings would be a claim the run did not earn; if you
pipe SARIF to `upload-sarif`, guard that step on the file being non-empty (see
**[docs/GITHUB_ACTION.md](./docs/GITHUB_ACTION.md)**). In that case there is no `✅ SUCCESS` line, and
`run.unscannable_files` says how many staged files went unexamined. Exit 2
takes precedence over exit 1, so gate on **any** non-zero exit rather than on
1 alone: a run that skipped files cannot report a complete finding set. See
**[docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md)** for why a directory scan
reports the same condition without failing on it.

```bash
vault-guard scan .                      # default: fail on medium and above
vault-guard scan . --fail-on critical   # only criticals block
vault-guard scan . --fail-on low        # block on anything (pre-1.4.0 behaviour)
vault-guard scan . --fail-on none       # advisory mode: report, never fail
```

The default is `medium` because the scanner deliberately downgrades findings to
`low` where they are usually not real leaks: generic patterns inside
`__tests__/`, `docs/`, `*.example` files, and public identifiers such as GCP
OAuth client IDs and Sentry DSNs. Set `"fail_on"` in `.vault-guard.json` to
change it repo-wide. The JSON `run` block reports both `fail_on` and
`blocking_matches`; gate on `blocking_matches`, not `summary.secrets`.

Structured output includes a `run` block (timing, files/bytes scanned, active pattern count, diagnostics). See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

---

## What it detects

- AI/ML API keys (Anthropic, OpenAI, Groq, OpenRouter, xAI, Perplexity, Mistral, DeepSeek, Together, Fireworks, LangSmith, HuggingFace, Replicate)
- Backend platforms (Supabase, Vercel Blob, PlanetScale, Doppler, Databricks, Cloudflare)
- Payment processors (Stripe live + test, PayPal)
- Cloud providers (AWS access keys, context-anchored AWS secret keys, GCP, Azure storage)
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Version control tokens (GitHub classic + fine-grained PATs, GitLab, Bitbucket)
- Communication (Slack webhooks + tokens, Discord webhooks)
- SaaS tokens (Notion, Airtable, Figma)
- SSH private keys, JWTs, and entropy-gated generic `api_key` / `secret` assignments

Full rule reference with severities: **[docs/RULES.md](./docs/RULES.md)**.

Note: `sk_live_` / `sk_test_` are used by both Stripe and Clerk and there is no
reliable discriminator in the key body, so a Clerk secret key is reported under
the `stripe` rule id. The finding is correct; only the vendor label may be off.

---

## How it compares

Vault Guard is **not** a history miner. It targets fast working-tree checks (the IDE, pre-commit gate, and CI on the checkout) and is designed to be composed with dedicated history scanners, not to replace them.

| Feature | Vault Guard | Gitleaks | TruffleHog | detect-secrets | GitHub Secret Protection | GitGuardian |
|---|---|---|---|---|---|---|
| Working-tree / staged-file scan | Yes | Yes | Yes | Yes | Push/PR focused | Yes |
| Git history mining | No | Yes | Yes | No | Hosted scanning | Yes |
| MCP / AI-agent scanning | Local MCP | No | No | No | Yes | Yes |
| GitHub Action (SARIF output) | Yes | Yes | No | No | Native platform | Yes |
| Pre-commit hook installer | Yes | Partial | No | Yes | No | Yes |
| Entropy gating on generic patterns | Yes | Partial | Yes | Yes | Provider-pattern focused | Yes |
| Config ignore paths / baselines | Yes | Yes | No | Yes | Platform-managed | Yes |
| Opt-in local token telemetry (Anthropic) | Yes | No | No | No | No | No |
| Local-only / no account required | Yes | Yes | Yes | Yes | No | No |

For credentials in Git history use **[Gitleaks](https://github.com/gitleaks/gitleaks)** or **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** alongside Vault Guard. They are complementary, not competing.


---

## Recommended stack

Use Vault Guard as the **local AI-edit firewall**, then compose with history scanners:

| Layer | Tool | Role |
|---|---|---|
| AI edits + staged files + CI checkout | **Vault Guard** (MCP, pre-commit, Action) | Fast working-tree gate; no account |
| Git history / deep local scan | [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline history + strong pre-commit rules |
| Verified / live-key audit | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Confirm credentials still work |

Vault Guard does **not** mine Git history: see [docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md). Pairing with Gitleaks/TruffleHog is the recommended production setup, not a competing choice.


---

## CI: GitHub Action

```yaml
jobs:
  secrets:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Required by the upload step. Without it the default token is read-only
      # and the upload fails with a 403 that has nothing to do with the scan.
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Required on pull requests: pull-request mode reads the config and
          # the baseline from the base branch, which a shallow clone does not have.
          fetch-depth: 0
      - uses: vaultcompasshq/vault-guard@v1.8.1
        id: vault-guard
        with:
          path: .
          format: sarif
          sarif-output: vault-guard-results.sarif
      - uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9 # v4.37.0
        # Guarded on the output being non-empty: a run that could not scan at
        # all writes no document, and handing that empty file to the uploader
        # fails the job with a parse error on top of the real message.
        if: always() && steps.vault-guard.outputs.results-file != ''
        with:
          sarif_file: ${{ steps.vault-guard.outputs.results-file }}
```

The uploader is pinned to a commit rather than to `v3`, because it runs in your
repository with your `security-events: write`. `vault-guard init` scaffolds this
same workflow, permissions and pin included.

No `version` input in that example, because the default is the scanner version
this Action tag shipped with. Leaving it out is the recommended shape: the tag
then decides the scanner, and there is one pin to bump instead of two that can
disagree.

**The Action tag and the scanner version are separate numbers, and they do not
have to match.** `vaultcompasshq/vault-guard@v1.8.0` installs
`@vaultcompass/vault-guard@1.8.0` -- this is a package release, so the two move
together. They are still allowed to come apart: `vaultcompasshq/vault-guard@v1.7.4`
installed `@vaultcompass/vault-guard@1.7.0`, because that release changed the
Action and nothing in the scanner, so there was no new scanner to publish. Read
the tag as "which version of the workflow step", not as "which version of the
scanner".

### Where the scanner comes from

The Action installs `@vaultcompass/vault-guard` from the registry into a prefix
under the runner temp and calls that copy by absolute path. It never runs the
checkout's own `node_modules`, and never starts npm with the checkout as its
working directory, so neither a committed `.npmrc` nor a package the head's
lockfile put in `node_modules` can decide which program does the scanning. Up to
and including `@v1.7.0` it ran `npx` from inside the checkout, and either of
those two files was enough for a pull request to choose the program that judged
it.

`version` no longer accepts a dist-tag, and no longer defaults to `latest`. Two
reasons. A tag means the scanner judging a pull request is whichever one the
registry served that morning rather than one decided in the workflow file. And
npm reads a value beginning with a dot, or ending in `.tgz`, as a PATH rather
than a version, which on a run that started inside the checkout was one
committed file away from the tree handing over its own scanner. **If you were
relying on the old `latest` default, remove the input**; a dist-tag is refused
with a message saying so.

The install step refuses npm older than **10.5.2**. Below that floor `npm audit signatures` reports a clean install of these packages as tampered, because the client's own bundled keys are stale. Installing Node 22 is not enough on its own: **Node 22.0.0 ships npm 10.5.1**. Node **20.13.0** and later, and 22.1.0 and later, carry a usable npm. The step checks the client it actually found and names that version when it refuses.

Details: **[docs/GITHUB_ACTION.md](./docs/GITHUB_ACTION.md)**. Branch protection setup: **[docs/GITHUB_BRANCH_PROTECTION.md](./docs/GITHUB_BRANCH_PROTECTION.md)**.

### Pull requests: the rules come from the base branch

**On a pull-request run, every control input comes from the base ref and the
head tree is the thing scanned.**

Without that, a pull request could turn the scanner off in the same commit that
carried the secret, and nothing in the output would say so. Measured on a
scratch repository, each of these on its own turned exit 1 into exit 0:
`ignore: {"paths": ["**"]}` added to `.vault-guard.json`, a `severity_overrides`
entry setting the matching rule to `off`, `"fail_on": "none"`, a
`.vault-guard.local.json` **swapped in for** the committed `.vault-guard.json`,
a `.vault-guard.baseline.json` rewritten to carry the fingerprint of the finding
being added, a `.gitignore` covering the file the key sits in, and the key
committed under a directory named `vendor`.

The local-config one needs the swap. The two filenames are tried in order within
a directory, so a `.vault-guard.local.json` added beside an existing
`.vault-guard.json` never wins; deleting the committed file in the same commit
is what hands the run to the added one.

The Action passes `--trust-base origin/$GITHUB_BASE_REF` on pull-request events
by default, through the step's `env` block rather than by substituting an
expression into a shell script. You can run the same judgment locally:

```bash
vault-guard scan . --trust-base origin/main
```

What changes in that mode:

- `.vault-guard.json`, `.vault-guard.local.json` and the baseline are read from
  the ref with `git show`. Nothing is checked out and nothing is written.
- A control input the head changed is printed as a proposal and **not applied**:
  `config changed in this pull request (2 patterns added to ignore, fail_on
  lowered)`. A control input that exists only in the head is a proposal too, and
  the run uses the defaults it would have used with no config at all.
- The file set is the **HEAD tree** (`git ls-tree -r HEAD`), so a `.gitignore`
  added by the pull request cannot hide a file that is already committed, and
  `git rm --cached` cannot either. Untracked and merely-staged files are **not**
  scanned in this mode: they are not part of the tree the pull request is
  proposing, and the index is local state the base ref says nothing about. Use
  `vault-guard scan --staged` for the pre-commit job of checking the index.
- The vendored-directory names (`vendor`, `dist`, `node_modules`, …) are
  anchored to the scan root, so a committed `src/vendor/` is scanned. The run
  prints how many directories it skipped, in yellow when that number is not
  zero, because a root-level vendored name still mutes by design.
- The run also prints how many files it skipped by extension or name (`.min.js`,
  `.lock`, `.map`, lockfiles). Those filters are unchanged: a key committed as
  `src/leak.min.js` is still skipped. What changed is that the run now says so
  rather than reporting clean in silence.
- Inline `vault-guard: ignore-line` directives are content, not configuration,
  so they are still honoured. A directive that hid a critical vendor-anchored
  finding gets its own count beside the total.
- A ref that will not resolve is **exit 2** with one line on stderr and nothing
  scanned. So is a ref that resolves to `HEAD`'s commit, or to a different
  commit carrying `HEAD`'s tree, which is what a merge ref looks like when the
  base has not moved. A missing base is never a reason to fall back to trusting
  the pull request.

Outside pull-request mode nothing changes. A pre-commit hook and a local
`vault-guard scan .` are already inside the trust boundary and must never pass
the flag.

**There is no action input that turns pull-request mode off**, and that is a
decision rather than an omission. On a same-repo `pull_request` event GitHub
runs the workflow file from the pull request head, so an off switch on the
action would be settable by the pull request it exists to judge: the boundary
would ship with its own off switch on the untrusted side. Base-ref judging is
the floor; the only kind of change the input accepts is a tightening. If you
need 1.6.0 behaviour while you arrange `fetch-depth: 0`, stay pinned to
`vaultcompasshq/vault-guard@v1.6.0` until you are ready, which is a choice a
maintainer makes on a protected branch -- knowing what it costs: **every tag
before `@v1.7.1` installs its scanner with `npx` from inside the checkout**, so
a pull request can choose the program that scans it. Pinning back trades that
boundary for time on a one-line checkout change.

**The workflow file itself has to be protected, deliberately.** On a same-repo
`pull_request` event GitHub runs the workflow from the pull request head, so the
job that runs this gate is as editable as any other file in the branch. No flag
can detect a job the pull request deleted. Make the check **required by name in
branch protection**, or move the gate into a **reusable workflow on a protected
ref** and call it. See
**[docs/GITHUB_BRANCH_PROTECTION.md](./docs/GITHUB_BRANCH_PROTECTION.md)**.

**Requiring a human to approve a config change is repository configuration, not
a vault-guard setting**, and there is deliberately no flag for it. Add a
`CODEOWNERS` entry for the control files and require code-owner review on the
protected branch:

```
# .github/CODEOWNERS
/.vault-guard.json           @your-org/security
/.vault-guard.local.json     @your-org/security
/.vault-guard.baseline.json  @your-org/security
```

It lives there because a setting that could relax the gate has to sit somewhere
the pull request cannot write. An in-repo knob for this would be the
vulnerability wearing a settings label: a pull request would simply flip it in
the same commit. Base-ref judgment is the floor and is always on; a required
human approval can only make the gate stricter.

---

## Configuration

Create `.vault-guard.json` at your repo root:

```json
{
  "fail_on": "medium",
  "ignore": {
    "paths": ["fixtures/**"]
  },
  "severity_overrides": {
    "jwt-token": "low"
  },
  "extra_patterns": [
    { "id": "my-internal-key", "regex": "INT-[A-Z0-9]{32}", "severity": "critical" }
  ]
}
```

`init` no longer ignores test trees by default. Ignoring `**/__tests__/**`
means the scanner never looks there, which is how a vendor-anchored key
committed to a test file can slip past the hook entirely. Instead, test trees
are scanned, and the low-precision rules (generic assignments, DSNs, JWTs, PEM
headers) are downgraded to `low` there.

**Vendor-anchored rules are not downgraded in test files at all.** That is the
point of the change, and also its cost: a vendor-shaped token in a test blocks
whether or not it is live, because the scanner cannot tell a real `sk-ant-` /
`ghp_` / `AKIA` string from a convincing fabricated one. Build fake tokens from
fragments joined at runtime, or use the documented placeholder words
(`EXAMPLE`, `test`, …). Keep a `fixtures/**`-style ignore only for directories
that hold deliberately-planted credential fixtures (a scanner's own
true-positive corpus).

JSON Schema for editor autocomplete: **[schemas/vault-guard-config.json](./schemas/vault-guard-config.json)**.

> **Upgrading to 1.7.0.** The config schema is now checked on **every** load, not
> only when you run `vault-guard config validate`. Through 1.6.0 an unrecognised
> top-level key was silently dropped and the scan carried on; from 1.7.0 it fails
> the run with the validation message. Realistic keys that were tolerated and are
> now refused include `$schema`, `comment` and `version`. Run
> `vault-guard config validate` once after upgrading, and delete or rename
> anything it names. Only the keys documented above are accepted.

> **Also upgrading to 1.7.0.** If your CI workflow runs on `pull_request`, add
> `fetch-depth: 0` to `actions/checkout`. Pull-request mode reads the config and
> the baseline from the base branch, and a shallow clone does not have it, so the
> scan exits 2 rather than falling back to trusting the pull request. There is no
> input that turns pull-request mode off, on purpose: on a same-repo
> `pull_request` event GitHub runs the workflow file from the pull request head,
> so an off switch would be settable by the pull request it judges. If you are
> not ready to change the checkout, stay pinned to
> `vaultcompasshq/vault-guard@v1.6.0` until you are -- but know the trade: every
> tag before `@v1.7.1` installs its scanner from inside the checkout it scans,
> so a pull request can choose the program that judges it.

> **Also moving to `@v1.7.1`.** It is an action-only release: the tag moves, the
> npm packages stay at 1.7.0. Two things change in a workflow. The `version`
> input takes an EXACT version now and refuses a dist-tag, so **delete
> `version: latest`** if you have it -- the default is the scanner this tag
> shipped with. And the `results-file` output is empty when the scan wrote no
> document, so a chained `upload-sarif` should be guarded on it rather than run
> unconditionally. Pinning `@v1.7.0` keeps the old Action, the one that installs
> its scanner from inside the tree it scans.

**Baseline**: fingerprint accepted findings so new issues still fail the gate:

```json
{ "version": 1, "fingerprints": ["<sha256 hex from scan JSON>", "…"] }
```

Each `--format json` match includes a `fingerprint` field. Copy values you accept into `.vault-guard.baseline.json`. See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

**Inline suppression:**

```ts
const key = "sk-ant-..."; // vault-guard: ignore-line
// vault-guard: ignore-next-line
const alsoFine = "...";
```

Suppressions never happen silently. Every run states how many findings the
baseline and inline directives hid: the text summary prints a `Suppressed:`
line (even at zero), and JSON and SARIF carry `run.baseline_suppressed` and
`run.inline_suppressed`, with a `suppression.inline` diagnostic naming the
suppressed line numbers.

---

## Opt-in token telemetry (Anthropic only)

Vault Guard can log Anthropic token usage locally; useful if you want to see what the proxy costs day-to-day.

```bash
vault-guard proxy --listen 127.0.0.1:8765
```

Forwards `POST /v1/messages` to `api.anthropic.com` and logs `model`, `input_tokens`, `output_tokens`, and estimated cost to **`~/.vault-guard/usage.sqlite`** (local only; nothing is sent to Vault & Compass servers).

Set `ANTHROPIC_BASE_URL=http://127.0.0.1:8765` to route a client through it. See **[docs/PRIVACY.md](./docs/PRIVACY.md)** for the full schema, opt-out steps, and data retention policy.

**Note:** this feature is Anthropic-specific. Token usage from Cursor's built-in models, Copilot, and other providers is not captured.

Inspect or wipe the local data:

```bash
vault-guard data status             # counts only; no raw paths
vault-guard data export -o out.json
vault-guard data reset              # interactive prompt
vault-guard data reset --yes        # non-interactive (CI)
```

Statusline JSON (for custom editor status bars):

```bash
vault-guard statusline --json
# { secrets_today, tokens_today_input, tokens_today_output, est_cost_usd, model }
```

Model hint from recent telemetry:

```bash
vault-guard suggest-model --json
```

---

## VS Code / Cursor extension

Inline diagnostics for open files (uses `@vaultcompass/vault-guard-core`). Package lives in
`packages/vscode-extension`.

**Local tryout:** `pnpm --filter vault-guard-vscode build`, then **Run Extension** from VS Code.

**Marketplace:** packaging is ready (`vsce package` / `vsce publish`). See
[packages/vscode-extension/README.md](./packages/vscode-extension/README.md). Publishing
requires the `vaultcompass` publisher token (maintainers only).

---

## Scripting & CI (stable JSON output)

`--format json` prints one JSON object on stdout (diagnostics on stderr; parse stdout only):

```bash
node packages/cli/dist/cli-entry.js scan /path/to/project --format json
```

Parse `summary.secrets`, `results`, and `run` as documented in **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

**If you are building a pass/fail gate, read `run.blocking_matches`, not `summary.secrets`.**
`summary.secrets` is a raw count of every finding in `results`, including ones below the
`--fail-on` threshold; it does not reflect the gate. `run.blocking_matches` is the count of
findings at or above the effective `fail_on` threshold and is exactly what drives vault-guard's
own exit code. An integrator gating on `summary.secrets` will fail builds that vault-guard itself
considers passing.

**Also check `run.unscannable_files`.** It is the number of files vault-guard reached but could
not read, so their contents were never examined. When it is present and non-zero, a
`blocking_matches` of 0 means "nothing found in what was scanned", not "nothing there".

---

## Docker & Homebrew

- **Docker:** `docker/README.md`, image installs the published npm CLI.
- **Homebrew:** `packaging/homebrew/README.md`, optional tap workflow (npm remains canonical).

---

## Maintainer dogfood

Before tagging a release, install on a ship machine and smoke the real paths: the MCP server, the pre-commit hook, optional telemetry, and `pnpm bench` / `node bench/run.cjs --assert`.

## Development

Requires **Node.js 22+** and **pnpm 9+**. (Node 20 reached EOL April 2026.)

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install
pnpm build
pnpm test
pnpm lint
```

Published packages: **`@vaultcompass/vault-guard`** (CLI), **`@vaultcompass/vault-guard-core`**, **`@vaultcompass/vault-guard-mcp`**, **`@vaultcompass/vault-guard-telemetry`**.

Run the precision/recall benchmark against the labeled fixture corpus:

```bash
node bench/run.cjs
```

---

Adopter feedback is a row in [FINDINGS.md](FINDINGS.md). How to change this repository is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, built and maintained by [Vault & Compass](https://vaultcompass.io)
