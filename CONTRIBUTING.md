# Contributing to vault-guard

## Public repository hygiene

This repo is **public**. Never commit names, paths, or context from other Vault &
Compass products, private monorepos, or internal portfolio work.

**Do not put in committed files** (including tests, fixtures, changelogs, comments):

- Other product or venture codenames (e.g. internal app/repo names)
- Paths like `/Users/.../Projects/<private-app>/` or workspace scan notes
- Session handoffs, AVS control state, or internal venture-tracker metadata (private)
- References to "portfolio" fixes tied to a specific private repo

**Use instead:** generic placeholders (`example-app/`, `my-service/`, `acme-corp/`)
and describe the *pattern* (e.g. "multi-env `.example` templates"), not the source repo.

Local-only notes belong in gitignored paths: `TODO.local.md`, `.local/`, `audit.md`,
`docs/sessions/`, `docs/plans/`.

Before opening a PR, search the diff for private product names and internal paths.
CI runs `pnpm check:private-names` (hash blocklist -- no plaintext codenames in the repo; an em dash or an en dash in a tracked file fails the same check). `pnpm lint` is ESLint and does not scan for those dashes.

## Release train

All four published packages (`@vaultcompass/vault-guard`, `-core`, `-mcp`,
`-telemetry`) are versioned in lockstep via [changesets](https://github.com/changesets/changesets).

### Rules

- One **minor** release every 2-4 weeks.
- **Patches** only for security fixes or correctness regressions -- not features.
- No ad-hoc edits to `version` in `package.json`. Use the train.
- **Do not reset to 0.x.** Stability comes from cadence, not renumbering.

### Every change needs a changeset

```bash
pnpm changeset   # interactive; picks minor/patch + writes a .changeset/*.md
```

Use Conventional Commit-style summaries: `fix(proxy): ...`, `feat(core): ...`.

### Cutting a release

Nothing lands on `main` directly, a release commit included. The version bump
goes through a pull request like any other change, and the tag is cut only
after `main`'s own CI is green on the merged result.

```bash
# 1. Accumulate changesets from all merged work, then branch off main:
git checkout main && git pull
git checkout -b release/vX.Y.Z

# 2. Bump all 4 packages + write CHANGELOG entries, and commit on the branch:
pnpm version-packages
git add -A && git commit -m "chore(release): vX.Y.Z"
git push -u origin release/vX.Y.Z

# 3. Open a PR, get it reviewed, and merge it.
gh pr create --base main --title "release: X.Y.Z"
```

Then, once the PR has merged and the CI run on `main` is green:

```bash
git checkout main && git pull
git tag -a vX.Y.Z -m "vX.Y.Z: <one-line summary>"
git push origin vX.Y.Z
# The release.yml workflow publishes @latest automatically.
```

Wait for `main`'s CI before tagging, not just the PR's. A registry `@latest`
publish cannot be undone, so the tag should only ever point at a commit that
has been validated in the state it will actually ship from.

### Soaking risky work on @next

```bash
pnpm release:next   # publishes to @next dist-tag; does not touch @latest
```

Promote to `@latest` by tagging once the soak passes.

## Pre-commit hook

The project installs a `vault-guard` pre-commit hook that scans staged files.
It requires the global `vault-guard` binary:

```bash
npm i -g @vaultcompass/vault-guard
```

If a clean rebuild drops the exec bit, run:

```bash
chmod +x packages/cli/dist/cli-entry.js
```

Never bypass with `--no-verify`.

## CI gates (must pass before merge)

- `test (22.x)` -- full test suite + coverage
- `lint` -- ESLint
- `bench` -- precision/recall regression gate (`node bench/run.cjs --assert`)
- `check:pack` -- no source maps or test artifacts in any tarball

Run the full suite locally before pushing:

```bash
pnpm install && pnpm build && pnpm check:pack
node scripts/gen-rules-doc.cjs && git diff --exit-code docs/RULES.md
pnpm lint && pnpm test && node bench/run.cjs --assert
```

## Out of scope (separate plans)

`vault-guard init` is **shipped** (see README Quickstart §0).

Do not start these without a dedicated plan signed off by the repo owner:

- Git history scanning
- Active AI-key verification (`--verify`)
- MCP deny-gate
- `.claude/` `.cursor/` artifact detection rule
- GitHub Action Marketplace listing
- TypeScript 6 upgrade

## Findings log

[FINDINGS.md](./FINDINGS.md) is a durable, append-by-PR record of what
vault-guard actually did when run against real code, including runs that
caught nothing. Open a PR to append a row after you run it against real
code, your own or someone else's.
