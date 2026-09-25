# @vaultcompass/vault-guard-mcp

## 1.7.0

### Patch Changes

- Config schema validation now runs on every load, so a `.vault-guard.json` that parses as JSON but fails the schema is reported through the existing config-error path instead of loading with the bad parts silently dropped.
- Updated dependencies
  - @vaultcompass/vault-guard-core@1.7.0
  - @vaultcompass/vault-guard-telemetry@1.7.0

## 1.6.0

### Patch Changes

- Updated dependencies
  - @vaultcompass/vault-guard-core@1.6.0
  - @vaultcompass/vault-guard-telemetry@1.6.0

## 1.5.0

### Minor Changes

- Security fixes and suppression visibility.

  **`git show :<path>` could be steered onto a different blob (core).** git's
  `:<path>` revision syntax also accepts `:<stage>:<path>`, so a staged file whose
  repo-relative path began `0:`, `1:`, `2:` or `3:` was read as a stage reference
  to a different, shorter path. Staged beside a clean file of that shorter name,
  the scanner read the clean neighbour while recording the finding against the
  crafted name, letting a real staged secret through under a clean result.
  `readGitIndexFile` now resolves the blob by object id (`git ls-files -s`, then
  `git cat-file blob`) so no attacker-controlled path text reaches git's revision
  grammar.

  **The MCP token walk followed symlinks out of the workspace (mcp).**
  `report_token_usage` walked with `fs.statSync`, followed symlinks, and kept no
  visited set, so a symlinked directory inside the workspace pointing outside was
  followed out of it and a cycle could recurse without bound. It now mirrors the
  core walker: `lstat` every entry, never follow a symlink, and gate descent on a
  realpath visited-set. `scan_file` and `scan_text` now refuse inputs above the
  same 10 MB cap `scan_workspace` already enforces.

  **A muted scanner now says so (core, cli).** Baseline and inline
  `vault-guard: ignore-line` / `ignore-next-line` suppressions were silent. The
  text summary now prints a suppression line every run, and JSON and SARIF carry
  `run.baseline_suppressed` and a new `run.inline_suppressed` field (emitted even
  at zero), with a `suppression.inline` diagnostic naming the suppressed line
  numbers. What is or is not suppressed is unchanged; only its visibility.

### Patch Changes

- Updated dependencies
  - @vaultcompass/vault-guard-core@1.5.0
  - @vaultcompass/vault-guard-telemetry@1.5.0

## 1.4.7

### Patch Changes

- **Three false-positive classes found by scanning a public Rust monorepo.**
  A scan of that repository produced 30 findings, 20 of them blocking, and
  every one was a test fixture, a hand-typed placeholder, or a Sentry DSN
  that is public by design. All three classes are fixed here; the same scan
  now reports 23 findings, all at `low`, and exits 0.

  **Rust test files are recognised.** `TEST_FILE_PATTERNS` covered JS/TS, Go
  and Python but not Rust. Cargo has no separate directory for unit tests, so
  a crate keeps them beside its source as `src/auth/auth_tests.rs`, and every
  throwaway token in one kept its full severity even though the rules
  involved were already on the test-path downgrade list. `*_tests.rs` and
  `*_test.rs` now downgrade the same way `*_test.go` does.

  **Inline `#[cfg(test)]` modules are recognised.** Rust's dominant unit-test
  convention puts the tests in the same file as the production code, which no
  path heuristic can see. A new content-side signal locates in-file test
  regions and grants a match inside one the same downgrade a test path
  grants. It is a line-based heuristic, not a parser: a `cfg` attribute
  mentioning `test` at column 0, introducing a `mod` or `fn`, opens a region
  that runs to end of file, closing early at a later `#[cfg(not(test))]` or at
  the next top-level item without the attribute. An indented attribute is
  ignored, so a test item nested inside an `impl` keeps its full severity.
  The finder is a per-language registry; Rust is the only implementation.

  **Alphabet-run placeholders no longer defeat the entropy gate.** Shannon
  entropy counts character frequencies and throws the order away, so a strict
  run such as `abcdefghijklmnopqrstuvwxyz0123456789` scores at the top of the
  range for its length and walks straight through. A new check ahead of the
  entropy gate drops any value where at least 75% of the characters sit
  inside runs of three or more consecutive code points, ascending or
  descending. A value that is half run and half random scores 50% and
  survives. Unlike the entropy gate this one applies to vendor-anchored rules
  too, which is where it matters: it is safe there because a real provider
  key comes from a random source and cannot be the alphabet.

  Both test-context changes are severity downgrades, never suppressions, and
  neither touches vendor-anchored provider keys: a real provider key is a
  real key even in a test file. If your repository carries a counting or
  alphabet-run placeholder under a real vendor prefix, that finding will now
  disappear rather than block.

- Updated dependencies
  - @vaultcompass/vault-guard-core@1.4.7
  - @vaultcompass/vault-guard-telemetry@1.4.7

## 1.4.6

### Patch Changes

- 9b09eb2: **`scan --staged` no longer reports success over files it never scanned.**
  Two defects combined into a fail-open in the pre-commit gate.

  First, the staged file list was read with a git command that honours
  `diff.relative`, an ordinary repo config. With it set, `git diff --cached
--name-only` printed paths relative to the caller's working directory and
  omitted every staged path above it, while the code resolved those paths as
  if they were relative to the worktree root. Run from a subdirectory, the
  scanner therefore missed staged files entirely and could not read the ones
  it did see. `diff.relative` and `core.quotePath` are now forced off per
  invocation, and staged paths resolve against the worktree root that git
  reports rather than the caller's cwd, so no repository setting can change
  which files the gate looks at.

  Second, a staged file the scanner could not read was downgraded to a
  warning, and the run still printed `SUCCESS: No secrets found` and exited 0. An unreadable staged file is now fatal: exit code 2, no success line, and
  a message naming each file and why it could not be read. JSON and SARIF
  carry the same fact as `run.unscannable_files` alongside the existing
  error-severity `file.read_error` diagnostic.

  A directory scan reports an unreadable file the same way but still exits on
  findings only. Its file set is discovered rather than declared by git, and
  unreadable entries in a walked tree are ordinary; `run.unscannable_files` is
  there for integrators who want the stricter rule.

  **Consumer-visible exit-code change.** When a `--staged` run both finds a
  secret AND could not read some staged file, it now exits 2 rather than 1.
  The incomplete scan dominating is deliberate, because a run that skipped
  files cannot report a complete finding set, but a script branching on `1`
  alone will stop seeing the secrets-found signal in that case. Treat any
  non-zero exit as a block; read `run.blocking_matches` and
  `run.unscannable_files` to tell the two apart. The installed pre-commit
  hooks were updated to match: on exit 2 they say the scan could not complete
  and offer no `--no-verify` hint, since the check never ran.

  A staged **submodule** pointer bump no longer blocks the commit. Its index
  entry is a gitlink rather than a blob, so there is no content to scan;
  `--ignore-submodules=all` drops it from the staged listing.

  A staged run is now anchored entirely at the **repository root** rather than
  at the caller's working directory: the config it loads, the baseline it
  consults, the `ignore` patterns it matches, the fingerprints it computes and
  every path it prints or serializes. Running the hook from a subdirectory
  previously emitted absolute machine paths in JSON `file` and SARIF `uri` for
  anything above that directory, applied `ignore` rules a root-level run would
  not have applied, and produced baseline fingerprints that only matched on one
  machine's layout.

  **Behaviour change for per-directory configs.** A `.vault-guard.json` or
  `.vault-guard.baseline.json` that lives only in a SUBDIRECTORY is no longer
  consulted on a staged run; only the repository root and above are searched.
  The staged file set is repository-wide, so the rules applied to it have to be
  repository-wide too. Loading a nested config and then matching it against the
  root was the bug: `ignore.paths: ["fixtures/**"]` in `sub/.vault-guard.json`
  meant `<root>/fixtures/` to the matcher and `sub/fixtures/` to whoever wrote
  it, so a staged secret at the root was silently exempted while the directory
  the author meant to exempt was scanned. Move such a config to the repository
  root to keep it in effect for `--staged`. A directory scan is unaffected and
  still loads its config from the directory it was pointed at.

- Updated dependencies [9b09eb2]
  - @vaultcompass/vault-guard-core@1.4.6
  - @vaultcompass/vault-guard-telemetry@1.4.6

## 1.4.5

### Patch Changes

- bb02f32: **SARIF output no longer leaks absolute local paths.** `artifactLocation.uri`
  is now relative to the scan root when the target sits outside the cwd
  (`--staged` uses cwd itself); an in-checkout target's uri is unchanged.
  Diagnostic ctx in SARIF notifications -- dir/path/file fields and
  free-form error text -- gets the same treatment, so scan warnings no
  longer carry absolute paths into the document either. JSON output is
  unchanged; its `file` paths stay cwd-relative.

  Covered by unit tests on both formatters and end-to-end scans of an
  in-tree and an out-of-tree target (one with an unreadable subdirectory),
  asserting no absolute path appears anywhere in the emitted document.

- Updated dependencies [bb02f32]
  - @vaultcompass/vault-guard-core@1.4.5
  - @vaultcompass/vault-guard-telemetry@1.4.5

## 1.4.4

### Patch Changes

- 06400b9: Fix the native pre-commit hook installing into husky 9's generated,
  gitignored hooks directory instead of the tracked hook file.

  Husky 9 sets core.hooksPath to .husky/_, a GENERATED directory that
  husky's own prepare script rewrites on every `pnpm install`. The file git
  actually runs there is a two-line dispatcher that sources husky's `h`
  shim, which in turn execs the TRACKED .husky/<hookname> file. The prior
  relative-hooksPath fix correctly resolved .husky/_ as the effective hooks
  directory, but the default native manager then wrote vault-guard's hook
  straight into that generated directory: init reported success, and the
  hook worked until the next `pnpm install` silently wiped it. The same bug
  made init's foreign-hook check read the generated dispatcher instead of
  the tracked hook, so a repository already using husky 9 got a confusing
  "Existing Husky pre-commit has no vault-guard stanza" conflict about the
  wrong file.

  The fix detects a husky-generated hooks directory by directory SHAPE
  alone: a resolved basename of `_` under a directory literally named
  `.husky`. Only the native manager is affected, and only when that shape
  matches; it then installs into the same tracked hook file husky's own
  `h` shim actually runs, saying so in the output. `--manager husky` is
  no longer required in this case. The foreign-hook check now resolves to
  the same tracked file, so it names and inspects the right thing.
  Nothing is ever written under the generated directory, and husky 8
  (core.hooksPath=.husky, no generated subdirectory) is untouched by this
  change -- its shape never matches, so the existing native install path
  keeps handling it exactly as before.

  The tracked-hook target is computed as the PARENT of the generated `_`
  directory, joined with the hook name -- never a fixed `<cwd>/.husky`.
  An earlier version of this fix hardcoded the latter, on the reasoning
  that it matched the explicit `husky` manager's own always-cwd
  convention; independent review proved that wrong with a functional
  husky shim and a real commit, for the ordinary monorepo shape where the
  package that owns husky's "prepare" script is not the git root
  (core.hooksPath like `packages/app/.husky/_`). Husky's shim resolves
  the tracked hook it actually executes relative to where the generated
  directory itself lives, not relative to the repository root, so the
  fixed-cwd answer reported success at a path git never read while git
  ran the nested one, unguarded. `install`/`init` must be run from the
  git repository root (not a package subdirectory) either way -- both
  already refuse outright otherwise.

  An earlier version of this detection also treated the presence of
  husky's `h` shim, or dispatcher-shaped content in an existing
  pre-commit file, as sufficient on their own to trigger the redirect.
  Review (informed by the same fix regressing in two sibling repos) caught
  that both are false-positive-prone taken alone -- an unrelated directory
  that happens to contain a file named `h`, or a coincidentally
  dispatcher-shaped foreign hook sitting somewhere that is not
  `.husky/_`, would have been misdetected as husky and silently
  redirected. Directory shape is now the only signal that may trigger the
  redirect at all.

  Also confirmed (with a scratch shell reproduction before writing the
  regression test) that the generated hook script's existing status
  handling -- `vault-guard scan --staged || { ... exit 1 }` -- stays safe
  under husky's own `sh -e` re-exec of the tracked hook: because the scan
  command is the first half of an OR list, POSIX exempts it from errexit,
  so the "COMMIT BLOCKED" explanation always prints. A naive rewrite using
  a bare `vault-guard scan --staged` line followed by `status=$?` would
  NOT be exempt and would silently lose that explanation under `sh -e`;
  proven wrong here on purpose, not shipped.

  Proven the same way as the relative-hooksPath fix: husky 9 and husky 8
  layouts built by hand, then real git commits driven through a stub
  vault-guard binary (exit codes 1 and 2) on PATH, asserting both that the
  commit is refused and that the stub's own announce line actually
  appears in the output -- so a crashed hook can never be mistaken for a
  real block.

  One more defect the reviewer found while re-checking uninstall, now
  that the redirect routes every husky 9 repo through it: uninstall only
  knew how to strip an appended "# --- vault-guard ---" block. A hook
  vault-guard wrote WHOLE from the template -- the fresh-install path,
  which is exactly what the husky redirect takes -- has no such block, so
  the old logic matched nothing, rewrote the file byte-identical, and
  reported success with the hook still installed. Fixed by giving the
  template its own header line and having uninstall recognize it: a
  whole-file hook is now removed entirely; an appended stanza is still
  just stripped, keeping whatever foreign content it was appended to;
  anything that merely mentions "vault-guard" in neither shape is left
  untouched with an honest message, and uninstall now reports success
  only when the hook no longer reads as installed afterwards.

- Updated dependencies [06400b9]
  - @vaultcompass/vault-guard-core@1.4.4
  - @vaultcompass/vault-guard-telemetry@1.4.4

## 1.4.3

### Patch Changes

- 3384dd4: Fix the native pre-commit hook installing to the wrong directory when
  core.hooksPath is a relative path.

  Git resolves a relative core.hooksPath against the working-tree root, not
  against the .git directory. PreCommitHook.getEffectiveHooksDir resolved it
  against .git instead, so a repository with husky 9 installed (which sets
  core.hooksPath=.husky/_) had vault-guard init and install-hook write the
  hook to .git/.husky/_/pre-commit, report success, and never actually run:
  git looks for the hook at .husky/\_/pre-commit and finds nothing there.

  The fix resolves a relative core.hooksPath against git rev-parse
  --show-toplevel instead. An absolute core.hooksPath is still used exactly
  as given, and no core.hooksPath at all still resolves against the git
  directory, which is unchanged and correct on its own: a linked worktree
  or a submodule has a git directory that is not its working-tree root, and
  an unset core.hooksPath has to keep pointing there.

  Proven with a test that drives a real git commit through a stub
  vault-guard binary that exits non-zero, rather than only asserting on the
  installed path: with the hook actually reaching the place git reads it,
  the commit is refused; before the fix it silently succeeded because the
  gate was never really there. An existing test in this file had asserted
  the old, wrong .git-relative location and has been corrected rather than
  left in place.

- Updated dependencies [3384dd4]
  - @vaultcompass/vault-guard-core@1.4.3
  - @vaultcompass/vault-guard-telemetry@1.4.3

## 1.4.2

### Patch Changes

- 46409ac: 1.4.2 close-out: a handful of loose ends from the last release.

  - `vault-guard init` was still writing a GitHub Actions workflow template
    pinned to `vaultcompasshq/vault-guard@v1.2.0`, three releases behind. It now
    pins the current release tag, and a test asserts the pin always matches the
    CLI's own package version so it cannot go stale again unnoticed.
  - SARIF output had two defects: results were missing `partialFingerprints`
    (needed for GitHub Code Scanning to track a finding's identity across
    runs), and `artifactLocation.uri` could come out as an absolute path with
    backslash separators on Windows-style input, which is not a legal SARIF
    relative-reference URI. Both are fixed: results now carry the same
    fingerprint the JSON output already emits per finding, and the uri is
    relative for files under the scan root, with forward slashes.
  - The JSON output documentation (README and docs/PRODUCT_SCOPE.md) now says
    plainly that a pass/fail gate must read `run.blocking_matches`, not
    `summary.secrets`. The first real integrator built its gate on
    `summary.secrets`, which ignores the fail_on threshold. The JSON shape is
    unchanged.
  - `qs`, pulled in transitively through `@modelcontextprotocol/sdk` under the
    MCP package, resolved to a version with two moderate audit advisories.
    Pinned via pnpm.overrides to a patched version; this repo's own
    `pnpm audit` is clean. That override only cleans this repo's own audit,
    though: a downstream consumer of the published MCP package still gets
    `qs` 6.16.0 by ordinary semver range resolution, not by any guarantee.
    The durable fix is an `@modelcontextprotocol/sdk` bump once one ships
    with a patched `qs` in its own dependency tree.
  - `better-sqlite3` was a hard dependency of the telemetry package, which was
    in turn a hard dependency of the CLI and MCP packages, and it compiles
    from source. A Windows CI job with no Visual Studio build tools failed at
    install, before any test ran. `better-sqlite3` is now an optional
    dependency, loaded lazily, and every telemetry entry point (recording and
    reading) degrades to a no-op when the native binding is unavailable
    instead of throwing. The CLI, MCP server, and statusline all keep working
    with telemetry absent; nothing is recorded, and nothing warns on every
    command.

- Updated dependencies [46409ac]
  - @vaultcompass/vault-guard-core@1.4.2
  - @vaultcompass/vault-guard-telemetry@1.4.2

## 1.3.0

### Minor Changes

- 0a8d125: Windows hook companion, staged-index scan fix, init conflict guidance, and 1.3.0 docs.

  Native `install-hook` / `init` write an optional `pre-commit.cmd` beside the POSIX
  `pre-commit` (Git for Windows still runs the extensionless hook via sh).
  `scan --staged` reads index blobs so staged-then-deleted or partially staged secrets
  are not skipped. `vault-guard init` detects Husky/Lefthook/pre-commit layouts,
  conflicts on foreign `.cmd` files, and refreshes the companion without overwriting
  foreign hooks. README adds a recommended stack (Vault Guard + Gitleaks + TruffleHog)
  and clarifies Windows hook behavior. TokenCounter uses `path.extname` on the basename
  so temp dirs with dots no longer mis-bucket files.

### Patch Changes

- Updated dependencies [0a8d125]
  - @vaultcompass/vault-guard-core@1.3.0
  - @vaultcompass/vault-guard-telemetry@1.3.0

## 1.2.3

### Patch Changes

- Updated dependencies
  - @vaultcompass/vault-guard-core@1.2.3
  - @vaultcompass/vault-guard-telemetry@1.2.3

## 1.2.2

### Patch Changes

- @vaultcompass/vault-guard-core@1.2.2
- @vaultcompass/vault-guard-telemetry@1.2.2

## 1.2.1

### Patch Changes

- @vaultcompass/vault-guard-core@1.2.1
- @vaultcompass/vault-guard-telemetry@1.2.1

## 1.2.0

### Patch Changes

- @vaultcompass/vault-guard-core@1.2.0
- @vaultcompass/vault-guard-telemetry@1.2.0

## 1.1.2

### Patch Changes

- @vaultcompass/vault-guard-core@1.1.2
- @vaultcompass/vault-guard-telemetry@1.1.2

## 1.1.1

### Patch Changes

- c358939: Harden MCP workspace boundaries and fix reported scan locations.

  MCP file, workspace, and token-report tools now reject paths outside the server
  workspace, including traversal and symlink escapes. MCP workspace scans now also
  honor `.vault-guard.json` ignore patterns.

  Scan matches now distinguish display columns from absolute offsets, so CLI,
  SARIF, editor diagnostics, and JSON output point at the right line-relative
  column. JSON output now includes `matches[].offset` for callers that need an
  absolute position. Baseline fingerprints remain compatible with existing
  `.vault-guard.baseline.json` entries.

  The GitHub Action now runs Node 22 and always emits `results-file` before
  returning the scanner exit code. `vault-guard check` now delegates to the normal
  scan path so config and baselines apply consistently.

- Updated dependencies [c358939]
  - @vaultcompass/vault-guard-core@1.1.1
  - @vaultcompass/vault-guard-telemetry@1.1.1

## 1.1.0

### Minor Changes

- fix(core): broaden OpenAI key detection with T3BlbkFJ watermark -- adds svcacct/admin/legacy

  The previous `openai` pattern (`sk-[a-zA-Z0-9]{48}`) was a fixed 48-char match
  from the pre-2024 key format. Modern OpenAI keys use a `T3BlbkFJ` watermark
  (base64 for "OpenAI") and come in four formats, all of which were missed:

  - `sk-proj-` -- project-scoped key (the current default)
  - `sk-svcacct-` -- service-account key for non-human identities
  - `sk-admin-` -- org-wide admin key (cannot call inference APIs)
  - `sk-` (legacy) -- pre-project user key with watermark at positions 20 and 40+

  Each format now has its own rule entry (distinct blast radius). The legacy `sk-`
  catch-all uses a token-boundary lookbehind and requires the watermark, preventing
  short/benign `sk-` identifiers from triggering false positives.

  Per-format recall tests and bench fixtures (TP + FP guard) are included.
  `docs/RULES.md` is updated to reflect the four OpenAI entries.

- fix(proxy): parse Anthropic SSE usage so streaming records real tokens and cost

  The proxy previously recorded `inputTokens: 0, outputTokens: 0` for all streaming
  responses (the "proxy-stream" telemetry source). Streaming is how Cursor and Claude
  Code actually send requests, so the cost-tracking value prop was non-functional for
  real traffic.

  The stream path now tees a bounded copy of the SSE body (same 1 MB cap as the
  non-streaming path) and parses token usage from the Anthropic SSE event stream:
  `message_start` carries `input_tokens`; the last `message_delta` carries cumulative
  `output_tokens`. The cost is computed automatically from the existing `calculateCost`
  table. If the tee cap is exceeded, a new `proxy-stream-overflow` source is recorded
  so missing usage is visible in telemetry.

  A new pure module `proxy-sse.ts` contains the parser; it is unit-testable without
  spinning up an HTTP server. The existing integration test that previously asserted
  the broken `inputTokens: 0` has been updated to assert real token counts.

### Patch Changes

- Updated dependencies
- Updated dependencies
  - @vaultcompass/vault-guard-core@1.1.0
  - @vaultcompass/vault-guard-telemetry@1.1.0
