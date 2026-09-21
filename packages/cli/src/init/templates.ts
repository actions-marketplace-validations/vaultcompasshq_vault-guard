/** Stable init template version; bump when file contents change materially. */
export const INIT_TEMPLATE_VERSION = '4';

/**
 * The Action tag the generated workflow pins, which is NOT the CLI package
 * version and must not be derived from it.
 *
 * This used to read `v${readCliVersion()}`, and 1.7.1 is where that broke: it
 * is an action-only release, so the tag moved to v1.7.1 while the packages
 * stayed at 1.7.0. Deriving the pin from the package version would have
 * scaffolded `@v1.7.0` — the action that installs its scanner from inside the
 * tree it scans, which is the vulnerability 1.7.1 exists to close — into every
 * repository that ran `vault-guard init` after the release.
 *
 * Read the tag as "which version of the workflow step", not as "which version
 * of the scanner". Bump it whenever a release moves the Action tag, package
 * release or action-only alike; `init.test.ts` pins the shape and the
 * separation, and docs/INVARIANTS.md lists every other place either number
 * appears.
 */
export const ACTION_TAG = 'v1.8.1';

/**
 * `github/codeql-action/upload-sarif`, pinned to a full commit SHA rather than
 * the mutable `v3` tag this template used to scaffold.
 *
 * A tag is a moving reference: the code that runs in the consumer's repository,
 * with the consumer's `security-events: write`, is whatever that tag points at
 * on the day of the run. It is the same reasoning the `version` input now
 * applies to the scanner, and the same SHA this repository's own `ci.yml` pins,
 * so there is one value to bump rather than two spellings of it.
 */
export const UPLOAD_SARIF_SHA = '99df26d4f13ea111d4ec1a7dddef6063f76b97e9';
export const UPLOAD_SARIF_TAG = 'v4.37.0';

export const MANIFEST_RELATIVE_PATH = '.vault-guard/manifest.json';

export const MANAGED_FILE_PATHS = [
  '.vault-guard.json',
  '.github/workflows/vault-guard.yml',
  '.vault-guard/mcp-snippet.json',
  '.vault-guard/agent-rules.md',
  MANIFEST_RELATIVE_PATH,
] as const;

export type ManagedFilePath = (typeof MANAGED_FILE_PATHS)[number];

export function defaultVaultGuardConfigJson(): string {
  // Test trees are SCANNED by default, not ignored.
  //
  // Ignoring `**/__tests__/**` is what let a vendor-anchored key sitting in a
  // test file slip past the hook entirely: an ignore is total, so the scanner
  // never looked. Since 1.5.0 the sequential-run and test-context downgrades
  // keep the LOW-PRECISION rules (generic assignments, DSNs, JWTs, PEM headers)
  // at `low` on a test path.
  //
  // Vendor-anchored rules are NOT downgraded on a test path at all. The precise
  // consequence, which is both the point of this change and its cost: a
  // vendor-shaped value in a test blocks whether or not it is live, because the
  // scanner cannot distinguish a real `sk-ant-`/`ghp_`/`AKIA` string from a
  // convincing fabricated one. Fabricate test tokens as fragments joined at
  // runtime, or use the documented placeholder words. `init` prints a one-line
  // note saying exactly this on first run.
  //
  // `fixtures/**` and `bench/fixtures/**` stay for a DIFFERENT reason: those
  // directories conventionally hold deliberately-planted, contiguous credential
  // fixtures (a scanner's own true-positive corpus), and vendor-anchored rules
  // are never downgraded even on a test path, so scanning them would flood with
  // findings that are working as intended. A test tree is unit tests; a
  // fixtures tree is planted secrets.
  return `${JSON.stringify(
    {
      ignore: {
        patterns: ['fixtures/**', 'bench/fixtures/**'],
      },
    },
    null,
    2,
  )}\n`;
}

export function githubWorkflowYaml(): string {
  return `name: Vault Guard

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  secrets:
    runs-on: ubuntu-latest
    # Declared explicitly, because the default GITHUB_TOKEN is read-only and the
    # upload step below then fails with a 403 that says nothing about the scan.
    # Declared narrowly for the same reason it is declared at all: this job
    # reads your code and writes one code-scanning log, and nothing else.
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Pull-request mode reads the config and the baseline from the base
          # branch, so the base branch has to exist locally. A shallow clone
          # makes the scan exit 2 rather than fall back to trusting the pull
          # request, so this line is required, not an optimisation.
          fetch-depth: 0
      - uses: vaultcompasshq/vault-guard@${ACTION_TAG}
        id: vault-guard
        with:
          # No \`version\` input on purpose. It takes an EXACT scanner version
          # now and defaults to the one this Action tag shipped with, so the tag
          # above is the only pin to keep up to date. \`version: latest\` is
          # refused: a dist-tag hands the choice of scanner to the registry on
          # the morning of the run.
          path: .
          format: sarif
          sarif-output: vault-guard-results.sarif
      - uses: github/codeql-action/upload-sarif@${UPLOAD_SARIF_SHA} # ${UPLOAD_SARIF_TAG}
        # always(), so a scan that found something still gets its findings into
        # code scanning -- and guarded on the output being non-empty, because a
        # run that could not scan at all writes no document. Handing that empty
        # file to the uploader fails the job with a SARIF parse error sitting on
        # top of the real message.
        if: always() && steps.vault-guard.outputs.results-file != ''
        with:
          sarif_file: \${{ steps.vault-guard.outputs.results-file }}
`;
}

export function mcpSnippetJson(): string {
  return `${JSON.stringify(
    {
      mcpServers: {
        'vault-guard': {
          command: 'npx',
          args: ['-y', '@vaultcompass/vault-guard-mcp'],
        },
      },
    },
    null,
    2,
  )}\n`;
}

export function agentRulesMarkdown(): string {
  return `# Vault Guard — agent guardrails

Vault Guard is the local secret scanner for this repository. Follow these rules
before writing, editing, or committing code.

## Before applying edits

1. Call the Vault Guard MCP tool \`scan_text\` on any proposed file content that
   may contain credentials (API keys, tokens, connection strings, private keys).
2. If findings are returned, do **not** write the secret material. Redact or
   replace with environment variables / placeholders and scan again.
3. For whole files on disk, use \`scan_file\`. For directories, use
   \`scan_workspace\`.

## Before committing

- Ensure \`vault-guard scan --staged\` passes (pre-commit hook enforces this).
- Never use \`git commit --no-verify\` to bypass secret checks unless the user
  explicitly requests an emergency bypass.

## Merge MCP config (manual)

Copy the \`mcpServers\` block from \`.vault-guard/mcp-snippet.json\` into your
editor MCP config (e.g. \`~/.cursor/mcp.json\` or Claude Desktop config). Vault
Guard does not modify files outside this repository.

## History scanning

Vault Guard does not scan Git history. Use Gitleaks or TruffleHog for retroactive
history mining alongside Vault Guard's working-tree protection.
`;
}

export function templateContentForPath(relativePath: ManagedFilePath): string {
  switch (relativePath) {
    case '.vault-guard.json':
      return defaultVaultGuardConfigJson();
    case '.github/workflows/vault-guard.yml':
      return githubWorkflowYaml();
    case '.vault-guard/mcp-snippet.json':
      return mcpSnippetJson();
    case '.vault-guard/agent-rules.md':
      return agentRulesMarkdown();
    default:
      throw new Error(`No template for ${relativePath}`);
  }
}

export interface InitManifest {
  initVersion: string;
  templateVersion: string;
  createdAt: string;
  hookManager?: string;
  hookPath?: string;
  files: Array<{ path: string; action: 'created' }>;
}

export function buildManifestContent(
  files: Array<{ path: string; action: 'created' }>,
  hook?: { manager: string; path: string },
): string {
  const manifest: InitManifest = {
    initVersion: '1',
    templateVersion: INIT_TEMPLATE_VERSION,
    createdAt: new Date().toISOString(),
    files,
    ...(hook ? { hookManager: hook.manager, hookPath: hook.path } : {}),
  };
  return `${JSON.stringify(manifest, null, 2)}\n`;
}
