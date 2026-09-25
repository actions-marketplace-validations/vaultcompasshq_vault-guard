#!/usr/bin/env node
/**
 * Generates the bench/fixtures/secrets/ directory at runtime.
 *
 * WHY THIS EXISTS
 * ---------------
 * Committing files that contain contiguous secret-shaped strings (even
 * synthetic ones) is blocked by GitHub Advanced Security push protection and
 * would also be flagged by vault-guard's own pre-commit hook.  Storing the
 * values as split fragments here prevents both triggers while still producing
 * realistic fixture files that exercise vault-guard's detection patterns.
 *
 * HOW IT WORKS
 * ------------
 * Each entry below has a `parts` array.  At generation time the parts are
 * joined to produce the full value.  No individual part matches a secret
 * pattern; the complete value does.  Generated files land in
 * bench/fixtures/secrets/ which is gitignored.
 *
 * Run automatically by bench/run.cjs before scanning.
 * Can also be run directly:  node bench/generate-fixtures.cjs
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const OUT_DIR = path.join(__dirname, 'fixtures', 'secrets');
fs.mkdirSync(OUT_DIR, { recursive: true });

function write(filename, lines) {
  fs.writeFileSync(path.join(OUT_DIR, filename), lines.join('\n') + '\n', 'utf-8');
}

/** Write under fixtures/secrets/ preserving nested paths (e.g. caddytest/key.pem). */
function writeNested(relPath, content) {
  const full = path.join(OUT_DIR, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, 'utf-8');
}

// ---------------------------------------------------------------------------
// Fixture definitions -- parts joined at generation time
// ---------------------------------------------------------------------------

const fixtures = [
  {
    file: 'anthropic.ts',
    comment: 'True positive: Anthropic API key',
    lines: (j) => [
      `// ${j.comment}`,
      `const apiKey = ${JSON.stringify(
        ['sk-ant-', 'api03-', 'Zg7kP2mQxN4Rv', 'T8wYhLs6Fj', 'EbDcA9uKpViW3nOe', 'X1yMt5lHqJr0CsIzBdGfU-AAA'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai.ts',
    comment: 'True positive: OpenAI project key (sk-proj-…T3BlbkFJ…)',
    lines: (j) => [
      `// ${j.comment}`,
      // Split at the sk-proj- prefix boundary so no single string literal matches the
      // full pattern (sk-proj- alone is not a secret; the watermark+suffix fragment does
      // not start with the required prefix). The joined value is a real-shaped key.
      `const OPENAI_KEY = ${JSON.stringify(
        ['sk-proj-', 'aB3cD4eF5gH6iJ7kLmNoPqRsTuVw' + 'T3BlbkFJ' + 'xYz0123456789abcdefghijklmno'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai-svcacct.ts',
    comment: 'True positive: OpenAI service-account key (sk-svcacct-…T3BlbkFJ…)',
    lines: (j) => [
      `// ${j.comment}`,
      `const OPENAI_SVCACCT = ${JSON.stringify(
        ['sk-svcacct-', 'aB3cD4eF5gH6iJ7kLmNoPqRsTuVw' + 'T3BlbkFJ' + 'xYz0123456789abcdefghijklmno'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai-admin.ts',
    comment: 'True positive: OpenAI admin key (sk-admin-…T3BlbkFJ…)',
    lines: (j) => [
      `// ${j.comment}`,
      `const OPENAI_ADMIN = ${JSON.stringify(
        ['sk-admin-', 'aB3cD4eF5gH6iJ7kLmNoPqRsTuVw' + 'T3BlbkFJ' + 'xYz0123456789abcdefghijklmno'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai-legacy.ts',
    comment: 'True positive: OpenAI legacy user key (sk-<20>T3BlbkFJ<20>)',
    lines: (j) => [
      `// ${j.comment}`,
      // Legacy format: sk- + exactly 20 alphanum + T3BlbkFJ + 20 alphanum (48 chars total after sk-)
      `const OPENAI_LEGACY = ${JSON.stringify(
        ['sk-', 'aB3cD4eF5gH6iJ7kLmNo' + 'T3BlbkFJ' + 'PqRsTuVwXyZ012345678'].join(''),
      )};`,
    ],
  },
  {
    file: 'aws.ts',
    comment: 'True positive: AWS access key',
    lines: (j) => [
      `// ${j.comment}`,
      `const AWS_ACCESS_KEY_ID = ${JSON.stringify(['AKIA', 'Z3KYR7N4QWXB2FGH'].join(''))};`,
    ],
  },
  {
    file: 'github.ts',
    comment: 'True positive: GitHub classic PAT',
    lines: (j) => [
      `// ${j.comment}`,
      `const GITHUB_TOKEN = ${JSON.stringify(['ghp_', 'AbCdEfGhIjKlMnOpQrStUv', 'WxYz0123456789AB'].join(''))};`,
      `const GITHUB_FINE  = ${JSON.stringify(['github_pat_11AB', 'CDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde'].join(''))};`,
    ],
  },
  {
    file: 'stripe.ts',
    comment: 'True positive: Stripe live secret key',
    lines: (j) => [
      `// ${j.comment}`,
      `const STRIPE_LIVE = ${JSON.stringify(['sk_live_', 'AbCdEfGhIjKlMnOp', 'QrStUvWxYzAbCdEfGhIj', 'KlMnOpQrStUvWx'].join(''))};`,
    ],
  },
  {
    file: 'stripe-test-key.ts',
    comment: 'True positive: Stripe test key (real credential, sandbox scope)',
    lines: (j) => [
      `// ${j.comment}`,
      `const STRIPE_TEST = ${JSON.stringify(['sk_test_', 'AbCdEfGhIjKlMnOp', 'QrStUvWxYzAbCdEfGhIj', 'KlMnOpQrStUvWx'].join(''))};`,
    ],
  },
  {
    file: 'resend.ts',
    comment: 'True positive: Resend API key (standalone token, high entropy)',
    lines: (j) => [
      `// ${j.comment}`,
      `const RESEND_API_KEY = ${JSON.stringify(['re_', 'A1b2C3d4E5f6', 'G7h8J9k0L1m2', 'N3o4P5q6R7s8'].join(''))};`,
    ],
  },
  // --- 1.4.0 provider pack: post-2023 AI providers and backend platforms ---
  {
    file: 'groq.ts',
    comment: 'True positive: Groq API key (gsk_ + 52)',
    lines: (j) => [
      `// ${j.comment}`,
      `const GROQ_API_KEY = ${JSON.stringify(
        ['gsk_', 'K3mQ8vR2xN7bL4wY', 'tD6fH9jS1cP5zA0e', 'gU3iO7kM2nB8rV4x', 'Wq7z'].join(''),
      )};`,
    ],
  },
  {
    file: 'openrouter.ts',
    comment: 'True positive: OpenRouter key (sk-or-v1- + 64 hex)',
    lines: (j) => [
      `// ${j.comment}`,
      `const OPENROUTER_KEY = ${JSON.stringify(
        ['sk-or-', 'v1-', '3f8a9c2e7b1d4056', 'a9e3f71c2b8d6405', '7e2c9a1f3b8d5064', 'c1e7a93f2b6d8450'].join(''),
      )};`,
    ],
  },
  {
    file: 'xai.ts',
    comment: 'True positive: xAI API key (xai- + 80)',
    lines: (j) => [
      `// ${j.comment}`,
      `const XAI_API_KEY = ${JSON.stringify(
        [
          'xai-',
          'K3mQ8vR2xN7bL4wYtD6fH9jS1cP5zA0e',
          'gU3iO7kM2nB8rV4xW6yE1qT9sF2hJ5dG',
          'pZ7cX3vB9nM1kL5j',
        ].join(''),
      )};`,
    ],
  },
  {
    file: 'supabase.ts',
    comment: 'True positive: Supabase personal access token (sbp_ + 40 hex)',
    lines: (j) => [
      `// ${j.comment}`,
      `const SUPABASE_TOKEN = ${JSON.stringify(
        ['sbp_', '3f8a9c2e7b1d4056', 'a9e3f71c2b8d6405', '7e2c9a1f'].join(''),
      )};`,
    ],
  },
  {
    file: 'doppler.ts',
    comment: 'True positive: Doppler service token (dp.pt. + 43)',
    lines: (j) => [
      `// ${j.comment}`,
      `const DOPPLER_TOKEN = ${JSON.stringify(
        ['dp.', 'pt.', 'K3mQ8vR2xN7bL4wYtD6fH9jS1cP5zA0e', 'gU3iO7kM2nB'].join(''),
      )};`,
    ],
  },
  {
    file: 'slack.ts',
    comment: 'True positive: Slack incoming webhook URL',
    lines: (j) => [
      `// ${j.comment}`,
      `const SLACK_WEBHOOK = ${JSON.stringify(
        ['https://hooks.slack.com/services/', 'T01ABCDEF01/', 'B02GHIJKL02/', 'xyz123abc456def789ghi012'].join(''),
      )};`,
    ],
  },
  {
    file: 'database.ts',
    comment: 'True positive: database URL with real-looking credentials on a remote host',
    lines: (j) => [
      `// ${j.comment}`,
      `const DB_URL = ${JSON.stringify(
        ['postgresql://', 'admin:S3cur3P@ssw0rdXYZ@', 'prod-db.acme-corp.com:5432/app'].join(''),
      )};`,
    ],
  },
  {
    file: 'remote-dsn.ts',
    comment: 'True positive: remote PostgreSQL DSN -- real host + real password (NOT local)',
    lines: (j) => [
      `// ${j.comment}`,
      `const PROD_DB = ${JSON.stringify(
        ['postgresql://', 'svc_app:Xj8kP2mQ9zRv@', 'db.prod.acme-corp.com:5432/main'].join(''),
      )};`,
    ],
  },
];

/**
 * Nested text fixtures (not limited to top-level .ts files).
 *
 * The PEM header/footer are stored as joined fragments for the SAME reason as
 * the secrets above: the marker `-----BEGIN <TYPE> PRIVATE KEY-----` matches
 * vault-guard's own `ssh-private-key` pattern, so a contiguous copy in this
 * committed file would be flagged by the pre-commit hook. The fragments are
 * split mid-word so no single string literal matches the detector, while the
 * joined result is a valid PEM marker.
 */
const nestedFixtures = [
  // --- 1.4.7 Rust test-context pack ---
  //
  // These two are TP fixtures, not clean ones, and that is deliberate. Both
  // classes they cover are severity DOWNGRADES, not suppressions, so the file
  // still produces a finding and cannot be labelled clean. They also cannot
  // prove the Rust-specific logic on their own: every path under bench/
  // contains the segment `fixtures`, which the existing test-path rule already
  // downgrades. What they do guard is the direction that can actually regress
  // here, a future change that turns either downgrade into a suppression and
  // silently loses recall on real Rust code. The Rust-specific behaviour is
  // covered by the unit tests in packages/core.
  {
    relPath: 'rust/auth_tests.rs',
    comment: 'True positive: JWT in a Rust *_tests.rs file (path downgrades severity to low)',
    content: () =>
      [
        '// Rust keeps unit tests beside the source: src/auth/auth_tests.rs.\n',
        '#[test]\n',
        'fn parses_a_bearer_token() {\n',
        `    let token = "${[
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
          '.',
          'eyJzdWIiOiJ2Zy1iZW5jaCIsImlhdCI6MTcwMDAwMDAwMH0',
          '.',
          'Kq7mZr2xVb9nTd4wHs6yLc3pJf8gRu5eNa1v',
        ].join('')}";\n`,
        '    assert!(decode(token).is_ok());\n',
        '}\n',
      ].join(''),
  },
  {
    relPath: 'rust/inline_cfg_module.rs',
    comment: 'True positive: generic key inside an inline #[cfg(test)] module (downgraded to low)',
    content: () =>
      [
        'use crate::auth::Client;\n',
        '\n',
        'pub fn build() -> Client {\n',
        '    Client::new()\n',
        '}\n',
        '\n',
        '#[cfg(test)]\n',
        'mod tests {\n',
        '    use super::*;\n',
        '\n',
        '    #[test]\n',
        '    fn builds_with_a_throwaway_key() {\n',
        `        let api_key = "${['Kq7mZr2xVb9n', 'Td4wHs6yLc3p'].join('')}";\n`,
        '        assert!(Client::with_key(api_key).is_ok());\n',
        '    }\n',
        '}\n',
      ].join(''),
  },
  {
    relPath: 'caddytest/key.pem',
    comment: 'True positive: RSA private key in caddytest/ (path downgrades severity to low)',
    content: () =>
      [
        ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join('') + '\n',
        'MIIEpAIBAAKCAQEAx32kL3AXuPTjn0Wd0+wN653+urjWMRkWxU5W2NCCNLUDly3o\n',
        ['-----END RSA PRIV', 'ATE KEY-----'].join('') + '\n',
      ].join(''),
  },
];

// ---------------------------------------------------------------------------

let written = 0;
for (const f of fixtures) {
  write(f.file, f.lines(f));
  written++;
}
for (const f of nestedFixtures) {
  writeNested(f.relPath, f.content(f));
  written++;
}

if (process.env.BENCH_VERBOSE || process.argv.includes('--verbose')) {
  console.log(`[generate-fixtures] wrote ${written} fixture files to bench/fixtures/secrets/`);
}
