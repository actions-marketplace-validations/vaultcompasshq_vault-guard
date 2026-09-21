import fs from 'fs';
import { SecretMatch } from '../types';
import { VaultGuardConfig } from '../config';
import { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from '../utils/entropy';
import { isPlaceholderSecret, isNonSecretConnectionString, isSampleJwt, isRedactedTemplateValue, isEnvVarNameToken, isCodeIdentifierReference, isPasswordHash, isPemHeaderWithoutBody, isSequentialRunPlaceholder } from '../utils/placeholder';
import { applyPathAwareSeverity } from '../utils/path-severity';
import { LOW_PRECISION_PATH_DOWNGRADE_IDS } from '../utils/path-downgrade-ids';
import { findInlineTestRegions, isInsideInlineTestRegion } from '../utils/inline-test-context';
import { shouldSuppressDocContextMatch, isInsidePythonTripleQuoted } from '../utils/doc-context';
import {
  validateRegexLength,
  validateRegexSafety,
} from '../utils/regex-safety';

// ---------------------------------------------------------------------------
// Pattern registry
// ---------------------------------------------------------------------------

interface PatternEntry {
  regex: RegExp;
  severity: SecretMatch['severity'];
  /**
   * Minimum Shannon entropy (bits/char) required for the raw matched value.
   * If set and the match falls below the threshold the match is dropped  -- 
   * this is the primary defence against false positives on broad patterns.
   */
  minEntropy?: number;
  /**
   * Apply the *aggressive* placeholder filter (test-fixture words such as
   * `test`, `password`, `sample`). Only set on low-precision generic /
   * assignment patterns -- vendor-anchored keys always use the standard filter
   * so recall on real credentials is unaffected.
   */
  aggressivePlaceholder?: boolean;
  /**
   * Treat the match as a database/Redis connection string and suppress it when
   * the host is local/docker/reserved-TLD or the password is a placeholder /
   * default (see {@link isNonSecretConnectionString}). Prevents the dominant
   * real-world false positive: localhost & example DSNs in docker-compose,
   * `.env.example`, and test fixtures.
   */
  connectionString?: boolean;
}

/**
 * Vendor-specific patterns anchored to known prefixes / structures.
 *
 * Deliberately NOT included (too broad / not actual secrets):
 *   - cohere            (`[a-zA-Z0-9]{40}`)   -- matches git SHAs, MD5s, …
 *   - aws-secret        (`[a-zA-Z0-9/+]{40}`) -- matches any base-64-ish string
 *   - circleci-token    (`[a-zA-Z0-9_-]{40}`) -- identical problem
 *   - jenkins-token     (`[a-zA-Z0-9]{32}`)   -- matches MD5 hashes
 *   - kubernetes-token  (JWT)                 -- merged into jwt-token
 *   - elasticsearch-url (`https://u:p@h:n`)   -- matches any auth URL
 *   - ssh-rsa-public    / ssh-ed25519-public  -- public keys are NOT secrets
 *   - google-analytics  / google-analytics-4  -- publishable measurement IDs
 *   - twilio-account    (AC…)                 -- public Account SID, not secret
 *
 * AWS secret access key is retained as a context-anchored pattern only.
 */
const BUILTIN_PATTERNS: ReadonlyMap<string, PatternEntry> = new Map([
  // --- AI / ML providers ---
  ['anthropic',         { regex: /sk-ant-[a-zA-Z0-9_-]{20,}/g,                                                         severity: 'critical' }],
  // OpenAI key formats. All current keys embed the T3BlbkFJ watermark (base64 "OpenAI").
  // Specific prefixes are ordered first so they get their own rule title (blast radius differs).
  // The legacy sk- catch-all uses the watermark + token-boundary so it does not shadow the
  // prefixed rules and avoids matching short benign identifiers.
  //
  // DELIBERATE: we do NOT match the pre-2023 bare `sk-<48 alphanumerics>` format (no watermark).
  // That pattern fires on any base64/hex blob following `sk-` and floods false positives; the
  // watermark is the only reliable discriminator, matching the gitleaks/trufflehog consensus.
  // Do not re-add a bare `sk-[A-Za-z0-9]{N,}` rule without an entropy gate and a bench FP guard.
  ['openai-project',    { regex: /sk-proj-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}/g,                       severity: 'critical' }],
  ['openai-svcacct',    { regex: /sk-svcacct-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}/g,                    severity: 'critical' }],
  ['openai-admin',      { regex: /sk-admin-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}/g,                      severity: 'critical' }],
  // Legacy user key (sk-<20>T3BlbkFJ<20+>). Token-boundary anchored so benign sk- prefixes
  // in identifiers (e.g. sk-None-short) don't fire without the watermark present.
  ['openai',            { regex: /(?<![A-Za-z0-9_-])sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20,}/g,                    severity: 'critical' }],
  ['huggingface',    { regex: /hf_[a-zA-Z0-9]{34,}/g,                                           severity: 'critical' }],
  ['replicate',      { regex: /r8_[a-zA-Z0-9]{32}/g,                                            severity: 'critical' }],
  // Post-2023 AI provider keys. The product's stated wedge is AI-assisted
  // coding, so these carry the same weight as the OpenAI/Anthropic rules.
  // Every one is prefix-anchored with a fixed length, so no entropy gate is
  // needed (same precision profile as `ghp_` / `hf_`).
  ['groq',           { regex: /(?<![A-Za-z0-9_-])gsk_[a-zA-Z0-9]{52}/g,                          severity: 'critical' }],
  ['openrouter',     { regex: /sk-or-v1-[a-f0-9]{64}/g,                                          severity: 'critical' }],
  ['xai',            { regex: /(?<![A-Za-z0-9_-])xai-[a-zA-Z0-9]{80}/g,                          severity: 'critical' }],
  ['perplexity',     { regex: /(?<![A-Za-z0-9_-])pplx-[a-zA-Z0-9]{40,}/g,                        severity: 'critical' }],
  ['mistral',        { regex: /(?:mistral_api_key|MISTRAL_API_KEY)\s*[=:]\s*["']?([a-zA-Z0-9]{32})/g, severity: 'critical' }],
  ['together-ai',    { regex: /(?:together_api_key|TOGETHER_API_KEY)\s*[=:]\s*["']?([a-f0-9]{64})/g,  severity: 'critical' }],
  ['fireworks-ai',   { regex: /(?<![A-Za-z0-9_-])fw_[a-zA-Z0-9]{24,}/g,                          severity: 'critical' }],
  ['langsmith',      { regex: /lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}/g,                       severity: 'critical' }],
  ['deepseek',       { regex: /(?:deepseek_api_key|DEEPSEEK_API_KEY)\s*[=:]\s*["']?(sk-[a-f0-9]{32})/g, severity: 'critical' }],

  // --- Payment processors ---
  // NOTE: `sk_live_` / `sk_test_` are not unique to Stripe -- Clerk uses the
  // same prefixes and there is no reliable discriminator in the key body, so a
  // Clerk secret key is reported under the `stripe` rule id. The finding is
  // correct (it IS a live secret key); only the vendor label may be wrong. The
  // id is kept as-is because baseline fingerprints include the rule id and
  // renaming it would silently invalidate every existing baseline entry.
  ['stripe',         { regex: /sk_live_[a-zA-Z0-9]{24,}/g,                                      severity: 'critical' }],
  ['stripe-test',    { regex: /sk_test_[a-zA-Z0-9]{24,}/g,                                      severity: 'high' }],
  ['paypal',         { regex: /access_token\$production\$[a-zA-Z0-9]{20,}/g,                    severity: 'critical' }],

  // --- Cloud providers ---
  ['aws-access',          { regex: /AKIA[0-9A-Z]{16}/g,                                          severity: 'critical' }],
  // Context-anchored AWS secret: only flags values that appear on the same
  // line as the canonical env-var / config-key name.
  ['aws-secret-context',  { regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([a-zA-Z0-9/+]{40})/gi, severity: 'critical' }],
  ['gcp-service-account', { regex: /"type":\s*"service_account"/g,                               severity: 'critical' }],
  ['gcp-api-key',         { regex: /AIza[a-zA-Z0-9_-]{35}/g,                                    severity: 'critical' }],
  // OAuth 2.0 client ID, not a secret: Google documents these as safe for
  // client-side / public embedding (only the paired client *secret* is
  // sensitive). Kept at low severity for visibility, not blocking.
  // The numeric client-id prefix is bounded ({1,64}) so a long unbroken digit
  // run cannot make `[0-9]+` backtrack quadratically. A real Google client-id
  // prefix is a short project number, well under 64 digits. Measured: the
  // unbounded form took 16.6s on a 200k-digit run (quadratic); bounded it is
  // linear.
  ['gcp-oauth',           { regex: /[0-9]{1,64}-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g, severity: 'low' }],
  ['azure-storage',       { regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}/g, severity: 'critical' }],

  // --- Database connection strings ---
  //
  // Every component is bounded. The unbounded form was quadratic: `[^:@\s]+`
  // ends at a `:`, but the NEXT class `[^@\s]+` also contains `:`, so every
  // colon is a viable split for the first component and each split rescans to
  // the end of the buffer looking for an `@` that may never come. On a buffer
  // of repeated scheme literals (many viable start offsets) that measured
  // 200k = 1.4s to 2.3s per rule, quadratic. Bounding each component to a sane
  // maximum (user/password/host 256, port 8 digits, path 1024) caps the
  // per-start work and makes all four linear; no real DSN comes close to these
  // limits.
  ['postgresql-url', { regex: /postgres(?:ql)?:\/\/[^:@\s]{1,256}:[^@\s]{1,256}@[^:\s/]{1,256}(?::\d{1,8})?\/\S{1,1024}/g, severity: 'critical', connectionString: true }],
  ['mysql-url',      { regex: /mysql:\/\/[^:@\s]{1,256}:[^@\s]{1,256}@[^:\s/]{1,256}(?::\d{1,8})?\/\S{1,1024}/g,            severity: 'critical', connectionString: true }],
  ['mongodb-url',    { regex: /mongodb(?:\+srv)?:\/\/[^:@\s]{1,256}:[^@\s]{1,256}@[^:\s/]{1,256}(?::\d{1,8})?/g,            severity: 'critical', connectionString: true }],
  ['redis-url',      { regex: /rediss?:\/\/[^:@\s]{1,256}:[^@\s]{1,256}@[^:\s/]{1,256}(?::\d{1,8})/g,                       severity: 'critical', connectionString: true }],

  // --- Source control tokens ---
  ['github-token',   { regex: /gh[pousor]_[a-zA-Z0-9]{36}/g,                                    severity: 'critical' }],
  ['github-pat',     { regex: /github_pat_[a-zA-Z0-9_]{82}/g,                                   severity: 'critical' }],
  ['gitlab-token',   { regex: /glpat-[a-zA-Z0-9_-]{20}/g,                                       severity: 'critical' }],
  ['bitbucket-token',{ regex: /BBDC-[a-zA-Z0-9_-]{40}/g,                                        severity: 'critical' }],

  // --- Communication platforms ---
  ['slack-webhook',  { regex: /hooks\.slack\.com\/services\/[A-Z0-9]{9,}\/[A-Z0-9]{9,}\/[a-zA-Z0-9]{20,}/g, severity: 'critical' }],
  ['slack-token',    { regex: /xox[baprs]-[a-zA-Z0-9-]{10,}/g,                                  severity: 'critical' }],
  ['discord-webhook',{ regex: /discord\.com\/api\/webhooks\/[0-9]{17,20}\/[a-zA-Z0-9_-]{60,}/g, severity: 'critical' }],

  // --- Email / messaging services ---
  ['sendgrid-api',   { regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,                     severity: 'critical' }],
  // `re_` is a short prefix that also occurs mid-identifier (e.g. a long Go
  // test name yields a `re_<camelCase>` substring). Anchor to a token boundary
  // so only standalone `re_<key>` tokens match, and entropy-gate to drop
  // low-entropy identifiers while keeping random Resend keys.
  ['resend-api',     { regex: /(?<![A-Za-z0-9_])re_[a-zA-Z0-9]{32,}/g,                            severity: 'critical', minEntropy: 3.5 }],
  ['mailgun-api',    { regex: /key-[a-zA-Z0-9]{32}/g,                                            severity: 'critical', minEntropy: 3.5 }],

  // --- Package managers ---
  ['npm-token',      { regex: /npm_[a-zA-Z0-9]{36}/g,                                            severity: 'critical' }],

  // --- Backend / infra platforms ---
  ['supabase-token',   { regex: /(?<![A-Za-z0-9_-])sbp_[a-f0-9]{40}/g,                          severity: 'critical' }],
  ['supabase-secret',  { regex: /(?<![A-Za-z0-9_-])sb_secret_[a-zA-Z0-9_-]{20,}/g,              severity: 'critical' }],
  ['vercel-blob',      { regex: /vercel_blob_rw_[a-zA-Z0-9]{20,}_[a-zA-Z0-9]{20,}/g,            severity: 'critical' }],
  ['planetscale',      { regex: /pscale_(?:tkn|pw)_[a-zA-Z0-9_-]{32,}/g,                        severity: 'critical' }],
  ['doppler-token',    { regex: /dp\.(?:pt|st|sa|scim|audit)\.[a-zA-Z0-9]{40,}/g,               severity: 'critical' }],
  ['databricks-token', { regex: /(?<![A-Za-z0-9_-])dapi[a-f0-9]{32}/g,                          severity: 'critical' }],
  ['cloudflare-token', { regex: /(?:cloudflare_api_token|CLOUDFLARE_API_TOKEN)\s*[=:]\s*["']?([a-zA-Z0-9_-]{40})/g, severity: 'critical' }],

  // --- SaaS / productivity ---
  ['notion-token',   { regex: /(?<![A-Za-z0-9_-])(?:ntn_[a-zA-Z0-9]{40,}|secret_[a-zA-Z0-9]{43})/g, severity: 'critical' }],
  ['airtable-pat',   { regex: /(?<![A-Za-z0-9_-])pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}/g,            severity: 'critical' }],
  ['figma-token',    { regex: /(?<![A-Za-z0-9_-])figd_[a-zA-Z0-9_-]{40,}/g,                     severity: 'critical' }],

  // --- Monitoring ---
  ['newrelic-api',   { regex: /NRAK-[a-zA-Z0-9]{26}/g,                                          severity: 'critical' }],
  // A Sentry DSN is designed to be embedded in client-side bundles -- the
  // public key it carries only permits event ingestion, not data read. Kept at
  // `low` for visibility under the same policy as `gcp-oauth`: real, but not a
  // credential leak worth blocking a commit over.
  ['sentry-dsn',     { regex: /https:\/\/[a-f0-9]{32}@o\d+\.ingest\.(?:[a-z]{2}\.)?sentry\.io\/\d+/g, severity: 'low' }],

  // --- E-commerce ---
  ['shopify-admin',  { regex: /shp(?:ss|at|ca)_[a-zA-Z0-9]{32}/g,                               severity: 'critical' }],

  // --- Keys and auth tokens ---
  // The algorithm prefix is optional. `-----BEGIN PRIVATE KEY-----` (PKCS#8)
  // has no prefix at all, and it is what modern OpenSSL emits by default and
  // what GCP service-account JSON embeds -- i.e. the most common private key
  // form in circulation. Requiring `[A-Z ]+` between BEGIN and PRIVATE meant
  // the scanner printed "No secrets found" on a bare PKCS#8 key file.
  // The optional key-type prefix lifts the space OUT of the repeated class
  // (`[A-Z0-9]+(?: [A-Z0-9]+)?` then a single required trailing space) so the
  // delimiter is no longer a member of the set it terminates. This removes the
  // ambiguous overlap in the old `[A-Z0-9 ]+ ` shape. Matches the same headers:
  // bare PKCS#8 (no prefix), plus one- or two-word types (RSA, EC, OPENSSH,
  // ENCRYPTED). Measured: the old form was already linear here, so this is
  // hardening, not a fix.
  //
  // `(?: BLOCK)?` matches the OpenPGP header, which ends
  // `PRIVATE KEY BLOCK-----` rather than `PRIVATE KEY-----`. Neither the old
  // nor the first bounded form matched it, and the test that claimed otherwise
  // manufactured the match by deleting " BLOCK" from the header. It is a fixed
  // optional literal with no quantifier, so it adds no backtracking (measured
  // alongside the other bounds).
  ['ssh-private-key',{ regex: /-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)? )?PRIVATE KEY(?: BLOCK)?-----/g, severity: 'critical' }],
  // Each base64url segment is bounded, and the `eyJ` prefix is token-boundary
  // anchored. Both are needed and they fix different halves of the same cost:
  //
  //   - The bound caps per-start backtracking. Unbounded, a buffer of repeated
  //     `eyJ` measured 50k=436ms, 100k=1,758ms, 200k=7,083ms (quadratic),
  //     because each segment runs to the end of the buffer hunting a `.`.
  //   - The lookbehind removes the start offsets. In `eyJeyJeyJ...` every third
  //     character starts a candidate; anchoring to a token boundary leaves one.
  //     Without it the cost is linear but scales with the bound (a {1,4096}
  //     bound alone still measured 622ms at 200k); with it, 200k is ~0.24ms,
  //     which is what makes a GENEROUS bound affordable.
  //
  // 4096 per segment is deliberately generous so a real token with fat claims
  // stays detected; a JWT glued directly to preceding word characters is not a
  // standalone token reference, the same rule eight other entries here apply.
  ['jwt-token',      { regex: /(?<![A-Za-z0-9_-])eyJ[a-zA-Z0-9_-]{1,4096}\.[a-zA-Z0-9_-]{1,4096}\.[a-zA-Z0-9_-]{1,4096}/g, severity: 'high' }],

  // Generic patterns -- entropy-gated AND placeholder-filtered (aggressive) to
  // suppress false positives on documentation samples and unit-test fixtures.
  ['bearer-token',   { regex: /Bearer [a-zA-Z0-9_-]{20,}/g,                                     severity: 'high',   minEntropy: 3.5, aggressivePlaceholder: true }],
  ['api-key-generic',{ regex: /api[_-]?key["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,         severity: 'high',   minEntropy: 3.5, aggressivePlaceholder: true }],
  ['secret-generic', { regex: /secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,               severity: 'high',   minEntropy: 3.5, aggressivePlaceholder: true }],
  // Negative lookbehind prevents matching when `password` is a suffix of a
  // compound identifier (e.g. `email-reset-password`, `changePassword`).
  // Only standalone assignments trigger -- `password =`, `password:`, etc.
  ['password-in-code',{ regex: /(?<![a-zA-Z0-9_-])password["']?\s*[:=]\s*["']([a-zA-Z0-9_\-!@#$%^&*]{12,})/gi, severity: 'high', minEntropy: 3.2, aggressivePlaceholder: true }],
]);

/**
 * Low-precision generic assignment patterns (`<key> = <value>`) whose captured
 * value may be an unquoted code identifier rather than a literal secret. Only
 * these are subject to the function-call suppression heuristic; vendor- and
 * context-anchored detectors are deliberately excluded.
 */
const GENERIC_ASSIGNMENT_IDS = new Set(['secret-generic', 'api-key-generic', 'password-in-code']);

/**
 * Rules exempt from {@link isSequentialRunPlaceholder}.
 *
 * That check suppresses outright, and the only thing that makes suppression
 * safe is the argument "a real credential is generated from a random source,
 * so it cannot be a run". The argument is sound for machine-issued tokens and
 * false for anything a person types: a weak password IS a keyboard run, and
 * being a run is the reason to report it, not evidence that it is fake.
 *
 * Reviewed against the whole rule table. These are the rules whose secret is
 * human-chosen:
 *
 *   - `password-in-code`: the value is a plaintext password somebody picked.
 *     The clearest case and the most costly, because its minimum capture is 12
 *     characters, which is also the run check's minimum value length, so short
 *     weak passwords were suppressed with nothing left at any severity to
 *     triage.
 *   - `postgresql-url`, `mysql-url`, `mongodb-url`, `redis-url`: the secret in
 *     a DSN is its password component, equally human-chosen. The rest of the
 *     URL dilutes run coverage but not reliably below the threshold, e.g.
 *     `redis://a:<52-character run>@b.io:1` lands at 75.4%.
 *
 * Deliberately NOT exempt, and why:
 *
 *   - Every vendor-anchored rule (`github-token`, `aws-access`, `stripe`,
 *     `anthropic`, …): provider-issued and random. This is where the check
 *     earns its keep, and where five of the eight criticals in the public-repo
 *     scan came from.
 *   - `api-key-generic`, `secret-generic`, `bearer-token`: the value is
 *     normally an issued token, and these are where the hand-typed run
 *     fixtures actually appeared in real code. They already carry an entropy
 *     gate and the aggressive placeholder filter, so they are treated as
 *     low-precision throughout. Residual risk accepted: a human-typed signing
 *     secret that is a pure run under `secret =` is suppressed.
 *   - `aws-secret-context`, `mistral`, `together-ai`, `deepseek`,
 *     `cloudflare-token`: context-anchored, but the value they capture is
 *     still a provider-issued key rather than a chosen one.
 *   - `jwt-token`: base64url of structured JSON, machine-generated.
 *   - `ssh-private-key`: the match is the PEM header, which holds no runs at
 *     all, so the check can never fire on it.
 */
const HUMAN_CHOSEN_VALUE_IDS = new Set([
  'password-in-code',
  'postgresql-url',
  'mysql-url',
  'mongodb-url',
  'redis-url',
]);

/**
 * Sink for inline ignore-directive suppressions observed during a single
 * {@link SecretScanner.scanContent} call (or the {@link SecretScanner.scan}
 * that wraps it).
 *
 * A suppression is the user's own decision and must be visible: a scanner that
 * can be silenced without saying so manufactures false confidence. When a
 * caller passes one of these, scanContent records every finding it dropped
 * solely because a `vault-guard: ignore-line` / `ignore-next-line` directive
 * covered its line -- counted AFTER the same overlap dedupe applied to reported
 * findings, so the count is "findings hidden", not "raw pattern hits".
 *
 * The object is mutated in place and accumulates across calls, so a caller
 * scanning many files can reuse one, or pass a fresh one per file to attribute
 * line numbers to that file.
 */
export interface IgnoreDirectiveHits {
  /** Findings suppressed by an inline ignore directive (post-dedupe). */
  count: number;
  /** 1-based line numbers of those suppressed findings, in encounter order. */
  lines: number[];
  /**
   * The subset of {@link count} that hid a CRITICAL finding from a vendor- or
   * context-anchored rule, rather than from one of the low-precision generic
   * ones.
   *
   * The two are not the same event and a single total lets the more serious one
   * hide inside the less serious one. A directive over `api_key = "..."` in a
   * fixture is routine housekeeping; a directive on the same line as a
   * provider-issued `sk-ant-` or `AKIA` string is somebody deciding that a real
   * key shape does not count, and on a pull request that is the line a reviewer
   * most needs to see. Both are still honoured: an inline directive is content,
   * not configuration, and content is what is under judgment.
   *
   * The severity is the rule's own, read before the path-aware downgrade, so a
   * key silenced inside a docs path is counted the same as one silenced in
   * source. Optional so callers that predate it keep compiling; it is set
   * whenever a suppression is recorded.
   */
  criticalVendorAnchored?: number;
}

/**
 * True for the vendor- and context-anchored rules: everything that is not one
 * of the low-precision generic shapes.
 *
 * Derived from the existing downgrade list rather than kept as a second
 * hand-maintained roster, so a rule added to one is not silently missing from
 * the other. That list is exactly the set this codebase already treats as
 * low-precision (generic assignments, DSNs, JWTs, PEM headers); everything
 * else captures a provider-issued token.
 */
function isVendorAnchoredRule(id: string): boolean {
  return !LOW_PRECISION_PATH_DOWNGRADE_IDS.has(id);
}

/**
 * Read-only metadata for built-in patterns (docs / codegen). Exposes
 * `RegExp#source` and flags only -- not live `RegExp` instances.
 */
export interface BuiltinPatternDocEntry {
  id: string;
  severity: SecretMatch['severity'];
  minEntropy?: number;
  regexSource: string;
  regexFlags: string;
}

/** Stable insertion order of {@link BUILTIN_PATTERNS}. */
export function getBuiltinPatternDocEntries(): BuiltinPatternDocEntry[] {
  return [...BUILTIN_PATTERNS.entries()].map(([id, entry]) => ({
    id,
    severity: entry.severity,
    ...(entry.minEntropy !== undefined ? { minEntropy: entry.minEntropy } : {}),
    regexSource: entry.regex.source,
    regexFlags: entry.regex.flags,
  }));
}

// ---------------------------------------------------------------------------
// Severity ranking (higher = worse)
// ---------------------------------------------------------------------------
const SEVERITY_RANK: Record<SecretMatch['severity'], number> = {
  critical: 4,
  high:     3,
  medium:   2,
  low:      1,
};

// ---------------------------------------------------------------------------
// SecretScanner
// ---------------------------------------------------------------------------

export class SecretScanner {
  private readonly patterns: Map<string, PatternEntry>;
  private readonly entropyThreshold: number;

  constructor(config?: VaultGuardConfig) {
    this.entropyThreshold = config?.entropy_threshold ?? DEFAULT_ENTROPY_THRESHOLD;

    // Start from a mutable copy of the built-ins.
    this.patterns = new Map(
      [...BUILTIN_PATTERNS].map(([k, v]) => [k, { ...v, regex: new RegExp(v.regex.source, v.regex.flags) }])
    );

    // Apply severity overrides / "off" switches.
    if (config?.severity_overrides) {
      for (const [id, override] of Object.entries(config.severity_overrides)) {
        if (override === 'off') {
          this.patterns.delete(id);
        } else {
          const entry = this.patterns.get(id);
          if (entry) {
            this.patterns.set(id, { ...entry, severity: override });
          }
        }
      }
    }

    // Compile and append extra patterns from config.
    //
    // Security policy: every user-supplied regex passes through
    // `validateRegexSafety` (heuristic ReDoS check). Patterns that fail are
    // **not** silently skipped -- that is exactly the behaviour the audit
    // flagged (Audit §14: silent error swallows). They are reported via
    // `extraPatternRejections` for the caller (CLI / MCP) to surface to the
    // user, then dropped.
    //
    // `extra_patterns_unsafe: true` opts out of the heuristic, but the length
    // cap still runs as a memory-use backstop.
    if (config?.extra_patterns) {
      const unsafe = config.extra_patterns_unsafe === true;

      for (const ep of config.extra_patterns) {
        const lengthCheck = validateRegexLength(ep.regex);
        if (!lengthCheck.ok) {
          this.extraPatternRejections.push({
            id: ep.id,
            reason: lengthCheck.reason ?? 'too_long',
            detail: lengthCheck.detail ?? 'pattern exceeds length cap',
          });
          continue;
        }

        if (!unsafe) {
          const safety = validateRegexSafety(ep.regex);
          if (!safety.ok) {
            this.extraPatternRejections.push({
              id: ep.id,
              reason: safety.reason ?? 'invalid_syntax',
              detail: safety.detail ?? 'pattern failed ReDoS safety check',
            });
            continue;
          }
        }

        try {
          this.patterns.set(ep.id, {
            regex: new RegExp(ep.regex, 'g'),
            severity: ep.severity,
            ...(ep.min_entropy !== undefined ? { minEntropy: ep.min_entropy } : {}),
          });
        } catch (e) {
          this.extraPatternRejections.push({
            id: ep.id,
            reason: 'invalid_syntax',
            detail: e instanceof Error ? e.message : String(e),
          });
        }
      }
    }
  }

  /**
   * Rejected `extra_patterns` from the most recent constructor call.
   *
   * Callers should surface these to the user (stderr today, structured
   * `diagnostics[]` channel post Phase 2.2). A non-empty list means the
   * user's `.vault-guard.json` declared rules that are not active.
   */
  readonly extraPatternRejections: Array<{
    id: string;
    reason: string;
    detail: string;
  }> = [];

  /** Number of built-in + extra patterns active after config (severity "off" removes rules). */
  getActivePatternCount(): number {
    return this.patterns.size;
  }

  /**
   * Scan a file and return deduplicated, ignore-directive-filtered matches.
   */
  scan(filePath: string, opts?: { ignoreHits?: IgnoreDirectiveHits }): SecretMatch[] {
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, 'utf-8');
    // Path-aware severity is applied here (not in scanContent) because it needs
    // the file path. scanContent callers that know the path (scanTextFile*)
    // apply it themselves, so this does not double-apply.
    return applyPathAwareSeverity(
      this.scanContent(content, { filePath, ignoreHits: opts?.ignoreHits }),
      filePath,
    );
  }

  /**
   * Scan arbitrary UTF-8 text (editor buffer, pasted snippet, MCP payload).
   * Line numbers and byte offsets are relative to this string.
   *
   * Pass `opts.filePath` when the content comes from a file on disk so
   * documentation-site suppressions (Algolia search keys, etc.) can apply.
   *
   * Each call uses fresh `RegExp` instances so overlapping `scanContent` work
   * (e.g. after an `await` in a concurrent worker pool) cannot corrupt
   * `lastIndex` on shared patterns.
   */
  scanContent(
    content: string,
    opts?: { filePath?: string; ignoreHits?: IgnoreDirectiveHits },
  ): SecretMatch[] {
    const lineIndex = this.buildLineIndex(content);
    const ignoredLines = this.parseIgnoreDirectives(content, lineIndex);

    const raw: SecretMatch[] = [];
    // Findings dropped solely because an ignore directive covered their line.
    // Only collected when a caller asked for the tally, so the ordinary hot
    // path allocates nothing extra. Deduped alongside `raw` below so the count
    // is "findings hidden", matching how reported findings are counted.
    const suppressedByDirective: SecretMatch[] | null = opts?.ignoreHits ? [] : null;

    // Fresh `RegExp` per invocation so concurrent or interleaved `scanContent`
    // calls (e.g. across `await` in a worker pool) never share `lastIndex`.
    const patternsForRun = new Map<string, PatternEntry>();
    for (const [k, v] of this.patterns) {
      patternsForRun.set(k, {
        ...v,
        regex: new RegExp(v.regex.source, v.regex.flags),
      });
    }

    for (const [type, entry] of patternsForRun) {
      const { regex, severity, minEntropy, aggressivePlaceholder, connectionString } = entry;
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const rawValue = match[1] ?? match[0];
        const fullMatch = match[0];

        // Ahead of the entropy gate on purpose. Shannon entropy ignores
        // character order, so a hand-typed alphabet run scores near the maximum
        // for its length and sails through. This runs for vendor-anchored rules
        // too. They have no entropy gate at all, and that is exactly where the
        // alphabet-run fixtures produced criticals. Safe there because a real
        // provider key is generated randomly and cannot be the alphabet.
        //
        // That safety argument does not hold for rules whose value a person
        // types, where a run is a weak password rather than a fake one, so
        // those rules are exempt. See HUMAN_CHOSEN_VALUE_IDS.
        if (!HUMAN_CHOSEN_VALUE_IDS.has(type) && isSequentialRunPlaceholder(rawValue)) {
          continue;
        }

        const threshold = minEntropy ?? (minEntropy === 0 ? 0 : undefined);
        if (threshold !== undefined && shannonEntropy(rawValue) < threshold) {
          continue;
        }

        // Suppress documentation samples / test fixtures (e.g. AWS's
        // `AKIAIOSFODNN7EXAMPLE`, `password: 'testPass1234'`). The aggressive
        // tier only applies to the low-precision generic patterns.
        if (isPlaceholderSecret(rawValue, { aggressive: aggressivePlaceholder === true })) {
          continue;
        }

        if (isRedactedTemplateValue(rawValue)) {
          continue;
        }

        if (GENERIC_ASSIGNMENT_IDS.has(type) && isEnvVarNameToken(rawValue)) {
          continue;
        }

        if (
          GENERIC_ASSIGNMENT_IDS.has(type) &&
          opts?.filePath?.endsWith('.py') &&
          isInsidePythonTripleQuoted(content, match.index)
        ) {
          continue;
        }

        // Suppress local/dev/example/placeholder connection strings -- the
        // dominant FP source on real repos (docker-compose, `.env.example`,
        // test fixtures all carry `postgres://user:pass@localhost/db`).
        if (connectionString === true && isNonSecretConnectionString(fullMatch)) {
          continue;
        }

        // Suppress the ubiquitous jwt.io sample token (John Doe / sub 1234567890)
        // that appears in API docs and tutorials everywhere.
        if (type === 'jwt-token' && isSampleJwt(fullMatch)) {
          continue;
        }

        // A password hash is the safe-at-rest form, not a usable credential.
        // Seed data and fixtures are full of bcrypt/argon2 digests.
        if (type === 'password-in-code' && isPasswordHash(rawValue)) {
          continue;
        }

        // A bare PEM header with no key material after it is a UI label or an
        // input placeholder, not a leaked key.
        if (
          type === 'ssh-private-key' &&
          isPemHeaderWithoutBody(content, match.index + fullMatch.length)
        ) {
          continue;
        }

        // Suppress unquoted assignments whose "value" is actually a function
        // call -- e.g. `csrf_secret = _add_new_csrf_cookie(request)`. The value
        // capture group stops at `(`, so a `(` immediately following the match
        // means we captured a callee identifier, not a literal secret. Scoped to
        // the low-precision generic assignment patterns only -- vendor-anchored
        // and context-anchored detectors (incl. critical `aws-secret-context`)
        // are never weakened by this heuristic.
        if (
          GENERIC_ASSIGNMENT_IDS.has(type) &&
          content[match.index + fullMatch.length] === '('
        ) {
          continue;
        }

        // Suppress unquoted assignments whose "value" is a bare reference to
        // another identifier -- e.g. `'x-api-key': scheduledIngestApiKey`. Only
        // applies when the captured value was NOT wrapped in quotes: a quoted
        // string is a literal, and literals are what we are hunting. Scoped to
        // the low-precision generic assignment patterns.
        if (GENERIC_ASSIGNMENT_IDS.has(type) && match[1] !== undefined) {
          const valueStart = fullMatch.lastIndexOf(rawValue);
          const charBefore = valueStart > 0 ? fullMatch[valueStart - 1] : '';
          const quoted = charBefore === '"' || charBefore === "'";
          if (!quoted && isCodeIdentifierReference(rawValue)) {
            continue;
          }
        }

        const line = this.lineFromIndex(lineIndex, match.index);
        const lineContent = this.lineContentAt(content, lineIndex, line);

        if (
          opts?.filePath &&
          shouldSuppressDocContextMatch(type, opts.filePath, rawValue, fullMatch, lineContent)
        ) {
          continue;
        }

        if (ignoredLines.has(line)) {
          // A genuine finding (it passed every filter above) hidden only by an
          // ignore directive. Record it for the caller's tally before dropping.
          if (suppressedByDirective) {
            suppressedByDirective.push({
              type,
              value: this.maskValue(fullMatch),
              line,
              column: match.index - (lineIndex[line - 1] ?? 0),
              offset: match.index,
              matchLength: fullMatch.length,
              severity,
            });
          }
          continue;
        }

        raw.push({
          type,
          value: this.maskValue(fullMatch),
          line,
          column: match.index - (lineIndex[line - 1] ?? 0),
          offset: match.index,
          matchLength: fullMatch.length,
          severity,
        });
      }
    }

    if (opts?.ignoreHits && suppressedByDirective) {
      // Dedupe with the same overlap rules used for reported findings so two
      // patterns matching one secret on an ignored line count as one hidden
      // finding, not two.
      const hidden = this.deduplicateMatches(suppressedByDirective);
      opts.ignoreHits.count += hidden.length;
      for (const m of hidden) opts.ignoreHits.lines.push(m.line);
      opts.ignoreHits.criticalVendorAnchored =
        (opts.ignoreHits.criticalVendorAnchored ?? 0) +
        hidden.filter(m => m.severity === 'critical' && isVendorAnchoredRule(m.type)).length;
    }

    // Applied after dedupe so the severity ranking that resolves overlapping
    // matches sees the rules' declared severities, exactly as it did before
    // in-file test context existed.
    return this.applyInlineTestSeverity(
      this.deduplicateMatches(raw),
      content,
      opts?.filePath,
    );
  }

  /**
   * Downgrade downgrade-eligible matches that sit inside an in-file test block
   * (today: Rust's `#[cfg(test)] mod tests { … }`) to `low`.
   *
   * This is the content-side twin of {@link applyPathAwareSeverity} and uses
   * the same rule set, so vendor-anchored provider keys are untouched: a real
   * provider key is a real key even in a test block.
   */
  private applyInlineTestSeverity(
    matches: SecretMatch[],
    content: string,
    filePath: string | undefined,
  ): SecretMatch[] {
    if (matches.length === 0 || !filePath) return matches;
    const regions = findInlineTestRegions(content, filePath);
    if (regions.length === 0) return matches;

    return matches.map(m => {
      if (
        m.severity !== 'low' &&
        LOW_PRECISION_PATH_DOWNGRADE_IDS.has(m.type) &&
        isInsideInlineTestRegion(regions, m.offset)
      ) {
        return { ...m, severity: 'low' as const };
      }
      return m;
    });
  }

  /**
   * Merge matches produced from chunked reads (e.g. line-by-line streaming)
   * using the same overlap / severity rules as a full-file scan.
   */
  mergeChunkedMatches(matches: SecretMatch[]): SecretMatch[] {
    return this.deduplicateMatches(matches);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Build an index of line-start byte offsets for O(log n) line lookup.
   * Index position 0 = start of line 1.
   */
  private buildLineIndex(content: string): number[] {
    const idx = [0];
    for (let i = 0; i < content.length; i++) {
      if (content[i] === '\n') idx.push(i + 1);
    }
    return idx;
  }

  /** Binary-search the line index to return a 1-based line number. */
  private lineFromIndex(lineIndex: number[], byteOffset: number): number {
    let lo = 0;
    let hi = lineIndex.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (lineIndex[mid] <= byteOffset) lo = mid + 1;
      else hi = mid - 1;
    }
    return lo; // 1-based
  }

  /** Return the full text of a 1-based line number (without trailing newline). */
  private lineContentAt(content: string, lineIndex: number[], lineNum: number): string {
    const start = lineIndex[lineNum - 1] ?? 0;
    const end = lineNum < lineIndex.length ? lineIndex[lineNum] - 1 : content.length;
    return content.slice(start, end);
  }

  /**
   * Parse inline ignore directives from file content.
   *
   * Supported forms (case-insensitive):
   *   `// vault-guard: ignore-line`        -- ignores that line
   *   `// vault-guard: ignore-next-line`   -- ignores the following line
   *   `# vault-guard: ignore-line`         -- same, for shell/Python/YAML
   *   `# vault-guard: ignore-next-line`
   *
   * Returns a Set of 1-based line numbers to ignore.
   */
  private parseIgnoreDirectives(content: string, lineIndex: number[]): Set<number> {
    const ignored = new Set<number>();
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1; // 1-based
      const lower = lines[i].toLowerCase();

      if (lower.includes('vault-guard: ignore-line') || lower.includes('vault-guard:ignore-line')) {
        ignored.add(lineNum);
      }
      if (lower.includes('vault-guard: ignore-next-line') || lower.includes('vault-guard:ignore-next-line')) {
        ignored.add(lineNum + 1);
      }
    }

    // lineIndex is available for future column-level ignore; unused here.
    void lineIndex;

    return ignored;
  }

  /**
   * Deduplicate matches by overlapping byte ranges.
   *
   * When two matches cover the same (or overlapping) bytes in the file the
   * more-specific (higher-severity or shorter) match is kept.  This prevents
   * the same secret from being reported multiple times when several patterns
   * overlap.
   */
  private deduplicateMatches(matches: SecretMatch[]): SecretMatch[] {
    if (matches.length <= 1) return matches;

    // Sort by start offset so we can do a linear sweep.
    const sorted = [...matches].sort((a, b) => a.offset - b.offset || a.line - b.line);
    const kept: SecretMatch[] = [];

    for (const candidate of sorted) {
      const cStart = candidate.offset;
      const cEnd = cStart + candidate.matchLength;

      let dominated = false;

      for (let i = kept.length - 1; i >= 0; i--) {
        const existing = kept[i];
        const eStart = existing.offset;
        const eEnd = eStart + existing.matchLength;

        // No possible overlap once we've passed the candidate start by more
        // than the max pattern length (optimisation -- safe upper bound: 512).
        if (eEnd < cStart - 512) break;

        const overlaps = cStart < eEnd && eStart < cEnd;
        if (!overlaps) continue;

        const existingRank = SEVERITY_RANK[existing.severity];
        const candidateRank = SEVERITY_RANK[candidate.severity];

        if (candidateRank > existingRank) {
          // Candidate is more severe -- replace existing.
          kept.splice(i, 1);
        } else {
          // Existing is at least as severe -- drop candidate.
          dominated = true;
          break;
        }
      }

      if (!dominated) kept.push(candidate);
    }

    return kept;
  }

  /**
   * Redact a matched secret to a low-information identifier.
   *
   * Format: `<prefix>…(<length>c)` -- e.g. `sk-a…(37c)`.
   *
   * Why not show more characters?
   *   - 4-char prefix is enough to identify vendor (sk-a, sk_l, ghp_, AKIA, …)
   *     without leaking meaningful entropy of the underlying secret.
   *   - The exact location is already in `line` / `column`, so users don't
   *     need a longer fragment to find the match in source.
   *   - Output of this tool is routinely pasted into PRs, Slack, terminals,
   *     SARIF uploads, and GitHub Code Scanning -- the surface area for
   *     leakage is large, so we keep the redaction conservative.
   *
   * For values shorter than 6 chars (rare; broad patterns enforce ≥20)
   * we redact entirely to `*…(<length>c)`.
   */
  private maskValue(value: string): string {
    const PREFIX = 4;
    const lengthTag = `(${value.length}c)`;
    if (value.length < 6) {
      return `*…${lengthTag}`;
    }
    return `${value.substring(0, PREFIX)}…${lengthTag}`;
  }
}
