/**
 * Recognise obviously non-secret placeholder / example / test values so that
 * broad patterns stop firing on documentation samples and unit-test fixtures  -- 
 * empirically the dominant real-world false-positive source (e.g. AWS's own
 * documented `AKIAIOSFODNN7EXAMPLE` key, or `const password = 'testPass1234'`).
 *
 * Two tiers, by precision cost:
 *
 *   - `standard` (safe for every pattern, including vendor-anchored keys):
 *     unambiguous markers that effectively never occur inside a real generated
 *     credential -- `EXAMPLE`, `changeme`, `your_token_here`, all-`x` padding, …
 *
 *   - `aggressive` (opt-in, used only by the low-precision generic / password
 *     assignment patterns): additionally treats common test-fixture words
 *     (`test`, `sample`, `password`, …) as placeholders. Scoped to those
 *     patterns so vendor-anchored keys keep full recall.
 *
 * Matching is substring-based on the lower-cased value. Markers are chosen to
 * be long/specific enough that a real high-entropy secret will not contain them
 * by chance.
 */

/** Unambiguous placeholder markers -- applied to all patterns. */
const STANDARD_MARKERS: readonly string[] = [
  'example',
  'changeme',
  'change-me',
  'change_me',
  'placeholder',
  'redacted',
  'notreal',
  'not-a-real',
  'dummy',
  'yourtoken',
  'yourkey',
  'yourapikey',
  'your_token',
  'your-token',
  'your_key',
  'your-key',
  'your_api_key',
  'your-api-key',
  'insertyour',
  'insert_your',
  'replace_me',
  'replaceme',
  'replace-with',
  'replace_with',
  'loremipsum',
  // Pure character repetition (e.g. `xxxxxxxx`, `00000000`) is handled by the
  // low-variety check below rather than literal markers, so it does not clash
  // with real keys that merely contain a short repeated run.
];

/** Common test / fixture markers -- applied only to generic assignment patterns. */
const AGGRESSIVE_MARKERS: readonly string[] = [
  'test',
  'sample',
  'demo',
  'fake',
  'mock',
  'foobar',
  'password',
  'passw0rd',
  'secret',
  'sensitive',
  'hunter2',
  'qwerty',
  'letmein',
  'your_', // your_google_places_key, your_api_key_here
  'your-', // your-anthropic-api-key -- hyphen form is just as common in docs
];

/** Known vendor key prefixes whose remainder is often redacted with X/* in docs. */
const REDACTED_PREFIXES: readonly RegExp[] = [
  /^sk_live_/i,
  /^sk_test_/i,
  /^sk-ant-api\d+-/i,
  /^sk-proj-/i,
  /^sk-/i,
  /^pk_live_/i,
  /^pk_test_/i,
  /^re_/i,
  /^whsec_/i,
  /^phc_/i,
  /^AIza/i,
  /^ghp_/i,
  /^gho_/i,
  /^npm_/i,
  /^xox[baprs]-/i,
];

export function isRedactedTemplateValue(value: string): boolean {
  if (!value) return false;
  if (/^replace-with-/i.test(value)) return true;
  if (value.length >= 8 && /^[Xx*]+$/.test(value)) return true;
  for (const prefix of REDACTED_PREFIXES) {
    const m = prefix.exec(value);
    if (!m) continue;
    const rest = value.slice(m[0].length);
    if (rest.length >= 8 && /^[Xx*_.-]+$/.test(rest)) return true;
  }
  return false;
}

/**
 * A stored password *hash* is the safe-at-rest form of a credential, not a
 * credential. Seed data, fixtures, and migration files are full of them, and
 * flagging them as `password-in-code` is noise: rotating them is meaningless
 * and they cannot be used to authenticate.
 *
 * Covers modular crypt format (bcrypt `$2a/2b/2y$`, sha-crypt `$1/5/6$`,
 * yescrypt `$y$`, `$argon2i/d/id$`, `$pbkdf2-*$`) and the Django/Passlib
 * `algo$iterations$salt$hash` convention.
 */
export function isPasswordHash(value: string): boolean {
  if (/^\$(?:2[abxy]?|1|5|6|7|y|gy|argon2(?:i|d|id)?|scrypt|pbkdf2(?:-[a-z0-9]+)?|sha1|md5|apr1|bcrypt)\$/i.test(value)) {
    return true;
  }
  // Django: pbkdf2_sha256$390000$<salt>$<hash>, argon2$..., bcrypt_sha256$...
  return /^(?:pbkdf2_[a-z0-9]+|argon2[a-z]*|bcrypt(?:_sha256)?|scrypt|sha1|md5|crypt|unsalted_[a-z0-9]+)\$\d*\$?/i.test(value);
}

/**
 * True when a PEM `-----BEGIN … PRIVATE KEY-----` header is not followed by
 * any key material.
 *
 * UI code and documentation carry the header on its own as a label or an
 * input placeholder (`const privateKeyBeginsWith = '-----BEGIN RSA PRIVATE
 * KEY-----'`). A header with no body leaks nothing. Real PEM files wrap their
 * base64 at 64 characters per line, so requiring a single long base64 run
 * right after the header separates the two cleanly, and still works when the
 * key is embedded in JSON with escaped newlines.
 */
export function isPemHeaderWithoutBody(content: string, headerEndOffset: number): boolean {
  const window = content.slice(headerEndOffset, headerEndOffset + 400);

  // Split on real newlines and on the escaped `\n` used when a key is embedded
  // in JSON or YAML, then strip the quoting that survives that embedding.
  const lines = window.split(/\r?\n|\\r\\n|\\n/);

  for (const line of lines) {
    const token = line.replace(/["'`\\\s]/g, '');
    // A PEM body wraps base64 at 64 characters, so a body line is base64 and
    // nothing else. Requiring the *whole* line to match is what separates it
    // from surrounding code: a long camelCase identifier such as
    // `onUpdateDatasourceSecureJsonDataOption` is a valid base64 substring,
    // but the line it sits on never is.
    if (token.length >= 32 && /^[A-Za-z0-9+/]+={0,2}$/.test(token)) {
      return false;
    }
  }

  return true;
}

/**
 * ALL_CAPS identifiers (e.g. `PLAID_TOKEN_ENCRYPTION_KEY`) are env-var names,
 * not secret values -- common in GitHub Actions `secret:NAME` checks.
 */
export function isEnvVarNameToken(value: string): boolean {
  return /^[A-Z][A-Z0-9_]{7,}$/.test(value);
}

/**
 * True when an **unquoted** captured value is a reference to a code
 * identifier rather than a literal credential -- e.g.
 *
 *     headers: { 'x-api-key': scheduledIngestApiKey }
 *     api_key = defaultServiceCredential
 *
 * The generic assignment patterns capture whatever follows `:`/`=`, and in
 * real code that is very often a variable, not a secret. An existing check
 * covers the function-call case (`= makeKey(...)`); this covers the far more
 * common bare-reference case.
 *
 * Discriminator: generated credentials are random, so they mix digits into the
 * alphabet and do not decompose into word-shaped segments. We require the
 * value to split (on `_` and camelCase boundaries) into **two or more**
 * segments that are each purely alphabetic and at least two characters long.
 *
 *   `scheduledIngestApiKey` → scheduled | Ingest | Api | Key  → identifier
 *   `default_service_token` → default | service | token       → identifier
 *   `x7Kf9mQ2pL8vB3nR5wT1`  → contains digits                 → NOT identifier
 *   `qwertyuiopasdfghjklz`  → one segment                     → NOT identifier
 *
 * Callers must only apply this to unquoted values on low-precision generic
 * patterns; a quoted string literal is a literal, and vendor-anchored rules
 * must never be weakened by it.
 */
export function isCodeIdentifierReference(value: string): boolean {
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value)) return false;
  if (/\d/.test(value)) return false;

  const segments = value
    .replace(/\$/g, '_')
    .split('_')
    .filter(s => s.length > 0)
    .flatMap(part => part.split(/(?=[A-Z])/));

  if (segments.length < 2) return false;
  if (!segments.every(s => s.length >= 2 && /^[A-Za-z]+$/.test(s))) return false;

  // Guard against alpha-only random keys with alternating capitals
  // (`PmZkQvXtLdRwNbGhYuJcEaSf` splits into twelve 2-char "segments"). Real
  // identifiers are made of words, so beyond a handful of segments the mean
  // segment length stays word-like. Values of three segments or fewer are
  // exempt: `myApiKey` is a legitimate identifier with short parts.
  if (segments.length > 3) {
    const mean = segments.reduce((n, s) => n + s.length, 0) / segments.length;
    if (mean < 3) return false;
  }

  return true;
}

/**
 * A value made of one or two distinct characters (e.g. `xxxxxxxx`, `00000000`)
 * is padding, never a real secret.
 */
function isLowVariety(value: string): boolean {
  return value.length >= 8 && new Set(value).size <= 2;
}

/**
 * Fraction of a value that must sit inside sequential runs before it is called
 * a placeholder.
 *
 * Chosen at 0.75 to sit clearly between the two cases that bound it. A value
 * that is half run and half random scores 0.50 and must survive, because a real
 * credential can contain an incidental run. A genuine alphabet-run placeholder
 * under a real vendor prefix scores at worst about 0.80: `AKIA` + `ABCDEF…P` is
 * 16 run characters in a 20-character value, because the fixed prefix is part
 * of the matched value and is not itself a run. 0.75 clears the first with a
 * 25-point margin and admits the second with a 5-point one.
 */
export const SEQUENTIAL_RUN_COVERAGE_THRESHOLD = 0.75;

/** Shortest run of consecutive code points that counts as sequential. */
const SEQUENTIAL_RUN_MIN_LENGTH = 3;

/**
 * Below this length, coverage is not evidence of anything: a four-character
 * value is trivially "all run". Every pattern that reaches this check matches
 * far longer values than this.
 */
const SEQUENTIAL_RUN_MIN_VALUE_LENGTH = 12;

/**
 * True when `value` is mostly made of runs of consecutive code points:
 * `abcdefghijklmnopqrstuvwxyz0123456789`, `ABCDEFGHIJKLMNOP`, `zyxwvu…`, or the
 * same short run repeated.
 *
 * WHY THIS EXISTS SEPARATELY FROM THE ENTROPY GATE
 * ------------------------------------------------
 * Shannon entropy counts how often each character occurs and throws the order
 * away. A strict alphabet run uses every character exactly once, which is the
 * flattest possible frequency distribution, so it scores at or near the maximum
 * for its length, higher than most real credentials. The entropy gate is
 * therefore structurally blind to the single most common way a developer types
 * a fake key by hand, and no threshold tuning can fix that: order is the signal,
 * and entropy does not look at order.
 *
 * Unlike the entropy gate this check runs for vendor-anchored rules too, which
 * is where it matters most, since those rules have no entropy gate at all. It is
 * safe there for the same reason it is useful: a real provider key is generated
 * from a random source and cannot come out as the alphabet.
 */
export function isSequentialRunPlaceholder(value: string): boolean {
  if (value.length < SEQUENTIAL_RUN_MIN_VALUE_LENGTH) return false;

  const covered: boolean[] = new Array(value.length).fill(false);

  let i = 0;
  while (i < value.length - 1) {
    const step = value.charCodeAt(i + 1) - value.charCodeAt(i);
    if (step !== 1 && step !== -1) {
      i++;
      continue;
    }

    let end = i + 1;
    while (end + 1 < value.length && value.charCodeAt(end + 1) - value.charCodeAt(end) === step) {
      end++;
    }

    if (end - i + 1 >= SEQUENTIAL_RUN_MIN_LENGTH) {
      for (let k = i; k <= end; k++) covered[k] = true;
    }
    i = end;
  }

  let inRuns = 0;
  for (const c of covered) if (c) inRuns++;

  return inRuns / value.length >= SEQUENTIAL_RUN_COVERAGE_THRESHOLD;
}

/** Hosts that are never a remotely-exploitable credential leak. */
const LOCAL_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]',
  'host.docker.internal',
]);

/** Reserved / non-routable TLD suffixes (RFC 6761 + docker/dev conventions). */
const LOCAL_TLD_SUFFIXES: readonly string[] = [
  '.local',
  '.localhost',
  '.test',
  '.example',
  '.invalid',
];

/**
 * Password tokens that are obviously defaults / placeholders rather than a
 * real secret. Matched case-insensitively against the password component of a
 * connection string. Deliberately scoped to the *password* -- usernames like
 * `admin` / `root` / `postgres` are extremely common in genuine leaks, so we
 * never suppress based on the username alone.
 */
const PLACEHOLDER_PASSWORDS: ReadonlySet<string> = new Set([
  'password', 'passwd', 'pass', 'pwd', 'secret',
  'changeme', 'example', 'test', 'user', 'username',
  'root', 'admin', 'postgres', 'mysql', 'mongo', 'mongodb', 'redis',
  'db', 'database', 'prisma', 'identifier', 'key', 'token', 'name',
  'randompassword', 'yourpassword', 'mypassword',
]);

/**
 * Return `true` when a database/Redis connection string is **not** a real
 * credential leak -- i.e. it targets a local/dev/docker/example host, or uses
 * obvious placeholder/default credentials.
 *
 * The exploitable secret in a DSN is the password against a *reachable* host.
 * We suppress when either:
 *   1. the host is local, a bare docker-compose service name, or a reserved
 *      TLD (`localhost`, `mysql`, `db.local`, …) -- not remotely reachable; or
 *   2. the password is a placeholder/default (`pass`, `PASSWORD`, `root:root`,
 *      `${DB_PASS}`, `<your-password>`, …).
 *
 * A real remote host with a real password (e.g.
 * `postgres://app:8Fk2$mQ9z@db.prod.example-corp.com/main`) is **not**
 * suppressed.
 */
/**
 * Recognise the canonical jwt.io / RFC 7519 sample token that is pasted into
 * countless READMEs, OpenAPI specs, and tutorials. Its decoded payload carries
 * the well-known sample claims (`sub: "1234567890"`, `name: "John Doe"`,
 * `iat: 1516239022`). These are never real credentials.
 */
export function isSampleJwt(token: string): boolean {
  const parts = token.split('.');
  if (parts.length < 2 || !parts[1]) return false;
  let payload: string;
  try {
    payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
  } catch {
    return false;
  }
  return (
    /"sub"\s*:\s*"1234567890"/.test(payload) ||
    /"name"\s*:\s*"John Doe"/.test(payload) ||
    /\b1516239022\b/.test(payload) ||
    // Supabase ships fixed anon / service_role keys for local development.
    // They are printed by `supabase start`, published in Supabase's own docs,
    // and signed with a well-known secret, so they appear verbatim in a large
    // share of Supabase projects. Same category as the jwt.io sample.
    /"iss"\s*:\s*"supabase-demo"/.test(payload)
  );
}

export function isNonSecretConnectionString(url: string): boolean {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^:@/\s]+):([^@/\s]+)@([^:/?\s]+)/i.exec(url);
  if (!m) return false;

  const user = m[1];
  const pass = m[2];
  const host = m[3].toLowerCase();

  // 1. Non-routable / local / docker-service / reserved-TLD host.
  if (LOCAL_HOSTS.has(host)) return true;
  if (LOCAL_TLD_SUFFIXES.some(suffix => host.endsWith(suffix))) return true;
  // Bare single-token host with no dot (and not a raw IPv4) is a docker-compose
  // service name (`mysql`, `db`, `postgres`) -- local to a compose network.
  if (!host.includes('.') && !host.includes(':') && !/^\d+$/.test(host)) return true;

  // 2. Placeholder / default password.
  const p = pass.toLowerCase();
  if (PLACEHOLDER_PASSWORDS.has(p)) return true;
  if (user.toLowerCase() === p) return true;            // root:root, prisma:prisma
  if (/^[A-Z][A-Z0-9_]*$/.test(pass)) return true;      // USER:PASSWORD, DBPASS
  if (pass.startsWith('$') || pass.startsWith('<') || pass.startsWith('{')) return true; // ${DB_PASS}, <pw>
  if (isPlaceholderSecret(pass, { aggressive: true })) return true;

  return false;
}

/**
 * @returns `true` when `value` looks like a placeholder / example / test
 * credential and should be suppressed.
 */
export function isPlaceholderSecret(
  value: string,
  opts: { aggressive?: boolean } = {},
): boolean {
  if (!value) return false;
  const v = value.toLowerCase();

  for (const marker of STANDARD_MARKERS) {
    if (v.includes(marker)) return true;
  }

  if (isLowVariety(value)) return true;

  if (opts.aggressive) {
    for (const marker of AGGRESSIVE_MARKERS) {
      if (v.includes(marker)) return true;
    }
  }

  return false;
}
