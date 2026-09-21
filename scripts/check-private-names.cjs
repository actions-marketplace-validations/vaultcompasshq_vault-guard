#!/usr/bin/env node
/*
 * Public-repo hygiene guard: fail CI if tracked files contain tokens whose
 * SHA-256 (lowercased) matches the blocklist below, a machine path, or an
 * em dash / en dash. Plaintext venture codenames are never stored in this
 * repo -- only hashes. To add an entry locally:
 *
 *   node -e "const c=require('crypto');const t=process.argv[1];console.log(c.createHash('sha256').update(t.toLowerCase()).digest('hex'))" '<token>'
 *
 * Paste the hash into BANNED_HASHES. See CONTRIBUTING.md, Public repository hygiene.
 *
 * UNION across the family (dep-guard, vault-guard, intent-guard, conductor):
 * every repository's hygiene script carries the same hash blocklist, the
 * same machine-path patterns, and the same em/en dash rule. The lists used
 * to be maintained separately and three lists diverged; they are one list
 * now, copied in full, and a new entry is added to every repository.
 */
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// SHA-256(lowercase token) -- no plaintext codenames in the repository.
const BANNED_HASHES = new Set([
  'bcbff8a223bdb66059e43ae951a28ed12598c9e782fb65c58dabcd347f65cabe',
  'ec4e8dbcdbe500197bb27e769cee7864c0a4b4876a604998a23c80bbcc979d4c',
  '8bb4b7a9e837acadf49af332f3211a29f98e2239aa985825f1fe62cdf780c068',
  'cd800cbc9cd106b8f8646762b9ba7c530812555958e019b97c0a9878b005c52f',
  '9f9f3ba21e38f52a4a40f521490c33c4a2da799b5235c53374ad159ea8d0000b',
  'd52aa800a6d18843a0369b60f374fefb59b2cb91318b83c040f9e9d561ee96c4',
  'e44dbe116f27c5aef9c3386906b82f94f8b557a48c4b036a248f3ba75ddaece1',
  '57cd823001a8558b03746dd1dac01fe13b4fc442728bed4b5840703a755b810e',
  '59f5eae64585bb2483b57c4618b144e92011ba0656565003a42db23f029f8bd5',
  'c227174107761c30f27338905527dc53032ac5daf6d225ce9561ba4110344d7d',
  'd792a2b651ecea40434f60efb0435efcef8eb60aaefaa85f0660e718d074de76',
  '7f5f6e890b491a749b2a764e033c6b8d19fc0a0022697d391438dd11af101b95',
  'c3b53b09f7f132caa42bd4ddb8acd99972439acb571e9322fe9607135197154b',
]);

const ALLOWLIST = new Set(['CONTRIBUTING.md', 'scripts/check-private-names.cjs']);

// Internal home-directory path shape. This previously pinned the literal
// "Desktop/Projects" segment, which is not where this repository actually
// lives, so the guard could not have caught a leaked path from the machine
// it runs on. Generalised (matching dep-guard's version of this guard) to
// any absolute /Users/<name>/... path running through a directory named
// "projects" at any depth and in any case, rather than one fixed layout.
const INTERNAL_PATH = /\/Users\/[^/\s]+\/(?:[^/\s]+\/)*[Pp]rojects\/[^/\s]+/;

// Em dash (code point 0x2014) and en dash (code point 0x2013), built from
// code points rather than typed as literal characters so this file itself
// never contains one -- the guard should not need an exemption from its own
// rule. Prose and commit messages are plain ASCII; either character is the
// most common way a non-ASCII dash slips in from a pasted or generated
// sentence. The allowlist exempts token and path scanning, not this rule.
const DASH = new RegExp(`[${String.fromCodePoint(0x2014)}${String.fromCodePoint(0x2013)}]`);

const TOKEN = /\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*\b/gi;

function hashToken(token) {
  return crypto.createHash('sha256').update(token.toLowerCase()).digest('hex');
}

// "_" is a word character to JavaScript's \b, so \b never fires inside a
// run like "my_codename_thing" or "CODENAME_API_KEY" -- the whole
// underscore-joined run is invisible to \b-based extraction, which is
// exactly the shape a codename most plausibly takes in source (an
// identifier or an env var). camelCase compounds ("theCodenameApp") have no
// non-word separator between humps at all, so they have the same problem.
// Insert a real breaking space at every underscore and every
// lower-to-upper camelCase hump before handing the text to the token
// regex, so each embedded word becomes its own \b-delimited token.
function splitCompoundWords(text) {
  return text.replace(/_/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2');
}

// Extracts every candidate token from a string: the existing hyphenated
// \b-delimited tokens (unchanged, so "some-codename-thing" still yields the
// whole hyphenated compound), the same extraction re-run over a
// snake_case/camelCase-split copy of the text (so "my_codename_thing",
// "CODENAME_API_KEY", and "theCodenameApp" each yield "codename" among
// their tokens), and each individual word of any hyphenated token (so
// "some-codename-thing" also yields "codename" on its own).
function extractTokens(text) {
  const tokens = new Set();

  for (const match of text.matchAll(TOKEN)) {
    tokens.add(match[0]);
  }
  for (const match of splitCompoundWords(text).matchAll(TOKEN)) {
    tokens.add(match[0]);
  }
  for (const token of [...tokens]) {
    if (token.includes('-')) {
      for (const part of token.split('-')) {
        tokens.add(part);
      }
    }
  }

  return tokens;
}

// bannedHashes is injectable so a test can prove the hash-matching mechanism
// with a made-up token, instead of needing a real banned plaintext.
function scanFile(rel, text, { allowlisted, bannedHashes = BANNED_HASHES }) {
  const findings = [];

  // The file's own path is visible on the public file tree whether or not
  // its contents are scanned, so this check runs even for allowlisted
  // files -- an allowlist exempts a file's CONTENTS from scanning, not its
  // name. A path like "docs/<codename>-migration.md" or a directory like
  // "fixtures/<codename>/" leaks the same way a line of file content
  // would, and gets a distinct message so the two cases are
  // distinguishable in the output.
  for (const token of extractTokens(rel)) {
    if (bannedHashes.has(hashToken(token))) {
      findings.push(`${rel}: blocked token in file path (hash match)`);
      break;
    }
  }

  const lines = text.split('\n');
  for (const [lineNum, line] of lines.entries()) {
    if (DASH.test(line)) {
      findings.push(`${rel}:${lineNum + 1}: em/en dash (non-ASCII) in tracked file`);
    }
  }

  if (allowlisted) {
    return findings;
  }

  const pathMatch = text.match(INTERNAL_PATH);
  if (pathMatch) {
    const line = text.slice(0, pathMatch.index).split('\n').length;
    findings.push(`${rel}:${line}: internal workspace path`);
  }

  for (const [lineNum, line] of lines.entries()) {
    for (const token of extractTokens(line)) {
      if (bannedHashes.has(hashToken(token))) {
        findings.push(`${rel}:${lineNum + 1}: blocked token (hash match)`);
      }
    }
  }

  return findings;
}

function main() {
  const files = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'buffer' })
    .toString('utf8')
    .split('\0')
    .filter(Boolean);

  let failed = false;

  for (const rel of files) {
    if (rel.startsWith('node_modules/')) continue;

    const abs = path.join(ROOT, rel);
    let text = '';
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch {
      text = '';
    }

    for (const finding of scanFile(rel, text, { allowlisted: ALLOWLIST.has(rel) })) {
      console.error(`\u2717 ${finding}`);
      failed = true;
    }
  }

  if (failed) {
    console.error('\ncheck-private-names: remove private portfolio references from tracked files.');
    console.error('See CONTRIBUTING.md § Public repository hygiene.');
    process.exit(1);
  }

  console.log('check-private-names: no private portfolio references in tracked files.');
}

if (require.main === module) {
  main();
}

module.exports = { scanFile, hashToken };
