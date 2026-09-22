import { validateRegexSafety, validateRegexLength, REGEX_MAX_LENGTH } from '../utils/regex-safety';

// ---------------------------------------------------------------------------
// Smoke test: every built-in pattern must pass the heuristic.
// If this test fails it means we tightened the heuristic and accidentally
// broke our own detection rules -- fix the heuristic, not the patterns.
// ---------------------------------------------------------------------------

describe('validateRegexSafety -- built-in pattern smoke test', () => {
  // These are the exact regex sources from BUILTIN_PATTERNS in secret-scanner.ts.
  // If a pattern changes there, update it here too (and check it still passes).
  const builtinSources = [
    /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    /sk-[a-zA-Z0-9]{48}/g,
    /sk-proj-[a-zA-Z0-9_-]{48,}/g,
    /hf_[a-zA-Z0-9]{34,}/g,
    /r8_[a-zA-Z0-9]{32}/g,
    /sk_live_[a-zA-Z0-9]{24,}/g,
    /sk_test_[a-zA-Z0-9]{24,}/g,
    /access_token\$production\$[a-zA-Z0-9]{20,}/g,
    /AKIA[0-9A-Z]{16}/g,
    /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([a-zA-Z0-9/+]{40})/gi,
    /"type":\s*"service_account"/g,
    /AIza[a-zA-Z0-9_-]{35}/g,
    /[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g,
    /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}/g,
    /postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?\/\S+/g,
    /mysql:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?\/\S+/g,
    /mongodb(?:\+srv)?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?/g,
    /rediss?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)/g,
    /gh[pousor]_[a-zA-Z0-9]{36}/g,
    /github_pat_[a-zA-Z0-9_]{82}/g,
    /glpat-[a-zA-Z0-9_-]{20}/g,
    /BBDC-[a-zA-Z0-9_-]{40}/g,
    /hooks\.slack\.com\/services\/[A-Z0-9]{9,}\/[A-Z0-9]{9,}\/[a-zA-Z0-9]{20,}/g,
    /xox[baprs]-[a-zA-Z0-9-]{10,}/g,
    /discord\.com\/api\/webhooks\/[0-9]{17,20}\/[a-zA-Z0-9_-]{60,}/g,
    /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    /re_[a-zA-Z0-9]{32,}/g,
    /key-[a-zA-Z0-9]{32}/g,
    /npm_[a-zA-Z0-9]{36}/g,
    /NRAK-[a-zA-Z0-9]{26}/g,
    /shp(?:ss|at|ca)_[a-zA-Z0-9]{32}/g,
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
    /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    /Bearer [a-zA-Z0-9_-]{20,}/g,
    /api[_-]?key["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,
    /secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,
    /password["']?\s*[:=]\s*["']([a-zA-Z0-9_\-!@#$%^&*]{12,})/gi,
  ].map(r => r.source);

  for (const src of builtinSources) {
    it(`accepts: ${src.slice(0, 60)}${src.length > 60 ? '…' : ''}`, () => {
      const result = validateRegexSafety(src);
      expect(result.ok).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Rejection cases
// ---------------------------------------------------------------------------

describe('validateRegexSafety -- rejections', () => {
  it('rejects a pattern longer than REGEX_MAX_LENGTH chars', () => {
    const longPattern = 'a'.repeat(REGEX_MAX_LENGTH + 1);
    const result = validateRegexSafety(longPattern);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('too_long');
    expect(result.detail).toContain(String(REGEX_MAX_LENGTH + 1));
  });

  it('rejects nested quantifier (a+)+', () => {
    const result = validateRegexSafety('(a+)+');
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('nested_quantifier');
  });

  it('rejects nested quantifier (\\d+)*', () => {
    const result = validateRegexSafety('(\\d+)*');
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('nested_quantifier');
  });

  it('rejects alternation under quantifier (a|b)+', () => {
    const result = validateRegexSafety('(a|b)+');
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('alternation_quantifier');
  });

  it('rejects alternation under quantifier (foo|bar)*', () => {
    const result = validateRegexSafety('(foo|bar)*');
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('alternation_quantifier');
  });

  it('rejects pattern with more than 25 quantifiers', () => {
    // 26 explicit `+` quantifiers; each on a literal character
    const many = 'a+'.repeat(26);
    const result = validateRegexSafety(many);
    // 26 chars * 2 = 52 chars, well under 256
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('too_many_quantifiers');
  });
});

// ---------------------------------------------------------------------------
// Accepted edge cases
// ---------------------------------------------------------------------------

describe('validateRegexSafety -- accepted patterns', () => {
  it('accepts quantifier characters inside a character class without counting them', () => {
    // [a-z?+*]{20,} -- the ?, +, * are inside [] so must not count as quantifiers
    // Only the outer {20,} is a quantifier (the `{` character = 1 quantifier)
    const result = validateRegexSafety('[a-z?+*]{20,}');
    expect(result.ok).toBe(true);
  });

  it('accepts a realistic but complex pattern with many non-nested quantifiers', () => {
    // A URL-ish pattern -- each `+` / `*` is on a distinct non-overlapping class
    const result = validateRegexSafety('https?://[^:@]+:[^@]+@[^:/]+(?::\\d+)?/\\S+');
    expect(result.ok).toBe(true);
  });

  it('accepts escaped quantifier characters (\\+ \\*)', () => {
    // Escaped quantifiers should not be counted
    const result = validateRegexSafety('\\+\\*\\?{literal}');
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// validateRegexLength -- backstop even with unsafe flag
// ---------------------------------------------------------------------------

describe('validateRegexLength', () => {
  it('rejects sources exceeding the length cap', () => {
    const result = validateRegexLength('x'.repeat(REGEX_MAX_LENGTH + 1));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('too_long');
  });

  it('accepts sources at or under the length cap', () => {
    expect(validateRegexLength('x'.repeat(REGEX_MAX_LENGTH)).ok).toBe(true);
    expect(validateRegexLength('(a+)+').ok).toBe(true); // ReDoS but under length
  });
});
