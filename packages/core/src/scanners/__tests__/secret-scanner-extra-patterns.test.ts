import { SecretScanner } from '../secret-scanner';
import { REGEX_MAX_LENGTH } from '../../utils/regex-safety';

describe('SecretScanner -- extra_patterns (ReDoS guard)', () => {
  // ---------------------------------------------------------------------------
  // Happy path
  // ---------------------------------------------------------------------------

  it('compiles a valid extra pattern and matches it', () => {
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'custom-token', regex: 'tok_[a-zA-Z0-9]{32,}', severity: 'high' },
      ],
    });
    expect(scanner.extraPatternRejections).toHaveLength(0);
    const matches = scanner.scanContent('const t = "tok_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";');
    expect(matches.some(m => m.type === 'custom-token')).toBe(true);
  });

  it('respects min_entropy on an extra pattern', () => {
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'hi-entropy', regex: 'tok_[a-zA-Z0-9]{20,}', severity: 'high', min_entropy: 3.5 },
      ],
    });
    // Low-entropy value "tok_AAAAAAAAAAAAAAAAAAAAAA" should not match
    expect(scanner.scanContent('tok_AAAAAAAAAAAAAAAAAAAAAA')).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // ReDoS rejections (heuristic)
  // ---------------------------------------------------------------------------

  it('rejects a nested-quantifier pattern and records it in extraPatternRejections', () => {
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'bad-pat', regex: '(a+)+', severity: 'high' },
      ],
    });
    expect(scanner.extraPatternRejections).toHaveLength(1);
    expect(scanner.extraPatternRejections[0].id).toBe('bad-pat');
    expect(scanner.extraPatternRejections[0].reason).toBe('nested_quantifier');
    // Pattern must not be compiled -- scanning with it should return no results
    expect(scanner.scanContent('aaaaaaaaaaaaa')).toHaveLength(0);
  });

  it('rejects an alternation-quantifier pattern', () => {
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'alt-pat', regex: '(foo|bar)*', severity: 'medium' },
      ],
    });
    expect(scanner.extraPatternRejections[0].id).toBe('alt-pat');
    expect(scanner.extraPatternRejections[0].reason).toBe('alternation_quantifier');
  });

  it('rejects a pattern exceeding 256 chars even when other checks would pass', () => {
    const longButSafe = 'a'.repeat(REGEX_MAX_LENGTH + 1);
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'too-long', regex: longButSafe, severity: 'low' },
      ],
    });
    expect(scanner.extraPatternRejections[0].id).toBe('too-long');
    expect(scanner.extraPatternRejections[0].reason).toBe('too_long');
  });

  it('records invalid regex syntax as invalid_syntax', () => {
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'invalid', regex: '[unclosed', severity: 'low' },
      ],
    });
    expect(scanner.extraPatternRejections[0].id).toBe('invalid');
    expect(scanner.extraPatternRejections[0].reason).toBe('invalid_syntax');
  });

  // ---------------------------------------------------------------------------
  // extra_patterns_unsafe flag
  // ---------------------------------------------------------------------------

  it('accepts a ReDoS-shaped pattern when extra_patterns_unsafe is true', () => {
    // The heuristic is bypassed -- only the length cap applies.
    // Note: we do NOT actually exec a pathological pattern here; just confirm
    // it compiles and appears in `patterns` (i.e. no rejection).
    const scanner = new SecretScanner({
      extra_patterns_unsafe: true,
      extra_patterns: [
        { id: 'unsafe-pat', regex: '(a|a)+', severity: 'low' },
      ],
    });
    expect(scanner.extraPatternRejections).toHaveLength(0);
  });

  it('still rejects a >256-char pattern even when extra_patterns_unsafe is true', () => {
    const longPattern = 'a'.repeat(REGEX_MAX_LENGTH + 1);
    const scanner = new SecretScanner({
      extra_patterns_unsafe: true,
      extra_patterns: [
        { id: 'unsafe-too-long', regex: longPattern, severity: 'low' },
      ],
    });
    // Length cap is the backstop regardless of the unsafe flag.
    expect(scanner.extraPatternRejections).toHaveLength(1);
    expect(scanner.extraPatternRejections[0].reason).toBe('too_long');
  });

  // ---------------------------------------------------------------------------
  // Multiple patterns -- mix of valid and rejected
  // ---------------------------------------------------------------------------

  it('compiles valid patterns while rejecting bad ones from the same config', () => {
    const scanner = new SecretScanner({
      extra_patterns: [
        { id: 'good', regex: 'GOOD_[a-zA-Z0-9]{20,}', severity: 'high' },
        { id: 'bad', regex: '(a+)+', severity: 'high' },
        { id: 'also-good', regex: 'ALSO_[a-zA-Z0-9]{20,}', severity: 'medium' },
      ],
    });
    // One rejection, two valid
    expect(scanner.extraPatternRejections).toHaveLength(1);
    expect(scanner.extraPatternRejections[0].id).toBe('bad');
    // Both good patterns should fire
    const content = 'GOOD_AbCdEfGhIjKlMnOpQrStUv ALSO_AbCdEfGhIjKlMnOpQrStUv';
    const matches = scanner.scanContent(content);
    expect(matches.map(m => m.type)).toEqual(expect.arrayContaining(['good', 'also-good']));
  });
});
