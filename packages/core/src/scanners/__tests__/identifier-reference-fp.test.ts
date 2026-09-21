import { SecretScanner } from '../secret-scanner';
import { isCodeIdentifierReference } from '../../utils/placeholder';

/**
 * Regression guards for the two false-positive classes found by scanning real
 * repositories in the 1.4.0 audit (neither was represented in `bench/`).
 */
describe('unquoted identifier references are not secrets', () => {
  const scanner = new SecretScanner();

  const shouldBeClean = [
    `headers: { "x-api-key": scheduledIngestApiKey },`,
    `api_key = default_service_credential`,
    `secret: internalSigningSecret,`,
    `const opts = { apiKey: externalBillingServiceKey };`,
    `password: currentUserPasswordField`,
  ];

  it.each(shouldBeClean)('does not flag %s', line => {
    expect(scanner.scanContent(line)).toEqual([]);
  });

  const shouldStillDetect = [
    `api_key = "x7Kf9mQ2pL8vB3nR5wT1cD4a"`,
    `API_KEY=x7Kf9mQ2pL8vB3nR5wT1cD4a`,
    `apiKey: "PmZkQvXtLdRwNbGhYuJcEaSf"`,
  ];

  it.each(shouldStillDetect)('still detects a literal value in %s', line => {
    expect(scanner.scanContent(line).length).toBeGreaterThan(0);
  });

  it('only suppresses unquoted values -- a quoted identifier-shaped literal still fires', () => {
    const quoted = scanner.scanContent(`api_key = "scheduledIngestApiKey"`);
    const unquoted = scanner.scanContent(`api_key = scheduledIngestApiKey`);
    expect(quoted.length).toBeGreaterThan(0);
    expect(unquoted).toEqual([]);
  });

  describe('isCodeIdentifierReference', () => {
    it.each([
      'scheduledIngestApiKey',
      'default_service_credential',
      'internalSigningSecret',
      'someVeryLongDescriptiveVariableName',
    ])('treats %s as an identifier', v => {
      expect(isCodeIdentifierReference(v)).toBe(true);
    });

    it.each([
      'PmZkQvXtLdRwNbGhYuJcEaSf', // alpha-only random, alternating caps
      'zmxncbvlkjhgfdsapoiuytre', // single lowercase run
      'x7Kf9mQ2pL8vB3nR5wT1', // contains digits
      'AKIAIOSFODNN7EXAMPLE',
    ])('rejects %s', v => {
      expect(isCodeIdentifierReference(v)).toBe(false);
    });
  });
});

describe('hyphenated your-* placeholders', () => {
  const scanner = new SecretScanner();

  it.each([
    `ANTHROPIC_API_KEY="your-anthropic-api-key"`,
    `OPENAI_API_KEY="your-openai-api-key-here"`,
    `api_key: "your-key-goes-right-here"`,
  ])('suppresses %s', line => {
    expect(scanner.scanContent(line)).toEqual([]);
  });

  it('still suppresses the underscore form (existing behaviour)', () => {
    expect(scanner.scanContent(`ANTHROPIC_API_KEY="your_anthropic_api_key"`)).toEqual([]);
  });
});
