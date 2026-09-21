/**
 * Recall tests for OpenAI key detection patterns.
 *
 * Uses fake-but-real-shaped keys that include the T3BlbkFJ watermark
 * (base64 for "OpenAI") but with clearly synthetic surrounding segments.
 * None of these values are real credentials.
 */
import { SecretScanner } from '../scanners/secret-scanner';

const scanner = new SecretScanner();

function matchedRules(text: string): string[] {
  return scanner.scanContent(text).map(m => m.type);
}

describe('OpenAI key detection recall', () => {
  describe('sk-proj- (project key)', () => {
    it('detects a project key with T3BlbkFJ watermark', () => {
      // Synthetic: random-looking prefix + watermark + suffix
      const key = 'sk-proj-' + 'aB3cD4eF5gH6iJ7kLmNoPqRs' + 'T3BlbkFJ' + 'tUvWxYz0123456789abcd';
      expect(matchedRules(`OPENAI_API_KEY=${key}`)).toContain('openai-project');
    });

    it('handles underscore/dash chars in project key', () => {
      const key = 'sk-proj-' + 'aB3_cD4-eF5_gH6-iJ7k_LmNo' + 'T3BlbkFJ' + 'tU_vW-xYz012_3456789ab';
      expect(matchedRules(`key = "${key}"`)).toContain('openai-project');
    });
  });

  describe('sk-svcacct- (service account key)', () => {
    it('detects a service account key with T3BlbkFJ watermark', () => {
      const key = 'sk-svcacct-' + 'aB3cD4eF5gH6iJ7kLmNoPqRsT' + 'T3BlbkFJ' + 'uVwXyZ0123456789abcde';
      expect(matchedRules(`token: ${key}`)).toContain('openai-svcacct');
    });
  });

  describe('sk-admin- (admin key)', () => {
    it('detects an admin key with T3BlbkFJ watermark', () => {
      const key = 'sk-admin-' + 'aB3cD4eF5gH6iJ7kLmNoPqRsT' + 'T3BlbkFJ' + 'uVwXyZ0123456789abcde';
      expect(matchedRules(`OPENAI_ADMIN_KEY=${key}`)).toContain('openai-admin');
    });
  });

  describe('sk- (legacy user key)', () => {
    it('detects a legacy key with T3BlbkFJ watermark at 20+8+20 length', () => {
      // Legacy format: sk- + 20 alphanum + T3BlbkFJ + 20 alphanum
      const key = 'sk-' + 'aB3cD4eF5gH6iJ7kLmNo' + 'T3BlbkFJ' + 'PqRsTuVwXyZ012345678';
      expect(matchedRules(`api_key = "${key}"`)).toContain('openai');
    });

    it('detects legacy key at line start', () => {
      const key = 'sk-' + 'Xk9Qp2Lm7Rt4Wx8Bn1Vc' + 'T3BlbkFJ' + '9zRvMn3Kp8Qx2Lm7Wt4Y';
      expect(matchedRules(key)).toContain('openai');
    });
  });

  describe('false positive guards', () => {
    it('does NOT flag a bare sk- identifier without watermark', () => {
      // Short, no watermark -- should not fire
      expect(matchedRules('const sk = "sk-short123"')).not.toContain('openai');
    });

    it('does NOT flag sk- mid-word (token boundary)', () => {
      // Embedded in an identifier -- not a standalone key
      expect(matchedRules('mysk-proj-config-value')).not.toContain('openai-project');
    });

    it('does NOT flag sk-proj- without the watermark', () => {
      // Missing T3BlbkFJ -- below threshold for watermark pattern
      const fakeish = 'sk-proj-' + 'a'.repeat(40);
      expect(matchedRules(fakeish)).not.toContain('openai-project');
    });
  });
});
