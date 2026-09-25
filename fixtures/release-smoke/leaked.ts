/**
 * Release smoke fixture -- pattern-only match for CI (not a real credential).
 * Uses the Anthropic key prefix format (sk-ant-) which vault-guard detects.
 * The fixtures/ directory is excluded from vault-guard pre-commit scans via
 * .vault-guard.json so this synthetic key does not block commits.
 */
export const _fixture = 'sk-ant-api03-fakekeyfortesting1234567890ABCDEFGHIJ';
