/**
 * Base error class for Vault Guard errors
 */
export class VaultGuardError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'VaultGuardError';
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error thrown when scanning fails
 */
export class ScanError extends VaultGuardError {
  constructor(message: string, public filePath?: string) {
    super(message, 'SCAN_ERROR');
    this.name = 'ScanError';
  }
}

/**
 * Error thrown when file access fails
 */
export class FileAccessError extends VaultGuardError {
  constructor(message: string, public filePath: string) {
    super(message, 'FILE_ACCESS_ERROR');
    this.name = 'FileAccessError';
  }
}

/**
 * Error thrown when hook installation fails
 */
export class HookError extends VaultGuardError {
  constructor(message: string, public operation: 'install' | 'uninstall') {
    super(message, 'HOOK_ERROR');
    this.name = 'HookError';
  }
}

/**
 * Error thrown when a `.vault-guard.json` config file cannot be read or parsed.
 *
 * Why this is a distinct error: silently falling back to defaults on a typo'd
 * config file is dangerous for a security tool -- the user thinks their
 * `severity_overrides` / `extra_patterns` are honoured when they are not.
 * Callers (CLI, MCP) catch this, print the file path + parser message, and
 * exit non-zero so the user can fix the config rather than ship undetected.
 *
 * @param message - Human-readable parse/read failure explanation.
 * @param filePath - Absolute path to the offending `.vault-guard.json`.
 */
export class ConfigError extends VaultGuardError {
  constructor(message: string, public readonly filePath: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'ConfigError';
  }
}

/**
 * Error thrown when git operations fail during a scan.
 *
 * Why this is a hard error: `getGitStagedFilePaths` returning `[]` on
 * git failure would silently produce a "✅ nothing staged" result during
 * pre-commit, allowing secrets to bypass detection without any feedback.
 * Callers should exit 2 and display this message so the user knows whether
 * the ✅ is genuine or git-broken.
 *
 * @param message - Human-readable failure details.
 * @param command - Git command that failed.
 * @param cause - Original thrown error (if available).
 */
export class GitError extends VaultGuardError {
  constructor(message: string, public readonly command: string, public readonly cause?: unknown) {
    super(message, 'GIT_ERROR');
    this.name = 'GitError';
  }
}
