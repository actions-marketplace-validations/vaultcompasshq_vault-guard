import fs from 'fs';
import chalk from 'chalk';
import {
  findVaultGuardConfigPath,
  validateVaultGuardConfig,
  SecretScanner,
} from '@vaultcompass/vault-guard-core';

/**
 * Validate the nearest `.vault-guard.json` / `.vault-guard.local.json`.
 * Exits 0 when missing (nothing to validate) or when structurally valid.
 */
export async function configValidateCommand(cwd: string = process.cwd()): Promise<number> {
  const configPath = findVaultGuardConfigPath(cwd);
  if (!configPath) {
    console.log(chalk.green('✓'), chalk.white('No Vault Guard config file in search path -- nothing to validate.'));
    return 0;
  }

  let raw: string;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    console.error(chalk.red('❌'), chalk.white(`Failed to read ${configPath}: ${detail}`));
    return 1;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    console.error(chalk.red('❌'), chalk.white(`Invalid JSON in ${configPath}: ${detail}`));
    return 1;
  }

  const v = validateVaultGuardConfig(parsed);
  if (!v.ok) {
    console.error(chalk.red('❌'), chalk.white(configPath));
    for (const err of v.errors) {
      console.error(chalk.gray('  ·'), chalk.white(err));
    }
    return 1;
  }

  const scanner = new SecretScanner(v.config);
  if (scanner.extraPatternRejections.length > 0) {
    console.error(chalk.yellow('⚠'), chalk.white('Some extra_patterns were rejected and are not active:'));
    for (const r of scanner.extraPatternRejections) {
      console.error(chalk.gray('  ·'), chalk.white(`${r.id}: ${r.reason} -- ${r.detail}`));
    }
    return 1;
  }

  console.log(chalk.green('✓'), chalk.white(`${configPath} is valid.`));
  return 0;
}
