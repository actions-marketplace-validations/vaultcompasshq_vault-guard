import * as vscode from 'vscode';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { SecretScanner, loadConfig, ConfigError } from '@vaultcompass/vault-guard-core';

const collection = vscode.languages.createDiagnosticCollection('vault-guard');

function mapSeverity(s: string): vscode.DiagnosticSeverity {
  if (s === 'critical' || s === 'high') return vscode.DiagnosticSeverity.Error;
  if (s === 'medium') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

/**
 * Load Vault Guard config, falling back to defaults on parse errors.
 * The extension host must not crash on a user config typo -- surface the
 * problem in the OUTPUT channel and continue scanning with built-in rules.
 */
function safeLoadConfig(dir: string): ReturnType<typeof loadConfig> {
  try {
    return loadConfig(dir);
  } catch (e) {
    if (e instanceof ConfigError) {
      void vscode.window.showWarningMessage(
        `Vault Guard: ignoring broken config at ${e.filePath}. ${e.message}`,
      );
      return {};
    }
    throw e;
  }
}

function refreshDocument(doc: vscode.TextDocument): void {
  if (doc.uri.scheme !== 'file') return;
  const dir = path.dirname(doc.uri.fsPath);
  const scanner = new SecretScanner(safeLoadConfig(dir));
  const matches = scanner.scanContent(doc.getText(), { filePath: doc.uri.fsPath });
  const diags: vscode.Diagnostic[] = matches.map(m => {
    const lineIdx = Math.max(0, m.line - 1);
    const line = doc.lineAt(lineIdx);
    const endChar = Math.min(line.text.length, m.column + Math.max(1, m.matchLength));
    const startChar = Math.min(line.text.length, m.column);
    const range = new vscode.Range(lineIdx, startChar, lineIdx, endChar);
    return new vscode.Diagnostic(
      range,
      `Possible secret (${m.type}, ${m.severity})`,
      mapSeverity(m.severity),
    );
  });
  collection.set(doc.uri, diags);
}

function updateStatusBar(item: vscode.StatusBarItem): void {
  const exe = vscode.workspace.getConfiguration('vaultGuard').get<string>('executable', 'vault-guard');
  const out = spawnSync(exe, ['statusline', '--json'], { encoding: 'utf8', timeout: 2500 });
  if (out.error || out.status !== 0) {
    item.text = '$(shield) vault-guard';
    item.tooltip = out.stderr?.trim() || out.error?.message || 'vault-guard statusline failed';
    item.show();
    return;
  }
  try {
    const j = JSON.parse(out.stdout) as {
      secrets_today: number;
      est_cost_usd: number;
      tokens_today_input: number;
      tokens_today_output: number;
    };
    item.text = `$(key) ~$${Number(j.est_cost_usd).toFixed(2)} · $(error) ${j.secrets_today}`;
    item.tooltip = `Tokens today (in/out): ${j.tokens_today_input} / ${j.tokens_today_output}\n${out.stdout.trim()}`;
  } catch {
    item.text = '$(shield) vault-guard';
    item.tooltip = 'Could not parse statusline JSON';
  }
  item.show();
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(collection);

  const onDoc = (doc: vscode.TextDocument) => {
    if (doc.uri.scheme === 'file') refreshDocument(doc);
  };

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(onDoc),
    vscode.workspace.onDidSaveTextDocument(onDoc),
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor?.document) onDoc(editor.document);
    }),
  );

  if (vscode.window.activeTextEditor) {
    onDoc(vscode.window.activeTextEditor.document);
  }

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.name = 'Vault Guard';
  updateStatusBar(status);
  const handle = setInterval(() => updateStatusBar(status), 30_000);
  context.subscriptions.push(status);
  context.subscriptions.push({ dispose: () => clearInterval(handle) });

  context.subscriptions.push(
    vscode.commands.registerCommand('vaultGuard.copyAllowListSnippet', async () => {
      const snippet =
        '{\n' +
        '  "ignore": {\n' +
        '    "paths": []\n' +
        '  },\n' +
        '  "severity_overrides": {}\n' +
        '}\n';
      await vscode.env.clipboard.writeText(snippet);
      void vscode.window.showInformationMessage('Copied .vault-guard.json starter snippet to clipboard.');
    }),
  );
}

export function deactivate(): void {
  collection.dispose();
}
