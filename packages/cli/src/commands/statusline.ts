import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

// TelemetryStore never throws (a missing/incompatible better-sqlite3 native
// binding degrades it to a no-op that reports zeroed stats), so this command
// never needs to special-case "telemetry unavailable": it always constructs,
// always prints something, and never prints an unavailability warning on
// every invocation (statusline can be invoked by an editor every few
// seconds; see @vaultcompass/vault-guard-telemetry's store.ts for the
// single, opt-in (VG_DEBUG=1) debug notice logged once per process instead).
export function statuslineCommand(asJson: boolean): void {
  const store = new TelemetryStore();

  try {
    const payload = store.getStatuslinePayload();
    if (asJson) {
      process.stdout.write(`${JSON.stringify(payload)}\n`);
      return;
    }
    process.stdout.write(
      `Vault Guard (today UTC): secrets=${payload.secrets_today} tokens in/out=${payload.tokens_today_input}/${payload.tokens_today_output} est_cost_usd≈${payload.est_cost_usd} model=${payload.model ?? ' -- '}\n`,
    );
  } finally {
    store.close();
  }
}
