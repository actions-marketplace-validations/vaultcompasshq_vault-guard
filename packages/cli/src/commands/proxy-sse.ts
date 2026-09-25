export interface SseUsage {
  inputTokens: number;
  outputTokens: number;
  model: string | null;
}

/**
 * Extract token usage from a buffered Anthropic SSE stream.
 *
 * Pure and synchronous -- no HTTP dependencies -- so it can be unit-tested
 * without spinning up a server. Call after the full response has been teed.
 *
 * Anthropic usage token delivery:
 *   message_start  → message.usage.input_tokens  (and initial output_tokens)
 *   message_delta  → usage.output_tokens          (cumulative; last one wins)
 *   message_stop   → no usage fields
 *
 * Unknown or malformed `data:` lines are silently skipped.
 */
export function parseAnthropicSseUsage(raw: string, fallbackModel: string | null): SseUsage {
  let inputTokens = 0;
  let outputTokens = 0;
  let model = fallbackModel;

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data:')) continue;
    const payload = trimmed.slice('data:'.length).trim();
    if (!payload || payload === '[DONE]') continue;

    let evt: {
      type?: string;
      message?: { model?: string; usage?: { input_tokens?: number; output_tokens?: number } };
      usage?: { input_tokens?: number; output_tokens?: number };
    };
    try {
      evt = JSON.parse(payload);
    } catch {
      continue;
    }

    if (evt.type === 'message_start' && evt.message) {
      if (typeof evt.message.model === 'string') model = evt.message.model;
      const u = evt.message.usage ?? {};
      if (typeof u.input_tokens === 'number') inputTokens = u.input_tokens;
      if (typeof u.output_tokens === 'number') outputTokens = u.output_tokens;
    } else if (evt.type === 'message_delta' && evt.usage) {
      if (typeof evt.usage.input_tokens === 'number') inputTokens = evt.usage.input_tokens;
      if (typeof evt.usage.output_tokens === 'number') outputTokens = evt.usage.output_tokens;
    }
  }

  return { inputTokens, outputTokens, model };
}
