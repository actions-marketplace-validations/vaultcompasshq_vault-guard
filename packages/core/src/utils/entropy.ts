/**
 * Compute Shannon entropy (bits per character) for a string.
 *
 * High-entropy strings (≥ ~3.5 bits/char) look random -- the hallmark of a
 * generated secret.  Low-entropy strings (< 3.5 bits/char) are readable
 * words, git SHAs composed of a small alphabet, or repetitive padding.
 *
 * Used as a secondary gate for broad "generic" patterns that cannot be
 * anchored to a vendor-specific prefix.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const ch of value) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }

  let h = 0;
  const len = value.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    h -= p * Math.log2(p);
  }

  return h;
}

/**
 * Default entropy threshold for generic / catch-all patterns.
 * Values below this are likely false positives (readable words, hex hashes…).
 */
export const DEFAULT_ENTROPY_THRESHOLD = 3.5;
