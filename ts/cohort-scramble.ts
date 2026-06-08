// SPDX-License-Identifier: Apache-2.0

// Per-cohort pseudonym-number scramble — closes the pool-range fingerprint.
//
// The engine returns a cohort where the real prompt carries low session numbers
// (EMAIL_1) and siblings carry high pool numbers (EMAIL_10001+). An adversary
// could just pick the low one as real — which defeats the whole point. This
// scramble rewrites EVERY pseudonym across all k prompts into one shared random
// space (per kind), so real and siblings are indistinguishable by number. It is
// fresh per call, so it also closes the deterministic-synthesis caveat.
//
// The real prompt's response comes back with scrambled pseudonyms; the caller
// un-scrambles via `realDemap` (scrambled → original session pseudonym) before
// reverse-mapping. Siblings are dropped, so their scrambled numbers map to
// nothing — no leak.

const PSEUDONYM = /\b([A-Z][A-Z0-9]*)_(\d+)\b/g;

/** Crypto-grade random int in [1, 1e6]. Math.random is predictable; for a
 *  privacy control the scramble must not be guessable. */
function randInt(): number {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return ((buf[0] ?? 0) % 1_000_000) + 1;
}

export interface ScrambledCohort {
  /** The k prompts with every pseudonym number randomized into one space. */
  prompts: string[];
  /** scrambled pseudonym → original (real prompt only), to undo on the reply. */
  realDemap: Map<string, string>;
}

/**
 * Rewrite every pseudonym across `cohort` into a fresh random number space
 * (distinct per kind), making the real prompt (index `realIndex`) numerically
 * indistinguishable from its siblings. Returns the rewritten prompts plus the
 * inverse map for the real prompt's pseudonyms.
 */
export function scrambleCohort(cohort: string[], realIndex: number): ScrambledCohort {
  // 1. Collect distinct pseudonyms, grouped by kind (prefix).
  const byKind = new Map<string, Set<string>>();
  for (const prompt of cohort) {
    for (const m of prompt.matchAll(PSEUDONYM)) {
      const kind = m[1]!;
      let set = byKind.get(kind);
      if (!set) {
        set = new Set();
        byKind.set(kind, set);
      }
      set.add(m[0]);
    }
  }

  // 2. Assign each distinct pseudonym a distinct random number within its kind.
  const remap = new Map<string, string>(); // original → scrambled
  for (const [kind, set] of byKind) {
    const used = new Set<number>();
    for (const pseudo of set) {
      let n = randInt();
      while (used.has(n)) n = randInt();
      used.add(n);
      remap.set(pseudo, `${kind}_${n}`);
    }
  }

  // 3. Rewrite every prompt with the scrambled numbers.
  const prompts = cohort.map((p) => applyPseudonymMap(p, remap));

  // 4. Inverse map for the real prompt's pseudonyms, so its reply un-scrambles.
  const realDemap = new Map<string, string>();
  const real = cohort[realIndex] ?? "";
  for (const m of real.matchAll(PSEUDONYM)) {
    const original = m[0];
    const scrambled = remap.get(original);
    if (scrambled) realDemap.set(scrambled, original);
  }

  return { prompts, realDemap };
}

/** Replace every `PREFIX_<n>` token in `text` using `map`; leave unmapped
 *  tokens untouched (same policy as the engine's reverse-map). */
export function applyPseudonymMap(text: string, map: Map<string, string>): string {
  return text.replace(PSEUDONYM, (tok) => map.get(tok) ?? tok);
}
