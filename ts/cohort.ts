// SPDX-License-Identifier: Apache-2.0

// Cohort blender — Phase 8 k-anon sampler (TS port stub).
//
// For a `private` prompt, we fan out K kind-shape-identical sibling prompts
// drawn from K-1 nearest-neighbor vault notes, so the wire-side adversary
// sees 1/K probability of identifying the real one. The full Phase 8
// machinery (StaticPoolSynthesizer, sibling-text rewrite, response audit) is
// in `claw-code/veil-phase-0` (Rust, 528 lines, 20 tests). This file is the
// TS surface that the router calls; the heavy synthesizer lands when the
// WASM bind from claw-code/veil-phase-0 is published.
//
// Citation: ~/brain/research-vault/experiments/E29-veil-phase-8-kanon.md.
//
// Storage layer is shipped in parallel by Athena's storage stream; we
// stub `VaultRef` to its expected shape so wiring lands at merge.

import type { Msg } from "./interface";

/**
 * Storage-layer handle for the local vault's vector index. The storage stream
 * ships the real implementation in parallel; this is the contract the router
 * codes against. Athena merges the wiring.
 */
export interface VaultRef {
  /**
   * K-NN search over vault embeddings. Returns up to `k` neighbors of the
   * query, each with a stable id and the (already pseudonymized) note body.
   * The storage layer is responsible for filtering by `tier` ≥ caller's tier.
   */
  search(query: string, k: number): Promise<VaultNeighbor[]>;
}

export interface VaultNeighbor {
  id: string;
  /** Pseudonymized note body, ready to substitute into a sibling prompt. */
  content: string;
  /** Optional similarity score in [0, 1] for diagnostics. */
  similarity?: number;
}

export interface CohortBlendOpts {
  /** Cohort size; default 8 (per VEIL.md §4.2). K=2 is the floor. */
  k?: number;
  /**
   * System message prepended to every cohort member, real and sibling. Useful
   * for telemetry — the router can stamp the cohort tag here.
   */
  systemPreamble?: string;
}

/**
 * Build a K-cohort for a `private` query. Returns K Msg arrays (one real, K-1
 * synthesized siblings) interleaved by index. Caller dispatches each Msg array
 * through the configured chat backend, keeps the real-index response, drops
 * the rest.
 *
 * For now the "synthesizer" is identity — the neighbor's pseudonymized
 * content is itself the sibling prompt. The full StaticPoolSynthesizer (which
 * rewrites entity tokens onto a session-disjoint pool) lands when the WASM
 * bind from claw-code/veil-phase-0 is published.
 */
export async function cohortBlend(
  query: string,
  vault: VaultRef,
  opts: CohortBlendOpts = {},
): Promise<CohortPlan> {
  const k = Math.max(2, Math.min(16, opts.k ?? 8));

  // Pull K-1 neighbors. Storage filters by tier; we trust its output.
  const neighbors = await vault.search(query, k - 1);

  // The real prompt and siblings are interleaved by random index in [0, K).
  // For now: deterministic position 0 for the real one — acceptable while
  // the storage layer's per-session pool randomization (Phase 8 v2) isn't
  // wired. Documented in VEIL.md §4.3 as "pool-range fingerprint".
  const cohort: Msg[][] = [];
  const realIndex = 0;

  const buildMsgs = (content: string): Msg[] => {
    const msgs: Msg[] = [];
    if (opts.systemPreamble) {
      msgs.push({ role: "system", content: opts.systemPreamble });
    }
    msgs.push({ role: "user", content, veilTier: "private" });
    return msgs;
  };

  cohort.push(buildMsgs(query));
  for (const n of neighbors) {
    cohort.push(buildMsgs(n.content));
  }

  // If storage returned fewer neighbors than asked, pad with the real query
  // duplicated — degrades the privacy guarantee gracefully (entropy drops to
  // log2(real-cohort-size)). Future: error-out under strict mode (E29
  // CohortFailure::Abort).
  while (cohort.length < k) {
    cohort.push(buildMsgs(query));
  }

  return {
    cohort,
    realIndex,
    requestedK: k,
    achievedK: cohort.length,
    neighborIds: neighbors.map((n) => n.id),
  };
}

/**
 * The shape returned to the router so it knows which cohort response to keep.
 * Sibling responses are logged + dropped per Phase 8 v1.
 */
export interface CohortPlan {
  /** Flat list of K Msg arrays. cohort[realIndex] is the user's real prompt. */
  cohort: Msg[][];
  /** Which index in `cohort` is the real prompt. */
  realIndex: number;
  /** Cohort size requested by the caller (post-clamp). */
  requestedK: number;
  /** Cohort size actually achieved (may be < requestedK if vault is sparse). */
  achievedK: number;
  /** IDs of the vault neighbors that contributed siblings — for audit. */
  neighborIds: string[];
}

/**
 * Convenience: turn a CohortPlan into a flat list of Msg arrays. Exported so
 * tests can introspect the cohort without the plan-shape ceremony.
 */
export function flattenCohort(plan: CohortPlan): Msg[][] {
  return plan.cohort;
}
