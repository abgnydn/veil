// SPDX-License-Identifier: Apache-2.0

// VeilEnforcer — the tier-enforcement hook a consumer (e.g. an MCP server)
// calls to push a prompt through veil end-to-end.
//
// It is the input-side checkpoint from VEIL.md §3.1 wired to the now-working
// engine round-trip:
//
//   public / internal  → dispatch raw to a backend (remote preferred).
//   private            → pseudonymize via the Rust engine (wrapWithVeil): the
//                        model sees EMAIL_1, the reply is reverse-mapped back.
//                        Falls back to a local backend (raw is OK on-device).
//   secret             → local backend only. If none, WITHHELD — never a
//                        remote LLM (Hard Invariant 1, fail-closed).
//
// The two hard invariants live here as control flow, not config: secret never
// reaches a non-local backend, and private never reaches a remote backend raw
// (wrapWithVeil pseudonymizes before egress; the AnthropicAdapter's own guard
// is the backstop).

import {
  argmaxTier,
  bumpTier,
  tierMargin,
  VeilRoutingError,
} from "./interface";
import type { Msg, Tier, TierScores, Token, VeilBackend } from "./interface";
import { classifyTierHeuristic } from "./classifier";
import type { RustPipelineClient } from "./rust-client";
import { wrapWithVeil } from "./veil-wrap";
import { applyPseudonymMap, scrambleCohort } from "./cohort-scramble";

export interface VeilEnforcerOpts {
  /** The Rust engine, used to pseudonymize `private` content before egress. */
  engine: RustPipelineClient;
  /** Conversation key for stable pseudonyms across turns. */
  sessionId: string;
  /** Remote backend (e.g. Anthropic). Used for public/internal, and for
   *  private *after* pseudonymization. Never receives secret or raw private. */
  remote?: VeilBackend;
  /** Local, on-device backend (`runsLocally`). The only place secret content
   *  may go; also the private fallback when no remote is configured. */
  local?: VeilBackend;
  /** Tier classifier. Defaults to the local heuristic. Must run locally —
   *  classifying on a remote model is itself a leak. */
  classify?: (text: string) => Promise<TierScores> | TierScores;
  /** Escalation margin; if the top-two tier gap is under this, bump one rung
   *  up (caution beats leak). Default 0.2 per VEIL.md §3.1. */
  escalationMargin?: number;
  /** k-anonymous cohort size for `private` content sent to a remote. When > 1,
   *  the private prompt is fanned out alongside k-1 pool-disjoint siblings so a
   *  wire-side adversary sees 1/k odds of picking the real one (entropy
   *  log2(k)). Default 1 (pseudonymize only, no fan-out). Cohort dispatch is
   *  batch, not streamed (VEIL.md §4.3). Costs k× the provider calls. */
  cohortK?: number;
}

/** Secret content with nowhere local to run — refused, not sent remote. */
export interface Withheld {
  withheld: true;
  tier: Tier;
  escalated: boolean;
  reason: string;
}

/** A prompt cleared for dispatch. `stream` is already reverse-mapped for the
 *  private path, so the caller always sees real entities. */
export interface Dispatched {
  withheld: false;
  tier: Tier;
  escalated: boolean;
  /** Id of the backend the request went to (`veil(anthropic)` when wrapped). */
  backendId: string;
  /** True iff the content was pseudonymized before egress (the private path). */
  transformed: boolean;
  /** Set when the private content was cohort-blended. `achievedK` siblings were
   *  fanned out; the wire saw `achievedK` indistinguishable prompts. */
  cohort?: { requestedK: number; achievedK: number };
  stream: AsyncIterable<Token>;
}

export type EnforceResult = Withheld | Dispatched;

const DEFAULT_ESCALATION_MARGIN = 0.2;

export class VeilEnforcer {
  constructor(private readonly opts: VeilEnforcerOpts) {}

  /**
   * Classify `input`, apply the escalation rule, and route per tier with the
   * hard invariants enforced in code. Returns either a (reverse-mapped) reply
   * stream or a `Withheld` verdict. Throws `VeilRoutingError` only when a tier
   * has no eligible backend at all.
   */
  async enforce(input: string): Promise<EnforceResult> {
    const classify = this.opts.classify ?? classifyTierHeuristic;
    const margin = this.opts.escalationMargin ?? DEFAULT_ESCALATION_MARGIN;

    const scores = await classify(input);
    const base = argmaxTier(scores);
    const escalated = tierMargin(scores) < margin;
    const tier: Tier = escalated ? bumpTier(base) : base;

    const { remote, local, engine, sessionId } = this.opts;

    switch (tier) {
      case "public":
      case "internal": {
        const backend = remote ?? local;
        if (!backend) {
          throw new VeilRoutingError(`No backend configured for tier '${tier}'.`);
        }
        return {
          withheld: false,
          tier,
          escalated,
          backendId: backend.id,
          transformed: false,
          stream: backend.chat([userMsg(input, tier)]),
        };
      }

      case "private": {
        if (remote) {
          const k = this.opts.cohortK ?? 1;
          if (k > 1) {
            // k-anonymous cohort fan-out (batch). The wire sees k indistinct
            // prompts; we keep the real response and reverse-map it.
            return await this.cohortDispatch(input, remote, escalated, k);
          }
          // Pseudonymize → forward → reverse-map. The model never sees raw PII.
          const wrapped = wrapWithVeil(remote, engine, { sessionId });
          return {
            withheld: false,
            tier,
            escalated,
            backendId: wrapped.id,
            transformed: true,
            stream: wrapped.chat([userMsg(input, "private")]),
          };
        }
        if (local) {
          // On-device: raw private is permitted (VEIL.md §3.4 fallback chain).
          return {
            withheld: false,
            tier,
            escalated,
            backendId: local.id,
            transformed: false,
            stream: local.chat([userMsg(input, "private")]),
          };
        }
        throw new VeilRoutingError("No backend available for 'private' content.");
      }

      case "secret": {
        // INVARIANT 1: secret never reaches a non-local backend. Fail closed.
        if (local && local.capabilities.runsLocally) {
          return {
            withheld: false,
            tier,
            escalated,
            backendId: local.id,
            transformed: false,
            stream: local.chat([userMsg(input, "secret")]),
          };
        }
        return {
          withheld: true,
          tier,
          escalated,
          reason:
            "No local backend available for secret-tier content; refusing to send " +
            "to a remote LLM (Hard Invariant 1).",
        };
      }
    }
  }

  /**
   * Cohort fan-out for `private` content. Asks the engine for k kind-shape-
   * identical prompts (real + k-1 pool-disjoint siblings), shuffles them for
   * positional unlinkability, dispatches all k with identical options (so they
   * are side-channel symmetric), keeps the real response, and reverse-maps it.
   * Batch only — streaming-with-cohort is future work (VEIL.md §4.3).
   */
  private async cohortDispatch(
    input: string,
    remote: VeilBackend,
    escalated: boolean,
    k: number,
  ): Promise<Dispatched> {
    const { engine, sessionId } = this.opts;
    const plan = await engine.cohort(sessionId, input, k);

    // Scramble every pseudonym number into one random space so the real prompt
    // (low session #) is indistinguishable from siblings (high pool #) — closes
    // the pool-range fingerprint, and being fresh per call, the determinism one.
    const { prompts: scrambled, realDemap } = scrambleCohort(plan.cohort, plan.realIndex);

    // Shuffle so the real prompt isn't always at index 0 on the wire — closes
    // the positional-fingerprint caveat the engine leaves to the caller.
    const order = scrambled.map((_, i) => i);
    for (let i = order.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [order[i], order[j]] = [order[j]!, order[i]!];
    }
    const realPos = order.indexOf(plan.realIndex);
    const prompts = order.map((i) => scrambled[i]!);

    // Fan out all k with identical opts (side-channel symmetry). Keep the real.
    const responses = await Promise.all(
      prompts.map((content) => collectText(remote.chat([{ role: "user", content }]))),
    );
    // Un-scramble the real reply (scrambled pseudonyms → session pseudonyms),
    // then reverse-map to real entities.
    const realResponse = applyPseudonymMap(responses[realPos] ?? "", realDemap);
    const restored = await engine.reverseMap(sessionId, realResponse);

    return {
      withheld: false,
      tier: "private",
      escalated,
      backendId: `cohort(${remote.id})`,
      transformed: true,
      cohort: { requestedK: k, achievedK: plan.achievedK },
      stream: singleToken(restored),
    };
  }
}

/** One-shot stream of an already-complete (reverse-mapped) reply. */
async function* singleToken(text: string): AsyncIterable<Token> {
  yield { text, done: true, finishReason: "stop" };
}

function userMsg(content: string, tier: Tier): Msg {
  return { role: "user", content, veilTier: tier };
}

/** Drain a token stream into a single string. Convenience for callers (like an
 *  MCP tool handler) that return a whole result rather than streaming. */
export async function collectText(stream: AsyncIterable<Token>): Promise<string> {
  let out = "";
  for await (const tok of stream) out += tok.text;
  return out;
}
