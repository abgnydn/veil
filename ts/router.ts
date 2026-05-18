// SPDX-License-Identifier: Apache-2.0

// Router — input-side checkpoint per VEIL.md §3.1.
//
// 1. Classify the input on the locally-resident classifier (heuristic for v1).
// 2. Argmax → tier; if marginal < 0.2, bump one rung up. False-positive
//    caution beats false-negative leak.
// 3. Branch:
//      - public/internal → pass-through.
//      - private         → cohort-blend; downstream dispatch keeps the real.
//      - secret          → never returns Anthropic. Local-only adapter or
//                          fail closed with VeilRoutingError.
//
// Hard invariants live in the adapter constructors / chat() entry, not here.
// This router is the "happy path" gate; the adapter throws on actual leak.

import type {
  Msg,
  Tier,
  TierScores,
  VeilBackend,
} from "./interface";
import {
  argmaxTier,
  bumpTier,
  tierMargin,
  VeilRoutingError,
} from "./interface";
import { classifyTierHeuristic } from "./classifier";
import { cohortBlend, type CohortPlan, type VaultRef } from "./cohort";

// ---- Context ----------------------------------------------------------------

export interface Ctx {
  /**
   * Tier classifier. Defaults to the heuristic in `classifier.ts`. Tests and
   * the router-time LLM classifier override via this seam.
   */
  classify?: (text: string) => Promise<TierScores> | TierScores;
  /** Vault handle for cohort blending. Required when tier === 'private'. */
  vault?: VaultRef;
  /**
   * Available adapters by id, e.g. {webllm, anthropic}. The router emits a
   * `recommendedAdapter` key — the caller (MCP server) actually dispatches.
   */
  adapters?: Record<string, VeilBackend>;
  /**
   * Per-tier preferred adapter id. Defaults sketched below; overridable by
   * the user via the Settings panel (§6).
   */
  preferences?: Partial<Record<Tier, string>>;
  /** Cohort size; default 8 per VEIL.md §4.2. */
  k?: number;
  /**
   * Escalation margin. If `marginal < this`, bump the tier one rung up.
   * Default 0.2 per VEIL.md §3.1.
   */
  escalationMargin?: number;
  /**
   * KVKK regulated-domain mode. Set true for the Example sibling
   * deployment. Under KVKK:
   *   - The router REFUSES any remote-tier dispatch without explicit
   *     per-call approval. Even `public` no longer auto-flows to a remote
   *     adapter — the dispatcher must consult the gate first.
   *   - The recommendedAdapter for non-local-eligible tiers is rewritten to
   *     the local default; if no local adapter is available, the router
   *     fails closed with VeilRoutingError.
   * The gate (`apps/mcp/src/permission.ts`) is the actual approval surface;
   * the router only signals the policy via `kvkkApprovalRequired` on the
   * RouteResult.
   */
  kvkkMode?: boolean;
  /**
   * Hook called when KVKK mode requires explicit approval before remote
   * dispatch. Returns `'allow'` to proceed, `'deny'` to fail closed. When
   * unset under KVKK mode, the router treats remote dispatch as denied.
   */
  kvkkApproval?: (info: { tier: Tier; adapterId: string }) => Promise<"allow" | "deny">;
}

// ---- Defaults ---------------------------------------------------------------

const DEFAULT_PREFERENCES: Record<Tier, string> = {
  // Default install: WebLLM is the go-to local adapter; Anthropic only for
  // public/internal and only when the user has flipped it on. The router
  // recommends WebLLM by default — the dispatcher swaps in Anthropic when the
  // user's settings say so.
  public: "webllm",
  internal: "webllm",
  private: "webllm",
  secret: "webllm",
};

const DEFAULT_ESCALATION_MARGIN = 0.2;

// ---- Output -----------------------------------------------------------------

export interface RouteResult {
  /** Final tier after argmax + escalation rule. */
  tier: Tier;
  /**
   * The Msg array to dispatch. For public/internal this is just the user's
   * input wrapped as a single user Msg. For private it's the real Msg from
   * the cohort plan; the full plan is in `cohortPlan` for fan-out.
   */
  transformedInput: Msg[];
  /** Adapter id the dispatcher should use. */
  recommendedAdapter: string;
  /** Raw classifier scores — useful for the audit log. */
  scores: TierScores;
  /**
   * Set when tier === 'private'. The dispatcher fans out cohortPlan.cohort,
   * keeps response[realIndex], drops the rest.
   */
  cohortPlan?: CohortPlan;
  /** True when the escalation rule fired. Diagnostic. */
  escalated: boolean;
  /**
   * Set true when KVKK mode is on AND the dispatcher must show a fresh
   * approval modal before any remote-adapter dispatch. The router has
   * already verified that an `kvkkApproval` hook (or an external gate)
   * granted permission — this flag is for the audit trail.
   */
  kvkkApprovalRequired?: boolean;
}

// ---- The router ------------------------------------------------------------

/**
 * Input-side checkpoint. See VEIL.md §3.1.
 *
 * Hard invariants enforced here:
 *   - tier === 'secret' MUST resolve to a local adapter, never Anthropic.
 *     If no local adapter is available, throws VeilRoutingError (fail-closed).
 *   - tier === 'private' MUST be cohort-blended. If no vault is available,
 *     throws VeilRoutingError (fail-closed) rather than dispatching raw.
 */
export async function routeMessage(
  input: string,
  ctx: Ctx = {},
): Promise<RouteResult> {
  const classify = ctx.classify ?? classifyTierHeuristic;
  const escalationMargin = ctx.escalationMargin ?? DEFAULT_ESCALATION_MARGIN;
  const preferences = { ...DEFAULT_PREFERENCES, ...(ctx.preferences ?? {}) };

  const scores = await classify(input);
  const baseTier = argmaxTier(scores);
  const margin = tierMargin(scores);
  const escalated = margin < escalationMargin;
  const tier: Tier = escalated ? bumpTier(baseTier) : baseTier;

  // ---- Hard-invariant filter on adapter selection -----------------------
  let recommendedAdapter = pickAdapter(tier, preferences, ctx.adapters);

  // ---- KVKK gate: refuse remote dispatch without explicit approval ------
  // Under regulated mode the router cannot auto-route to a remote adapter
  // for ANY tier (not even `public`). The dispatcher must obtain fresh
  // per-call approval through `ctx.kvkkApproval` first; absent that hook,
  // we either fall back to a local adapter or fail closed.
  let kvkkApprovalRequired = false;
  if (ctx.kvkkMode) {
    const chosen = ctx.adapters?.[recommendedAdapter];
    const isRemote = chosen ? chosen.capabilities.runsLocally !== true : false;
    if (isRemote) {
      kvkkApprovalRequired = true;
      const verdict = ctx.kvkkApproval
        ? await ctx.kvkkApproval({ tier, adapterId: recommendedAdapter })
        : "deny";
      if (verdict === "deny") {
        // Try to fall back to a local adapter that can serve this tier.
        const localFallback = ctx.adapters
          ? Object.values(ctx.adapters).find(
              (a) =>
                a.capabilities.runsLocally === true &&
                a.capabilities.maxTiersAllowed.includes(tier),
            )
          : undefined;
        if (!localFallback) {
          throw new VeilRoutingError(
            `KVKK mode: remote adapter "${recommendedAdapter}" denied for tier '${tier}', no local fallback available.`,
          );
        }
        recommendedAdapter = localFallback.id;
      }
    }
  }

  // Branch on the resolved tier.
  switch (tier) {
    case "public":
    case "internal": {
      const transformedInput: Msg[] = [
        { role: "user", content: input, veilTier: tier },
      ];
      return {
        tier,
        transformedInput,
        recommendedAdapter,
        scores,
        escalated,
        kvkkApprovalRequired,
      };
    }

    case "private": {
      if (!ctx.vault) {
        throw new VeilRoutingError(
          "Cannot route 'private' content without a VaultRef for cohort blending.",
        );
      }
      const plan = await cohortBlend(input, ctx.vault, { k: ctx.k });
      const realMsgs = plan.cohort[plan.realIndex];
      if (!realMsgs) {
        throw new VeilRoutingError(
          `Cohort plan missing realIndex=${plan.realIndex} (cohort size=${plan.cohort.length}).`,
        );
      }
      // Tag every Msg with `private` so AnthropicAdapter's Invariant-2 guard
      // refuses dispatch if a router bug ever sends it here. Local adapters
      // ignore the tag.
      const transformedInput = realMsgs.map((m) => ({ ...m, veilTier: "private" as Tier }));
      return {
        tier,
        transformedInput,
        recommendedAdapter,
        scores,
        cohortPlan: plan,
        escalated,
        kvkkApprovalRequired,
      };
    }

    case "secret": {
      // INVARIANT 1: secret never reaches a remote adapter. pickAdapter
      // already filtered on capabilities.runsLocally; we double-check here.
      const adapter = ctx.adapters?.[recommendedAdapter];
      if (adapter && adapter.capabilities.runsLocally !== true) {
        throw new VeilRoutingError(
          `INVARIANT 1: 'secret' content cannot route to non-local adapter "${recommendedAdapter}".`,
        );
      }
      const transformedInput: Msg[] = [
        { role: "user", content: input, veilTier: "secret" },
      ];
      return {
        tier,
        transformedInput,
        recommendedAdapter,
        scores,
        escalated,
        kvkkApprovalRequired,
      };
    }
  }
}

// ---- Adapter selection -----------------------------------------------------

function pickAdapter(
  tier: Tier,
  preferences: Record<Tier, string>,
  adapters: Record<string, VeilBackend> | undefined,
): string {
  const preferred = preferences[tier];

  // No adapter registry passed in — caller is wiring its own dispatch and just
  // wants the recommendation. Return the preference verbatim.
  if (!adapters) {
    return preferred;
  }

  // Filter the registry by tier compatibility:
  //   - tier === 'secret'  → must be runsLocally === true.
  //   - tier === 'private' → backend must accept 'private' OR be local (raw).
  //                          Remote backends are allowed only post-cohort, but
  //                          this router emits the same recommendation in both
  //                          cases — the dispatcher cohort-blends regardless.
  //   - others             → backend.maxTiersAllowed must include tier.
  const eligible = Object.values(adapters).filter((a) => {
    if (tier === "secret" && !a.capabilities.runsLocally) return false;
    return a.capabilities.maxTiersAllowed.includes(tier);
  });

  if (eligible.length === 0) {
    throw new VeilRoutingError(
      `No adapter available for tier '${tier}'. Configured: [${Object.keys(adapters).join(", ")}].`,
    );
  }

  // Prefer the user's choice if it's eligible; otherwise the first eligible.
  const preferredAdapter = adapters[preferred];
  if (preferredAdapter && eligible.includes(preferredAdapter)) {
    return preferred;
  }
  const fallback = eligible[0];
  // After the length check above, eligible[0] is guaranteed defined; the cast
  // is for noUncheckedIndexedAccess.
  if (!fallback) {
    throw new VeilRoutingError(`Adapter selection invariant broken for tier '${tier}'.`);
  }
  return fallback.id;
}
