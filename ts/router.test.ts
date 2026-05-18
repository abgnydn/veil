// SPDX-License-Identifier: Apache-2.0

// router.test.ts — round-trip routing test (per VEIL.md acceptance).
//
// "I had a fight with my sister" → heuristic argmax `private` → cohort-blended
// → recommended adapter = WebLLM by default. No real network or model load.

import { describe, expect, test } from "bun:test";

import { routeMessage } from "./router";
import { WebLLMAdapter } from "./webllm";
import type { VaultNeighbor, VaultRef } from "./cohort";
import { argmaxTier } from "./interface";
import { classifyTierHeuristic } from "./classifier";

function mockVault(neighbors: VaultNeighbor[]): VaultRef {
  return {
    async search(_q: string, k: number): Promise<VaultNeighbor[]> {
      return neighbors.slice(0, k);
    },
  };
}

describe("routeMessage", () => {
  test("classifies 'fight with my sister' as private and uses cohort blender", async () => {
    const input = "I had a fight with my sister";

    // Sanity: heuristic alone reads it as private.
    const scores = classifyTierHeuristic(input);
    expect(argmaxTier(scores)).toBe("private");

    // Build a stub WebLLM adapter — engineOverride dodges the dynamic import.
    const webllm = new WebLLMAdapter({
      engineOverride: {
        reload: async () => {},
        chat: { completions: { create: async () => emptyStream() } },
      },
    });

    const vault = mockVault([
      { id: "n1", content: "neighbor note one — also family-related" },
      { id: "n2", content: "neighbor note two — emotionally charged" },
      { id: "n3", content: "neighbor note three" },
      { id: "n4", content: "neighbor note four" },
      { id: "n5", content: "neighbor note five" },
      { id: "n6", content: "neighbor note six" },
      { id: "n7", content: "neighbor note seven" },
    ]);

    const result = await routeMessage(input, {
      vault,
      adapters: { webllm },
    });

    expect(result.tier).toBe("private");
    expect(result.recommendedAdapter).toBe("webllm");
    expect(result.cohortPlan).toBeDefined();
    expect(result.cohortPlan?.cohort.length).toBe(8); // default K
    expect(result.cohortPlan?.neighborIds.length).toBe(7);
    // Every Msg the dispatcher will see is tagged 'private' so the
    // AnthropicAdapter's Invariant-2 guard refuses it if the dispatcher routes
    // wrong.
    for (const m of result.transformedInput) {
      expect(m.veilTier).toBe("private");
    }
  });

  test("public/internal text passes through with WebLLM recommendation", async () => {
    const webllm = new WebLLMAdapter({
      engineOverride: {
        reload: async () => {},
        chat: { completions: { create: async () => emptyStream() } },
      },
    });
    const result = await routeMessage("the weather today is fine", {
      adapters: { webllm },
    });
    expect(result.tier === "internal" || result.tier === "public").toBe(true);
    expect(result.recommendedAdapter).toBe("webllm");
    expect(result.cohortPlan).toBeUndefined();
  });

  test("secret content never recommends a remote adapter", async () => {
    // A Msg with an api-key-shaped token is heuristically `secret`. The
    // router must not return Anthropic even when it's the only registered
    // adapter — instead it fails closed.
    const fakeAnthropic = {
      id: "anthropic",
      displayName: "Anthropic",
      capabilities: {
        chat: true,
        embed: false,
        classify: false,
        pii: false,
        streaming: true,
        jsonMode: true,
        tools: true,
        maxTiersAllowed: ["public" as const, "internal" as const],
        runsLocally: false,
      },
      init: async () => {},
      isReady: () => true,
      classifyTier: async () => ({ public: 1, internal: 0, private: 0, secret: 0 }),
      detectPII: async () => [],
      chat: async function* () {},
      embed: async () => new Float32Array(),
    };

    await expect(
      routeMessage("export AWS_SECRET_ACCESS_KEY=abcdef0123456789abcdef0123456789", {
        adapters: { anthropic: fakeAnthropic },
      }),
    ).rejects.toThrow(/secret|tier/i);
  });
});

async function* emptyStream(): AsyncIterable<{ choices: never[] }> {
  // Yield nothing — chat() under WebLLM will then synthesize a `done: true`
  // terminator. Used only to keep the engineOverride shape complete.
}
