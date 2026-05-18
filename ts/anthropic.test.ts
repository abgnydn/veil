// SPDX-License-Identifier: Apache-2.0

// anthropic.test.ts — secret-block invariant under unit test.
//
// Confirms AnthropicAdapter.chat throws VeilInvariantViolation when ANY Msg
// in the input array is tagged `secret`, before any HTTP work happens.

import { describe, expect, test } from "bun:test";

import { AnthropicAdapter } from "./anthropic";
import type { AnthropicSettings } from "./anthropic";
import { VeilInvariantViolation } from "./interface";

function settings(): AnthropicSettings {
  return {
    getApiKey: () => "sk-ant-test-key-not-real",
    getDefaultModel: () => "claude-test",
  };
}

async function drain<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of iter) out.push(v);
  return out;
}

describe("AnthropicAdapter — hard invariants", () => {
  test("throws VeilInvariantViolation(1) when a Msg is tagged 'secret'", async () => {
    let fetchCalled = false;
    const adapter = new AnthropicAdapter({
      settings: settings(),
      fetchImpl: (async () => {
        fetchCalled = true;
        throw new Error("fetch must not be called when secret content is present");
      }) as unknown as typeof fetch,
    });

    const stream = adapter.chat([
      { role: "system", content: "you are helpful" },
      { role: "user", content: "my AWS key is here", veilTier: "secret" },
    ]);

    await expect(drain(stream)).rejects.toBeInstanceOf(VeilInvariantViolation);
    expect(fetchCalled).toBe(false);
  });

  test("throws VeilInvariantViolation(2) when a 'private' Msg arrives raw", async () => {
    const adapter = new AnthropicAdapter({
      settings: settings(),
      fetchImpl: (async () => {
        throw new Error("fetch must not be called for raw private content");
      }) as unknown as typeof fetch,
    });

    const stream = adapter.chat([
      { role: "user", content: "my therapist said...", veilTier: "private" },
    ]);

    await expect(drain(stream)).rejects.toBeInstanceOf(VeilInvariantViolation);
  });

  test("setSecretGuard catches secret content even when veilTier tag is missing", async () => {
    const adapter = new AnthropicAdapter({
      settings: settings(),
      fetchImpl: (async () => {
        throw new Error("fetch must not be called when guard fires");
      }) as unknown as typeof fetch,
    });

    adapter.setSecretGuard((m) => {
      // Treat any message containing "API_KEY=" as secret regardless of tag.
      if (m.content.includes("API_KEY=")) return "secret";
      return undefined;
    });

    const stream = adapter.chat([
      { role: "user", content: "value is API_KEY=hunter2hunter2hunter2" }, // no tag
    ]);

    await expect(drain(stream)).rejects.toBeInstanceOf(VeilInvariantViolation);
  });

  test("capabilities matrix is locked to public+internal only", () => {
    const adapter = new AnthropicAdapter({ settings: settings() });
    expect(adapter.capabilities.runsLocally).toBe(false);
    expect(adapter.capabilities.maxTiersAllowed).toEqual(["public", "internal"]);
    expect(adapter.capabilities.maxTiersAllowed).not.toContain("secret");
    expect(adapter.capabilities.maxTiersAllowed).not.toContain("private");
  });

  test("embed() throws BackendUnsupported (Anthropic ships no embeddings)", async () => {
    const adapter = new AnthropicAdapter({ settings: settings() });
    await expect(adapter.embed("anything")).rejects.toThrow(/embed/i);
  });

  test("classifyTier() throws (remote classification is itself a leak)", async () => {
    const adapter = new AnthropicAdapter({ settings: settings() });
    await expect(adapter.classifyTier("anything")).rejects.toThrow(/classifyTier/i);
  });

  test("detectPII() throws (remote PII detection leaks the very PII)", async () => {
    const adapter = new AnthropicAdapter({ settings: settings() });
    await expect(adapter.detectPII("call me at 555-0100")).rejects.toThrow(/detectPII/i);
  });
});
