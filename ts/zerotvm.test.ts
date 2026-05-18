// SPDX-License-Identifier: Apache-2.0

// zerotvm.test.ts — unit tests for ZeroTVMAdapter with the upstream engine
// fully mocked. Confirms:
//   1. Lazy-import semantics: dynamic import only fires on init(), never in
//      the constructor or via capability inspection.
//   2. chat() streams tokens in order and terminates with done=true.
//   3. embed() throws BackendUnsupported (Zero-TVM is decoder-only).
//   4. The capability matrix matches the contract in VEIL.md §2.e.
//   5. classifyTier / detectPII delegate to the heuristic (don't touch GPU).
//   6. splitForCompleteAPI maps Msg[] to (system, user) faithfully.

import { describe, expect, test } from "bun:test";

import { ZeroTVMAdapter, splitForCompleteAPI } from "./zerotvm";
import { BackendUnsupported } from "./interface";
import type { Msg } from "./interface";

// ---- Mock factories -------------------------------------------------------

interface MockEngine {
  complete: (system: string, user: string, maxTokens: number) => Promise<string>;
  slotCount: number;
  idleSlots: () => number;
  tokenizer: {
    encode: (s: string) => number[];
    decode: (ids: number[]) => string;
    bosId: number;
    eosId: number;
  };
}

function makeMockEngine(reply = "hello from zero-tvm"): MockEngine {
  return {
    complete: async (_system: string, _user: string, _maxTokens: number) => reply,
    slotCount: 1,
    idleSlots: () => 1,
    tokenizer: {
      encode: (s: string) => Array.from(s).map((c) => c.charCodeAt(0)),
      decode: (ids: number[]) =>
        ids.map((i) => String.fromCharCode(i)).join(""),
      bosId: 1,
      eosId: 2,
    },
  };
}

interface InitCalls {
  count: number;
  lastConfig: { maxSlots?: number; onLog?: (msg: string) => void } | null;
}

interface MockModule {
  initSlottedEngine: (cfg: {
    maxSlots?: number;
    onLog?: (msg: string) => void;
  }) => Promise<MockEngine>;
}

function makeMockModule(engine: MockEngine = makeMockEngine()): {
  module: MockModule;
  calls: InitCalls;
} {
  const calls: InitCalls = { count: 0, lastConfig: null };
  const module: MockModule = {
    initSlottedEngine: async (cfg) => {
      calls.count += 1;
      calls.lastConfig = cfg;
      return engine;
    },
  };
  return { module, calls };
}

async function drain<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of iter) out.push(v);
  return out;
}

// ---- Tests ----------------------------------------------------------------

describe("ZeroTVMAdapter — lazy-import contract", () => {
  test("constructor does NOT trigger dynamic import or engine init", () => {
    const { module: mockMod, calls } = makeMockModule();
    const adapter = new ZeroTVMAdapter({ moduleOverride: mockMod });

    // Constructor ran, but neither the dynamic-import path nor the
    // initSlottedEngine call should have fired.
    expect(adapter._dynamicImportCount()).toBe(0);
    expect(calls.count).toBe(0);
    expect(adapter.isReady()).toBe(false);
  });

  test("inspecting capabilities does NOT trigger init", () => {
    const { module: mockMod, calls } = makeMockModule();
    const adapter = new ZeroTVMAdapter({ moduleOverride: mockMod });

    const caps = adapter.capabilities;
    expect(caps).toBeDefined();
    expect(calls.count).toBe(0);
    expect(adapter.isReady()).toBe(false);
  });

  test("init() runs initSlottedEngine exactly once", async () => {
    const { module: mockMod, calls } = makeMockModule();
    const adapter = new ZeroTVMAdapter({
      moduleOverride: mockMod,
      maxSlots: 3,
      onLog: () => {},
    });

    await adapter.init();
    await adapter.init(); // second call must be a no-op

    expect(calls.count).toBe(1);
    expect(calls.lastConfig?.maxSlots).toBe(3);
    expect(adapter.isReady()).toBe(true);
  });

  test("init() throws if module lacks initSlottedEngine export", async () => {
    const adapter = new ZeroTVMAdapter({
      moduleOverride: {} as never, // no exports
    });

    await expect(adapter.init()).rejects.toThrow(/initSlottedEngine/);
    expect(adapter.isReady()).toBe(false);
  });

  test("engineOverride bypasses both module load and init", async () => {
    const engine = makeMockEngine("override speaks");
    const adapter = new ZeroTVMAdapter({ engineOverride: engine });
    await adapter.init();
    expect(adapter.isReady()).toBe(true);
    expect(adapter._dynamicImportCount()).toBe(0);
  });
});

describe("ZeroTVMAdapter — capability matrix matches VEIL.md §2.e", () => {
  test("matches the exact contract", () => {
    const adapter = new ZeroTVMAdapter({ moduleOverride: makeMockModule().module });
    expect(adapter.capabilities).toEqual({
      chat: true,
      embed: false,
      classify: true, // heuristic delegate
      pii: true, // heuristic delegate
      streaming: true,
      jsonMode: false,
      tools: false,
      maxTiersAllowed: ["public", "internal", "private", "secret"],
      runsLocally: true,
    });
  });

  test("secret tier IS allowed (this is the showcase: secret-tier eligible)", () => {
    const adapter = new ZeroTVMAdapter({ moduleOverride: makeMockModule().module });
    expect(adapter.capabilities.maxTiersAllowed).toContain("secret");
    expect(adapter.capabilities.runsLocally).toBe(true);
  });
});

describe("ZeroTVMAdapter — chat() streams tokens", () => {
  test("yields tokens in order then terminates with done=true", async () => {
    const engine = makeMockEngine("the bronze automaton speaks");
    const adapter = new ZeroTVMAdapter({ engineOverride: engine });
    await adapter.init();

    const tokens = await drain(
      adapter.chat([{ role: "user", content: "hi" }]),
    );

    // Expect at least one content token + a done terminator.
    expect(tokens.length).toBeGreaterThanOrEqual(2);
    const last = tokens[tokens.length - 1];
    expect(last?.done).toBe(true);
    expect(last?.finishReason).toBe("stop");

    // Concatenated content equals the engine's reply.
    const concat = tokens
      .filter((t) => !t.done)
      .map((t) => t.text)
      .join("");
    expect(concat).toBe("the bronze automaton speaks");
  });

  test("chat() throws if init() never ran", async () => {
    const adapter = new ZeroTVMAdapter({
      engineOverride: makeMockEngine(),
    });
    // No init() — the requireEngine() guard fires.
    await expect(
      drain(adapter.chat([{ role: "user", content: "hi" }])),
    ).rejects.toThrow(/not initialized/);
  });

  test("chat() honors AbortSignal that fires before the call", async () => {
    const adapter = new ZeroTVMAdapter({ engineOverride: makeMockEngine() });
    await adapter.init();

    const ctrl = new AbortController();
    ctrl.abort();
    const tokens = await drain(
      adapter.chat([{ role: "user", content: "hi" }], { signal: ctrl.signal }),
    );

    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.done).toBe(true);
    expect(tokens[0]?.finishReason).toBe("aborted");
  });
});

describe("ZeroTVMAdapter — embed() is unsupported", () => {
  test("throws BackendUnsupported", async () => {
    const adapter = new ZeroTVMAdapter({ engineOverride: makeMockEngine() });
    await adapter.init();
    await expect(adapter.embed("anything")).rejects.toBeInstanceOf(
      BackendUnsupported,
    );
  });

  test("the error mentions embed and the backend id", async () => {
    const adapter = new ZeroTVMAdapter({ engineOverride: makeMockEngine() });
    await adapter.init();
    await expect(adapter.embed("anything")).rejects.toThrow(/embed/);
    await expect(adapter.embed("anything")).rejects.toThrow(/zero-tvm/);
  });
});

describe("ZeroTVMAdapter — classifyTier and detectPII delegate to heuristic", () => {
  test("classifyTier returns scores summing to ~1 (heuristic contract)", async () => {
    const adapter = new ZeroTVMAdapter({ engineOverride: makeMockEngine() });
    // Note: classifyTier doesn't require init() — it's a pure heuristic delegate.
    const scores = await adapter.classifyTier("nothing sensitive here");
    const sum = scores.public + scores.internal + scores.private + scores.secret;
    expect(Math.abs(sum - 1)).toBeLessThan(0.01);
  });

  test("detectPII returns [] for the heuristic path", async () => {
    const adapter = new ZeroTVMAdapter({ engineOverride: makeMockEngine() });
    const spans = await adapter.detectPII("call me at 555-0100");
    expect(spans).toEqual([]);
  });
});

describe("splitForCompleteAPI — Msg[] → (system, user)", () => {
  test("single user turn → empty system, content as user", () => {
    const out = splitForCompleteAPI([{ role: "user", content: "hi" }]);
    expect(out.system).toBe("");
    expect(out.user).toBe("hi");
  });

  test("system + user → system populates, user is the final turn", () => {
    const out = splitForCompleteAPI([
      { role: "system", content: "you are helpful" },
      { role: "user", content: "what is 2+2?" },
    ]);
    expect(out.system).toBe("you are helpful");
    expect(out.user).toBe("what is 2+2?");
  });

  test("multi-turn with prior assistant — history folded into system", () => {
    const msgs: Msg[] = [
      { role: "system", content: "policy" },
      { role: "user", content: "first question" },
      { role: "assistant", content: "first answer" },
      { role: "user", content: "follow-up" },
    ];
    const out = splitForCompleteAPI(msgs);
    expect(out.user).toBe("follow-up");
    expect(out.system).toContain("policy");
    expect(out.system).toContain("User: first question");
    expect(out.system).toContain("Assistant: first answer");
  });

  test("tool message marked as [tool result]", () => {
    const out = splitForCompleteAPI([
      { role: "system", content: "policy" },
      { role: "tool", content: "{\"answer\":42}", toolCallId: "t1" },
    ]);
    expect(out.user).toBe('[tool result] {"answer":42}');
  });

  test("empty input → empty pair", () => {
    const out = splitForCompleteAPI([]);
    expect(out.system).toBe("");
    expect(out.user).toBe("");
  });
});

describe("ZeroTVMAdapter — dispose()", () => {
  test("dispose() flips ready back to false", async () => {
    const adapter = new ZeroTVMAdapter({ engineOverride: makeMockEngine() });
    await adapter.init();
    expect(adapter.isReady()).toBe(true);
    await adapter.dispose();
    expect(adapter.isReady()).toBe(false);
  });
});
