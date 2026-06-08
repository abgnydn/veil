// SPDX-License-Identifier: Apache-2.0

// enforce.test.ts — tier enforcement end-to-end, hermetic.
//
// A fake engine (mock fetch) + fake backends that record what they were sent.
// Proves the four tiers route correctly and the two hard invariants hold:
//   - secret never reaches a non-local backend (withheld when no local).
//   - private never reaches the remote raw (it arrives pseudonymized).

import { describe, expect, test } from "bun:test";

import { RustPipelineClient } from "./rust-client";
import { VeilEnforcer, collectText } from "./enforce";
import type { Dispatched } from "./enforce";
import type { Msg, Token, TierScores, VeilBackend } from "./interface";

// ---- fakes -----------------------------------------------------------------

/** Engine that pseudonymizes a fixed table and reverse-maps it back. */
function fakeEngine(table: Record<string, string>): RustPipelineClient {
  const inverse = Object.fromEntries(Object.entries(table).map(([k, v]) => [v, k]));
  const fetchImpl = (async (url: string, init: RequestInit = {}) => {
    const path = url.replace(/^.*\/v1/, "/v1");
    const req = JSON.parse((init.body as string) ?? "{}");
    if (path === "/v1/pseudonymize") {
      let text = req.text;
      for (const [real, pseudo] of Object.entries(table)) text = text.split(real).join(pseudo);
      return Response.json({ text, spans: [] });
    }
    if (path === "/v1/reverse-map") {
      let text = req.text;
      for (const [pseudo, real] of Object.entries(inverse)) text = text.split(pseudo).join(real);
      return Response.json({ text });
    }
    throw new Error(`unexpected ${path}`);
  }) as unknown as typeof fetch;
  return new RustPipelineClient({ fetchImpl });
}

/** Backend that records the messages it was handed and echoes the user content. */
function recordingBackend(id: string, runsLocally: boolean, sink: { seen: Msg[][] }): VeilBackend {
  return {
    id,
    displayName: id,
    capabilities: {
      chat: true,
      embed: false,
      classify: false,
      pii: false,
      streaming: true,
      jsonMode: false,
      tools: false,
      maxTiersAllowed: runsLocally
        ? ["public", "internal", "private", "secret"]
        : ["public", "internal"],
      runsLocally,
    },
    async init() {},
    isReady: () => true,
    async classifyTier() {
      throw new Error("unused");
    },
    async detectPII() {
      return [];
    },
    async embed() {
      throw new Error("unused");
    },
    async *chat(messages: Msg[]): AsyncIterable<Token> {
      sink.seen.push(messages);
      const u = messages.find((m) => m.role === "user");
      yield { text: `reply: ${u?.content ?? ""}`, done: false };
      yield { text: "", done: true, finishReason: "stop" };
    },
  };
}

/** Deterministic classifier returning a one-hot score for `tier`. */
function fixedTier(tier: keyof TierScores): (t: string) => TierScores {
  const base: TierScores = { public: 0, internal: 0, private: 0, secret: 0 };
  return () => ({ ...base, [tier]: 1 });
}

// ---- tests -----------------------------------------------------------------

describe("VeilEnforcer — tier routing + hard invariants", () => {
  test("public/internal: dispatched raw to the remote backend, untransformed", async () => {
    const remoteSink = { seen: [] as Msg[][] };
    const enforcer = new VeilEnforcer({
      engine: fakeEngine({}),
      sessionId: "s",
      remote: recordingBackend("anthropic", false, remoteSink),
      classify: fixedTier("internal"),
    });
    const res = (await enforcer.enforce("what is the capital of France")) as Dispatched;
    expect(res.withheld).toBe(false);
    expect(res.tier).toBe("internal");
    expect(res.transformed).toBe(false);
    expect(res.backendId).toBe("anthropic");
    expect(await collectText(res.stream)).toBe("reply: what is the capital of France");
    // Remote saw the raw text (nothing to pseudonymize at this tier).
    expect(remoteSink.seen[0]?.[0]?.content).toBe("what is the capital of France");
  });

  test("private: remote sees ONLY pseudonyms; caller gets real entity back", async () => {
    const remoteSink = { seen: [] as Msg[][] };
    const enforcer = new VeilEnforcer({
      engine: fakeEngine({ "alice@acme.com": "EMAIL_1" }),
      sessionId: "s",
      remote: recordingBackend("anthropic", false, remoteSink),
      classify: fixedTier("private"),
    });
    const res = (await enforcer.enforce("remind alice@acme.com")) as Dispatched;
    expect(res.transformed).toBe(true);
    expect(res.backendId).toBe("veil(anthropic)");
    // Drain first — the wrapped chat generator is lazy; pseudonymization runs
    // only when iterated. Caller sees the real entity, reverse-mapped.
    const out = await collectText(res.stream);
    expect(out).toBe("reply: remind alice@acme.com");
    // INVARIANT 2: the remote never saw the raw email.
    expect(remoteSink.seen[0]?.[0]?.content).toBe("remind EMAIL_1");
    expect(remoteSink.seen[0]?.[0]?.content).not.toContain("alice@acme.com");
  });

  test("private with cohortK>1: k indistinguishable prompts on the wire, real reverse-mapped", async () => {
    // Cohort-aware fake engine: real prompt gets EMAIL_1, siblings get
    // pool-disjoint EMAIL_1000x; reverse-map restores EMAIL_1.
    const cohortEngine = (() => {
      const fetchImpl = (async (url: string, init: RequestInit = {}) => {
        const path = url.replace(/^.*\/v1/, "/v1");
        const req = JSON.parse((init.body as string) ?? "{}");
        if (path === "/v1/cohort") {
          const real = req.text.split("alice@acme.com").join("EMAIL_1");
          const cohort = [real];
          for (let i = 1; i < req.k; i++) cohort.push(real.split("EMAIL_1").join(`EMAIL_${10000 + i}`));
          return Response.json({ cohort, real_index: 0, requested_k: req.k, achieved_k: cohort.length });
        }
        if (path === "/v1/reverse-map") {
          return Response.json({ text: req.text.split("EMAIL_1").join("alice@acme.com") });
        }
        throw new Error(`unexpected ${path}`);
      }) as unknown as typeof fetch;
      return new RustPipelineClient({ fetchImpl });
    })();

    const remoteSink = { seen: [] as Msg[][] };
    const enforcer = new VeilEnforcer({
      engine: cohortEngine,
      sessionId: "s",
      remote: recordingBackend("anthropic", false, remoteSink),
      classify: fixedTier("private"),
      cohortK: 4,
    });

    const res = (await enforcer.enforce("remind alice@acme.com")) as Dispatched;
    expect(res.transformed).toBe(true);
    expect(res.backendId).toBe("cohort(anthropic)");
    expect(res.cohort).toEqual({ requestedK: 4, achievedK: 4 });

    // 4 prompts were dispatched (fan-out happened during enforce()).
    expect(remoteSink.seen).toHaveLength(4);
    const dispatched = remoteSink.seen.map((m) => m[0]?.content ?? "");
    // None carry raw PII; all are the same kind-shape "remind EMAIL_x".
    for (const p of dispatched) {
      expect(p).not.toContain("alice@acme.com");
      expect(p).toMatch(/^remind EMAIL_\d+$/);
    }
    // The k prompts are distinct → log2(k) entropy, not collapsed.
    expect(new Set(dispatched).size).toBe(4);

    // The caller still gets the real response, reverse-mapped.
    expect(await collectText(res.stream)).toBe("reply: remind alice@acme.com");
  });

  test("secret WITH a local backend: stays on-device, never withheld", async () => {
    const localSink = { seen: [] as Msg[][] };
    const remoteSink = { seen: [] as Msg[][] };
    const enforcer = new VeilEnforcer({
      engine: fakeEngine({}),
      sessionId: "s",
      remote: recordingBackend("anthropic", false, remoteSink),
      local: recordingBackend("ollama", true, localSink),
      classify: fixedTier("secret"),
    });
    const res = (await enforcer.enforce("API_KEY=hunter2hunter2hunter2")) as Dispatched;
    expect(res.withheld).toBe(false);
    expect(res.backendId).toBe("ollama");
    await collectText(res.stream);
    expect(localSink.seen).toHaveLength(1);
    // INVARIANT 1: the remote was never touched.
    expect(remoteSink.seen).toHaveLength(0);
  });

  test("secret WITHOUT a local backend: WITHHELD, remote never touched", async () => {
    const remoteSink = { seen: [] as Msg[][] };
    const enforcer = new VeilEnforcer({
      engine: fakeEngine({}),
      sessionId: "s",
      remote: recordingBackend("anthropic", false, remoteSink),
      classify: fixedTier("secret"),
    });
    const res = await enforcer.enforce("my passport number is X1234567");
    expect(res.withheld).toBe(true);
    if (res.withheld) {
      expect(res.tier).toBe("secret");
      expect(res.reason).toMatch(/Invariant 1/i);
    }
    expect(remoteSink.seen).toHaveLength(0);
  });

  test("private falls back to a local backend (raw OK on-device) when no remote", async () => {
    const localSink = { seen: [] as Msg[][] };
    const enforcer = new VeilEnforcer({
      engine: fakeEngine({ "alice@acme.com": "EMAIL_1" }),
      sessionId: "s",
      local: recordingBackend("ollama", true, localSink),
      classify: fixedTier("private"),
    });
    const res = (await enforcer.enforce("email alice@acme.com")) as Dispatched;
    expect(res.backendId).toBe("ollama");
    expect(res.transformed).toBe(false);
    await collectText(res.stream); // drive the lazy generator
    // On-device: raw is permitted, so the local backend sees the real entity.
    expect(localSink.seen[0]?.[0]?.content).toBe("email alice@acme.com");
  });
});
