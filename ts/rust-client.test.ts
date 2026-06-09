// SPDX-License-Identifier: Apache-2.0

// rust-client.test.ts — hermetic tests for the engine client + the wrap.
//
// No network: a mock `fetchImpl` asserts request shapes and feeds responses,
// and a fake client drives the streaming reverse-map boundary logic. The
// live end-to-end against a real `veil_server` is exercised separately (see
// the manual e2e in the step-3 verification), kept out of the default suite so
// `bun test` stays hermetic and stable.

import { describe, expect, test } from "bun:test";

import {
  RustPipelineClient,
  RustPipelineError,
  kindFloorTier,
} from "./rust-client";
import { reverseMapStream, wrapWithVeil } from "./veil-wrap";
import type { Msg, Token, VeilBackend } from "./interface";

// ---- helpers ---------------------------------------------------------------

/** Build a fetch mock that records the last request and returns `body` as JSON. */
function mockFetch(
  handler: (url: string, init: RequestInit) => { status?: number; body: unknown },
): { fetchImpl: typeof fetch; calls: Array<{ url: string; init: RequestInit }> } {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = (async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init });
    const { status = 200, body } = handler(url, init);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

async function drain<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of iter) out.push(v);
  return out;
}

async function* fromTokens(tokens: Token[]): AsyncIterable<Token> {
  for (const t of tokens) yield t;
}

// ---- client transport ------------------------------------------------------

describe("RustPipelineClient — wire transport", () => {
  test("pseudonymize sends the contract body and parses {text, spans}", async () => {
    const { fetchImpl, calls } = mockFetch(() => ({
      body: {
        text: "ping EMAIL_1",
        spans: [
          { start: 5, end: 12, kind: "email", score: 1.0, replacement: "EMAIL_1", source: "regex" },
        ],
      },
    }));
    const client = new RustPipelineClient({ fetchImpl, baseUrl: "http://127.0.0.1:9999/" });
    const res = await client.pseudonymize("s1", "ping a@b.com");

    expect(res.text).toBe("ping EMAIL_1");
    expect(res.spans[0]?.replacement).toBe("EMAIL_1");
    // Trailing slash on baseUrl is normalized away.
    expect(calls[0]?.url).toBe("http://127.0.0.1:9999/v1/pseudonymize");
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({
      session_id: "s1",
      text: "ping a@b.com",
    });
    expect((calls[0]?.init.method ?? "").toUpperCase()).toBe("POST");
  });

  test("reverseMap unwraps {text} and round-trips with the same session", async () => {
    const { fetchImpl } = mockFetch((_url, init) => {
      const { text } = JSON.parse(init.body as string);
      return { body: { text: text.replace("EMAIL_1", "alice@acme.com") } };
    });
    const client = new RustPipelineClient({ fetchImpl });
    expect(await client.reverseMap("s1", "sent to EMAIL_1")).toBe("sent to alice@acme.com");
  });

  test("audit returns the findings array", async () => {
    const { fetchImpl } = mockFetch(() => ({
      body: {
        findings: [
          { start: 0, end: 8, text: "EMAIL_99", reason: { type: "unknown_pseudonym", kind: "email" } },
        ],
      },
    }));
    const client = new RustPipelineClient({ fetchImpl });
    const findings = await client.audit("s1", "EMAIL_99 is fake");
    expect(findings[0]?.reason.type).toBe("unknown_pseudonym");
  });

  test("cohort sends {session_id,text,k} and maps snake_case → camelCase", async () => {
    const { fetchImpl, calls } = mockFetch(() => ({
      body: {
        cohort: ["remind EMAIL_1", "remind EMAIL_10001"],
        real_index: 0,
        requested_k: 2,
        achieved_k: 2,
      },
    }));
    const client = new RustPipelineClient({ fetchImpl });
    const res = await client.cohort("s", "remind alice@acme.com", 2);
    expect(res.cohort).toHaveLength(2);
    expect(res.realIndex).toBe(0);
    expect(res.achievedK).toBe(2);
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({
      session_id: "s",
      text: "remind alice@acme.com",
      k: 2,
      content_hiding: false,
    });
  });

  test("cohort forwards the content_hiding flag", async () => {
    const { fetchImpl, calls } = mockFetch(() => ({
      body: { cohort: ["x"], real_index: 0, requested_k: 1, achieved_k: 1 },
    }));
    const client = new RustPipelineClient({ fetchImpl });
    await client.cohort("s", "t", 4, true);
    expect(JSON.parse(calls[0]?.init.body as string).content_hiding).toBe(true);
  });

  test("health is true on 2xx and false (never throws) on failure", async () => {
    const up = new RustPipelineClient({
      fetchImpl: (async () => new Response("", { status: 200 })) as unknown as typeof fetch,
    });
    expect(await up.health()).toBe(true);

    const down = new RustPipelineClient({
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });
    expect(await down.health()).toBe(false);
  });

  test("deleteSession issues a DELETE with an encoded id", async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ status: 204, body: null }));
    const client = new RustPipelineClient({ fetchImpl, baseUrl: "http://127.0.0.1:8787" });
    await client.deleteSession("a/b session");
    expect((calls[0]?.init.method ?? "").toUpperCase()).toBe("DELETE");
    expect(calls[0]?.url).toBe("http://127.0.0.1:8787/v1/session/a%2Fb%20session");
  });

  test("non-2xx POST raises RustPipelineError carrying the status", async () => {
    const { fetchImpl } = mockFetch(() => ({ status: 500, body: { error: "boom" } }));
    const client = new RustPipelineClient({ fetchImpl });
    await expect(client.pseudonymize("s1", "x")).rejects.toBeInstanceOf(RustPipelineError);
  });
});

describe("kindFloorTier", () => {
  test("credential kinds floor at secret, identifying kinds at private", () => {
    expect(kindFloorTier("api_key")).toBe("secret");
    expect(kindFloorTier("credit_card")).toBe("secret");
    expect(kindFloorTier("ssn")).toBe("secret");
    expect(kindFloorTier("email")).toBe("private");
    expect(kindFloorTier("person")).toBe("private");
  });
});

// ---- streaming reverse-map boundary logic ----------------------------------

/** Fake client whose reverseMap applies a fixed pseudonym→real table and
 *  records each chunk it was asked to map (to assert boundary safety). */
function fakeClient(table: Record<string, string>) {
  const mappedChunks: string[] = [];
  const client = {
    async reverseMap(_sessionId: string, text: string): Promise<string> {
      mappedChunks.push(text);
      return text.replace(/[A-Z][A-Z0-9]*_\d+/g, (m) => table[m] ?? m);
    },
  } as unknown as RustPipelineClient;
  return { client, mappedChunks };
}

describe("reverseMapStream — boundary buffering", () => {
  test("reassembles a pseudonym split across two stream tokens", async () => {
    const { client, mappedChunks } = fakeClient({ EMAIL_1: "alice@acme.com" });
    // "replied to EMAIL_1 now" arrives as three tokens, splitting EMAIL_1.
    const tokens: Token[] = [
      { text: "replied to EMAIL", done: false },
      { text: "_1 now", done: false },
      { text: "", done: true, finishReason: "stop" },
    ];
    const out = await drain(reverseMapStream(fromTokens(tokens), client, "s1"));
    const joined = out.map((t) => t.text).join("");
    expect(joined).toBe("replied to alice@acme.com now");
    // The half-formed "EMAIL" was never sent to the server on its own.
    expect(mappedChunks.some((c) => /EMAIL$/.test(c))).toBe(false);
    // The final token preserves the finish reason.
    expect(out.at(-1)?.done).toBe(true);
    expect(out.at(-1)?.finishReason).toBe("stop");
  });

  test("a pseudonym ending exactly at a token boundary still maps", async () => {
    const { client } = fakeClient({ PATH_1: "/Users/x/y" });
    const tokens: Token[] = [
      { text: "file at PATH_1", done: false },
      { text: " opened", done: false },
      { text: "", done: true, finishReason: "stop" },
    ];
    const out = await drain(reverseMapStream(fromTokens(tokens), client, "s1"));
    expect(out.map((t) => t.text).join("")).toBe("file at /Users/x/y opened");
  });

  test("plain text with no pseudonyms streams through untouched (no server call)", async () => {
    const { client, mappedChunks } = fakeClient({});
    const tokens: Token[] = [
      { text: "the capital of France ", done: false },
      { text: "is Paris.", done: false },
      { text: "", done: true, finishReason: "stop" },
    ];
    const out = await drain(reverseMapStream(fromTokens(tokens), client, "s1"));
    expect(out.map((t) => t.text).join("")).toBe("the capital of France is Paris.");
    expect(mappedChunks).toHaveLength(0); // MAYBE_PSEUDONYM gate skipped the server
  });

  test("trailing pseudonym with no following boundary flushes on done", async () => {
    const { client } = fakeClient({ EMAIL_1: "bob@corp.com" });
    const tokens: Token[] = [
      { text: "contact EMAIL", done: false },
      { text: "_1", done: true, finishReason: "stop" },
    ];
    const out = await drain(reverseMapStream(fromTokens(tokens), client, "s1"));
    expect(out.map((t) => t.text).join("")).toBe("contact bob@corp.com");
  });
});

// ---- wrapWithVeil end-to-end (fake client + fake inner backend) ------------

/** Inner backend that pseudonymizes-faithful: it echoes back exactly what it
 *  was sent (as the model would when told to reference EMAIL_1), so the wrap's
 *  reverse-map is what restores the real entity. */
function echoBackend(seen: { messages: Msg[][] }): VeilBackend {
  return {
    id: "echo",
    displayName: "Echo",
    capabilities: {
      chat: true,
      embed: false,
      classify: false,
      pii: false,
      streaming: true,
      jsonMode: false,
      tools: false,
      maxTiersAllowed: ["public", "internal", "private", "secret"],
      runsLocally: true,
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
      seen.messages.push(messages);
      // Echo the (already pseudonymized) user content back as the "reply".
      const user = messages.find((m) => m.role === "user");
      yield { text: `re: ${user?.content ?? ""}`, done: false };
      yield { text: "", done: true, finishReason: "stop" };
    },
  };
}

describe("wrapWithVeil — full round-trip", () => {
  test("model sees EMAIL_1; caller sees the real entity back", async () => {
    // Fake engine: pseudonymize mints EMAIL_1, reverseMap restores it.
    const fetchImpl = (async (url: string, init: RequestInit = {}) => {
      const path = url.replace(/^.*\/v1/, "/v1");
      const req = JSON.parse((init.body as string) ?? "{}");
      if (path === "/v1/pseudonymize") {
        return Response.json({
          text: req.text.replace("alice@acme.com", "EMAIL_1"),
          spans: [],
        });
      }
      if (path === "/v1/reverse-map") {
        return Response.json({ text: req.text.replace("EMAIL_1", "alice@acme.com") });
      }
      throw new Error(`unexpected path ${path}`);
    }) as unknown as typeof fetch;

    const client = new RustPipelineClient({ fetchImpl });
    const seen = { messages: [] as Msg[][] };
    const wrapped = wrapWithVeil(echoBackend(seen), client, { sessionId: "conv1" });

    const out = await drain(
      wrapped.chat([{ role: "user", content: "remind alice@acme.com", veilTier: "private" }]),
    );

    // The inner backend (the "model") only ever saw the pseudonym.
    expect(seen.messages[0]?.[0]?.content).toBe("remind EMAIL_1");
    // The tier tag was dropped before dispatch (content is now safe).
    expect(seen.messages[0]?.[0]?.veilTier).toBeUndefined();
    // The caller gets the real entity restored in the streamed reply.
    expect(out.map((t) => t.text).join("")).toBe("re: remind alice@acme.com");
    // Capability now advertises PII handling even though echo's own is false.
    expect(wrapped.capabilities.pii).toBe(true);
  });
});
