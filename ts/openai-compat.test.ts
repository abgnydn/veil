// SPDX-License-Identifier: Apache-2.0

// openai-compat.test.ts — unit tests for OpenAICompatAdapter.
//
// Mocks `fetch` for both SSE chat streaming and one-shot /v1/embeddings.
// Confirms:
//   1. Capability matrix matches VEIL.md §2.a (local, all tiers allowed).
//   2. baseURL is configurable (Ollama, LM Studio, llamafile all work) and a
//      trailing slash is normalized.
//   3. chat() streams tokens in order via the SSE [DONE] terminator.
//   4. embed() returns a Float32Array sized to the model's embedding dim.
//   5. Bearer auth header is sent only when apiKey is set.
//   6. When the daemon is unreachable, chat()/embed() throw with a clear
//      "set baseURL to your Ollama / LM Studio / llamafile server" hint.
//   7. Cancelling the chat stream mid-flight cancels the underlying reader
//      and does NOT leak further token reads past the cancel point.
//   8. Pre-aborted AbortSignal short-circuits before any HTTP work.

import { describe, expect, test } from "bun:test";

import { OpenAICompatAdapter } from "./openai-compat";
import { BackendUnsupported } from "./interface";

// ---- Helpers -------------------------------------------------------------

async function drain<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of iter) out.push(v);
  return out;
}

/**
 * Build a Response whose body streams the provided SSE frames in order.
 * Each frame is sent as one chunk with the trailing blank line included.
 */
function sseResponse(frames: string[], status = 200): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const f of frames) {
        controller.enqueue(encoder.encode(f + "\n\n"));
      }
      controller.close();
    },
  });
  return new Response(stream, {
    status,
    headers: { "content-type": "text/event-stream" },
  });
}

interface FetchCall {
  url: string;
  init: RequestInit | undefined;
}

function makeFetchMock(
  handler: (url: string, init: RequestInit | undefined) => Promise<Response> | Response,
) {
  const calls: FetchCall[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    return handler(url, init);
  }) as unknown as typeof fetch;
  return { fn, calls };
}

const okModelsList = () =>
  new Response(JSON.stringify({ data: [{ id: "phi3.5:3.8b" }] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

// ---- Tests ---------------------------------------------------------------

describe("OpenAICompatAdapter — capability matrix", () => {
  test("matches VEIL.md §2.a (local, all tiers allowed)", () => {
    const { fn } = makeFetchMock(() => okModelsList());
    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });
    expect(adapter.capabilities.chat).toBe(true);
    expect(adapter.capabilities.streaming).toBe(true);
    expect(adapter.capabilities.runsLocally).toBe(true);
    expect(adapter.capabilities.maxTiersAllowed).toEqual([
      "public",
      "internal",
      "private",
      "secret",
    ]);
    // No embedModel → embed unsupported until the user configures one.
    expect(adapter.capabilities.embed).toBe(false);
  });

  test("embed capability flips on when embedModel is set", () => {
    const { fn } = makeFetchMock(() => okModelsList());
    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      embedModel: "nomic-embed-text",
      fetchImpl: fn,
      skipHealthCheck: true,
    });
    expect(adapter.capabilities.embed).toBe(true);
  });
});

describe("OpenAICompatAdapter — baseURL configurability", () => {
  test("default points at Ollama (localhost:11434/v1)", async () => {
    const { fn, calls } = makeFetchMock(async (url) => {
      if (url.endsWith("/models")) return okModelsList();
      throw new Error("unexpected " + url);
    });
    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
    });
    await adapter.init();
    expect(adapter.isReady()).toBe(true);
    expect(calls[0]?.url).toBe("http://localhost:11434/v1/models");
  });

  test("LM Studio URL works (port 1234)", async () => {
    const { fn, calls } = makeFetchMock(async () => okModelsList());
    const adapter = new OpenAICompatAdapter({
      baseURL: "http://localhost:1234/v1",
      model: "lmstudio-community/phi-3.5",
      fetchImpl: fn,
    });
    await adapter.init();
    expect(calls[0]?.url).toBe("http://localhost:1234/v1/models");
  });

  test("trailing slash on baseURL is normalized", async () => {
    const { fn, calls } = makeFetchMock(async () => okModelsList());
    const adapter = new OpenAICompatAdapter({
      baseURL: "http://localhost:11434/v1/",
      model: "phi3.5:3.8b",
      fetchImpl: fn,
    });
    await adapter.init();
    expect(calls[0]?.url).toBe("http://localhost:11434/v1/models");
  });
});

describe("OpenAICompatAdapter — chat() streams tokens", () => {
  test("yields tokens in order, then a done terminator", async () => {
    const frames = [
      `data: ${JSON.stringify({ choices: [{ delta: { content: "Hello" } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: ", " } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: "world" } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: "!" }, finish_reason: "stop" }] })}`,
      "data: [DONE]",
    ];
    const { fn } = makeFetchMock(async (url) => {
      if (url.endsWith("/models")) return okModelsList();
      if (url.endsWith("/chat/completions")) return sseResponse(frames);
      throw new Error("unexpected " + url);
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });

    const tokens = await drain(
      adapter.chat([{ role: "user", content: "hi" }]),
    );

    const content = tokens
      .filter((t) => !t.done && t.text)
      .map((t) => t.text)
      .join("");
    // Note: the finish-frame carries "!" with done=true, so it appears in the
    // content stream too — concatenating all .text fields recovers the reply.
    const allText = tokens.map((t) => t.text).join("");
    expect(allText).toBe("Hello, world!");
    expect(content).toBe("Hello, world");

    const last = tokens[tokens.length - 1];
    expect(last?.done).toBe(true);
    expect(last?.finishReason).toBe("stop");
  });

  test("Msg[] maps to OpenAI message format directly", async () => {
    let bodyCapture: unknown = null;
    const { fn } = makeFetchMock(async (url, init) => {
      if (url.endsWith("/chat/completions")) {
        bodyCapture = JSON.parse(init?.body as string);
        return sseResponse(["data: [DONE]"]);
      }
      return okModelsList();
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });

    await drain(
      adapter.chat([
        { role: "system", content: "be terse" },
        { role: "user", content: "ping" },
      ]),
    );

    const body = bodyCapture as { model: string; messages: unknown[]; stream: boolean };
    expect(body.model).toBe("phi3.5:3.8b");
    expect(body.stream).toBe(true);
    expect(body.messages).toEqual([
      { role: "system", content: "be terse" },
      { role: "user", content: "ping" },
    ]);
  });
});

describe("OpenAICompatAdapter — embed()", () => {
  test("returns a Float32Array of the model's dim", async () => {
    const vec = Array.from({ length: 768 }, (_, i) => i / 768);
    const { fn, calls } = makeFetchMock(async (url) => {
      if (url.endsWith("/models")) return okModelsList();
      if (url.endsWith("/embeddings")) {
        return new Response(JSON.stringify({ data: [{ embedding: vec }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error("unexpected " + url);
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      embedModel: "nomic-embed-text",
      fetchImpl: fn,
      skipHealthCheck: true,
    });

    const out = await adapter.embed("hello");
    expect(out).toBeInstanceOf(Float32Array);
    expect(out.length).toBe(768);
    expect(out[0]).toBeCloseTo(0);
    expect(out[767]).toBeCloseTo(767 / 768);
    // After first call, capability dim is now honest.
    expect(adapter.capabilities.embeddingDim).toBe(768);
    // Verify we hit the right URL.
    const embedCall = calls.find((c) => c.url.endsWith("/embeddings"));
    expect(embedCall).toBeDefined();
  });

  test("throws BackendUnsupported when embedModel is unset", async () => {
    const { fn } = makeFetchMock(async () => okModelsList());
    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });
    await expect(adapter.embed("anything")).rejects.toBeInstanceOf(
      BackendUnsupported,
    );
  });
});

describe("OpenAICompatAdapter — auth header", () => {
  test("Bearer header is sent when apiKey is set", async () => {
    let authHeader: string | undefined;
    const { fn } = makeFetchMock(async (url, init) => {
      const headers = init?.headers as Record<string, string> | undefined;
      if (url.endsWith("/chat/completions")) {
        authHeader = headers?.["authorization"];
        return sseResponse(["data: [DONE]"]);
      }
      return okModelsList();
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      apiKey: "sk-local-secret",
      fetchImpl: fn,
      skipHealthCheck: true,
    });
    await drain(adapter.chat([{ role: "user", content: "hi" }]));
    expect(authHeader).toBe("Bearer sk-local-secret");
  });

  test("no Authorization header when apiKey is unset (Ollama / LM Studio default)", async () => {
    let authHeader: string | undefined = "<not-captured>";
    const { fn } = makeFetchMock(async (url, init) => {
      const headers = init?.headers as Record<string, string> | undefined;
      if (url.endsWith("/chat/completions")) {
        authHeader = headers?.["authorization"];
        return sseResponse(["data: [DONE]"]);
      }
      return okModelsList();
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });
    await drain(adapter.chat([{ role: "user", content: "hi" }]));
    expect(authHeader).toBeUndefined();
  });
});

describe("OpenAICompatAdapter — unreachable server hint", () => {
  test("chat() throws BackendUnsupported with the friendly hint", async () => {
    const { fn } = makeFetchMock(async () => {
      throw new TypeError("fetch failed: ECONNREFUSED");
    });
    const adapter = new OpenAICompatAdapter({
      baseURL: "http://localhost:9999/v1",
      model: "ghost",
      fetchImpl: fn,
    });
    await adapter.init();
    expect(adapter._isReachable()).toBe(false);

    await expect(
      drain(adapter.chat([{ role: "user", content: "hi" }])),
    ).rejects.toThrow(/Ollama \/ LM Studio \/ llamafile/);
  });

  test("embed() throws BackendUnsupported with the friendly hint", async () => {
    const { fn } = makeFetchMock(async () => {
      throw new TypeError("fetch failed: ECONNREFUSED");
    });
    const adapter = new OpenAICompatAdapter({
      baseURL: "http://localhost:9999/v1",
      model: "ghost",
      embedModel: "nomic-embed-text",
      fetchImpl: fn,
    });
    await adapter.init();
    await expect(adapter.embed("hi")).rejects.toThrow(
      /Ollama \/ LM Studio \/ llamafile/,
    );
  });
});

describe("OpenAICompatAdapter — stream cancellation", () => {
  test("breaking out of the for-await loop cancels the reader", async () => {
    let cancelled = false;
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode(
            `data: ${JSON.stringify({ choices: [{ delta: { content: "a" } }] })}\n\n`,
          ),
        );
        controller.enqueue(
          encoder.encode(
            `data: ${JSON.stringify({ choices: [{ delta: { content: "b" } }] })}\n\n`,
          ),
        );
        // Don't close — keep the stream open so the consumer must explicitly
        // cancel. If cancellation didn't propagate, this test would hang.
      },
      cancel() {
        cancelled = true;
      },
    });

    const { fn } = makeFetchMock(async (url) => {
      if (url.endsWith("/chat/completions")) {
        return new Response(body, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        });
      }
      return okModelsList();
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });

    const stream = adapter.chat([{ role: "user", content: "hi" }]);
    let received = "";
    for await (const tok of stream) {
      if (tok.text) received += tok.text;
      if (received === "a") break; // bail out mid-stream
    }
    // Give the finally block a microtask to land cancel().
    await new Promise((r) => setTimeout(r, 5));
    expect(cancelled).toBe(true);
    expect(received).toBe("a"); // no leak past the break
  });

  test("pre-aborted AbortSignal short-circuits with finishReason='aborted'", async () => {
    let chatHit = false;
    const { fn } = makeFetchMock(async (url) => {
      if (url.endsWith("/chat/completions")) {
        chatHit = true;
        return sseResponse(["data: [DONE]"]);
      }
      return okModelsList();
    });

    const adapter = new OpenAICompatAdapter({
      model: "phi3.5:3.8b",
      fetchImpl: fn,
      skipHealthCheck: true,
    });

    const ctrl = new AbortController();
    ctrl.abort();
    const tokens = await drain(
      adapter.chat([{ role: "user", content: "hi" }], { signal: ctrl.signal }),
    );
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.done).toBe(true);
    expect(tokens[0]?.finishReason).toBe("aborted");
    expect(chatHit).toBe(false); // no HTTP work for a pre-aborted call
  });
});
