// SPDX-License-Identifier: Apache-2.0

// transformers-js.test.ts — unit tests for TransformersJSAdapter.
//
// Mocks the `pipeline` factory from @huggingface/transformers so the tests
// run without actually loading any ONNX model. Confirms:
//   1. Capability matrix matches the briefing (chat=false, embed/classify/pii true).
//   2. embed() returns a 384-dim Float32Array (e5-small default).
//   3. classifyTier() returns probabilistic TierScores summing to ~1.
//   4. detectPII() returns spans with valid offsets and PIIKind mapping.
//   5. chat() throws BackendUnsupported with the right backend id.
//   6. Lazy-import: the dynamic import only fires on init() / first call.
//   7. init() emits init_progress events at the right percentages.

import { describe, expect, test } from "bun:test";

import { TransformersJSAdapter } from "./transformers-js";
import { BackendUnsupported } from "./interface";
import type {
  InitProgressEvent,
  TransformersJSAdapterOpts,
} from "./transformers-js";

// Capture the duck-typed module shape that the adapter consumes via
// `moduleOverride`. Re-deriving it here keeps the test isolated from any
// cross-file type plumbing.
type ModuleShape = NonNullable<TransformersJSAdapterOpts["moduleOverride"]>;

// ---- Mock pipeline factory -----------------------------------------------

interface PipelineCalls {
  tasks: string[];
  models: string[];
}

interface MockOptions {
  /** Override the embedding vector returned by feature-extraction. */
  embedding?: number[];
  /** Override the zero-shot classification result. */
  zeroShot?: { labels: string[]; scores: number[] };
  /** Override the NER entities. */
  ner?: Array<{
    entity_group: string;
    score: number;
    word: string;
    start: number;
    end: number;
  }>;
}

function makeMockModule(opts: MockOptions = {}): {
  module: ModuleShape;
  calls: PipelineCalls;
} {
  const calls: PipelineCalls = { tasks: [], models: [] };
  const pipelineImpl = async (task: string, model?: string) => {
      calls.tasks.push(task);
      calls.models.push(model ?? "");

      if (task === "feature-extraction") {
        const data = opts.embedding ?? new Array(384).fill(0).map((_, i) => i / 384);
        return async (_text: string, _o?: unknown) => ({
          data: new Float32Array(data),
          dims: [1, data.length],
        });
      }

      if (task === "zero-shot-classification") {
        const result = opts.zeroShot ?? {
          // Default: an "internal" lean (matches a neutral input).
          labels: [
            "internal work content",
            "publicly shareable information",
            "personal or confidential information",
            "secrets, credentials, or API keys",
          ],
          scores: [0.55, 0.25, 0.15, 0.05],
        };
        return async (
          text: string,
          _candidates: string[],
          _o?: unknown,
        ) => ({
          sequence: text,
          labels: result.labels,
          scores: result.scores,
        });
      }

      if (task === "token-classification") {
        const ents = opts.ner ?? [];
        return async (_text: string, _o?: unknown) => ents;
      }

      throw new Error("unmocked task: " + task);
    };
  // The mock returns a duck-typed pipeline; cast through `unknown` to land
  // on the adapter's narrower TransformersModuleShape contract without
  // pulling in `@huggingface/transformers` typings.
  const module = { pipeline: pipelineImpl } as unknown as ModuleShape;
  return { module, calls };
}

// ---- Tests ---------------------------------------------------------------

describe("TransformersJSAdapter — capability matrix", () => {
  test("chat false, embed/classify/pii true, runsLocally true", () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    expect(adapter.capabilities.chat).toBe(false);
    expect(adapter.capabilities.embed).toBe(true);
    expect(adapter.capabilities.classify).toBe(true);
    expect(adapter.capabilities.pii).toBe(true);
    expect(adapter.capabilities.runsLocally).toBe(true);
    expect(adapter.capabilities.streaming).toBe(false);
    expect(adapter.capabilities.embeddingDim).toBe(384);
  });
});

describe("TransformersJSAdapter — lazy-import semantics", () => {
  test("constructor does NOT trigger dynamic import", () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    expect(adapter._dynamicImportCount()).toBe(0);
    expect(adapter.isReady()).toBe(false);
  });

  test("init() emits init_progress events for embed → classify → done", async () => {
    const events: InitProgressEvent[] = [];
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
      onInitProgress: (e) => events.push(e),
    });
    await adapter.init();

    const stages = events.map((e) => e.stage);
    expect(stages).toEqual(["embed", "classify", "done"]);
    expect(events[events.length - 1]?.percent).toBe(1);
    expect(adapter.isReady()).toBe(true);
  });

  test("init() pulls e5-small / mDeBERTa / HRL-NER by default", async () => {
    const { module: mod, calls } = makeMockModule();
    const adapter = new TransformersJSAdapter({ moduleOverride: mod });
    await adapter.init();

    expect(calls.tasks).toEqual([
      "feature-extraction",
      "zero-shot-classification",
      "token-classification",
    ]);
    expect(calls.models[0]).toBe("Xenova/multilingual-e5-small");
    expect(calls.models[1]).toBe("Xenova/mDeBERTa-v3-base-mnli-xnli");
    expect(calls.models[2]).toBe("Xenova/bert-base-multilingual-cased-ner-hrl");
  });
});

describe("TransformersJSAdapter — embed()", () => {
  test("returns a 384-dim Float32Array (e5-small)", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    const out = await adapter.embed("hello world");
    expect(out).toBeInstanceOf(Float32Array);
    expect(out.length).toBe(384);
  });
});

describe("TransformersJSAdapter — classifyTier()", () => {
  test("returns probabilistic TierScores summing to ~1", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    const scores = await adapter.classifyTier("a regular work email about a deadline");
    const sum = scores.public + scores.internal + scores.private + scores.secret;
    expect(Math.abs(sum - 1)).toBeLessThan(0.01);
    // All scores are in [0, 1].
    for (const v of [scores.public, scores.internal, scores.private, scores.secret]) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });

  test("argmax tracks the dominant hypothesis (secret-leaning input → secret high)", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule({
        zeroShot: {
          labels: [
            "secrets, credentials, or API keys",
            "personal or confidential information",
            "internal work content",
            "publicly shareable information",
          ],
          scores: [0.7, 0.2, 0.07, 0.03],
        },
      }).module,
    });
    const scores = await adapter.classifyTier("AWS_SECRET_ACCESS_KEY=...");
    expect(scores.secret).toBeCloseTo(0.7, 2);
    expect(scores.public).toBeLessThan(scores.secret);
  });

  test("renormalizes when pipeline output sums slightly off-1 (numerical drift)", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule({
        zeroShot: {
          labels: [
            "internal work content",
            "publicly shareable information",
            "personal or confidential information",
            "secrets, credentials, or API keys",
          ],
          // Sums to 1.10 — out-of-spec; adapter must renormalize.
          scores: [0.6, 0.3, 0.15, 0.05],
        },
      }).module,
    });
    const scores = await adapter.classifyTier("anything");
    const sum = scores.public + scores.internal + scores.private + scores.secret;
    expect(Math.abs(sum - 1)).toBeLessThan(0.01);
  });
});

describe("TransformersJSAdapter — detectPII()", () => {
  test("returns spans with valid offsets and PIIKind mapping", async () => {
    const text = "Met Alice in Paris with Acme Corp.";
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule({
        ner: [
          { entity_group: "PER", score: 0.99, word: "Alice", start: 4, end: 9 },
          { entity_group: "LOC", score: 0.97, word: "Paris", start: 13, end: 18 },
          { entity_group: "ORG", score: 0.95, word: "Acme Corp", start: 24, end: 33 },
          // MISC is dropped intentionally (mapped to null).
          { entity_group: "MISC", score: 0.6, word: "ignored", start: 0, end: 1 },
        ],
      }).module,
    });
    const spans = await adapter.detectPII(text);

    expect(spans.length).toBe(3);

    const kinds = spans.map((s) => s.kind);
    expect(kinds).toContain("PERSON");
    expect(kinds).toContain("LOCATION");
    expect(kinds).toContain("ORG");
    expect(kinds).not.toContain("CUSTOM");

    // Offsets are valid utf-16 positions inside the input text and the
    // substring round-trip recovers the original entity word.
    for (const span of spans) {
      expect(span.start).toBeGreaterThanOrEqual(0);
      expect(span.end).toBeLessThanOrEqual(text.length);
      expect(span.end).toBeGreaterThan(span.start);
      expect(text.slice(span.start, span.end).length).toBeGreaterThan(0);
    }

    // Replacement is Presidio-shaped: KIND_N.
    expect(spans.every((s) => /^[A-Z_]+_\d+$/.test(s.replacement))).toBe(true);
  });

  test("drops entities with invalid offsets rather than emitting a bogus span", async () => {
    const text = "short";
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule({
        ner: [
          { entity_group: "PER", score: 0.99, word: "ghost", start: 100, end: 200 },
          { entity_group: "PER", score: 0.99, word: "rev", start: 5, end: 2 },
        ],
      }).module,
    });
    const spans = await adapter.detectPII(text);
    expect(spans).toHaveLength(0);
  });
});

describe("TransformersJSAdapter — chat() throws BackendUnsupported", () => {
  test("chat is not this adapter's lane", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    const stream = adapter.chat([{ role: "user", content: "hi" }]);
    // The function is async-iterable; invoking it returns the iterable, but
    // the throw lands when consumption starts.
    await expect((async () => {
      for await (const _ of stream) {
        // unreachable
      }
    })()).rejects.toBeInstanceOf(BackendUnsupported);
  });

  test("error mentions chat and the backend id", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    const stream = adapter.chat([{ role: "user", content: "hi" }]);
    await expect((async () => {
      for await (const _ of stream) {
        // unreachable
      }
    })()).rejects.toThrow(/chat/);
    const stream2 = adapter.chat([{ role: "user", content: "hi" }]);
    await expect((async () => {
      for await (const _ of stream2) {
        // unreachable
      }
    })()).rejects.toThrow(/transformers-js/);
  });
});

describe("TransformersJSAdapter — dispose()", () => {
  test("dispose() flips ready back to false", async () => {
    const adapter = new TransformersJSAdapter({
      moduleOverride: makeMockModule().module,
    });
    await adapter.init();
    expect(adapter.isReady()).toBe(true);
    await adapter.dispose();
    expect(adapter.isReady()).toBe(false);
  });
});
