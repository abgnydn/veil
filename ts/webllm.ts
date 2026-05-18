// SPDX-License-Identifier: Apache-2.0

// WebLLMAdapter — in-tab WebGPU LLM via @mlc-ai/web-llm.
//
// The default for zero-install users. Loads Phi-3.5-mini-instruct-q4f16_1
// from OPFS + Cache API on first run; subsequent loads are instant.
//
// Threading note: the production deployment runs this in a Service Worker so
// the SolidJS UI never stalls (see VEIL.md §2.b). This main-thread variant is
// the contract-shaped reference impl — the SW proxy satisfies the same
// VeilBackend interface via MessagePort. Both share this class's logic.
//
// Hard invariant note: WebLLM runs locally → maxTiersAllowed includes
// `secret`. There is no remote-leak path on this adapter; the `secret`
// invariant is enforced on AnthropicAdapter, not here.

import type {
  BackendCapabilities,
  ChatOpts,
  Msg,
  PIISpan,
  TierScores,
  Token,
  VeilBackend,
} from "./interface";
import { BackendUnsupported } from "./interface";
import { classifyTierHeuristic, detectPIIHeuristic } from "./classifier";

/**
 * Minimal duck-typed shape of @mlc-ai/web-llm's MLCEngine. We dynamic-import
 * the package at init() so this file typechecks without the dep installed.
 * The full surface is documented at github.com/mlc-ai/web-llm.
 */
interface MLCEngine {
  reload(model: string): Promise<void>;
  chat: {
    completions: {
      create(opts: {
        messages: Array<{ role: string; content: string }>;
        stream: boolean;
        temperature?: number;
        max_tokens?: number;
        stop?: string[];
        response_format?: { type: "json_object" };
      }): Promise<AsyncIterable<{
        choices: Array<{
          delta?: { content?: string };
          finish_reason?: string | null;
        }>;
      }>>;
    };
  };
  embeddings?: {
    create(opts: { input: string }): Promise<{
      data: Array<{ embedding: number[] }>;
    }>;
  };
}

interface WebLLMModuleShape {
  CreateMLCEngine?(model: string): Promise<MLCEngine>;
  MLCEngine?: new () => MLCEngine;
}

export interface WebLLMAdapterOpts {
  /** MLC model record id. Default: "Phi-3.5-mini-instruct-q4f16_1-MLC". */
  model?: string;
  /** Optional override for the dynamic import target — useful for tests. */
  webllmModuleSpecifier?: string;
  /** Test seam: inject a pre-built engine instead of loading the real one. */
  engineOverride?: MLCEngine;
}

const DEFAULT_MODEL = "Phi-3.5-mini-instruct-q4f16_1-MLC";

export class WebLLMAdapter implements VeilBackend {
  readonly id = "webllm";
  readonly displayName = "WebLLM (in-tab)";
  readonly capabilities: BackendCapabilities = {
    chat: true,
    embed: false, // model-dependent; flipped to true in init() if engine has embeddings
    classify: true,
    pii: true, // heuristic-only; advertised true so the router uses us as PII fallback
    streaming: true,
    jsonMode: true,
    tools: false, // preliminary in WebLLM 0.2.83; declare false until proven
    maxTiersAllowed: ["public", "internal", "private", "secret"],
    runsLocally: true,
  };

  private engine: MLCEngine | null = null;
  private ready = false;
  private readonly model: string;
  private readonly moduleSpecifier: string;
  private readonly engineOverride: MLCEngine | undefined;

  constructor(opts: WebLLMAdapterOpts = {}) {
    this.model = opts.model ?? DEFAULT_MODEL;
    this.moduleSpecifier = opts.webllmModuleSpecifier ?? "@mlc-ai/web-llm";
    this.engineOverride = opts.engineOverride;
  }

  async init(): Promise<void> {
    if (this.ready) return;

    if (this.engineOverride) {
      this.engine = this.engineOverride;
      this.ready = true;
      this.refreshCapabilities();
      return;
    }

    // Dynamic import keeps the dep optional at typecheck time and lets us
    // ship a server-side bundle that doesn't pull WebLLM into Node.
    const mod = (await import(/* @vite-ignore */ this.moduleSpecifier)) as WebLLMModuleShape;
    if (typeof mod.CreateMLCEngine === "function") {
      this.engine = await mod.CreateMLCEngine(this.model);
    } else if (typeof mod.MLCEngine === "function") {
      const engine = new mod.MLCEngine();
      await engine.reload(this.model);
      this.engine = engine;
    } else {
      throw new Error(
        `WebLLMAdapter: module "${this.moduleSpecifier}" exposes neither CreateMLCEngine nor MLCEngine.`,
      );
    }
    this.ready = true;
    this.refreshCapabilities();
  }

  isReady(): boolean {
    return this.ready;
  }

  private refreshCapabilities(): void {
    if (this.engine?.embeddings) {
      this.capabilities.embed = true;
    }
  }

  private requireEngine(): MLCEngine {
    if (!this.engine || !this.ready) {
      throw new Error("WebLLMAdapter not initialized — call init() first.");
    }
    return this.engine;
  }

  // ---- classify / PII: thin heuristic wrappers ---------------------------
  // Real classification will use the loaded chat model with a 4-class JSON
  // prompt; until the JSON-mode prompt + post-parse are validated against
  // Phi-3.5-mini, we use the heuristic. Cheap, predictable, no warm-up.

  async classifyTier(text: string): Promise<TierScores> {
    return classifyTierHeuristic(text);
  }

  async detectPII(text: string): Promise<PIISpan[]> {
    return detectPIIHeuristic(text);
  }

  // ---- chat: streaming WebLLM completion ---------------------------------

  async *chat(messages: Msg[], opts: ChatOpts = {}): AsyncIterable<Token> {
    const engine = this.requireEngine();

    const stream = await engine.chat.completions.create({
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      stream: true,
      ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
      ...(opts.maxTokens !== undefined ? { max_tokens: opts.maxTokens } : {}),
      ...(opts.stop !== undefined ? { stop: opts.stop } : {}),
      ...(opts.jsonMode ? { response_format: { type: "json_object" as const } } : {}),
    });

    for await (const chunk of stream) {
      const choice = chunk.choices[0];
      if (!choice) continue;
      const delta = choice.delta?.content ?? "";
      const finish = choice.finish_reason;
      if (delta) {
        yield { text: delta, done: false };
      }
      if (finish) {
        yield {
          text: "",
          done: true,
          finishReason:
            finish === "stop" || finish === "length" || finish === "tool_use"
              ? finish
              : "stop",
        };
        return;
      }
    }
    // Stream ended without a finish_reason — emit a synthetic terminator so
    // the caller's for-await loop closes cleanly.
    yield { text: "", done: true, finishReason: "stop" };
  }

  // ---- embed: model-dependent --------------------------------------------

  async embed(text: string): Promise<Float32Array> {
    const engine = this.requireEngine();
    if (!engine.embeddings) {
      throw new BackendUnsupported(
        "embed",
        `${this.id} (use transformers.js adapter for embed when this model lacks an embedding head)`,
      );
    }
    const result = await engine.embeddings.create({ input: text });
    const vector = result.data[0]?.embedding;
    if (!vector) {
      throw new Error("WebLLMAdapter.embed: empty embedding response.");
    }
    return new Float32Array(vector);
  }

  async dispose(): Promise<void> {
    this.engine = null;
    this.ready = false;
  }
}
