// SPDX-License-Identifier: Apache-2.0

// OpenAICompatAdapter — the lingua-franca local-server backend.
//
// Talks to anything that exposes the OpenAI `/v1` surface: Ollama, LM Studio,
// llamafile-server, llama.cpp's `server`, vLLM, plus any future OAI-compat
// daemon. One adapter, ~80% of the local-server landscape (see
// ~/the host application/research/veil-backends.md).
//
// Hard invariant note: the user runs the daemon on their own machine, so we
// classify this as `runsLocally: true` and accept all four tiers including
// `secret`. The remote-leak invariant is enforced on AnthropicAdapter, not
// here. (If a user mis-points `baseURL` at a hosted OpenAI endpoint, that is a
// configuration mistake, not an adapter contract bug — the Settings UI is
// expected to surface a clear "this URL looks remote" warning.)
//
// We don't depend on the `openai` SDK — `fetch` + an SSE parser keeps the
// bundle thin. The Anthropic adapter follows the same pattern; this file
// mirrors that structure.

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

// ---- Adapter options ------------------------------------------------------

export interface OpenAICompatAdapterOpts {
  /**
   * Root of the OpenAI-compat surface. Trailing `/v1` IS expected — we
   * concatenate `/chat/completions` and `/embeddings` directly. Defaults to
   * Ollama's local port. Common values:
   *   - Ollama:     http://localhost:11434/v1
   *   - LM Studio:  http://localhost:1234/v1
   *   - llamafile:  http://localhost:8080/v1   (depends on user's launch flags)
   *   - vLLM:       http://localhost:8000/v1
   */
  baseURL?: string;

  /** Default chat model id, e.g. `phi3.5:3.8b` (Ollama) or `lmstudio-community/...` (LM Studio). */
  model: string;

  /**
   * Default embedding model id. Optional. When unset, `embed()` throws
   * BackendUnsupported. Ollama serves `nomic-embed-text`; LM Studio loads any
   * embed-capable GGUF; vLLM exposes whatever model was started with
   * `--task embedding`.
   */
  embedModel?: string;

  /**
   * Optional bearer token. Local servers usually don't require it; if set,
   * sent as `Authorization: Bearer <apiKey>`. LM Studio ignores it. Ollama
   * ignores it. vLLM may require it depending on `--api-key` launch flag.
   */
  apiKey?: string;

  /** Test seam: inject a fetch impl. Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;

  /**
   * Skip the construction-time health check. The default is to fire-and-
   * forget a `GET /v1/models` so `isReady()` reflects reachability without
   * blocking the constructor. Tests turn this off when they don't want the
   * background fetch.
   */
  skipHealthCheck?: boolean;

  /** Default max tokens per chat turn when ChatOpts.maxTokens is unset. */
  defaultMaxTokens?: number;
}

const DEFAULT_BASE_URL = "http://localhost:11434/v1";
const DEFAULT_MAX_TOKENS = 2048;

const UNREACHABLE_HINT =
  "set baseURL to your Ollama / LM Studio / llamafile server (e.g. http://localhost:11434/v1)";

export class OpenAICompatAdapter implements VeilBackend {
  readonly id = "openai-compat";
  readonly displayName = "OpenAI-compat (Ollama / LM Studio / llamafile / vLLM)";
  readonly capabilities: BackendCapabilities = {
    chat: true,
    embed: false, // flipped to true in constructor when embedModel is set
    classify: true, // heuristic delegate
    pii: true, // heuristic delegate
    streaming: true,
    jsonMode: true, // OpenAI-compat surface includes response_format
    tools: false, // depends on daemon; default off, opt-in is a future stream
    maxTiersAllowed: ["public", "internal", "private", "secret"],
    runsLocally: true,
  };

  private readonly baseURL: string;
  private readonly model: string;
  private readonly embedModel: string | undefined;
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly defaultMaxTokens: number;
  private reachable = false;
  private ready = false;

  constructor(opts: OpenAICompatAdapterOpts) {
    // Strip a single trailing slash so we can append `/chat/completions` etc.
    const raw = opts.baseURL ?? DEFAULT_BASE_URL;
    this.baseURL = raw.endsWith("/") ? raw.slice(0, -1) : raw;

    this.model = opts.model;
    this.embedModel = opts.embedModel;
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.defaultMaxTokens = opts.defaultMaxTokens ?? DEFAULT_MAX_TOKENS;

    if (this.embedModel) {
      this.capabilities.embed = true;
      // 0 means "we don't know yet" — embed() returns the actual length on the
      // first call. Some embed models are 384, others 768 / 1024 / 4096. The
      // adapter doesn't pre-declare a specific dim because the model knob is
      // user-configurable.
      this.capabilities.embeddingDim = 0;
    }

    if (!opts.skipHealthCheck) {
      // Fire-and-forget health check. Don't block construction; flip
      // `reachable` when the probe succeeds. chat()/embed() throw with a
      // friendly message when the server isn't there.
      void this.healthCheck();
    } else {
      // Tests skip the probe; assume reachable so isReady() returns true.
      this.reachable = true;
      this.ready = true;
    }
  }

  /**
   * GET /v1/models — confirms the daemon is alive. Doesn't validate that
   * `this.model` is among them: model lists are async-loadable on Ollama and
   * LM Studio, and a not-yet-loaded model is still serveable on the next
   * /chat/completions call (the daemon side-loads).
   */
  private async healthCheck(): Promise<void> {
    try {
      const res = await this.fetchImpl(`${this.baseURL}/models`, {
        method: "GET",
        headers: this.authHeaders(),
      });
      this.reachable = res.ok;
    } catch {
      this.reachable = false;
    } finally {
      this.ready = true;
    }
  }

  async init(): Promise<void> {
    // No model load; the daemon owns its own warm-up. We just confirm
    // reachability synchronously if the constructor's background probe hasn't
    // completed yet.
    if (!this.ready) {
      await this.healthCheck();
    }
  }

  isReady(): boolean {
    return this.ready;
  }

  /** Test-only accessor: did the construction-time probe see the server? */
  _isReachable(): boolean {
    return this.reachable;
  }

  // ---- classify / PII: heuristic delegates --------------------------------
  // Same pattern as WebLLM and Zero-TVM. Real classification will route
  // through transformers.js; this method exists so the VeilBackend surface is
  // total. The adapter's own JSON-mode 4-class call (per VEIL.md §2.a) is a
  // future upgrade — keeps the heuristic fast and predictable for v1.

  async classifyTier(text: string): Promise<TierScores> {
    return classifyTierHeuristic(text);
  }

  async detectPII(text: string): Promise<PIISpan[]> {
    return detectPIIHeuristic(text);
  }

  // ---- chat: SSE streaming via fetch + ReadableStream ----------------------

  async *chat(messages: Msg[], opts: ChatOpts = {}): AsyncIterable<Token> {
    if (!this.reachable && this.ready) {
      // Re-probe once: the user may have started Ollama after the adapter
      // was constructed. If still unreachable, throw with the friendly hint.
      await this.healthCheck();
      if (!this.reachable) {
        throw new BackendUnsupported(
          `chat (server unreachable at ${this.baseURL} — ${UNREACHABLE_HINT})`,
          this.id,
        );
      }
    }

    const body: Record<string, unknown> = {
      model: opts.model ?? this.model,
      messages: messages.map(toOpenAIMessage),
      stream: true,
      max_tokens: opts.maxTokens ?? this.defaultMaxTokens,
    };
    if (opts.temperature !== undefined) body.temperature = opts.temperature;
    if (opts.stop && opts.stop.length > 0) body.stop = opts.stop;
    if (opts.jsonMode) body.response_format = { type: "json_object" };

    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "text/event-stream",
      ...this.authHeaders(),
    };

    if (opts.signal?.aborted) {
      yield { text: "", done: true, finishReason: "aborted" };
      return;
    }

    const response = await this.fetchImpl(`${this.baseURL}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      ...(opts.signal ? { signal: opts.signal } : {}),
    });

    if (!response.ok || !response.body) {
      const errText = await safeText(response);
      throw new Error(
        `OpenAICompatAdapter: HTTP ${response.status} ${response.statusText}: ${errText}`,
      );
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buf = "";
    let finished = false;

    try {
      while (!finished) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        // SSE frames are separated by blank lines. Parse all complete frames
        // and keep the trailing partial frame in `buf`. Cancellation drops
        // any in-flight frame on the floor — the finally block cancels the
        // reader, releasing the underlying connection.
        let sep = buf.indexOf("\n\n");
        while (sep !== -1) {
          const frame = buf.slice(0, sep);
          buf = buf.slice(sep + 2);
          const parsed = parseOpenAISSEFrame(frame);
          if (parsed === "DONE") {
            yield { text: "", done: true, finishReason: "stop" };
            finished = true;
            break;
          }
          if (parsed) {
            yield parsed;
            if (parsed.done) {
              finished = true;
              break;
            }
          }
          sep = buf.indexOf("\n\n");
        }
      }
    } finally {
      try {
        await reader.cancel();
      } catch {
        // ignore — cancellation races during error/abort are expected
      }
    }

    if (!finished) {
      yield { text: "", done: true, finishReason: "stop" };
    }
  }

  // ---- embed: POST /v1/embeddings -----------------------------------------

  async embed(text: string): Promise<Float32Array> {
    if (!this.embedModel) {
      throw new BackendUnsupported(
        "embed (no embedModel configured — pass `embedModel` in adapter opts, e.g. 'nomic-embed-text')",
        this.id,
      );
    }

    if (!this.reachable && this.ready) {
      await this.healthCheck();
      if (!this.reachable) {
        throw new BackendUnsupported(
          `embed (server unreachable at ${this.baseURL} — ${UNREACHABLE_HINT})`,
          this.id,
        );
      }
    }

    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...this.authHeaders(),
    };

    const response = await this.fetchImpl(`${this.baseURL}/embeddings`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: this.embedModel,
        input: text,
      }),
    });

    if (!response.ok) {
      const errText = await safeText(response);
      throw new Error(
        `OpenAICompatAdapter.embed: HTTP ${response.status} ${response.statusText}: ${errText}`,
      );
    }

    const json = (await response.json()) as {
      data?: Array<{ embedding?: number[] }>;
    };
    const vector = json.data?.[0]?.embedding;
    if (!vector || vector.length === 0) {
      throw new Error("OpenAICompatAdapter.embed: empty embedding response.");
    }

    // Cache the dim so capability inspection is honest after the first call.
    this.capabilities.embeddingDim = vector.length;

    return new Float32Array(vector);
  }

  async dispose(): Promise<void> {
    this.reachable = false;
    this.ready = false;
  }

  // ---- helpers -----------------------------------------------------------

  private authHeaders(): Record<string, string> {
    return this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {};
  }
}

// ---- Msg → OpenAI message format -----------------------------------------

interface OpenAIMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_call_id?: string;
}

function toOpenAIMessage(m: Msg): OpenAIMessage {
  const out: OpenAIMessage = { role: m.role, content: m.content };
  if (m.role === "tool" && m.toolCallId) {
    out.tool_call_id = m.toolCallId;
  }
  return out;
}

// ---- SSE parsing ---------------------------------------------------------

interface OpenAIDelta {
  choices?: Array<{
    delta?: { content?: string };
    finish_reason?: string | null;
  }>;
}

/**
 * Parses one OpenAI-compat SSE frame. Returns:
 *   - "DONE" when the frame is `data: [DONE]` (the canonical OAI terminator)
 *   - a Token when the frame carries a content delta or a finish_reason
 *   - null when the frame is metadata (role announcement, ping, etc.)
 */
function parseOpenAISSEFrame(frame: string): Token | "DONE" | null {
  let data = "";
  for (const line of frame.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const field = line.slice(0, colon);
    const value = line.slice(colon + 1).replace(/^ /, "");
    if (field === "data") data += (data ? "\n" : "") + value;
  }
  if (!data) return null;
  if (data === "[DONE]") return "DONE";

  let payload: OpenAIDelta;
  try {
    payload = JSON.parse(data) as OpenAIDelta;
  } catch {
    return null;
  }

  const choice = payload.choices?.[0];
  if (!choice) return null;

  const text = choice.delta?.content ?? "";
  const finish = choice.finish_reason;

  if (finish) {
    // Some daemons emit content + finish in the same frame; if so, prefer to
    // surface the content first by yielding here without `done` and let the
    // [DONE] frame close the stream. But OAI canon emits finish in its own
    // frame after content frames, so we treat `finish` as terminator.
    return {
      text,
      done: true,
      finishReason:
        finish === "stop" || finish === "length" || finish === "tool_use"
          ? finish
          : "stop",
    };
  }

  if (text) {
    return { text, done: false };
  }
  return null;
}

async function safeText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "<unreadable body>";
  }
}
