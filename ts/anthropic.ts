// SPDX-License-Identifier: Apache-2.0

// AnthropicAdapter — remote fallback for `public` and `internal` tiers only.
//
// HARD INVARIANTS (enforced in this constructor and on chat() entry, not at
// the call site):
//
//   1. `secret` content NEVER reaches this adapter. The chat() method scans
//      every Msg for tier-tagged `secret` content and throws
//      VeilInvariantViolation before any HTTP work happens. No flag, no
//      override, no per-message escape hatch.
//
//   2. `private` content NEVER reaches this adapter raw. The router-level
//      cohort blender owns this; the adapter additionally exposes a
//      `setSecretGuard(get)` injection point so an in-process classifier can
//      veto non-tagged Msgs before egress (e.g. when the router's tag
//      propagation has a bug).
//
// Capability matrix (per VEIL.md §2.d):
//
//   chat: true,  embed: false, classify: false, pii: false,
//   streaming: true, jsonMode: true, tools: true,
//   maxTiersAllowed: ['public', 'internal'],
//   runsLocally: false
//
// We don't depend on the @anthropic-ai/sdk — `fetch` + the SSE format keeps
// deps thin (the adapter is leaf-product code; the brain shouldn't pull a
// vendor SDK into the bundle for a dozen lines of streaming).

import type {
  BackendCapabilities,
  ChatOpts,
  Msg,
  PIISpan,
  Tier,
  TierScores,
  Token,
  VeilBackend,
} from "./interface";
import { BackendUnsupported, VeilInvariantViolation } from "./interface";

// ---- Settings store contract ----------------------------------------------

/**
 * Read-side of the user's settings. The adapter receives a getter, not a
 * static key, so the user can rotate keys at runtime without re-instantiating
 * the adapter. The Settings panel (Apollo+Hermes stream) populates this.
 */
export interface AnthropicSettings {
  /** Live API key. Returns null when unset; chat() refuses to dispatch. */
  getApiKey(): string | null;
  /** Default model. Override per-call via ChatOpts.model. */
  getDefaultModel(): string;
  /** Optional override of the API base URL — for tests / proxies. */
  getBaseUrl?(): string;
}

/**
 * Pluggable secret-tier guard. The router injects a function that maps a Msg
 * to its known tier (typically by reading `msg.veilTier` plus a local
 * classifier pass). The adapter calls this on every Msg before egress; a
 * `secret` return throws VeilInvariantViolation(1, ...).
 */
export type SecretGuard = (msg: Msg) => Tier | undefined;

export interface AnthropicAdapterOpts {
  settings: AnthropicSettings;
  /** Test seam: inject a fetch impl. Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Override anthropic-version header. */
  anthropicVersion?: string;
}

const ANTHROPIC_API_DEFAULT = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION_DEFAULT = "2023-06-01";

export class AnthropicAdapter implements VeilBackend {
  readonly id = "anthropic";
  readonly displayName = "Anthropic (api.anthropic.com)";
  readonly capabilities: BackendCapabilities = {
    chat: true,
    embed: false,
    classify: false,
    pii: false,
    streaming: true,
    jsonMode: true,
    tools: true,
    maxTiersAllowed: ["public", "internal"],
    runsLocally: false,
  };

  private readonly settings: AnthropicSettings;
  private readonly fetchImpl: typeof fetch;
  private readonly anthropicVersion: string;
  private secretGuard: SecretGuard | null = null;

  constructor(opts: AnthropicAdapterOpts) {
    this.settings = opts.settings;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.anthropicVersion = opts.anthropicVersion ?? ANTHROPIC_VERSION_DEFAULT;

    // Constructor-time invariant check: capability matrix must be locked. If a
    // caller monkey-patches `maxTiersAllowed` later we still re-check on each
    // chat() call; this assertion catches misconfiguration at boot.
    if (
      this.capabilities.maxTiersAllowed.includes("secret") ||
      this.capabilities.maxTiersAllowed.includes("private")
    ) {
      throw new VeilInvariantViolation(
        1,
        "AnthropicAdapter capability matrix must not include 'private' or 'secret'.",
      );
    }
  }

  async init(): Promise<void> {
    // No model load, no warm-up. Returning ready is just "key configured".
  }

  isReady(): boolean {
    return this.settings.getApiKey() !== null;
  }

  /**
   * Inject a router-side function that returns the tier of any given Msg.
   * The adapter calls this on every Msg in chat() and refuses dispatch if any
   * returns `secret`. This is the second line of defense after the router.
   */
  setSecretGuard(getSensitivity: SecretGuard): void {
    this.secretGuard = getSensitivity;
  }

  async classifyTier(_text: string): Promise<TierScores> {
    // Tier classification on a remote model is itself a leak — see VEIL.md
    // §2.d. Always classify locally; this method refuses unconditionally.
    throw new BackendUnsupported("classifyTier", this.id);
  }

  async detectPII(_text: string): Promise<PIISpan[]> {
    // PII detection on a remote model leaks the very thing being detected.
    throw new BackendUnsupported("detectPII", this.id);
  }

  async embed(_text: string): Promise<Float32Array> {
    // Anthropic ships no embeddings endpoint as of 2026-04. Voyage-via-
    // Anthropic, if it lands, becomes a separate adapter — we don't quietly
    // route through there.
    throw new BackendUnsupported("embed", this.id);
  }

  // ---- chat: the secret-block lives here --------------------------------

  async *chat(messages: Msg[], opts: ChatOpts = {}): AsyncIterable<Token> {
    // ---- HARD INVARIANT 1: secret content never leaves the device --------
    for (const m of messages) {
      const tier = m.veilTier ?? this.secretGuard?.(m);
      if (tier === "secret") {
        throw new VeilInvariantViolation(
          1,
          `AnthropicAdapter.chat refused: Msg tagged 'secret' (role=${m.role}). Hard rule.`,
        );
      }
      if (tier === "private") {
        // Private content must arrive cohort-blended (router responsibility).
        // If a Msg is tagged `private` raw at this point, the router skipped
        // its blend step. Refuse rather than leak.
        throw new VeilInvariantViolation(
          2,
          `AnthropicAdapter.chat refused: Msg tagged 'private' reached the remote adapter raw. Cohort blend missing.`,
        );
      }
    }

    const apiKey = this.settings.getApiKey();
    if (!apiKey) {
      throw new Error("AnthropicAdapter: no API key configured.");
    }

    const baseUrl =
      this.settings.getBaseUrl?.() ?? ANTHROPIC_API_DEFAULT;
    const model = opts.model ?? this.settings.getDefaultModel();

    // Anthropic's Messages API splits system out from the rest, and forbids
    // the `tool` role on the input side. We map roles conservatively: any
    // `tool` message becomes a synthetic `user` content block flagged as a
    // tool result. Full tool-use mapping is a future stream — for v1 we
    // expose the streaming text path only.
    const systemMsgs = messages.filter((m) => m.role === "system");
    const convo = messages.filter((m) => m.role !== "system");

    const body: Record<string, unknown> = {
      model,
      max_tokens: opts.maxTokens ?? 4096,
      stream: true,
      messages: convo.map((m) => ({
        role: m.role === "assistant" ? "assistant" : "user",
        content: m.content,
      })),
    };
    if (systemMsgs.length > 0) {
      body.system = systemMsgs.map((m) => m.content).join("\n\n");
    }
    if (opts.temperature !== undefined) {
      body.temperature = opts.temperature;
    }
    if (opts.stop && opts.stop.length > 0) {
      body.stop_sequences = opts.stop;
    }

    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": this.anthropicVersion,
      accept: "text/event-stream",
    };

    const response = await this.fetchImpl(baseUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      ...(opts.signal ? { signal: opts.signal } : {}),
    });

    if (!response.ok || !response.body) {
      const text = await safeText(response);
      throw new Error(
        `AnthropicAdapter: HTTP ${response.status} ${response.statusText}: ${text}`,
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
        // and keep the trailing partial frame in `buf`.
        let sep = buf.indexOf("\n\n");
        while (sep !== -1) {
          const frame = buf.slice(0, sep);
          buf = buf.slice(sep + 2);
          const evt = parseSSEFrame(frame);
          if (evt) {
            const tok = mapAnthropicEvent(evt);
            if (tok) {
              yield tok;
              if (tok.done) {
                finished = true;
                break;
              }
            }
          }
          sep = buf.indexOf("\n\n");
        }
      }
    } finally {
      try {
        await reader.cancel();
      } catch {
        // ignore cancellation errors
      }
    }

    if (!finished) {
      yield { text: "", done: true, finishReason: "stop" };
    }
  }

  async dispose(): Promise<void> {
    this.secretGuard = null;
  }
}

// ---- SSE parsing helpers --------------------------------------------------

interface SSEEvent {
  event?: string;
  data: string;
}

function parseSSEFrame(frame: string): SSEEvent | null {
  let event: string | undefined;
  let data = "";
  for (const line of frame.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const field = line.slice(0, colon);
    const value = line.slice(colon + 1).replace(/^ /, "");
    if (field === "event") event = value;
    else if (field === "data") data += (data ? "\n" : "") + value;
  }
  if (!data) return null;
  return event !== undefined ? { event, data } : { data };
}

interface AnthropicStreamPayload {
  type?: string;
  delta?: {
    type?: string;
    text?: string;
    stop_reason?: string;
  };
}

function mapAnthropicEvent(evt: SSEEvent): Token | null {
  let payload: AnthropicStreamPayload;
  try {
    payload = JSON.parse(evt.data) as AnthropicStreamPayload;
  } catch {
    return null;
  }

  const type = payload.type ?? evt.event;
  if (type === "content_block_delta" && payload.delta?.type === "text_delta") {
    const text = payload.delta.text ?? "";
    if (!text) return null;
    return { text, done: false };
  }
  if (type === "message_delta" && payload.delta?.stop_reason) {
    const reason = payload.delta.stop_reason;
    return {
      text: "",
      done: true,
      finishReason:
        reason === "end_turn" || reason === "stop_sequence"
          ? "stop"
          : reason === "max_tokens"
            ? "length"
            : reason === "tool_use"
              ? "tool_use"
              : "stop",
    };
  }
  if (type === "message_stop") {
    return { text: "", done: true, finishReason: "stop" };
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
