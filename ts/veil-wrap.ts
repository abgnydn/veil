// SPDX-License-Identifier: Apache-2.0

// wrapWithVeil — the TS-side counterpart of Rust's `ProviderClient::Veil`.
//
// Wraps any VeilBackend so its chat path runs the pseudonymization round-trip
// through the Rust engine (via RustPipelineClient): real entities go in, the
// model sees `EMAIL_1`, and the model's reply is reverse-mapped back before
// the caller sees it — including across streamed token boundaries.
//
// This is what makes "the model sees EMAIL_1; the user sees alice@acme.com
// back" actually work on the TypeScript side. Before this, the TS path had no
// substitution engine at all.

import type {
  BackendCapabilities,
  ChatOpts,
  Msg,
  PIISpan,
  TierScores,
  Token,
  VeilBackend,
} from "./interface";
import type { RustPipelineClient } from "./rust-client";

// A token that, before the closing `\b`, could still be a forming pseudonym.
// We hold back any trailing run of word chars and only reverse-map text that
// is boundary-terminated, so a pseudonym split across two stream tokens
// (`…EMAIL` + `_1…`) is never mapped half-formed.
const TRAILING_WORD_RUN = /[A-Za-z0-9_]*$/;

// Cheap client-side gate: only call the server for a chunk that actually
// contains a pseudonym-shaped token. Avoids a loopback round trip per word.
// A false positive only costs an extra (correct) server call; a false negative
// is impossible because this is strictly broader than the engine's pattern.
const MAYBE_PSEUDONYM = /[A-Z][A-Z0-9]*_\d+/;

/**
 * Reverse-map a stream of tokens, buffering across token boundaries so a
 * pseudonym never gets mapped while still forming.
 *
 * Invariant: every chunk handed to `reverseMap` both starts and ends on a word
 * boundary, so it contains only whole pseudonyms — mapping chunks independently
 * is identical to mapping the full reply at once (the engine keys on
 * `\b<PREFIX>_\d+\b`, which cannot straddle a boundary).
 */
export async function* reverseMapStream(
  inner: AsyncIterable<Token>,
  client: RustPipelineClient,
  sessionId: string,
): AsyncIterable<Token> {
  let buffer = "";
  let emitted = 0;

  const mapChunk = async (chunk: string): Promise<string> =>
    MAYBE_PSEUDONYM.test(chunk) ? client.reverseMap(sessionId, chunk) : chunk;

  for await (const tok of inner) {
    if (tok.text) {
      buffer += tok.text;
      const pendingLen = TRAILING_WORD_RUN.exec(buffer)?.[0].length ?? 0;
      const safeEnd = buffer.length - pendingLen;
      if (safeEnd > emitted) {
        const mapped = await mapChunk(buffer.slice(emitted, safeEnd));
        emitted = safeEnd;
        if (mapped) yield { text: mapped, done: false };
      }
    }

    if (tok.done) {
      // Flush the held-back tail — now complete — carrying the finish reason.
      const tail = emitted < buffer.length ? buffer.slice(emitted) : "";
      const mapped = tail ? await mapChunk(tail) : "";
      emitted = buffer.length;
      yield { ...tok, text: mapped };
      return;
    }
  }
}

export interface WrapOpts {
  /** Conversation key. Same id → stable pseudonyms across turns (CONTRACT.md §6). */
  sessionId: string;
}

/**
 * Wrap `inner` so its chat path pseudonymizes outbound message content and
 * reverse-maps the inbound stream. Non-chat methods delegate unchanged.
 *
 * Message content is pseudonymized **sequentially** (not concurrently): the
 * engine assigns pseudonyms in first-seen order, so concurrent requests would
 * make `EMAIL_1`/`EMAIL_2` numbering nondeterministic. Sequential keeps it
 * stable and reproducible.
 */
export function wrapWithVeil(
  inner: VeilBackend,
  client: RustPipelineClient,
  opts: WrapOpts,
): VeilBackend {
  return new VeilWrappedBackend(inner, client, opts.sessionId);
}

class VeilWrappedBackend implements VeilBackend {
  readonly id: string;
  readonly displayName: string;
  readonly capabilities: BackendCapabilities;

  constructor(
    private readonly inner: VeilBackend,
    private readonly client: RustPipelineClient,
    private readonly sessionId: string,
  ) {
    this.id = `veil(${inner.id})`;
    this.displayName = `Veil → ${inner.displayName}`;
    // Capabilities are the inner backend's: the wrap changes *what crosses the
    // wire*, not what the backend can do. PII is now genuinely handled (via the
    // engine), so advertise it even if the inner backend's own detector is a
    // no-op.
    this.capabilities = { ...inner.capabilities, pii: true };
  }

  init(): Promise<void> {
    return this.inner.init();
  }

  isReady(): boolean {
    return this.inner.isReady();
  }

  classifyTier(text: string): Promise<TierScores> {
    return this.inner.classifyTier(text);
  }

  detectPII(text: string): Promise<PIISpan[]> {
    // Delegate to the inner backend's own detector. Engine-backed detection
    // flows through chat()'s pseudonymize pass, which mints into the session
    // table; a standalone detectPII must NOT mint, so it stays on the inner
    // (browser NER or no-op) path. See CONTRACT.md §7.
    return this.inner.detectPII(text);
  }

  embed(text: string): Promise<Float32Array> {
    return this.inner.embed(text);
  }

  async *chat(messages: Msg[], opts?: ChatOpts): AsyncIterable<Token> {
    const pseudonymized: Msg[] = [];
    for (const m of messages) {
      const { text } = await this.client.pseudonymize(this.sessionId, m.content);
      // Drop any tier tag: the content is now pseudonymized and safe to send.
      const { veilTier: _drop, ...rest } = m;
      pseudonymized.push({ ...rest, content: text });
    }
    yield* reverseMapStream(this.inner.chat(pseudonymized, opts), this.client, this.sessionId);
  }

  dispose(): Promise<void> {
    return this.inner.dispose?.() ?? Promise.resolve();
  }
}
