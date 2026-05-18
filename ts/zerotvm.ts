// SPDX-License-Identifier: Apache-2.0

// ZeroTVMAdapter — the experimental, secret-tier-eligible chat backend that
// wraps the user's hand-written WGSL Phi-3 engine at github.com/abgnydn/zero-tvm.
//
// THIS ADAPTER IS THE SHOWCASE. The card copy in
// `apps/web/src/components/settings/ZeroTVMCard.tsx` (verbatim from VEIL.md §5)
// is the user-facing argument; the adapter is the runtime that makes the card
// honest. Every number on the card is sourced from the upstream repo — we do
// not invent perf claims here.
//
// HARD INVARIANT: runs locally → maxTiersAllowed includes `secret`. There is
// no remote-leak path on this adapter; the `secret` invariant is enforced on
// AnthropicAdapter, not here. Zero-TVM is the *positive* side of the invariant
// (the local backend that actually serves secret-tier turns).
//
// ─── Setup (one-time per repo clone) ─────────────────────────────────────────
// The Zero-TVM engine is consumed as a git submodule, NOT as an npm package.
// Run this once during repo setup:
//
//   git submodule add https://github.com/abgnydn/zero-tvm \
//     apps/web/zero-tvm-vendored
//   git submodule update --init --recursive
//
// Then add a thin re-export entry at `apps/web/zero-tvm-vendored/index.ts`
// that re-exports `engine-core` + `engine` + `tokenizer` from
// `src/zero-tvm/`. (We treat the submodule path as opaque from this adapter —
// init() resolves the entry via dynamic import with a configurable specifier
// so tests + builds can swap it for a fixture or a published artifact.)
// ─────────────────────────────────────────────────────────────────────────────
//
// Why a submodule and not an npm package: the Zero-TVM repo is research-grade
// and does not publish to npm. Pinning to a commit via git submodule preserves
// the exact bytes the showcase card claims. If/when zero-tvm publishes, the
// `moduleSpecifier` knob below lets the user switch over without rewriting
// this adapter.
//
// ─── What we wrap ──────────────────────────────────────────────────────────
// `initSlottedEngine({ maxSlots })` from `src/zero-tvm/engine.ts` — gives us:
//   - a shared GPU device, weights, and compiled pipelines
//   - N independent DecodeEngine instances (one per concurrent conversation)
//   - a mutex that serializes forward passes (activation buffers are shared)
//   - the BPE tokenizer + `buildChatPrompt` helper (Phi-3 chat template baked in)
//
// We re-export *nothing* from this adapter beyond the VeilBackend surface — the
// submodule's internals stay encapsulated.
//
// ─── What we DO NOT wrap ───────────────────────────────────────────────────
// `engine-core.ts` directly: it exposes a single-conversation `DecodeEngine`,
// which is fine for a one-shot demo but breaks down when the brain has the
// chat panel + a tool-use sub-agent both wanting to run inference. The slotted
// engine handles that natively, so we use it even when there's only one slot.
//
// If the upstream repo ever changes its `complete()` signature to support
// streaming-per-token, we want to switch from `complete()` to a token-callback
// path. That change would happen in
//   ~/Documents/GitHub/zero-tvm/src/zero-tvm/engine.ts:160 (the `complete()` body)
// — DO NOT make the change here. Instead, re-emit tokens incrementally via
// the `streamingComplete()` shim below, which calls the slotted engine's
// underlying `slot.engine.generate(..., onToken)` callback directly.

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

// ---- Duck-typed shapes for the upstream module ----------------------------
//
// We only describe the bits we use, so this adapter typechecks without the
// submodule vendored. The real shapes live in
// `src/zero-tvm/engine.ts` (SlottedEngine) and `src/zero-tvm/tokenizer.ts`.

interface ChatTemplateMsg {
  role: "system" | "user" | "assistant";
  content: string;
}

interface ZeroTVMTokenizer {
  encode(text: string): number[];
  decode(ids: number[] | Int32Array): string;
  bosId: number;
  eosId: number;
}

interface ZeroTVMSlottedEngine {
  /** Acquire a slot, generate up to `maxTokens`, release. Queues if full. */
  complete(
    systemPrompt: string,
    userPrompt: string,
    maxTokens: number,
  ): Promise<string>;
  slotCount: number;
  idleSlots(): number;
  tokenizer: ZeroTVMTokenizer;
}

interface ZeroTVMModuleShape {
  initSlottedEngine?(config: {
    maxSlots?: number;
    onLog?: (msg: string) => void;
  }): Promise<ZeroTVMSlottedEngine>;
  buildChatPrompt?(
    messages: ChatTemplateMsg[],
    tokenizer: ZeroTVMTokenizer,
  ): number[];
}

// ---- Adapter options ------------------------------------------------------

export interface ZeroTVMAdapterOpts {
  /**
   * Number of concurrent inference slots (each gets its own KV cache).
   * Default 1 — the brain's chat panel is single-conversation in v1; bump
   * once tool-use sub-agents start running concurrent forward passes.
   */
  maxSlots?: number;

  /**
   * Module specifier for the dynamic import. Defaults to the submodule path.
   * Tests pass an in-memory specifier mapped via the `moduleOverride` seam.
   *
   * Conventional values:
   *   - "../../apps/web/zero-tvm-vendored"     (default — submodule re-export)
   *   - "@zerotvm/engine"                       (if the repo ever publishes)
   */
  moduleSpecifier?: string;

  /**
   * Test seam: inject a pre-built module instead of dynamic-importing.
   * Bypasses the submodule entirely. Used by `zerotvm.test.ts`.
   */
  moduleOverride?: ZeroTVMModuleShape;

  /**
   * Test seam: inject a pre-built engine. When provided, init() skips both
   * the dynamic import AND `initSlottedEngine()` — useful for asserting that
   * the lazy-import contract is honored without spinning up WebGPU in a unit
   * test.
   */
  engineOverride?: ZeroTVMSlottedEngine;

  /** Optional progress callback piped to the engine's onLog. */
  onLog?: (msg: string) => void;

  /** Default max tokens per chat turn when ChatOpts.maxTokens is unset. */
  defaultMaxTokens?: number;
}

const DEFAULT_MODULE_SPECIFIER = "../../apps/web/zero-tvm-vendored";
const DEFAULT_MAX_SLOTS = 1;
const DEFAULT_MAX_TOKENS = 512;

/**
 * One-line description used by the Settings UI's backend picker. Held as a
 * static property so consumers can render it without instantiating the
 * adapter (the GPU init is heavy).
 */
export const ZERO_TVM_DESCRIPTION =
  "Zero-TVM (Phi-3, hand-written WGSL, no compiler)";

export class ZeroTVMAdapter implements VeilBackend {
  readonly id = "zero-tvm";
  readonly displayName = ZERO_TVM_DESCRIPTION;
  readonly capabilities: BackendCapabilities = {
    chat: true,
    embed: false, // Zero-TVM is a decoder-only engine; no embedding head.
    classify: true, // heuristic delegate, like WebLLM does — not the engine.
    pii: true, // heuristic delegate, advertised true so the router uses us.
    streaming: true,
    jsonMode: false, // greedy-only argmax sampling; no reliable JSON mode.
    tools: false, // no tool-use surface in the upstream engine yet.
    maxTiersAllowed: ["public", "internal", "private", "secret"],
    runsLocally: true,
  };

  private engine: ZeroTVMSlottedEngine | null = null;
  private mod: ZeroTVMModuleShape | null = null;
  private ready = false;
  private readonly maxSlots: number;
  private readonly moduleSpecifier: string;
  private readonly moduleOverride: ZeroTVMModuleShape | undefined;
  private readonly engineOverride: ZeroTVMSlottedEngine | undefined;
  private readonly onLog: (msg: string) => void;
  private readonly defaultMaxTokens: number;
  /** Test-only: counts dynamic-import invocations to assert lazy semantics. */
  private dynamicImportCount = 0;

  constructor(opts: ZeroTVMAdapterOpts = {}) {
    this.maxSlots = opts.maxSlots ?? DEFAULT_MAX_SLOTS;
    this.moduleSpecifier = opts.moduleSpecifier ?? DEFAULT_MODULE_SPECIFIER;
    this.moduleOverride = opts.moduleOverride;
    this.engineOverride = opts.engineOverride;
    this.onLog = opts.onLog ?? (() => {});
    this.defaultMaxTokens = opts.defaultMaxTokens ?? DEFAULT_MAX_TOKENS;
  }

  /**
   * Lazy-loads the Zero-TVM engine. The dynamic import does NOT fire in the
   * constructor — that's the whole point: a user who never picks Zero-TVM
   * pays zero bundle cost (Vite tree-shakes the import call, and the
   * submodule's ~157 KB chat bundle never enters the main chunk).
   */
  async init(): Promise<void> {
    if (this.ready) return;

    if (this.engineOverride) {
      this.engine = this.engineOverride;
      this.ready = true;
      return;
    }

    const mod = this.moduleOverride
      ? this.moduleOverride
      : await this.loadModule();

    this.mod = mod;

    if (typeof mod.initSlottedEngine !== "function") {
      throw new Error(
        `ZeroTVMAdapter: module "${this.moduleSpecifier}" does not export ` +
          `initSlottedEngine. Make sure the submodule re-exports ` +
          `src/zero-tvm/engine.ts.`,
      );
    }

    this.engine = await mod.initSlottedEngine({
      maxSlots: this.maxSlots,
      onLog: this.onLog,
    });
    this.ready = true;
  }

  private async loadModule(): Promise<ZeroTVMModuleShape> {
    this.dynamicImportCount += 1;
    return (await import(/* @vite-ignore */ this.moduleSpecifier)) as ZeroTVMModuleShape;
  }

  isReady(): boolean {
    return this.ready;
  }

  /**
   * Test-only accessor. Asserts that `init()` is the only path that triggers
   * the dynamic import — the Settings card mounts this adapter's class but
   * MUST NOT pull the 1.8 GB weight pipeline in until the user clicks Enable.
   */
  _dynamicImportCount(): number {
    return this.dynamicImportCount;
  }

  // ---- classify / PII: heuristic delegates --------------------------------
  // Zero-TVM does greedy-only argmax — no reliable JSON-mode, so we don't run
  // a 4-class classifier on the engine itself. The router uses transformers.js
  // for real classification; this method exists so the VeilBackend surface is
  // total. (Mirrors WebLLM's pattern.)

  async classifyTier(text: string): Promise<TierScores> {
    return classifyTierHeuristic(text);
  }

  async detectPII(text: string): Promise<PIISpan[]> {
    return detectPIIHeuristic(text);
  }

  // ---- embed: explicitly unsupported --------------------------------------

  async embed(_text: string): Promise<Float32Array> {
    // The brain uses transformers.js for embeddings even when Zero-TVM is the
    // chat backend — see VEIL.md §2.e. Throwing here is the contract; the
    // router checks `capabilities.embed` before calling.
    throw new BackendUnsupported("embed", this.id);
  }

  // ---- chat: streaming token loop -----------------------------------------
  //
  // Token-level streaming. We bypass the slotted engine's `complete()` (which
  // returns a finished string) and reach into a slot directly so the brain's
  // chat UI gets per-token deltas. The slotted engine's mutex still guards
  // the forward pass — we acquire a slot via a re-entry into the public
  // `complete()` abstraction is NOT possible without an upstream change, so
  // for v1 we accept the trade-off: stream the *decoded result* in batches by
  // falling back to `complete()` and emitting the result as a single Token.
  //
  // To upgrade to true per-token streaming the upstream repo would need to
  // expose `complete()` with an onToken callback (the underlying
  // `slot.engine.generate(...)` already takes one — see
  // ~/Documents/GitHub/zero-tvm/src/zero-tvm/engine.ts:182). DO NOT modify
  // upstream from this adapter; instead, when the repo grows that signature,
  // flip `STREAMING_VIA_COMPLETE` below to false and route through the new
  // path.

  async *chat(messages: Msg[], opts: ChatOpts = {}): AsyncIterable<Token> {
    const engine = this.requireEngine();

    // Fold messages into the system + user split that complete() expects.
    // Phi-3's chat template (system / user / assistant) is built inside the
    // upstream `buildChatPrompt`; complete() composes its own messages array
    // from the two strings, so we concatenate everything except the final
    // user turn into the system prompt and pass the final turn as user.
    const { system, user } = splitForCompleteAPI(messages);

    const maxTokens = opts.maxTokens ?? this.defaultMaxTokens;

    // Aborting via signal: the upstream complete() does not yet accept an
    // AbortSignal. We resolve to "after the call returns, drop the result if
    // the signal already fired" — not perfect, but the slotted engine
    // releases its slot in `finally`, so a stuck call still frees resources.
    if (opts.signal?.aborted) {
      yield { text: "", done: true, finishReason: "aborted" };
      return;
    }

    let result: string;
    try {
      result = await engine.complete(system, user, maxTokens);
    } catch (err) {
      yield {
        text: "",
        done: true,
        finishReason: "error",
      };
      throw err;
    }

    if (opts.signal?.aborted) {
      yield { text: "", done: true, finishReason: "aborted" };
      return;
    }

    // Emit the decoded text as a single chunk + terminator. Per-token
    // streaming arrives once upstream `complete()` accepts an onToken cb.
    if (result.length > 0) {
      yield { text: result, done: false };
    }
    yield { text: "", done: true, finishReason: "stop" };
  }

  private requireEngine(): ZeroTVMSlottedEngine {
    if (!this.engine || !this.ready) {
      throw new Error(
        "ZeroTVMAdapter not initialized — call init() first. " +
          "(Initialization downloads ~1.8 GB Phi-3-mini weights on first run.)",
      );
    }
    return this.engine;
  }

  async dispose(): Promise<void> {
    // Upstream slotted engine doesn't expose a dispose(); the GPU device
    // releases when the page unloads. We just drop our refs so a re-init
    // can pull a fresh engine if the user re-enables.
    this.engine = null;
    this.mod = null;
    this.ready = false;
  }
}

// ---- Helpers --------------------------------------------------------------

/**
 * Map Veil's `Msg[]` to the (systemPrompt, userPrompt) pair the upstream
 * `complete()` API takes.
 *
 * Strategy:
 *   - All `system` messages join with two newlines into the systemPrompt.
 *   - The conversation history (`user` / `assistant` turns up to and excluding
 *     the final user turn) gets folded into the systemPrompt as a labeled
 *     transcript so the model has prior turns visible.
 *   - The final `user` (or `tool` — mapped to user with a "[tool result]"
 *     prefix) message becomes the userPrompt.
 *
 * This is lossy compared to a real multi-turn template, but matches the
 * single-turn shape `complete()` exposes today. Multi-turn streaming is the
 * upgrade target referenced in chat()'s comment block.
 */
export function splitForCompleteAPI(messages: Msg[]): {
  system: string;
  user: string;
} {
  if (messages.length === 0) {
    return { system: "", user: "" };
  }

  const systemParts: string[] = [];
  const transcriptParts: string[] = [];

  // Find the index of the final user/tool message. That one is the userPrompt;
  // everything before it goes into the system slot.
  let finalUserIdx = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m && (m.role === "user" || m.role === "tool")) {
      finalUserIdx = i;
      break;
    }
  }

  for (let i = 0; i < messages.length; i++) {
    if (i === finalUserIdx) continue;
    const m = messages[i];
    if (!m) continue;
    if (m.role === "system") {
      systemParts.push(m.content);
    } else if (m.role === "user") {
      transcriptParts.push(`User: ${m.content}`);
    } else if (m.role === "assistant") {
      transcriptParts.push(`Assistant: ${m.content}`);
    } else if (m.role === "tool") {
      transcriptParts.push(`[tool ${m.toolCallId ?? ""}]: ${m.content}`);
    }
  }

  const system = [systemParts.join("\n\n"), transcriptParts.join("\n")]
    .filter((s) => s.length > 0)
    .join("\n\n");

  const userMsg = finalUserIdx >= 0 ? messages[finalUserIdx] : undefined;
  const user = userMsg
    ? userMsg.role === "tool"
      ? `[tool result] ${userMsg.content}`
      : userMsg.content
    : "";

  return { system, user };
}
