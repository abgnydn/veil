---
title: Veil — privacy layer + pluggable backend interface for the host application
type: spec
tags: [veil, privacy, backends, zero-tvm, showcase, talos]
status: draft
permalink: veil-spec
created: 2026-04-26
forged_by: Talos
canonized_for: the host application
upstream_research: research/veil-backends.md
sibling_streams: [Hephaestus-Backend (MCP), Hephaestus-DevOps (SolidJS UI), Scholar (paper)]
---

# Veil

> **What this is.** The privacy layer that sits between the host application's UI/agent and any LLM. One TypeScript interface, five interchangeable adapters, deterministic routing keyed off `sensitivity:` frontmatter and runtime tier classification, plus a k-anonymous cohort blender for `private` content.
>
> **What this is not.** Not the MCP server (Hephaestus-Backend's stream). Not the SolidJS frontend (Hephaestus-DevOps's stream). Not the paper (Scholar's stream). Veil is consumed *by* the MCP server and the UI. This document is the contract they code against.

---

## 0. Glossary (one paragraph each)

- **Tier.** The four-level sensitivity ladder already used in `~/brain/.brain/CLAUDE.md`: `public | internal | private | secret`. The vault stores tier as YAML frontmatter; new content (typed prompts, model output, tool results) gets a tier from `classifyTier()` at runtime.
- **Adapter / backend.** A class implementing `VeilBackend`. Adapters are interchangeable; the brain treats them as plug-ins addressed by name (`ollama`, `lmstudio`, `webllm`, `transformers-js`, `anthropic`, `zero-tvm`, …).
- **Cohort blend.** The k-anonymous fan-out from Phase 8 (E29) — a `private` prompt is sent alongside `k-1` kind-shape-identical sibling prompts so the wire-side adversary sees `1/k` probability of identifying the real one. See §4.
- **Hard invariant.** A rule the routing layer must enforce in code, not via configuration. Two of them in this spec; both about `secret`.

---

## 1. The pluggable interface

One TypeScript file. Every adapter implements it. Everything else in the brain — MCP server, SolidJS UI, agent loop — programs against this and only this.

```ts
// veil/src/backend.ts

export type Tier = 'public' | 'internal' | 'private' | 'secret';

export interface TierScores {
  public: number;
  internal: number;
  private: number;
  secret: number;
  // invariant: public + internal + private + secret === 1.0 (within fp tolerance)
  // probabilistic on purpose: the brain decides escalation, not the classifier.
}

export type PIIKind =
  | 'EMAIL' | 'PHONE' | 'PERSON' | 'LOCATION' | 'ORG' | 'URL'
  | 'IP_ADDRESS' | 'CREDIT_CARD' | 'IBAN' | 'CRYPTO_ADDRESS'
  | 'PATH' | 'API_KEY' | 'SSN' | 'NATIONAL_ID' | 'DOB' | 'CUSTOM';

export interface PIISpan {
  start: number;          // utf-16 char offset, inclusive
  end: number;            // utf-16 char offset, exclusive
  kind: PIIKind;
  score: number;          // 0..1 detector confidence
  replacement: string;    // pseudonym, e.g. "EMAIL_1" — Presidio-shaped
  source: 'regex' | 'ner' | 'llm' | 'context';
}

export interface Msg {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  toolCallId?: string;
  toolCalls?: ToolCall[];
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: unknown; // JSON
}

export interface ChatOpts {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  stop?: string[];
  jsonMode?: boolean;
  tools?: ToolSchema[];
  signal?: AbortSignal;
  // Veil-specific:
  veilTag?: string;       // for telemetry/audit trail
  forceLocal?: boolean;   // ignore fallback chain, fail rather than escalate
}

export interface Token {
  text: string;
  done: boolean;
  toolCalls?: ToolCall[];
  finishReason?: 'stop' | 'length' | 'tool_use' | 'aborted' | 'error';
}

export interface BackendCapabilities {
  chat: boolean;
  embed: boolean;
  classify: boolean;
  pii: boolean;
  streaming: boolean;
  jsonMode: boolean;
  tools: boolean;
  maxTiersAllowed: Tier[];   // e.g. anthropic: ['public', 'internal']
  runsLocally: boolean;       // never leaves the device
  embeddingDim?: number;
}

export interface VeilBackend {
  readonly id: string;
  readonly displayName: string;
  readonly capabilities: BackendCapabilities;

  init(): Promise<void>;
  isReady(): boolean;

  classifyTier(text: string): Promise<TierScores>;
  detectPII(text: string): Promise<PIISpan[]>;
  chat(messages: Msg[], opts?: ChatOpts): AsyncIterable<Token>;
  embed(text: string): Promise<Float32Array>;

  dispose?(): Promise<void>;
}
```

Methods that an adapter cannot fulfil throw `BackendUnsupported(method)`; the router checks `capabilities` before calling. `classifyTier` is **always** probabilistic — see §3 for why.

---

## 2. The five adapters

Each adapter is a single class implementing `VeilBackend`. Everything below is contract-level: the implementer follows this; the brain calls it through the interface; nothing else changes.

### 2.a OpenAI-compat HTTP — `OpenAICompatBackend`

The lingua-franca adapter. ~80% of the surface (per `research/veil-backends.md`).

| Field | Value |
|---|---|
| **Where it runs** | Anywhere reachable over HTTP; defaults to `localhost`. |
| **Targets** | Ollama (`:11434`), LM Studio (`:1234`), llamafile-server, llama.cpp `server`, vLLM, any future OAI-compat daemon. |
| **Dependencies** | None beyond `fetch`. No SDK. |
| **Init cost** | A health-ping (`GET /v1/models`); no model load. |
| **Per-call cost** | One HTTP round trip per `chat()` (streamed via SSE), one per `embed()`. `classifyTier` and `detectPII` are layered on top of `chat()` with a tiny system prompt. |

**Configuration:**
```ts
new OpenAICompatBackend({
  id: 'ollama-local',
  baseUrl: 'http://localhost:11434/v1',
  apiKey: 'ollama',                 // Ollama ignores; LM Studio also; vLLM may require
  chatModel: 'phi3.5:3.8b',
  embedModel: 'nomic-embed-text',
  classifyModel: 'gemma3:1b',       // tiny model for tier classification
  timeoutMs: 30_000
})
```

**Method mapping:**
- `chat()` → `POST /v1/chat/completions` with `stream: true`. SSE → `Token` stream. Tool calls passed through verbatim where the daemon supports them (Ollama yes, vLLM yes, llama.cpp partial — declare via `capabilities.tools`).
- `embed()` → `POST /v1/embeddings`. Returns `Float32Array` (length = `embeddingDim`).
- `classifyTier()` → internal helper: prompts `classifyModel` with a 4-class JSON-mode schema (`{public, internal, private, secret}` softmaxed). One round trip; ~80–200 ms on local Ollama with a 1B model.
- `detectPII()` → routes to a sidecar Presidio process if configured (`presidioUrl`), otherwise falls back to the regex-only kernel in `veil/src/pii-regex.ts` plus an optional LLM ambiguity pass for un-classified spans.

**Capability matrix:**
```
chat: true,  embed: true,  classify: true,  pii: 'regex+optional-llm',
streaming: true,  jsonMode: true,  tools: 'depends-on-daemon',
maxTiersAllowed: ['public', 'internal', 'private', 'secret'],   // local => OK for everything
runsLocally: true
```

**Caveats** (per upstream research):
- Ollama OpenAI-compat does not expose `logprobs` or `tool_choice`, base64-only images. Don't promise either in `capabilities`.
- LM Studio uses no API key; the field is accepted-but-ignored.
- llama.cpp's `server` is OAI-compat in spirit but tool-calling is partial — declare per-deployment.

### 2.b WebLLM — `WebLLMBackend`

In-tab WebGPU LLM. Default for zero-install users.

| Field | Value |
|---|---|
| **Where it runs** | The user's browser tab, on a Service Worker so the SolidJS UI never stalls. |
| **Dependencies** | `@mlc-ai/web-llm` v0.2.83+ (2026-04-24). WebGPU + (optionally) `shader-f16`. |
| **Init cost** | First load: ~1–2 GB weight download per model, cached in OPFS + Cache API. Subsequent loads: instant. |
| **Per-call cost** | Pure GPU compute, no network. Verified perf: Phi-3.5-mini ~71 tok/s, Llama-3.1-8B ~41 tok/s, Llama-3.2-3B ~60 tok/s on M3 Max (per `research/veil-backends.md`). |

**Threading model.** `WebLLMBackend` runs in a dedicated Service Worker (`veil/workers/webllm-sw.ts`). The main thread holds a `MessagePort`-backed proxy that satisfies the `VeilBackend` interface. Token streams cross the port as `postMessage` events; back-pressure via a per-call promise queue.

**Method mapping:**
- `chat()` → `engine.chatCompletion({...})` with `stream: true`. Already OpenAI-compatible; trivial mapping to `Token`.
- `embed()` → `engine.embeddings.create()` (v0.2.83+ supports embedding models when the model record declares them; if not, fall back to `transformers-js` adapter for embeddings).
- `classifyTier()` → same JSON-mode trick as OpenAI-compat; uses whichever model is loaded (Phi-3.5-mini is the recommended default).
- `detectPII()` → defers to `transformers-js` adapter if available, else regex-only.

**Capability matrix:**
```
chat: true,  embed: 'model-dependent',  classify: true,  pii: 'regex+ner-via-tjs',
streaming: true,  jsonMode: true,  tools: 'preliminary',
maxTiersAllowed: ['public', 'internal', 'private', 'secret'],
runsLocally: true
```

### 2.c transformers.js — `TransformersJSBackend`

For embeddings, NER, and the tiny tier classifier. Faster cold start than WebLLM for non-chat tasks.

| Field | Value |
|---|---|
| **Where it runs** | Browser, ONNX Runtime Web on WebGPU (default GPU EP since 2026; FP16 in Chrome 121+). |
| **Dependencies** | `@huggingface/transformers` v4 preview (2026-02-09 release). |
| **Init cost** | First model: <100 MB typical (multilingual-e5-small is 384-dim, ~117 MB int8). Subsequent: cached. |
| **Per-call cost** | Embed: <100 ms for short docs. NER: 50–200 ms per chunk. Classifier: <50 ms with a distilled head. |

**Method mapping:**
- `embed()` → `pipeline('feature-extraction', model)` with `device: 'webgpu'`. Default model: **multilingual-e5-small** (384-dim, int8). Optional heavy: **BGE-M3** (8192 ctx, 100+ langs). Optional 2026-fresh: **Nomic Embed Text v2** (MoE).
- `detectPII()` → `pipeline('token-classification', nerModel)` plus the regex kernel. Default NER: `gliner_multi_pii-v1` (browser-portable, zero-shot — *NB: perf at April 2026 unverified, see §7*).
- `classifyTier()` → `pipeline('text-classification', classifyModel)` over a 4-class head distilled from a labeled tier-corpus (the user has not built this yet; see §7). Until that exists, this method delegates to whichever chat-capable backend is loaded.
- `chat()` → throws `BackendUnsupported`. This adapter is *not* a chat backend.

**Capability matrix:**
```
chat: false,  embed: true,  classify: true,  pii: true,
streaming: false,  jsonMode: false,  tools: false,
maxTiersAllowed: ['public', 'internal', 'private', 'secret'],
runsLocally: true,  embeddingDim: 384  // for e5-small
```

### 2.d Anthropic — `AnthropicBackend`

The remote fallback. Loud, capable, **never sees `secret`, never sees raw `private`**.

| Field | Value |
|---|---|
| **Where it runs** | `api.anthropic.com`, ZDR-eligible. |
| **Dependencies** | `@anthropic-ai/sdk`. |
| **Init cost** | None. |
| **Per-call cost** | Network round trip + Anthropic rate. |

**Hard rule:** `capabilities.maxTiersAllowed = ['public', 'internal']`. The router checks this before dispatch and refuses (`VeilRoutingError`) if a higher tier reaches the adapter. This is enforced in code, not in config.

**Method mapping:**
- `chat()` → `messages.stream()`, mapped to `Token`. Tool use passes through.
- `embed()` → throws `BackendUnsupported`. Anthropic doesn't ship an embeddings endpoint as of 2026-04; if Voyage-via-Anthropic ships, add later.
- `classifyTier()` → could call Claude Haiku, but **don't**. Tier classification on remote is a leak. Always classify locally; this method throws or returns a degenerate `{public: 1, ...}` response if forced.
- `detectPII()` → throws `BackendUnsupported`; PII detection on remote leaks the very thing it's detecting.

**Capability matrix:**
```
chat: true,  embed: false,  classify: false,  pii: false,
streaming: true,  jsonMode: true,  tools: true,
maxTiersAllowed: ['public', 'internal'],
runsLocally: false
```

### 2.e Zero-TVM — `ZeroTVMBackend` (the showcase)

The user's flagship research, switched in as the secret-tier chat backend so the visitor sees their own kernels running.

| Field | Value |
|---|---|
| **Where it runs** | The user's browser tab. WebGPU + `shader-f16` required (Chrome/Edge 120+; Safari pre-TP not yet). |
| **Source repo** | `~/Documents/GitHub/zero-tvm` · [github.com/abgnydn/zero-tvm](https://github.com/abgnydn/zero-tvm) · live at [zerotvm.com](https://zerotvm.com). |
| **Dependencies** | None added to the host — Zero-TVM bundles its own ~3k-line TS engine + the WGSL kernels. The brain imports the entry module from a path or pins the published artifact. |
| **Init cost** | First load: ~1.8 GB Phi-3-mini-q4f16_1 weights from HuggingFace (cached in OPFS, parallel-shard fetch with streaming GPU upload). ~3.6 GB GPU memory budget once warm. Subsequent loads: instant from OPFS. |
| **Per-call cost** | Decode throughput **42.14 tok/s** on M2 Pro (BENCH.md, median of `bench(128, 3)`); **22% slower than WebLLM 0.2.80 (51.5 tok/s)** on identical hardware and identical weight bytes. Per-token GPU compute: 20.19 ms. The gap is honest and we ship it as a feature, not a footnote. |

**What gets wrapped.**

The Zero-TVM repo exposes `engine-core.ts` (the reference path, ~451 lines, used by `validate.html`) and `chat.ts` (~1,086 lines, the experimental progressive-streaming path used by `zero-tvm.html`). For Veil we consume `engine-core.ts` because it's the cleaner DOM-free entry. Veil ships `veil/adapters/zero-tvm-adapter.ts` (~150 lines, *to be written*) that:

1. Imports `buildDecodeEngine` from Zero-TVM.
2. Wraps `forwardLogits` + the greedy decode loop in an `AsyncIterable<Token>`.
3. Reuses Zero-TVM's `tokenizer.ts` (BPE, ~283 lines) via re-export — no second tokenizer in the brain.
4. Routes weight loading through Zero-TVM's own tiered cache (OPFS → Cache API → HuggingFace), which already piggybacks on WebLLM's `tvmjs` storage so a user who has run WebLLM in this origin pays zero re-download cost.

**Method mapping:**
- `chat()` → wraps Zero-TVM's decode loop. Phi-3-mini-4k-instruct only; the chat template (`<|system|>...<|end|>\n<|user|>...<|end|>\n<|assistant|>\n`, stop tokens `{2, 32000, 32007}`) is baked into Zero-TVM's `tokenizer.ts:buildChatPrompt` — pass `Msg[]` through unchanged.
- `embed()` → throws `BackendUnsupported`. Zero-TVM is decoder-only; the brain uses `transformers-js` for embeddings even when Zero-TVM is the chat backend.
- `classifyTier()` → throws `BackendUnsupported` (or delegates). Zero-TVM does greedy-only argmax sampling; the JSON-mode trick used by other adapters won't reliably emit valid JSON. Tier classification stays on the small classifier.
- `detectPII()` → throws `BackendUnsupported`; PII detection stays on Presidio/regex/transformers-js.

**Capability matrix:**
```
chat: true,  embed: false,  classify: false,  pii: false,
streaming: true,  jsonMode: false,  tools: false,
maxTiersAllowed: ['public', 'internal', 'private', 'secret'],   // local => OK for everything, secret-tier eligible
runsLocally: true
```

**Hard rule for Veil's integration with this adapter:**

- **The adapter never modifies the Zero-TVM repo.** The repo is research; the brain is a downstream consumer. Bug fixes belong upstream.
- **Numbers in the showcase card (§5) are sourced from `~/Documents/GitHub/zero-tvm/README.md` + `BENCH.md`.** If those change, the card changes — not the other way around.

---

## 3. Routing logic — the heart of Veil

Two checkpoints, one fallback chain, two hard invariants.

### 3.1 Input checkpoint (user types a message)

Before the message touches any chat backend:

1. Run `classifyTier(userText)` on the locally-resident classifier (default: `transformers-js` 4-class head; fallback: OpenAI-compat with a 1B model in JSON mode).
2. Take `tier = argmax(scores)`. Compute `marginal = scores[tier] - max(scores excluding tier)`.
3. **Escalation rule.** If `marginal < 0.2`, bump tier one rung up the ladder (`public→internal→private→secret`). The brain values false-positive caution over false-negative leak. Threshold is configurable; see §7.
4. Branch on tier:
   - **`public` or `internal`**: pass through clean to the configured chat backend (Anthropic, local, or Zero-TVM — user's choice, see §6).
   - **`private`**: detect PII → mint pseudonyms (the existing Phase 0–7 Veil pipeline) → run **cohort blender** (§4) → fan out `k` requests to the chosen backend → keep the real one's response, drop the rest. Reverse-map pseudonyms before display.
   - **`secret`**: route entire turn to a `runsLocally: true` backend. **Never** hit Anthropic. If the configured secret-tier backend is unavailable, refuse with `VeilRoutingError('No local backend available for secret-tier content')` — do not fall back to remote.

### 3.2 Fetch checkpoint (agent calls `mcp__the host__get_document`)

The MCP server is built by Hephaestus-Backend; this section is the contract the MCP server's `get_document` handler implements *via* Veil.

When the agent fetches a document for context injection:

1. Read the document's `sensitivity:` frontmatter. If unset, apply `.brain/config.yaml` slot default. If still unset, default to `private`.
2. Apply identical tier logic to the document content as in §3.1 — same `classifyTier` + escalation rule, with the frontmatter tier as the floor (i.e. `tier = max(frontmatterTier, classifiedTier)`).
3. `public/internal`: inject raw into the agent's context.
4. `private`: pseudonymize → cohort-blend → inject the cohort-of-k into context. The agent sees `k` superficially-equivalent versions; the wire-side adversary cannot tell which is real.
5. `secret`: refuse to inject into a remote agent's context. The MCP server short-circuits with a `[secret content withheld]` placeholder and a note that the user can opt into a local-only agent run.

### 3.3 Hard invariants (enforced in code, not config)

```
INVARIANT 1: secret content NEVER goes to a remote LLM. No override flag, no per-message escape hatch.
             Implementation: the router's adapter-selection step filters by adapter.capabilities.runsLocally === true
             when tier === 'secret'. If the filter empties, the call fails closed.

INVARIANT 2: private content NEVER goes raw to a remote LLM. Veil-transformed only.
             Implementation: when tier === 'private' AND adapter.capabilities.runsLocally === false,
             the request is run through pseudonymize() + cohort_blend() unconditionally before serialization.
             The pre-dispatch hook asserts no raw PII span survives in the outbound payload (audit-pass; reuse
             the existing Phase 0 audit harness in claw-code's veil-phase-0 branch).
```

These are the two rules that make Veil meaningful. They live in `veil/src/router.ts` as static guards, not in user-editable settings.

### 3.4 Default fallback chain

For each tier, the brain attempts adapters in this order, advancing on init-failure or unreachability:

| Tier | Try 1 | Try 2 | Try 3 | Try 4 |
|---|---|---|---|---|
| public | Anthropic | OpenAI-compat (Ollama/LM Studio) | WebLLM | Zero-TVM |
| internal | Anthropic | OpenAI-compat | WebLLM | Zero-TVM |
| private | OpenAI-compat (cohort-blended) | WebLLM (cohort-blended) | Zero-TVM (cohort-blended) | Anthropic (cohort-blended; only if `runsLocally` chain exhausted) |
| secret | OpenAI-compat | WebLLM | Zero-TVM | **fail closed** |

User can override per-tier in settings (§6). The order above is the install-default.

---

## 4. Cohort blender (Phase 8 k-anon sampler)

The brain ships the existing Phase 8 sampler from `claw-code/veil-phase-0` — it is not re-implemented here. This section is the contract Veil-the-TS-package exposes, and the wiring to embeddings.

> Citation: Ternary Veil Phase 8 — k-anonymous cohort sampler. See `~/brain/research-vault/experiments/E29-veil-phase-8-kanon.md` (the Phase 8 writeup with threat model, privacy guarantee, and what falsifies the claim) and the implementation in `claw-code/veil-phase-0` branch (`crates/veil/src/cohort.rs`, 528 lines, 20 unit tests).

### 4.1 What the cohort blender does

For a `private` text whose pseudonymized entity set is `E = {e_1, ..., e_n}`:

1. **Embed.** `embedBackend.embed(text) → Float32Array`.
2. **K-NN over the vault.** Find `K-1` nearest-neighbor notes from `~/brain/` whose embeddings live in the local vector index. Filter: same `tier` or higher, same kind-shape (configurable per `EntityKind`).
3. **Synthesize siblings.** For each neighbor, run `CohortSynthesizer.synthesize` (the Rust `StaticPoolSynthesizer` exposed via WASM, or its TS port) to produce a kind-shape-identical pseudonym set drawn from a pool disjoint from the live session table.
4. **Substitute.** `veil::substitute_pseudonyms` rewrites each sibling text with its sibling pseudonym set. The cohort `{P_real, P'_1, ..., P'_{K-1}}` is `K` indistinguishable kind-shape-identical prompts.
5. **Fan out.** Dispatch `K` chat requests through whichever backend the router picked. Keep the real one's response, log+drop the siblings (per current Phase 8 design).

### 4.2 Defaults

| Knob | Default | Notes |
|---|---|---|
| `K` | **8** | Tunable in settings. K=2 is the minimum-meaningful (1 sibling). K=16 is the upper bound for reasonable cost. |
| Embedding model | **multilingual-e5-small** (384-dim, int8) | Smallest model that handles cross-lingual notes (the user writes in TR + EN). |
| Optional heavy embed | **BGE-M3** (8192 ctx, 100+ langs) | When the user's notes are long-form. |
| Optional 2026 embed | **Nomic Embed Text v2** (MoE) | If the brain wants to ride the latest. |
| Sibling response handling | **log + drop** | Per Phase 8 v1. Future: audit sibling responses for inadvertent leak (see E29 §"What this does NOT solve"). |
| Pool source | **`StaticPoolSynthesizer`**, reserved range `*_10001..=*_10016` | Deterministic. Per-session pool randomization is deferred to Phase 8 v2 (E29 documents the residual fingerprint risk). |
| Failure mode | **`Drop`** (fail-open) by default; `Abort` (fail-closed) opt-in per-tier | E29's `CohortFailure` enum. |

### 4.3 What this does NOT solve (still true, ship the caveats)

Verbatim from E29's threat-model section:
- **Request-time jitter.** Serial dispatch via one `reqwest` client; an adversary with µs-precision can fingerprint. Mitigation deferred.
- **Pool-range fingerprint.** `EMAIL_10001` vs `EMAIL_1` is distinguishable by number alone. Mitigation deferred to per-session pool randomization (Phase 8 v2).
- **Streaming.** Cohort fan-out is batch-only in v1; streaming-with-cohort is documented as future work.

These caveats are surfaced in the Veil settings panel (§6) so the user knows what they're getting.

---

## 5. Zero-TVM showcase card (verbatim, ready to ship)

Where it appears: **Settings → Privacy backends → Zero-TVM card** (one of five backend cards in the panel).

What follows is the in-product copy. Numbers verified against `~/Documents/GitHub/zero-tvm/README.md` + `BENCH.md` on 2026-04-26. If you change a number, change the source first; if the source's numbers move, update this card.

> **Note on a discrepancy I'm flagging instead of hiding:** the brain's `projects/zero-tvm.md` says "11 kernel roles / 30 WGSL files / 49 kB JS bundle / post-292 dispatches", while the canonical README.md says "10 kernel roles / 27 WGSL files / 157 kB JS bundle / 228 (f16 KV) or 260 (int8 KV) dispatches per decode". The README + BENCH.md are the source of truth (the project page is older). The card below uses the README's numbers. **Verify before shipping the card.**

---

### Card copy — begin

**Run Phi-3 in your tab on hand-written WGSL kernels — no compiler, no framework.**

Most browser LLMs ship a TVM-autotuned compiler that emits 85 WGSL kernels and a WASM scheduler to drive them. **Zero-TVM replaces that whole stack** with 10 hand-written kernel roles (27 WGSL files counting subgroup/tiled/int8 variants) and ~2,000 lines of TypeScript — using the same Phi-3-mini-q4f16_1 weights.

|                              | WebLLM (TVM)                  | Zero-TVM                           |
|------------------------------|-------------------------------|------------------------------------|
| Unique WGSL kernels          | 85                            | **10 roles / 27 files**            |
| Total WGSL lines             | 12,962 (generated)            | **3,078 (hand-written)**           |
| Dispatches per decode step   | 342                           | **228 (f16 KV) / 260 (int8 KV)**   |
| Decode throughput (M2 Pro)   | **51.5 tok/s**                | 42.14 tok/s — 22% behind, honest   |
| Runtime                      | TVM → WASM scheduler          | **Plain TypeScript, no runtime**   |
| Tokenizer                    | Bundled from WebLLM           | **BPE from scratch** (`tokenizer.ts`) |
| JS bundle (chat, excl. weights) | 5.9 MB / 2.1 MB gz         | **157 kB / 33 kB gz**              |

**The honest gap:** Zero-TVM is ~22% slower decode than WebLLM's autotuned compiler on identical hardware and identical weight bytes. The wins are everywhere else: 8.4× fewer kernels, 4.2× fewer WGSL lines, 38× smaller JS bundle, no compiler in the loop. Every FLOP the model executes is in a file you can open.

**Why we ship this as the secret-tier chat option:** when content is sensitive enough to never leave your device, the engine running it should also be one you can audit end-to-end. Zero-TVM is that engine.

[github.com/abgnydn/zero-tvm](https://github.com/abgnydn/zero-tvm) — *this is our research.*

⚠ **Experimental** — research-grade. Phi-3-mini only. Requires WebGPU + `shader-f16` (Chrome/Edge 120+). May have edge cases on unusual Unicode in the BPE tokenizer.

### Card copy — end

---

## 6. Settings UX sketch (Privacy backends panel)

Layout described, not drawn (Hephaestus-DevOps owns the SolidJS implementation).

**Top bar.** Title: *Privacy backends*. Subtitle: *Who runs your prompts, and where.* Single global toggle: *Allow remote LLMs at all* (default on; flipping off forces every tier to a `runsLocally: true` adapter and disables Anthropic from showing up anywhere).

**Detected backends list** (auto-populated at startup, with a "Re-scan" button):
- ✓ **Ollama** — `http://localhost:11434` — 4 models loaded — *active*
- ✓ **LM Studio** — `http://localhost:1234` — 2 models loaded — *available*
- ✓ **WebLLM** — in-tab — Phi-3.5-mini cached in OPFS — *available*
- ✓ **transformers.js** — in-tab — multilingual-e5-small cached — *active (embeddings)*
- ✓ **Anthropic** — `api.anthropic.com` — key configured — *available*
- ⚙ **Zero-TVM (experimental)** — in-tab — Phi-3-mini cached in OPFS (1.8 GB) — *not yet enabled* `[Enable]`

**Per-tier preference panel** (a 4-row table, one row per tier, columns *chat*, *embed*, *classify*, *PII detect* — each cell a dropdown of compatible backends):

```
                  chat              embed          classify       PII detect
public            [Anthropic ▾]     [tjs/e5-s ▾]   [tjs ▾]        [Presidio ▾]
internal          [Anthropic ▾]     [tjs/e5-s ▾]   [tjs ▾]        [Presidio ▾]
private           [Ollama ▾]        [tjs/e5-s ▾]   [tjs ▾]        [Presidio ▾]
secret            [Zero-TVM ▾]      [tjs/e5-s ▾]   [tjs ▾]        [Presidio ▾]
                  ⓘ Zero-TVM:                                                
                    research-grade,                                          
                    may have edge cases.                                     
```

**Cohort blender section** (collapsible):
- *K (cohort size)*: slider 2–16, default **8**.
- *Embedding model*: radio — `multilingual-e5-small` (default) / `BGE-M3` / `Nomic Embed Text v2`.
- *On cohort failure*: radio — `Drop sibling, send real anyway (availability)` / `Abort whole request (strict privacy)`. Default Drop.
- Caveat block (always visible, three bullets verbatim from §4.3).

**Showcase row** — when the user picks Zero-TVM in the secret-tier chat dropdown, the panel expands an inline showcase card (§5 verbatim). This is the *moment*: the product transparently tells them *here's what the standard way does, here's what your-tab-right-now does, here's the honest gap, here's why it's interesting anyway.* Footer link to the repo.

**Hard rules in the UI:**
- The `secret` tier's *chat* dropdown only lists backends with `runsLocally: true`. Anthropic is greyed out with tooltip *"Disabled by Veil hard invariant 1"*.
- The `private` tier's chat dropdown lists everything, but next to remote backends a lock-icon tooltip says *"Will be cohort-blended before dispatch"*.
- Switching the cohort-K slider away from default surfaces a banner: *"Lower K reduces privacy entropy from log₂(K) bits."*

---

## 7. Open questions for the user

These are the design decisions Veil cannot make on the user's behalf. Listed in expected order of "blocks shipping".

1. **Anthropic-fallback in v1: ship or skip?** The cleanest demo of Veil's thesis is "we use local, full stop." Including Anthropic at all weakens the showcase. Including it gives users the ergonomics they expect for `public`/`internal`. Pick one — recommendation from Talos: ship it but default the per-tier `public/internal` chat preference to local Ollama-or-WebLLM if either is detected, so Anthropic only fires for users who explicitly opted in.

2. **Default secret-tier chat backend: Zero-TVM or Ollama?** Zero-TVM is the showcase but it's Phi-3-only and 22% slower. Ollama-on-Phi-3.5-mini is faster, more flexible, but doesn't *show off* anything. Talos's pick: **Zero-TVM by default, Ollama as the "if Zero-TVM fails to init" fallback** — the showcase is the point of the product.

3. **Tier-classifier escalation threshold (the `marginal < 0.2` rule).** Should it be a single global knob or per-tier asymmetric (e.g. `private→secret` upgrade triggers at a tighter margin than `internal→private`)? Conservative recommendation: ship one global knob in v1, instrument it, decide from logs.

4. **Default K for cohort blender.** §4 says 8. The Phase 8 paper's empirical sweet-spot has not been written yet (Phase 9 is the harness). If the PUPA harness lands first, set the default from its results; if it doesn't, ship 8 and accept the cost.

5. **PII vs ambiguous-PII boundary.** Presidio + regex give high-precision spans for `EMAIL`, `PHONE`, `CREDIT_CARD`, `IBAN`, `IP_ADDRESS` deterministically. `PERSON`, `LOCATION`, `ORG` are NER-driven and routinely produce false positives ("Apple", "Bangkok"). Should ambiguous spans (a) auto-pseudonymize anyway (high recall, more friction), (b) prompt the user inline, (c) escalate to local LLM for disambiguation (the LangExtract path Presidio 2.2.362 added)? Talos's pick: (c), with a per-user default knob between (a) and (b) for users who don't want LLM-in-the-loop.

6. **Default NER model in transformers.js.** GLiNER (`gliner_multi_pii-v1`) is browser-portable and zero-shot but unverified at April 2026. spaCy-via-onnx (`en_core_web_sm`) is bulletproof but English-only and bigger. The user writes TR + EN. Decision needed; recommendation: GLiNER for v1 with a hard-coded fallback to spaCy if init fails, and a user-visible toggle.

7. **OPFS budget.** WebLLM, Zero-TVM, and the embedding model all want OPFS. Three Phi-3-class models is ~5 GB. Should Veil auto-evict on disk pressure (LRU? user-confirm?), or just refuse to install model #4? Recommendation: warn at >75% browser quota, refuse at >90%, never silently delete the user's stuff.

---

## 7.1 Resolutions (v1 — decided 2026-06-08)

The canonical path is now **Rust engine + TS shell** (see `../CLAUDE.md`), and an
end-to-end MCP consumer (`../examples/mcp-server/`) is wired. That changes the
footing for several of these: some are now answered by what shipped, others are
explicitly punted with a revisit date. Each decision below supersedes the
recommendation above where they differ.

| # | Question | v1 decision | Status |
|---|---|---|---|
| 1 | Anthropic fallback | **Ship it.** `AnthropicAdapter` is built; `VeilEnforcer` uses the remote for `public`/`internal` and for `private` *after* pseudonymization. The thesis is protected by invariant, not by omission: `secret` and raw `private` never reach it. | **Decided** — implemented. |
| 2 | Default secret-tier backend | **Ollama (OpenAI-compat local), not Zero-TVM.** Zero-TVM is Phi-3-only, ~22% slower, and currently a stub (needs the vendored submodule). Ollama is what actually runs end-to-end in the enforcer today. Zero-TVM stays the opt-in *showcase* backend once vendored — a UX choice, not the secret-tier default. Honest divergence from Talos's pick. | **Decided** — reflects built wiring. |
| 3 | Escalation threshold | **One global knob, default 0.2.** Implemented as `VeilEnforcer`/`routeMessage` `escalationMargin`. Per-tier asymmetry deferred until there are logs to set it from. | **Decided** — implemented. |
| 4 | Default cohort K | **K=8 stands; cohort fan-out is now WIRED** (2026-06-08). The engine exposes `/v1/cohort` (Rust `StaticPoolSynthesizer` + `substitute_pseudonyms`) and `VeilEnforcer` fans out k shuffled prompts when `cohortK>1`, keeping the real response. Off by default (`cohortK` unset → pseudonymize-only) since it costs k× provider calls. Residual §4.3 caveats (pool-range fingerprint, deterministic synthesis) still open — per-session pool randomization deferred to **2026-09-01**. | **Decided + shipped (v1).** |
| 5 | PII vs ambiguous-PII | **Auto-pseudonymize the deterministic regex kinds; defer ambiguous NER kinds to Phase 1.** The Rust `RegexDetector` already auto-pseudonymizes `email/url/ip/path/uuid` (high precision). `person`/`location`/`org` need the learned detector (`BitnetDetector`, Phase 1, not yet built); until then they are **audit-log-only** (`AuditReason::LikelyLeaked`), matching the auditor's existing "watch the FP rate before escalating" stance. The LLM-disambiguation path (Talos's pick (c)) is reconsidered once Phase 1 exists. | **Decided (v1) / revisit with Phase 1.** |
| 6 | Default browser NER model | **GLiNER (`gliner_multi_pii-v1`) for the browser fallback, spaCy fallback on init failure.** Low priority now: with the Rust engine canonical, `transformers-js` NER is only the no-server fallback, off the critical path. Revisit when the browser shell ships. | **Punted (dated)** — by **2026-09-01**. |
| 7 | OPFS budget | **Warn >75%, refuse >90%, never silently delete.** A browser-shell concern only (WebLLM/Zero-TVM/transformers-js); the Rust-engine path doesn't touch OPFS. Decided in principle; enforced when the browser shell is built. | **Decided (principle)** — implement with browser shell. |

### v1 status (re: #4) — cohort blending now shipped

`VeilEnforcer` protects `private` content by **pseudonymization** (real entities
→ `EMAIL_1`, reverse-mapped on return) by default, and by **cohort blending**
(the k-anonymous fan-out of §4) when `cohortK>1`. Both are shipped and tested:
the engine's `/v1/cohort` builds the k-prompt cohort and the enforcer shuffles +
fans out, keeping the real response. The §4 k-anonymity guarantee holds at
`log2(achieved_k)` bits — **with the §4.3 caveats still open** (pool-range
fingerprint, deterministic synthesis; positional fingerprint is closed by the
caller's shuffle). So: claim k-anonymity *with those caveats*, not unqualified.

---

## Appendix A — file layout (sketch, for the implementer)

```
the host application/
└── veil/
    ├── VEIL.md                    ← this file
    ├── package.json               (private to brain; published as @abgnydn/veil)
    ├── src/
    │   ├── backend.ts             (the interface from §1)
    │   ├── router.ts              (the §3 routing logic + hard invariants)
    │   ├── tier.ts                (TierScores, escalation rule)
    │   ├── pii-regex.ts           (the regex kernel)
    │   ├── cohort.ts              (the §4 cohort blender — TS port or WASM bind to claw-code/veil-phase-0)
    │   ├── audit.ts               (the pre-dispatch invariant guard)
    │   └── index.ts               (public surface)
    ├── adapters/
    │   ├── openai-compat.ts       (§2.a)
    │   ├── webllm.ts              (§2.b — main-thread proxy)
    │   ├── transformers-js.ts     (§2.c)
    │   ├── anthropic.ts           (§2.d)
    │   └── zero-tvm-adapter.ts    (§2.e — wraps ~/Documents/GitHub/zero-tvm/src/zero-tvm/engine-core.ts)
    ├── workers/
    │   └── webllm-sw.ts           (the Service Worker for §2.b)
    └── tests/
        ├── routing.test.ts        (the hard invariants — must fail closed)
        ├── cohort.test.ts         (entropy = log2(K), pool disjoint, etc.)
        └── adapters.test.ts       (capability matrix conformance)
```

---

## Appendix B — what Veil deliberately does not do

- **Does not implement the MCP server.** Hephaestus-Backend's stream owns `mcp__the host__*`. Veil is consumed by it.
- **Does not implement the SolidJS UI.** Hephaestus-DevOps's stream owns the rendering of §6. Veil exposes the data model the UI binds against.
- **Does not write the paper.** Scholar's stream owns the arXiv draft. Veil ships the system the paper measures.
- **Does not modify the Zero-TVM repo.** Talos's rule. The showcase is downstream of the research.
- **Does not invent perf numbers.** Every quantitative claim in §2.e and §5 is sourced from `zero-tvm/README.md` or `BENCH.md`. If you can't find it there, mark *(verify before shipping the card)*.

---

*Forged by Talos for the host application. Hand on anvil.*
