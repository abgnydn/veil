# CLAUDE.md — veil

Privacy / tier-enforcement layer for any app that proxies user content to third-party LLMs. See `README.md` for the product overview.

## 🎯 Resume here (on "continue")

_Updated: 2026-06-05 — canonical path DECIDED: **Rust engine + TS shell**._

### Canonical path (decided 2026-06-05)

**Rust `VeilPipeline` is the canonical pseudonymization engine; TS is the
orchestration shell that calls it.** Rationale: the detect → substitute →
stable-session-table → reverse-map round-trip (the product's core promise)
exists *only* in Rust (`VeilPipeline`, 105 tests). The TS side is the tier
algebra + adapter ecosystem, but its `detectPIIHeuristic` is a no-op (`[]`)
and there is no TS substitution/reverse-map engine — only `transformers-js`
does browser-side NER detection, and even it never pseudonymizes. So the two
halves are **complementary, not competing**: Rust = engine, TS = shell. This
matches the original spec intent (TS adapters call out to a Rust server) and
throws away nothing tested. The "TS canonical" path was rejected because it
would re-implement the entire tested Rust engine in TypeScript.

**Steps (next, in priority order):**

1. **Shared pseudonym + wire contract** — `docs/CONTRACT.md` + `docs/veil-wire.schema.json`.
   _Status: drafted 2026-06-05._ Reconciles Rust's 6 `EntityKind`s with TS's
   16 `PIIKind`s onto one canonical kind↔prefix table, fixes the prefix
   collisions (`IP_1` vs `IP_ADDRESS_1`, etc.) and the offset convention clash
   (Rust UTF-8 bytes vs TS UTF-16 chars), and defines the local HTTP surface.
2. ✅ **Rust local HTTP server** (landed 2026-06-05) — `rust/src/server.rs` +
   `rust/src/bin/veil_server.rs`. axum, one `VeilPipeline` per `session_id`,
   all 7 contract endpoints + `/v1/health`, loopback-only (binary refuses a
   non-loopback `VEIL_BIND`), idle-session reaper (`VEIL_SESSION_TTL_SECS`).
   7 new tests (unit + live-HTTP round-trip); live output verified against
   `veil-wire.schema.json`. Run: `cargo run --bin veil_server`.
3. ✅ **TS `RustPipelineClient`** (landed 2026-06-05) — `ts/rust-client.ts`
   (typed wire client: pseudonymize/reverse-map/audit + json variants, health,
   deleteSession) + `ts/veil-wrap.ts` (`wrapWithVeil` runs the round-trip
   around any backend's chat; `reverseMapStream` buffers across token
   boundaries so a pseudonym split mid-stream never maps half-formed). The TS
   round-trip now actually works — verified live against `veil_server`. The
   no-op `detectPIIHeuristic` stays only as the browser fallback when no local
   engine answers `/v1/health`. 12 new hermetic tests.
4. **Phase 1 on the Rust side** — swap `RegexDetector` for `BitnetDetector`
   against a local BitNet inference server. `Detector` trait boundary is
   drop-in. The line between "research demo" and "actually private."
5. ✅ **MCP tier-enforcement consumer** (landed 2026-06-08) — `ts/enforce.ts`
   (`VeilEnforcer`: classify → route → engine round-trip, both hard invariants
   as control flow) + `examples/mcp-server/` (real MCP server, `@modelcontextprotocol/sdk`,
   one `veil_ask` tool). Verified end-to-end: 4 in-memory-transport MCP tests +
   a live stdio handshake smoke; private prompts reach the remote pseudonymized,
   secret prompts are withheld. 5 new core tests.
6. ✅ **7 v1-gating decisions** resolved/punted with dates — `docs/VEIL.md §7.1`
   (decided 2026-06-08). Notably: cohort fan-out is NOT wired in v1 (the
   `private` path pseudonymizes only — see the limitation note in §7.1).
7. 🔄 **Phase 1 — learned detector** (in progress, 2026-06-08). Model decided:
   **GLiNER, not BitNet** (detection is token-classification, not generation;
   GLiNER is zero-shot/multilingual/exact-spans/browser-portable — see
   `examples/gliner-detector/README.md`). Done: detector generalized to the
   model-agnostic `HttpNerDetector` (`BitnetDetector` kept as alias) with
   zero-shot `labels`; `EntityKind` gained `Location`/`Org` so GLiNER's value
   over regex is real; detect protocol documented (`docs/CONTRACT.md §8`);
   reference GLiNER server shipped (`examples/gliner-detector/`, real + stub
   modes); verified end-to-end (`cargo run --example smoke_gliner` against the
   stub: Alice→PERSON_1, bob@acme.com→EMAIL_1, Bangkok→LOCATION_1, Acme→ORG_1,
   merged + round-tripped; non-ASCII byte offsets verified on Turkish).
   Also wired into the running server: `veil_server` builds a regex+learned
   `MergeFallback` when `VEIL_DETECTOR_URL` is set, so the full chain
   (MCP → VeilEnforcer → RustPipelineClient → engine → GLiNER) flows
   `person`/`location`/`org` end-to-end — no TS change needed, the shell already
   calls the engine. Wire `source` is reported accurately (regex vs ner by
   kind). Verified live with the **real** `knowledgator/gliner-pii-base-v1.0`
   model (2026-06-08): through veil_server, "Alice Johnson"→PERSON_1, "Acme
   Corp"→ORG_1, "Bangkok"→LOCATION_1, email via regex, reverse-mapped exactly;
   Turkish "Ayşe Yılmaz"/"İstanbul" with byte offsets correct through the
   multibyte chars. Peak RSS ~1.9 GB, load ~48s cold / ~15s warm. Verified
   combo: python 3.12, gliner 0.2.26, torch 2.12.0, transformers 5.1.0 (in
   `examples/gliner-detector/.venv`, gitignored). **Phase 1 is functionally
   complete.** Accuracy measured (`examples/gliner-detector/eval.py`, EN+TR,
   relaxed match): base model F1 0.89 / recall 0.91 at threshold **0.5**
   (confirmed optimal — the server default; 0.3 adds FPs, 0.7 drops recall);
   person strongest, org weakest (ambiguity). ~9% miss rate even at best — why
   secret stays local + regex covers deterministic kinds. Edge variant is a
   different token-level arch (UniEncoderTokenGLiNER), needs its own invocation,
   deferred. Remaining: a real labeled-corpus benchmark (this set is small/
   synthetic) if a published number is ever needed.

8. ✅ **Cohort blending (k-anonymity) shipped** (2026-06-08) — the last big
   feature gap. Engine `/v1/cohort` (Rust `StaticPoolSynthesizer` +
   `substitute_pseudonyms`, single-sourced pool now covers Location/Org);
   `VeilEnforcer.cohortK>1` fans out k shuffled, side-channel-symmetric prompts,
   keeps the real response, reverse-maps it; MCP example reads `VEIL_COHORT_K`.
   Verified live: k=4 → 4 kind-shape-identical prompts, distinct pseudonym sets,
   real reverse-maps / siblings don't. **Hardened** (2026-06-08): the enforcer
   now crypto-scrambles every pseudonym number into one random space
   (`ts/cohort-scramble.ts`) + shuffles, **closing** the §4.3 pool-range
   fingerprint, deterministic-synthesis, and positional caveats (verified live:
   wire shows `EMAIL_919463`-style randoms, no `EMAIL_1`/`EMAIL_10001` tell).
   Still open: content-template reveal (needs vault-neighbor siblings —
   embeddings/KNN, not built) and timing side-channel. Off by default (k× cost).

**Acceptance for this Resume — ALL MET (2026-06-08):**
- ✅ One canonical path decided and documented at the top of this file (2026-06-05).
- ✅ Shared contract landed (`docs/CONTRACT.md` + JSON schema); both vocabularies reconciled (2026-06-05).
- ✅ At least one MCP server enforces tier algebra via veil end-to-end (`examples/mcp-server/`, 2026-06-08).
- ✅ 7 v1-gating decisions answered or punted with a written date (`docs/VEIL.md §7.1`, 2026-06-08).

## Layout

```
rust/
├── src/                Phase 0 regex pseudonymizer + Phase 0.5 ProviderClient + MessageStream wrapping
├── src/server.rs       Phase 7 loopback HTTP seam (wire contract in docs/CONTRACT.md)
├── src/bin/veil_server.rs  binary: `cargo run --bin veil_server` (127.0.0.1:8787)
├── tests/, examples/, Cargo.toml
ts/
├── interface.ts        VeilBackend + tier algebra + error classes
├── classifier.ts       caution-biased heuristic classifier
├── cohort.ts           k-anonymous cohort blender
├── anthropic.ts        Anthropic adapter (hard-blocks secret + raw private at construction)
├── openai-compat.ts    Ollama / LM Studio / llamafile / vLLM adapter (SSE streaming)
└── router.ts           input + fetch checkpoints with hard invariants
docs/VEIL.md            full design spec
```

## Working agreement

- Don't run cargo/npm tests on either subtree without confirming first — both halves are mid-evolution.
- **Pseudonym determinism is load-bearing on the Rust side**: `EMAIL_1` / `PATH_1` / `URL_1` / `IP_1` must stay stable across turns of the same conversation. Any refactor that breaks round-trip is a regression — gate behind an explicit decision.
- Adapter constructors enforce tier algebra. Never paper over a "wrong tier" error with a runtime check; fix at the construction site.
