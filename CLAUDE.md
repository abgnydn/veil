# CLAUDE.md — veil

Privacy / tier-enforcement layer for any app that proxies user content to third-party LLMs. See `README.md` for the product overview.

## 🎯 Resume here (on "continue")

_Updated: 2026-05-18 — two independent implementations (Rust crate + TypeScript adapters) that don't talk to each other yet._

**Steps (next, in priority order):**

1. **Decide canonical path.** Three honest options:
   - **Rust crate is canonical.** TS is a temporary stand-in until the Rust HTTP server ships; then TS adapters call out to the Rust server. Matches the original architecture intent.
   - **TS adapters are canonical.** Rust crate stays as a research-grade reference for the regex pseudonymizer. Faster to ship; loses the BitNet detector roadmap.
   - **Maintain both** with the shared spec in `docs/VEIL.md`. Expensive; only worth it if both have real downstream consumers.
2. **Continue Phase 1 on the Rust side** — swap `RegexDetector` for `BitnetDetector` against a local BitNet inference server. The `Detector` trait boundary is drop-in. Phase 1 is the line between "research demo" and "actually private."
3. **Resolve the 7 v1-gating decisions** in `docs/VEIL.md` (cohort K default, ambiguous-PII handling, OPFS quota policy, etc.).
4. **Build a working tier-enforcement hook for an MCP server** so the TS side has at least one realistic end-to-end consumer.

**Acceptance for this Resume:**
- One canonical path decided and documented at the top of this file.
- At least one MCP server (your own or example) enforces tier algebra via veil end-to-end.
- 7 v1-gating decisions either answered or punted with a written date.

## Layout

```
rust/
├── src/                Phase 0 regex pseudonymizer + Phase 0.5 ProviderClient + MessageStream wrapping
├── tests/, examples/, Cargo.toml
ts/
├── interface.ts        VeilBackend + tier algebra + error classes
├── classifier.ts       caution-biased heuristic classifier
├── cohort.ts           k-anonymous cohort blender
├── anthropic.ts        Anthropic adapter (hard-blocks secret + raw private at construction)
├── openai-compat.ts    Ollama / LM Studio / llamafile / vLLM adapter (SSE streaming)
└── kvkk-*.ts           KVKK Madde 11 (b/c/d/e/f) compliance suite
docs/VEIL.md            full design spec
```

## Working agreement

- Don't run cargo/npm tests on either subtree without confirming first — both halves are mid-evolution.
- **Pseudonym determinism is load-bearing on the Rust side**: `EMAIL_1` / `PATH_1` / `URL_1` / `IP_1` must stay stable across turns of the same conversation. Any refactor that breaks round-trip is a regression — gate behind an explicit decision.
- Adapter constructors enforce tier algebra. Never paper over a "wrong tier" error with a runtime check; fix at the construction site.
