# veil

Ternary Veil — privacy-preserving pseudonymization for Claw Code's LLM requests.

## What this crate does (Phase 0)

- Detects sensitive entities (emails, filesystem paths, IPs, URLs, UUIDs) in a text using regex.
- Replaces each detected entity with a stable, session-scoped pseudonym (`EMAIL_1`, `PATH_2`, …).
- Reverse-maps pseudonyms back to their originals, so a model's reply reads naturally to the user while the wire payload stays redacted.

The detector is deliberately a regex stub — Phase 1 swaps it for a BitNet-b1.58-2B pseudonymizer served over HTTP. The public API (`Detector` trait) stays stable across that swap.

## What this crate does NOT do (yet)

- **No provider wiring.** The `ProviderClient::Veil` wrapping variant lands in Phase 0.5 as a focused follow-up PR.
- **No multi-turn coreference.** Phase 2 promotes the flat `SessionTable` to a persistent entity graph that survives context compaction.
- **No output re-identification auditor.** Phase 3 adds a second BitNet pass to catch hallucinated co-references.
- **No k-anonymous cohort sampling.** Phase 4 replaces unique placeholders with attribute-preserving cohort members drawn from a federated distribution — the genuine novel contribution.
- **No streaming.** Phase 0 operates on complete strings. Streaming pseudonymization is a Phase-1 concern since it interacts with BitNet's forward-pass latency.

## Scope, in three lines

```
in:  "reach me at a@b.com about /Users/baris/x.ts"
     ↓  pipeline.pseudonymize(...)
out: "reach me at EMAIL_1 about PATH_1"
     ↓  [ ... sent to model ... reply received ... ]
in:  "I looked at PATH_1 and emailed EMAIL_1"
     ↓  pipeline.reverse_map(...)
out: "I looked at /Users/baris/x.ts and emailed a@b.com"
```

## Verification

From `rust/`:

```
cargo fmt --package veil
cargo clippy --package veil --all-targets -- -D warnings
cargo test --package veil
```

## Design notes

- `SessionTable` is a bidirectional map with per-`EntityKind` counters. Same real entity seen twice yields the same pseudonym — necessary for multi-turn consistency.
- `VeilPipeline` is generic over `D: Detector` so the Phase-1 BitNet detector plugs in without refactoring the pipeline.
- Pseudonym format is `{KIND}_{N}` with `KIND ∈ {EMAIL, PATH, IP, URL, UUID}` in Phase 0. The `\b(EMAIL|PATH|IP|URL|UUID)_\d+\b` pattern is used for reverse-mapping. Later phases may widen the kind set.
- Overlap resolution: when regex matches overlap (e.g., URL contains an email-shaped substring), the earliest-starting match wins; ties broken by length (longer wins).

## Paper / prior art

See `~/brain/resources/concepts/privacy-preserving-prompting.md` (in user's brain vault) for the full literature survey that motivated this design. Direct priors:

- HaS-LLM (arXiv:2309.03057) — canonical two-local-model pseudonymization.
- PAPILLON (NAACL 2025, arXiv:2410.17127) — closest living cousin.
- "Say Something Else" (arXiv 2025/26) — defines the multi-turn attack Phase 3 closes.
- basic-memory schema (`basicmachines-co/basic-memory`) — atomic-note format borrowed by the brain.
