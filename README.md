# veil

A privacy layer that sits between your application and any third-party LLM. veil pseudonymizes emails, file paths, URLs, and IPs deterministically before the request hits the wire, then reverses the mapping on the response — including streamed tokens. Round-trip-stable, so the model sees `EMAIL_1` and you see `alice@acme.com` back.

## Two implementations

| | path | what it is |
|---|---|---|
| Rust crate | `rust/` | Regex pseudonymizer, `ProviderClient` wrapping variant, streamed `MessageStream` reverse-mapping. Phase 0.5. |
| TypeScript adapters | `ts/` | Interface + tier algebra, classifier, k-anonymous cohort blender, Anthropic + OpenAI-compat adapters, KVKK Madde 11 (b/c/d/e/f) compliance suite (deletion, subject-access request, PDF export). |

## Why

LLM prompts leak PII by default. Once an email or document path goes upstream, it's logged, cached, possibly trained on. veil intercepts the request at the SDK boundary, swaps real identifiers for stable pseudonyms, asks the model, and rewrites the answer back to the user's view. The model sees no real names; the user sees no pseudonyms.

## Tier algebra

veil classifies content into four tiers — `public`, `caution`, `private`, `secret` — and refuses to forward higher tiers to providers that aren't allowlisted for them. Adapter constructors enforce the algebra (e.g. the Anthropic adapter hard-blocks secret + raw private at construction, so a mis-configured deploy fails fast instead of silently leaking).

## Status

WIP. The Rust crate is at Phase 0.5; Phase 1 swaps the regex detector for a BitNet detector. The TS adapters ship the KVKK compliance work but the MCP tier-enforcement hook is unfinished. Pick one as canonical or maintain both with the shared spec in `docs/VEIL.md`.

## License

Apache-2.0.
