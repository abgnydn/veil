# veil — shared pseudonym + wire contract

> **Status:** draft, 2026-06-05. The contract both halves of veil code against.
> Canonical path (per [CLAUDE.md](../CLAUDE.md)): **Rust `VeilPipeline` is the
> engine; TS is the shell that calls it over the local HTTP surface defined in
> §4.** This document is the single source of truth for the pseudonym grammar,
> the entity-kind vocabulary, the offset convention, and the wire types. When
> Rust `EntityKind` and TS `PIIKind` disagree, **this table wins** and both
> sides change to match it.

---

## 1. Why this exists

Before this contract the two halves were mutually unintelligible:

| problem | Rust side | TS side | resolution (this doc) |
|---|---|---|---|
| **kind vocabulary** | 6 `EntityKind`s | 16 `PIIKind`s | one canonical table (§2); supersets map down |
| **pseudonym prefix** | `IP_1` | `IP_ADDRESS_1` (`${kind}_${n}`) | canonical underscore-free prefix per kind (§2) |
| **offset units** | UTF-8 byte offsets | UTF-16 char offsets | wire is UTF-8 bytes (§3); callers convert at the boundary |
| **UUID** | `EntityKind::Uuid` | absent | added to canonical table; TS gains `UUID` |

The pseudonym **prefix** is the load-bearing interop primitive: reverse-mapping
keys on it (`<PREFIX>_<n>`), so it MUST be byte-identical on both sides.

---

## 2. Canonical entity kinds ↔ pseudonym prefixes

A pseudonym is `<PREFIX>_<n>` where:

- `PREFIX` matches `[A-Z][A-Z0-9]*` — **underscore-free**, so the reverse-map
  scanner `\b([A-Z][A-Z0-9]*)_\d+\b` is unambiguous. (This is why
  `CREDIT_CARD` → `CC`, not `CREDIT_CARD`; an underscore in the prefix would
  make `CREDIT_CARD_1` ambiguous to parse.)
- `n` is a **per-(session, kind)** 1-based counter, assigned in first-seen
  order. `EMAIL_1` is the first distinct email in the session, `EMAIL_2` the
  second, and so on.

| canonical kind | prefix | Rust `EntityKind` | TS `PIIKind` | detector class | deterministic? |
|---|---|---|---|---|---|
| `email`          | `EMAIL`   | `Email`  | `EMAIL`          | regex   | yes |
| `url`            | `URL`     | `Url`    | `URL`            | regex   | yes |
| `ip`             | `IP`      | `Ip`     | `IP_ADDRESS`     | regex   | yes |
| `path`           | `PATH`    | `Path`   | `PATH`           | regex   | yes |
| `uuid`           | `UUID`    | `Uuid`   | _(add `UUID`)_   | regex   | yes |
| `phone`          | `PHONE`   | _(add)_  | `PHONE`          | regex   | yes |
| `credit_card`    | `CC`      | _(add)_  | `CREDIT_CARD`    | regex (Luhn) | yes |
| `iban`           | `IBAN`    | _(add)_  | `IBAN`           | regex   | yes |
| `crypto_address` | `CRYPTO`  | _(add)_  | `CRYPTO_ADDRESS` | regex   | yes |
| `api_key`        | `APIKEY`  | _(add)_  | `API_KEY`        | regex   | yes |
| `ssn`            | `SSN`     | _(add)_  | `SSN`            | regex   | yes |
| `national_id`    | `NID`     | _(add)_  | `NATIONAL_ID`    | regex   | yes |
| `dob`            | `DOB`     | _(add)_  | `DOB`            | regex   | partial |
| `person`         | `PERSON`  | `Person` | `PERSON`         | learned | no |
| `location`       | `LOCATION`| _(add)_  | `LOCATION`       | learned | no |
| `org`            | `ORG`     | _(add)_  | `ORG`            | learned | no |
| `custom`         | `CUSTOM`  | _(add)_  | `CUSTOM`         | caller-supplied | n/a |

**Implementation phasing.** A side need not implement every kind at once — but
the kinds it *does* implement MUST use the canonical prefix above. Rust's
`RegexDetector` ships `email/url/ip/path/uuid` today and gains `person` via the
learned detector; the remaining regex kinds (`phone/cc/iban/crypto/api_key/
ssn/nid/dob`) are additive and do not change the table. Detectors emitting a
kind not yet in the table is a contract violation — extend the table first.

**`deterministic?` column** flags whether the same input always yields the same
span. Regex kinds are deterministic; `person/location/org` come from a learned
detector and are best-effort. Tier routing must not assume learned kinds are
exhaustively caught (this is why `secret`-tier content stays local regardless).

---

## 3. Offsets

`PIISpan.start` / `.end` on the wire are **UTF-8 byte offsets** into the exact
request string, `start` inclusive, `end` exclusive. Rationale: the engine is
Rust, whose `&str` indexing is byte-based; defining the wire in the engine's
native units avoids a conversion on every span the server emits.

- **TS callers** that need UTF-16 offsets (e.g. to splice into a JS string)
  convert at the boundary. Most callers never touch offsets: the primary
  endpoints are text-in/text-out (§4.1), and the returned span list is for
  **audit/telemetry**, not for the caller to re-apply.
- The `replacement` field (the pseudonym string) is offset-free and is the
  safe primitive when a caller wants to act on a span without offset math.

---

## 4. Local HTTP surface (the seam)

The Rust crate exposes `VeilPipeline` behind a **loopback-only** HTTP server.
One pipeline instance per `session_id`; the server owns the session map. All
bodies are JSON; all responses are the types in §5 (and `veil-wire.schema.json`).

> **Security:** bind `127.0.0.1` only. This server holds the real↔pseudonym
> table — it is the one component that sees raw PII *and* the mapping. It MUST
> NOT be exposed off-host. Auth is out of scope for v1 (loopback trust);
> revisit before any non-loopback bind.

### 4.1 Text round-trip

```
POST /v1/pseudonymize        { session_id, text }          → { text, spans }
POST /v1/reverse-map         { session_id, text }          → { text }
POST /v1/audit               { session_id, reply }         → { findings }
```

- `pseudonymize` — detect + substitute; mints/reuses pseudonyms in the session
  table; returns the rewritten text and the spans it replaced.
- `reverse-map` — rewrite pseudonyms this session minted back to real entities;
  unknown pseudonyms pass through unchanged (never guess).
- `audit` — scan a **raw** model reply (call before `reverse-map`) for
  `UnknownPseudonym` (a `<PREFIX>_<n>` this session never minted) and
  `LikelyLeaked` (a raw entity the model wrote directly). Maps to
  `VeilPipeline::audit_reply` / `audit_reply_async`.

### 4.2 Tool-call JSON round-trip

```
POST /v1/pseudonymize-json   { session_id, value }         → { value, spans }
POST /v1/reverse-map-json    { session_id, value }         → { value }
POST /v1/audit-json          { session_id, value }         → { findings }
```

Walk every string leaf of an arbitrary JSON value (the Anthropic wire carries
tool args as JSON). Depth-bounded; values under reserved wire keys (`role`,
`system`) are skipped. Maps to the Phase 5/6 JSON walkers already in
`pipeline.rs`. `findings[].start/.end` are offsets **within the string leaf**,
not the serialized document — cross-leaf offset math is not meaningful.

### 4.3 Session lifecycle

```
DELETE /v1/session/{session_id}                            → 204
```

Sessions are created implicitly on first use of any endpoint. `DELETE` drops
the table (and thus the ability to reverse-map that conversation) — call it
when a conversation ends so real↔pseudonym mappings don't linger in memory.

---

## 5. Wire types

Mirror of `docs/veil-wire.schema.json`. TS imports these as the
`RustPipelineClient` request/response types; Rust derives `Serialize`/
`Deserialize` for the same shapes.

```ts
type CanonicalKind =
  | "email" | "url" | "ip" | "path" | "uuid" | "phone" | "credit_card"
  | "iban" | "crypto_address" | "api_key" | "ssn" | "national_id" | "dob"
  | "person" | "location" | "org" | "custom";

interface PIISpan {
  start: number;        // UTF-8 byte offset, inclusive (§3)
  end: number;          // UTF-8 byte offset, exclusive
  kind: CanonicalKind;
  score: number;        // detector confidence, 0..1
  replacement: string;  // the pseudonym, e.g. "EMAIL_1"
  source: "regex" | "ner" | "llm" | "context";
}

type AuditReason =
  | { type: "unknown_pseudonym"; kind: CanonicalKind }
  | { type: "likely_leaked";     kind: CanonicalKind };

interface AuditFinding {
  start: number;        // UTF-8 byte offset (within the audited string)
  end: number;
  text: string;         // the offending token, e.g. "EMAIL_99" or "a@b.com"
  reason: AuditReason;
}

// Requests
interface TextReq { session_id: string; text: string; }
interface ReplyReq { session_id: string; reply: string; }
interface JsonReq { session_id: string; value: unknown; }

// Responses
interface PseudonymizeRes { text: string; spans: PIISpan[]; }
interface ReverseMapRes   { text: string; }
interface AuditRes        { findings: AuditFinding[]; }
interface PseudonymizeJsonRes { value: unknown; spans: PIISpan[]; }
```

---

## 6. Determinism invariant (load-bearing — see CLAUDE.md)

Within a single `session_id`:

1. The same real entity always maps to the same pseudonym, across any number of
   calls and across `pseudonymize` / `pseudonymize-json`.
2. `reverse_map(pseudonymize(x)) == x` for any `x` whose entities are all
   detected (round-trip identity on the detected set).
3. Counters are per-kind and assigned first-seen: distinct entities of the same
   kind get distinct increasing `n`.
4. Coref (Phase 2): surface variants of one underlying entity (`Dr. Smith` /
   `Smith`) collapse onto one pseudonym; reverse-map restores the **first-seen**
   surface form.

Any change that breaks (1)–(4) is a regression and is gated behind an explicit
decision (CLAUDE.md working agreement). The Rust suite already enforces these;
the TS `RustPipelineClient` must preserve them by deferring entirely to the
server (no client-side minting).

---

## 7. What this contract deliberately leaves open

- **Cross-version pseudonym stability.** Stable *within* a session only. Pool
  randomization for cohort blending (Phase 8 v2) may renumber across sessions
  by design — see `docs/VEIL.md` §4.3.
- **Non-loopback transport.** v1 is loopback-trust. Auth, TLS, and rate limits
  are out of scope until a non-loopback bind is on the table.
- **Streaming reverse-map over the wire.** The in-process Rust `MessageStream`
  reverse-maps streamed tokens; exposing that incrementally over HTTP (vs. the
  batch `reverse-map` here) is future work.

---

## 8. Detector wire protocol (learned NER)

Separate from the engine HTTP surface (§4): the engine itself calls an optional
**learned NER detector** over HTTP for the freeform kinds regex cannot do
(`person`/`location`/`org`). The recommended model is **GLiNER** (zero-shot,
multilingual, ONNX/browser-portable); BitNet, spaCy, or any server speaking
this protocol also work. Rust side: `HttpNerDetector` (alias `BitnetDetector`),
composed with `RegexDetector` via `MergeFallback` (regex for structured kinds,
the learned model for freeform). Reference server: `examples/gliner-detector/`.

```
POST {detector}/detect
  request:  { "text": "...", "labels": ["PERSON","LOCATION","ORG"] }
  response: { "entities": [ { "kind": "PERSON", "start": 0, "end": 5 }, ... ] }
```

- **`labels`** — the kinds to extract, as **uppercase canonical kinds**
  (= the pseudonym prefixes of §2: `PERSON`, `LOCATION`, `ORG`, …). A zero-shot
  model (GLiNER) uses them directly; a fixed-label server may ignore them. The
  server maps these to whatever label strings its model wants and back.
- **`kind`** in the response — same uppercase-canonical vocabulary. For the
  kinds the engine implements today the prefix is just the canonical kind
  uppercased (`person`↔`PERSON`), so there is no second vocabulary.
- **`start`/`end`** — **UTF-8 byte offsets** into `text`, same as §3. A server
  whose model returns Unicode codepoint offsets (e.g. Python string indices)
  **must convert to byte offsets** — this matters for non-ASCII input (e.g.
  Turkish `ş`/`ı`/`ğ`). Getting this wrong shifts every downstream span.

**Robustness (enforced engine-side by `HttpNerDetector`):** HTTP failure,
timeout, malformed JSON, or invalid spans all collapse to an empty result — so
a down detector degrades to regex-only via `MergeFallback`, never a crash. Each
returned span is validated: unknown `kind`, out-of-bounds, or non-char-boundary
spans are dropped, and the span text is **re-extracted from the input** so a
buggy/hostile server cannot inject content by claiming a span.

---

## 9. Cohort endpoint (k-anonymity)

For `private` content bound for a remote model, pseudonymization hides the
*values* but the prompt still reveals there is one real user. The cohort
endpoint adds **prompt-space k-anonymity** (VEIL.md §4): it returns `k`
kind-shape-identical prompts — the real one plus `k-1` siblings whose
pseudonyms are drawn from a pool disjoint from the session — so a wire-side
adversary picks the real one with probability `1/k` (entropy `log2(k)`).

```
POST /v1/cohort  { "session_id": "...", "text": "...", "k": 8,
                   "content_hiding": false }
              -> { "cohort": ["...", "..."], "real_index": 0,
                   "requested_k": 8, "achieved_k": 8 }
```

- `cohort[real_index]` carries the **session** pseudonyms (`EMAIL_1`); siblings
  carry **pool** pseudonyms (`EMAIL_10001`, …). All k are the same template
  with the same entity kinds in the same positions.
- The caller (TS `VeilEnforcer`) **shuffles** the cohort for positional
  unlinkability, fans out all k to the provider with **identical options**
  (side-channel symmetry), keeps `real_index`'s response, drops the rest, and
  reverse-maps the kept response. Sibling pool pseudonyms were never minted, so
  reverse-map leaves them untouched — dropping siblings leaks nothing.
- **Fail-open:** `k≤1`, an exhausted pool, or a pool↔session collision degrades
  `achieved_k` toward 1 (pseudonymize-only) rather than blocking the turn. The
  real prompt always ships.
- **Cost:** k× provider calls. **Batch only** — streaming-with-cohort is future
  work. Backed by Rust `StaticPoolSynthesizer` + `substitute_pseudonyms`.

**Closed caveats** (the caller, `VeilEnforcer`, handles these):
- *Pool-range fingerprint.* The enforcer scrambles every pseudonym number
  across all k prompts into one crypto-random space per kind, so the real
  prompt no longer carries the tell-tale low number (`EMAIL_1`) nor siblings the
  pool number (`EMAIL_10001`). The real reply is un-scrambled before reverse-map.
- *Deterministic synthesis.* The scramble is fresh per call, so the same real
  set no longer produces the same wire numbers across turns.
- *Positional fingerprint.* The cohort is shuffled before dispatch.

**Partially addressed — `content_hiding` (opt-in):**
- With `content_hiding: false` (default), siblings are renumbered copies of the
  real prompt, so all k share the same non-pseudonym text — the adversary learns
  the prompt's template/topic, just not which entity set is real.
- With `content_hiding: true`, siblings become topic-diverse **decoy sentences**
  (a built-in corpus indexed by entity profile; falls back to renumbered copies
  for uncovered profiles). This hides the **entity-relationship structure** —
  but **not** the real prompt's distinctive non-entity vocabulary: the real
  keeps the user's own phrasing (e.g. the word "contract"), which generic decoys
  don't contain, so a vocabulary-aware adversary can still single it out. Most
  effective for short, entity-centric prompts; weak for content-rich ones. True
  content-indistinguishability needs decoys drawn from the user's own
  distribution (the vault-neighbor approach of §4.1: embeddings + K-NN over a
  local note store — not built).

**Still open:**
- *Timing side-channel.* Fan-out is concurrent but an adversary with precise
  timing could still correlate. Mitigation deferred.
