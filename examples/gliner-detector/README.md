# gliner-detector

The learned-NER backend for veil's Rust `HttpNerDetector`. A small HTTP server
that runs **GLiNER** (zero-shot, multilingual PII NER) and speaks veil's detect
protocol ([`docs/CONTRACT.md` §8](../../docs/CONTRACT.md)).

This is what closes the "research demo → actually private" gap: regex handles
the structured kinds (`email`, `path`, `ip`, `url`, `uuid`); this server handles
the freeform kinds regex fundamentally can't — `person`, `location`, `org`.

## Why GLiNER (not BitNet)

PII detection is **token classification**, not generation. GLiNER is a
purpose-built bidirectional-encoder NER model: zero-shot (you pass the kinds you
want as labels, no retraining), multilingual (handles TR + EN), ~55–60 entity
types, and small enough to run locally or in-browser via ONNX. A generative LLM
like BitNet is the wrong tool — weaker recall (a miss is a leak), no exact
spans, slower. The veil `Detector` boundary is model-agnostic, so this server
can be swapped, but GLiNER is the recommended default.

## Protocol

```
POST /detect  { "text": "...", "labels": ["PERSON","LOCATION","ORG"] }
           -> { "entities": [ { "kind": "PERSON", "start": 0, "end": 5 } ] }
GET  /health -> { "ok": true, "detector": "..." }
```

`labels`/`kind` are uppercase canonical kinds (= pseudonym prefixes). `start`/
`end` are **UTF-8 byte offsets** — GLiNER yields Python char offsets, which this
server converts (correctness matters for non-ASCII, e.g. Turkish `ş`/`ı`/`ğ`).

## Run

```bash
# Stub mode — deterministic gazetteer, no model download. For wiring/tests:
GLINER_STUB=1 python3 server.py

# Real model:
pip install -r requirements.txt
python3 server.py            # downloads knowledgator/gliner-pii-base-v1.0 (~1GB)
```

Env: `VEIL_DETECTOR_BIND` (default `127.0.0.1:8808`), `GLINER_MODEL`,
`GLINER_THRESHOLD`, `GLINER_STUB=1`.

## Accuracy

`eval.py` runs the real model over a small hand-labeled EN+TR set (person/
location/org, with ambiguous cases and PII-free negatives) and reports per-kind
precision/recall/F1 across a threshold sweep. Run: `.venv/bin/python eval.py`.

`gliner-pii-base-v1.0`, relaxed matching, 22 sentences / 34 gold entities — small
and synthetic, so these show *shape*, not a benchmark F1:

| threshold | precision | recall | F1 |
|---|---|---|---|
| 0.3 | 0.76 | 0.91 | 0.83 |
| **0.5** | **0.86** | **0.91** | **0.89** ← default |
| 0.7 | 0.91 | 0.85 | 0.88 |

Per-kind at 0.5: person 1.00 P / 0.92 R · location 0.86 / 0.92 · org 0.73 / 0.89.

Findings:
- **0.5 is the sweet spot** (the server default): max F1, and recall is already
  at peak — dropping to 0.3 only adds false positives, while 0.7 sacrifices
  recall (a missed entity is a leak).
- **person** is strongest; **org** is weakest — false positives on ambiguous
  surfaces (e.g. "Apple", "Amazon").
- Even at the best setting, recall is ~0.91 — i.e. ~9% of entities slip. This is
  *why* veil keeps secret-tier content local regardless and uses regex for the
  deterministic kinds: the learned detector is a strong layer, not a guarantee.
- The **edge** variant (`gliner-pii-edge-v1.0`) is a different token-level
  architecture; evaluating it needs its own invocation (not done here).

## Wire it into veil

```rust
use veil::{HttpNerDetector, MergeFallback, RegexDetector, VeilPipeline};

let detector = MergeFallback::new(
    HttpNerDetector::new("http://127.0.0.1:8808"), // GLiNER: person/location/org
    RegexDetector::new(),                           // regex: email/path/ip/url/uuid
);
let pipeline = VeilPipeline::new(detector);
```

End-to-end smoke (stub server must be running):

```bash
GLINER_STUB=1 python3 server.py &
cd ../../rust && cargo run -q --example smoke_gliner
```

If the server is down, `MergeFallback` degrades to regex-only — never a crash.

### Or point the engine server at it (no Rust code)

`veil_server` wires this in automatically when `VEIL_DETECTOR_URL` is set, so
the whole stack — including the MCP server — gets `person`/`location`/`org`:

```bash
GLINER_STUB=1 python3 server.py &                       # detector :8808
cd ../../rust
VEIL_DETECTOR_URL=http://127.0.0.1:8808 cargo run --bin veil_server
# now /v1/pseudonymize returns PERSON/LOCATION/ORG spans (source: "ner")
```
