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

## Head-to-head vs the state of the art (PUPA)

`pupa.py` runs veil on **[PUPA](https://huggingface.co/datasets/Columbia-NLP/PUPA)**
— the 901-prompt benchmark from [PAPILLON](https://arxiv.org/abs/2410.17127),
the published "use a local model as a privacy proxy" system — using its own
leakage metric (fraction of annotated PII units that reach the remote model).

| system | leakage ↓ | reversible? | notes |
|---|---|---|---|
| **PAPILLON** (paper) | ~7.5% | ❌ lossy | local LLM rewrites the whole prompt |
| **veil — default** (GLiNER + regex) | 33.5% | ✅ exact | fixed kinds only — leaks phones/IDs/dates/addresses |
| **veil + LLM-detector** | **~4%** | ✅ exact | LLM finds the long tail → `PII` catch-all ([`../llm-detector/`](../llm-detector/)) |

**The default detector loses to PAPILLON ~4.5×** — it can't touch the phone
numbers, IDs, dates, and addresses PUPA annotates (recall 66.5%, fully sanitizes
68.6% of prompts). **But swapping GLiNER for an LLM-detector behind the same
`Detector` boundary closes it** — ~4% leakage on a PUPA sample, *with exact
reversibility intact*, which PAPILLON's lossy rewrite can't offer. See
[`examples/llm-detector/`](../llm-detector/) for the wired, measured upgrade.

> Run it: `./.venv/bin/python pupa.py` (needs `datasets`; streams PUPA).

## Accuracy (per-kind, ai4privacy)

`eval.py` runs the real model over a small hand-labeled EN+TR set (person/
location/org, with ambiguous cases and PII-free negatives) and reports per-kind
precision/recall/F1 across a threshold sweep. Run: `.venv/bin/python eval.py`.

**Real benchmark** (`benchmark.py`) — `gliner-pii-base-v1.0` on **500 English
examples from [ai4privacy/pii-masking-200k](https://huggingface.co/datasets/ai4privacy/pii-masking-200k)**
(353 gold person/location/org spans), independent-overlap matching:

| threshold | precision | recall | F1 |
|---|---|---|---|
| 0.3 | 0.31 | 0.94 | 0.47 |
| **0.5** | **0.45** | **0.92** | **0.60** ← server default |
| 0.7 | 0.60 | 0.80 | 0.69 |

Per-kind at 0.5: person 0.65 P / 0.95 R · location 0.42 / 0.88 · org 0.14 / 0.77.

Findings (the honest picture — this corrects the optimistic hand-labeled eval below):
- **Recall is strong** (0.92 at 0.5, 0.94 at 0.3) — for a privacy filter that's
  what matters most: a missed entity is a leak. ~8% still slip, which is *why*
  secret-tier stays local and regex covers the deterministic kinds.
- **Precision is mediocre** (0.45 at 0.5) — the model over-predicts, worst on
  **org** (0.14). Two reasons: GLiNER genuinely over-flags orgs, and precision
  here is a **lower bound** — only 6 ai4privacy labels are mapped to gold, so a
  GLiNER hit on an entity the dataset labeled differently counts as a false
  positive unfairly.
- **Threshold trade-off:** 0.5 maximizes recall-leaning F1 (the privacy default);
  0.7 trades recall (0.80) for precision (0.60) if over-pseudonymization friction
  matters more than the odd miss.
- The **edge** variant (`gliner-pii-edge-v1.0`) is a different token-level
  architecture; evaluating it needs its own invocation (not done here).

> Run it yourself: `./.venv/bin/python benchmark.py 500` (streams the dataset,
> no full download).

**Hand-labeled sanity set** (`eval.py`) — 22 clean EN+TR sentences, F1 0.89 at
0.5. Useful as a quick smoke, but *optimistic*: the sentences are easy. The
ai4privacy benchmark above is the number to trust.

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
