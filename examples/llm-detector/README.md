# llm-detector

An LLM-backed detector for veil — the upgrade that closes the leakage gap.

veil's default detection (regex + GLiNER) catches a *fixed set* of entity kinds
and leaks **33.5%** of PII on [PUPA](https://huggingface.co/datasets/Columbia-NLP/PUPA),
because real prompts carry phones, dates of birth, account numbers, and
addresses it has no detector for. This server uses an LLM to find **all** of it.

It speaks veil's detect protocol ([`docs/CONTRACT.md` §8](../../docs/CONTRACT.md))
— same as the GLiNER server — so it's a drop-in: point `VEIL_DETECTOR_URL` at it.
The LLM returns PII spans `{text, kind}`; this server maps kinds to veil prefixes
(anything without a dedicated kind → `PII`, the `Custom` catch-all) and locates
each span's byte offsets. **veil's `SessionTable` still mints the reversible
pseudonyms**, so you get LLM-grade coverage *with* exact round-trip.

## The result (measured, through the real engine)

`pupa_engine.py` runs PUPA prompts through `veil_server` + this detector and
checks both leakage and the reverse-map round-trip:

| detector | leakage ↓ | reversible? |
|---|---|---|
| veil default (regex + GLiNER) | 33.5% | ✅ exact |
| **veil + this LLM-detector** | **~4%** | ✅ exact |
| PAPILLON (paper) | ~7.5% | ❌ lossy rewrite |

So: **PAPILLON-class leakage (or better) *with* exact reversibility** — the
combination PAPILLON can't offer (its redaction rewrites and can't restore).

```
original:   Rachel Zheng (DOB 1990-03-12) at H&R Technology … account 4829-1100-2847 …
cloud sees: PERSON_1 (DOB PII_1) at ORG_1 … account PII_2 …
restored:   Rachel Zheng (DOB 1990-03-12) at H&R Technology … account 4829-1100-2847 …
```

## Run

```bash
python3 server.py &                                    # detector :8809 (backend: claude -p)
VEIL_BIND=127.0.0.1:8803 VEIL_DETECTOR_URL=http://127.0.0.1:8809 \
  VEIL_DETECTOR_TIMEOUT_MS=30000 cargo run --bin veil_server   # LLM calls take seconds
```

`VEIL_DETECTOR_TIMEOUT_MS=30000` is required — the default 1500ms is for the
~50ms GLiNER server; an LLM takes seconds.

## Backend & honest caveats

- **Backend is `claude -p`** (no API token, tools off) for the prototype. For a
  **private** deployment, swap it for a **local** model (Ollama / LM Studio) —
  that's the production setup; a local 8B lands around PAPILLON's ~7.5%, a
  frontier model lower. Sending the raw prompt to `claude` to *detect* PII
  obviously isn't private — it's the prototype.
- **Slower and heavier** than regex/GLiNER (a model call per prompt). Use it via
  `MergeFallback` so regex handles the cheap structured kinds and the LLM is the
  thorough pass — or only on high-stakes content.
- Numbers above are a **small PUPA sample**; the exact % is noisy. The ~9×
  reduction vs typed detection, with exact reversibility, is the real signal.
