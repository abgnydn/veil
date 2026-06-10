# SPDX-License-Identifier: Apache-2.0
"""
veil on PUPA — head-to-head leakage vs PAPILLON, on PAPILLON's own benchmark.

PUPA (Columbia-NLP/PUPA, 901 real WildChat prompts) annotates the PII units in
each user prompt. PAPILLON's leakage metric = fraction of private info that
reaches the remote API model. We measure the same idea for veil:

    leakage = annotated PII units that veil FAILS to detect (so they'd reach the
              cloud verbatim) / total annotated units.

This applies veil's exact detection strategy — GLiNER (person/location/org @
threshold 0.5) ∪ regex (email/url/ip) — the same union the Rust engine runs via
MergeFallback. Detection coverage is what determines leakage, so this is a
faithful veil number; it just skips the HTTP round-trip, which doesn't affect
what leaks.

A unit counts as caught if any detected span overlaps it (either contains the
other, case-insensitive) — relaxed matching, since PUPA splits names loosely.

PAPILLON reports ~7.5% leakage (Llama-3.1-8B local + GPT-4o-mini remote).

  ./.venv/bin/python pupa.py
"""

import re

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL = re.compile(r"https?://[^\s)\]}>\"',`<]+")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
GLINER_LABELS = ["person", "location", "organization"]


def caught(unit: str, spans: list[str]) -> bool:
    u = unit.strip().casefold()
    if not u:
        return True
    return any(u in s or s in u for s in spans if s)


def main() -> None:
    from datasets import load_dataset
    from gliner import GLiNER

    model_id = "knowledgator/gliner-pii-base-v1.0"
    print(f"model: {model_id}  ·  detection: GLiNER(person/location/org@0.5) ∪ regex(email/url/ip)")
    model = GLiNER.from_pretrained(model_id)

    rows = []
    for cfg in ("pupa_tnb", "pupa_new"):
        rows += list(load_dataset("Columbia-NLP/PUPA", cfg, split="train"))
    total_units = sum(len([u for u in (r["pii_units"] or "").split("||") if u.strip()]) for r in rows)
    print(f"corpus: {len(rows)} prompts, {total_units} annotated PII units\n")

    leaked = 0
    units = 0
    prompts_fully_clean = 0
    for r in rows:
        text = r["user_query"]
        spans = [e["text"].casefold() for e in model.predict_entities(text, GLINER_LABELS, threshold=0.5)]
        spans += [m.group(0).casefold() for rx in (EMAIL, URL, IP) for m in rx.finditer(text)]
        gold = [u for u in (r["pii_units"] or "").split("||") if u.strip()]
        miss = [u for u in gold if not caught(u, spans)]
        units += len(gold)
        leaked += len(miss)
        if not miss and gold:
            prompts_fully_clean += 1

    rate = leaked / units if units else 0.0
    print(f"=== veil leakage on PUPA ===")
    print(f"  PII units leaked:        {leaked} / {units}   = {rate:.1%}")
    print(f"  recall (caught):         {1 - rate:.1%}")
    print(f"  prompts fully sanitized: {prompts_fully_clean} / {len(rows)}   = {prompts_fully_clean/len(rows):.1%}")
    print(f"\n  PAPILLON (paper):        ~7.5% leakage")
    print(f"  (lower leakage = better; both measure PII reaching the remote model)")


if __name__ == "__main__":
    main()
