# SPDX-License-Identifier: Apache-2.0
"""
Benchmark the veil GLiNER detector on a published labeled corpus
(ai4privacy/pii-masking-200k) — a real per-kind precision/recall/F1 number, vs
the small hand-labeled `eval.py` which only shows shape.

Streams N English examples (no full 200k download), maps the dataset's labels to
veil's learned kinds (person/location/org), runs GLiNER, and scores with
*independent overlap* matching:
  - recall    = gold spans with ≥1 overlapping same-kind prediction / all gold
  - precision = predictions overlapping ≥1 same-kind gold / all predictions
This is robust to boundary/granularity differences (the dataset splits names
into FIRSTNAME+LASTNAME; GLiNER emits one "person" span).

  ./.venv/bin/python benchmark.py [N]        # default N=500, threshold sweep
"""

import os
import sys

# ai4privacy label → veil canonical kind. Conservative: only unambiguous ones.
LABEL_MAP = {
    "FIRSTNAME": "person",
    "LASTNAME": "person",
    "MIDDLENAME": "person",
    "CITY": "location",
    "STATE": "location",
    "COUNTY": "location",
    "COMPANYNAME": "org",
}
KINDS = ["person", "location", "org"]
GLINER_LABELS = ["person", "location", "organization"]
GLINER_TO_KIND = {"person": "person", "location": "location", "organization": "org"}


def overlaps(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]  # (start, end) half-open


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    from datasets import load_dataset
    from gliner import GLiNER

    model_id = os.environ.get("GLINER_MODEL", "knowledgator/gliner-pii-base-v1.0")
    print(f"model: {model_id}")
    model = GLiNER.from_pretrained(model_id)

    ds = load_dataset("ai4privacy/pii-masking-200k", split="train", streaming=True)

    examples = []
    for ex in ds:
        if ex.get("language") != "en":
            continue
        gold = [
            (s["start"], s["end"], LABEL_MAP[s["label"]])
            for s in ex["privacy_mask"]
            if s["label"] in LABEL_MAP
        ]
        examples.append((ex["source_text"], gold))
        if len(examples) >= n:
            break
    n_gold = sum(len(g) for _, g in examples)
    print(f"corpus: {len(examples)} English examples, {n_gold} gold person/location/org spans\n")

    for thr in (0.3, 0.5, 0.7):
        rec_tp = {k: 0 for k in KINDS}
        rec_n = {k: 0 for k in KINDS}
        pre_tp = {k: 0 for k in KINDS}
        pre_n = {k: 0 for k in KINDS}

        for text, gold in examples:
            preds = []
            for e in model.predict_entities(text, GLINER_LABELS, threshold=thr):
                kind = GLINER_TO_KIND.get(e["label"])
                if kind:
                    preds.append((e["start"], e["end"], kind))
            for kind in KINDS:
                g = [s for s in gold if s[2] == kind]
                p = [s for s in preds if s[2] == kind]
                for gs in g:
                    rec_n[kind] += 1
                    if any(overlaps(gs, ps) for ps in p):
                        rec_tp[kind] += 1
                for ps in p:
                    pre_n[kind] += 1
                    if any(overlaps(ps, gs) for gs in g):
                        pre_tp[kind] += 1

        print(f"=== threshold {thr} ===")
        print(f"  {'kind':9s} {'P':>6s} {'R':>6s} {'F1':>6s}")
        TP_p = TP_r = N_p = N_r = 0
        for k in KINDS:
            p = pre_tp[k] / pre_n[k] if pre_n[k] else 0.0
            r = rec_tp[k] / rec_n[k] if rec_n[k] else 0.0
            f = 2 * p * r / (p + r) if p + r else 0.0
            print(f"  {k:9s} {p:6.2f} {r:6.2f} {f:6.2f}")
            TP_p += pre_tp[k]; N_p += pre_n[k]; TP_r += rec_tp[k]; N_r += rec_n[k]
        P = TP_p / N_p if N_p else 0.0
        R = TP_r / N_r if N_r else 0.0
        F = 2 * P * R / (P + R) if P + R else 0.0
        print(f"  {'OVERALL':9s} {P:6.2f} {R:6.2f} {F:6.2f}\n")


if __name__ == "__main__":
    main()
