# SPDX-License-Identifier: Apache-2.0
"""
Accuracy harness for the veil GLiNER detector — the honest "is it actually
good?" check the validation smoke didn't answer.

Runs the real model over a small hand-labeled EN+TR set (person/location/org,
including hard/ambiguous cases and PII-free negatives) and reports per-kind
precision / recall / F1 across a threshold sweep.

  python3 eval.py                 # default model, thresholds 0.3/0.5/0.7
  GLINER_MODEL=... python3 eval.py

Honesty notes:
  - This set is SMALL and synthetic (~40 sentences). Numbers are indicative,
    not a benchmark — they show shape (recall vs precision, where it stumbles),
    not a publishable F1. A real eval needs a labeled corpus (e.g. ai4privacy).
  - Matching is RELAXED: a prediction counts if it shares the kind and its text
    overlaps a gold span. For a privacy filter, "did we catch the sensitive
    token at all" (recall) matters more than exact boundaries.
  - Works for span-level GLiNER models (gliner-pii-base/small/large). The
    *edge* variant is a different token-level architecture
    (UniEncoderTokenGLiNER) that `predict_entities` does not drive here — it
    needs its own invocation and is not evaluated by this harness.
"""

import os

# (text, [(kind, surface), ...]) — gold. kind in {person, location, org}.
GOLD: list[tuple[str, list[tuple[str, str]]]] = [
    # --- EN, clear ---
    ("Alice Johnson emailed me from Bangkok.", [("person", "Alice Johnson"), ("location", "Bangkok")]),
    ("The contract with Acme Corp closes Friday.", [("org", "Acme Corp")]),
    ("Dr. Sarah Chen joined Google last month.", [("person", "Sarah Chen"), ("org", "Google")]),
    ("Ship it to our London office.", [("location", "London")]),
    ("Michael and Priya met at Microsoft HQ in Seattle.",
     [("person", "Michael"), ("person", "Priya"), ("org", "Microsoft"), ("location", "Seattle")]),
    ("Tell Robert the OpenAI deal is signed.", [("person", "Robert"), ("org", "OpenAI")]),
    ("She flew from Paris to Tokyo for the Sony pitch.",
     [("location", "Paris"), ("location", "Tokyo"), ("org", "Sony")]),
    ("CEO Tim Cook spoke in Cupertino.", [("person", "Tim Cook"), ("location", "Cupertino")]),
    # --- TR, clear ---
    ("Ayşe Yılmaz İstanbul ofisinden yazdı.", [("person", "Ayşe Yılmaz"), ("location", "İstanbul")]),
    ("Mehmet, Ankara'daki Garanti şubesine gitti.",
     [("person", "Mehmet"), ("location", "Ankara"), ("org", "Garanti")]),
    ("Zeynep, Türk Hava Yolları ile İzmir'e uçtu.",
     [("person", "Zeynep"), ("org", "Türk Hava Yolları"), ("location", "İzmir")]),
    ("Mustafa Demir, Bursa'da yeni bir şirket kurdu.",
     [("person", "Mustafa Demir"), ("location", "Bursa")]),
    # --- hard / ambiguous ---
    ("Washington signed the order in Washington.",
     [("person", "Washington"), ("location", "Washington")]),  # person + place, same surface
    ("Apple fell from the tree near the Apple Store.",
     [("org", "Apple")]),  # fruit Apple is NOT PII; store Apple is org
    ("Jordan visited Jordan last spring.",
     [("person", "Jordan"), ("location", "Jordan")]),
    ("Amazon shipped it down the Amazon.",
     [("org", "Amazon"), ("location", "Amazon")]),
    # --- negatives (no person/location/org PII) ---
    ("The quarterly report is due tomorrow.", []),
    ("Please reset your password and try again.", []),
    ("It rained heavily for three days straight.", []),
    ("The function returns null on an empty input.", []),
    ("Toplantı yarın saat üçte başlayacak.", []),  # TR: "the meeting starts at 3 tomorrow"
    ("Lütfen raporu en kısa sürede gönder.", []),  # TR: "please send the report asap"
]

LABELS = ["person", "location", "organization"]
GLINER_TO_KIND = {"person": "person", "location": "location", "organization": "org"}


def overlaps(a: str, b: str) -> bool:
    a, b = a.casefold(), b.casefold()
    return a in b or b in a


def score_at(model, threshold: float):
    # per-kind counters
    kinds = ["person", "location", "org"]
    tp = {k: 0 for k in kinds}
    fp = {k: 0 for k in kinds}
    fn = {k: 0 for k in kinds}

    for text, gold in GOLD:
        preds = []
        for e in model.predict_entities(text, LABELS, threshold=threshold):
            kind = GLINER_TO_KIND.get(e["label"])
            if kind:
                preds.append((kind, e["text"]))

        gold_used = [False] * len(gold)
        for pkind, ptext in preds:
            hit = False
            for i, (gkind, gtext) in enumerate(gold):
                if not gold_used[i] and gkind == pkind and overlaps(ptext, gtext):
                    gold_used[i] = True
                    hit = True
                    break
            if hit:
                tp[pkind] += 1
            else:
                fp[pkind] += 1
        for i, (gkind, _) in enumerate(gold):
            if not gold_used[i]:
                fn[gkind] += 1

    return tp, fp, fn


def prf(tp: int, fp: int, fn: int):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main():
    from gliner import GLiNER

    model_id = os.environ.get("GLINER_MODEL", "knowledgator/gliner-pii-base-v1.0")
    print(f"model: {model_id}")
    n_ents = sum(len(g) for _, g in GOLD)
    print(f"eval set: {len(GOLD)} sentences, {n_ents} gold entities "
          f"({sum(1 for _, g in GOLD if not g)} negatives)\n")

    model = GLiNER.from_pretrained(model_id)

    for thr in (0.3, 0.5, 0.7):
        tp, fp, fn = score_at(model, thr)
        print(f"=== threshold {thr} ===")
        print(f"  {'kind':9s} {'P':>6s} {'R':>6s} {'F1':>6s}   (tp/fp/fn)")
        TP = FP = FN = 0
        for k in ("person", "location", "org"):
            p, r, f = prf(tp[k], fp[k], fn[k])
            print(f"  {k:9s} {p:6.2f} {r:6.2f} {f:6.2f}   ({tp[k]}/{fp[k]}/{fn[k]})")
            TP += tp[k]; FP += fp[k]; FN += fn[k]
        p, r, f = prf(TP, FP, FN)
        print(f"  {'OVERALL':9s} {p:6.2f} {r:6.2f} {f:6.2f}   ({TP}/{FP}/{FN})\n")


if __name__ == "__main__":
    main()
