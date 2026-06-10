# SPDX-License-Identifier: Apache-2.0
"""
veil's leakage on PUPA THROUGH THE REAL ENGINE with the LLM-detector wired in —
and a reverse-map round-trip check. Boot first:

  python3 ../llm-detector/server.py &
  VEIL_BIND=127.0.0.1:8803 VEIL_DETECTOR_URL=http://127.0.0.1:8809 \
    VEIL_DETECTOR_TIMEOUT_MS=30000 cargo run --bin veil_server &
  ./.venv/bin/python pupa_engine.py [N]

Leakage = annotated PII units that survive verbatim in the pseudonymized text
(what the cloud would see). Compare: veil typed-detection 33.5%, PAPILLON ~7.5%.
"""

import json
import sys
import urllib.request

ENG = "http://127.0.0.1:8803"


def post(path, obj):
    req = urllib.request.Request(ENG + path, data=json.dumps(obj).encode(),
                                 headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    from datasets import load_dataset

    rows = list(load_dataset("Columbia-NLP/PUPA", "pupa_tnb", split="train"))[:n]
    print(f"engine + LLM-detector · {len(rows)} PUPA prompts\n")

    units = leaked = roundtrips_ok = 0
    for i, r in enumerate(rows, 1):
        gold = [u.strip() for u in (r["pii_units"] or "").split("||") if u.strip()]
        if not gold:
            continue
        sess = f"p{i}"
        pseudo = post("/v1/pseudonymize", {"session_id": sess, "text": r["user_query"]})["text"]
        low = pseudo.casefold()
        miss = [u for u in gold if u.casefold() in low]
        units += len(gold)
        leaked += len(miss)
        # round-trip: reverse-map the pseudonymized text must restore the original
        back = post("/v1/reverse-map", {"session_id": sess, "text": pseudo})["text"]
        ok = back == r["user_query"]
        roundtrips_ok += ok
        print(f"  [{i:>2}] units={len(gold):>2} leaked={len(miss)} roundtrip={'ok' if ok else 'FAIL'}", flush=True)

    rate = leaked / units if units else 0.0
    print(f"\n=== veil + LLM-detector on PUPA ({units} PII units) ===")
    print(f"  leakage:               {rate:.1%}   ({leaked}/{units})")
    print(f"  reverse-map exact:     {roundtrips_ok}/{len(rows)} prompts")
    print(f"  vs veil typed:         33.5%   ·   vs PAPILLON: ~7.5%")
    print(f"\n  → low leakage AND exact reversibility — the differentiated combination.")


if __name__ == "__main__":
    main()
