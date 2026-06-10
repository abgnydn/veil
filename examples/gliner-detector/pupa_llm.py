# SPDX-License-Identifier: Apache-2.0
"""
The decisive experiment: does an LLM redactor close veil's leakage gap?

veil's typed detection leaks 33.5% on PUPA (pupa.py). PAPILLON leaks ~7.5% by
rewriting the whole prompt with a local LLM. This measures whether an LLM
redactor — the technique veil could drop behind its Detector boundary — gets
into that range, on a 30-prompt PUPA sample, with the SAME leakage metric
(annotated PII unit survives verbatim in the text sent onward = leaked).

Honesty: this uses `claude -p` (no API token) as the redactor, so during the
test the raw PII goes to the cloud — we're measuring redaction *quality*, not
running it privately. In production the redactor would be a LOCAL model
(Ollama / LM Studio), exactly like PAPILLON.

  ./.venv/bin/python pupa_llm.py [N]      # default N=30
"""

import subprocess
import sys

REDACT = """Replace every piece of personally identifiable information in the text below — names, organizations, locations, emails, phone numbers, dates, ID/account numbers, addresses, anything identifying a specific person or entity — with a bracketed placeholder like [NAME], [ORG], [LOCATION], [EMAIL], [ID]. Keep the rest of the text exactly intact. Output ONLY the redacted text, no preamble.

TEXT:
{text}"""


def redact(text: str) -> str:
    p = subprocess.run(
        ["claude", "-p", REDACT.format(text=text), "--allowed-tools", ""],
        capture_output=True, text=True,
    )
    return p.stdout.strip()


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    from datasets import load_dataset

    rows = list(load_dataset("Columbia-NLP/PUPA", "pupa_tnb", split="train"))[:n]
    print(f"LLM-redactor experiment · {len(rows)} PUPA prompts · redactor = claude -p (tools off)\n")

    units = leaked = 0
    for i, r in enumerate(rows, 1):
        gold = [u.strip() for u in (r["pii_units"] or "").split("||") if u.strip()]
        if not gold:
            continue
        out = redact(r["user_query"]).casefold()
        miss = [u for u in gold if u.casefold() in out]  # survived verbatim = leaked
        units += len(gold)
        leaked += len(miss)
        print(f"  [{i:>2}/{len(rows)}] units={len(gold):>2}  leaked={len(miss)}", flush=True)

    rate = leaked / units if units else 0.0
    print(f"\n=== leakage on {len(rows)} PUPA prompts ({units} PII units) ===")
    print(f"  LLM redactor (claude):   {rate:.1%}   ({leaked}/{units})")
    print(f"  veil typed detection:    33.5%   (full PUPA, pupa.py)")
    print(f"  PAPILLON (paper):        ~7.5%")
    print()
    if rate <= 0.12:
        print("  → DECISIVE: LLM redaction reaches PAPILLON-class leakage. The fix works —")
        print("    wire a LOCAL LLM redactor behind veil's Detector boundary.")
    elif rate < 0.25:
        print("  → PROMISING: well below veil's 33.5%, not yet PAPILLON-class. Worth pursuing.")
    else:
        print("  → NEGATIVE: LLM redaction doesn't close the gap on this sample. Reconsider.")


if __name__ == "__main__":
    main()
