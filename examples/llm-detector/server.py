# SPDX-License-Identifier: Apache-2.0
"""
LLM-backed detector for veil — drops in behind the Rust HttpNerDetector exactly
like the GLiNER server, but uses an LLM to find the long tail of PII (phones,
dates, IDs, addresses, account numbers) that fixed-kind detection misses. veil's
SessionTable still mints the REVERSIBLE pseudonyms, so you get PAPILLON-class
coverage with exact round-trip — which lossy LLM-rewrite redaction can't.

Speaks the detect protocol (docs/CONTRACT.md §8):
    POST /detect  { "text": ..., "labels": [...] }
               -> { "entities": [ { "kind": "PERSON"|"PII"|..., "start", "end" } ] }

The LLM returns PII as {text, kind}; this server maps kinds to veil prefixes
(anything without a dedicated kind → PII, the Custom catch-all) and locates each
span's UTF-8 byte offsets in the input. Labels are ignored — it extracts ALL PII.

Backend: `claude -p` (no API token, tools off). For a PRIVATE deployment, point
`LLM_CMD` at a local model (Ollama/LM Studio) — that's the production setup.

  python3 server.py        # 127.0.0.1:8809
"""

import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# LLM kind  ->  veil pseudonym prefix.  Anything not listed → PII (Custom).
KIND_TO_PREFIX = {
    "person": "PERSON", "name": "PERSON",
    "location": "LOCATION", "place": "LOCATION", "city": "LOCATION",
    "org": "ORG", "organization": "ORG", "company": "ORG",
    "email": "EMAIL", "url": "URL", "ip": "IP", "ip_address": "IP",
}

PROMPT = """List every piece of personally identifiable information in the TEXT below as a JSON array of objects {{"text": <exact substring as it appears>, "kind": <one of: person, location, org, email, url, ip, phone, date, id, address, account, other>}}. Include names, organizations, locations, emails, phone numbers, dates of birth, ID/account numbers, addresses — anything identifying a specific person or entity. Use the exact substring from the text. Output ONLY the JSON array, no prose, no code fences.

TEXT:
{text}"""


def run_llm(prompt: str) -> str:
    # claude -p with tools disabled — answers only from the prompt we give it.
    p = subprocess.run(["claude", "-p", prompt, "--allowed-tools", ""], capture_output=True, text=True)
    return p.stdout


def parse_items(out: str):
    out = out.strip()
    out = re.sub(r"^```(json)?|```$", "", out, flags=re.MULTILINE).strip()
    m = re.search(r"\[.*\]", out, re.DOTALL)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    return [it for it in items if isinstance(it, dict) and it.get("text")]


def locate(text: str, sub: str):
    """All non-overlapping (byte_start, byte_end) of `sub` in `text`."""
    out, start = [], 0
    while sub:
        i = text.find(sub, start)
        if i == -1:
            break
        bs = len(text[:i].encode("utf-8"))
        out.append((bs, bs + len(sub.encode("utf-8"))))
        start = i + len(sub)
    return out


def detect(text: str):
    entities = []
    for it in parse_items(run_llm(PROMPT.format(text=text))):
        prefix = KIND_TO_PREFIX.get(str(it.get("kind", "")).lower(), "PII")
        for bs, be in locate(text, it["text"]):
            entities.append({"kind": prefix, "start": bs, "end": be})
    return entities


def make_handler():
    class H(BaseHTTPRequestHandler):
        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            self._json(200, {"ok": True, "detector": "llm:claude"}) if self.path == "/health" else self._json(404, {})

        def do_POST(self):  # noqa: N802
            if self.path != "/detect":
                self._json(404, {}); return
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or "{}")
                self._json(200, {"entities": detect(req.get("text", ""))})
            except Exception as err:  # noqa: BLE001
                self._json(500, {"error": str(err)})

        def log_message(self, format, *args):  # noqa: A002
            pass

    return H


def main():
    host, _, port = os.environ.get("VEIL_DETECTOR_BIND", "127.0.0.1:8809").rpartition(":")
    ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler()).serve_forever()


if __name__ == "__main__":
    print("llm-detector: 127.0.0.1:8809 (backend: claude -p, tools off)", flush=True)
    main()
