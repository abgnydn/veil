# SPDX-License-Identifier: Apache-2.0
"""
GLiNER detector server for veil — the learned-NER backend behind the Rust
`HttpNerDetector`. Speaks the detect protocol in docs/CONTRACT.md §8:

    POST /detect  { "text": ..., "labels": ["PERSON","LOCATION","ORG"] }
               -> { "entities": [ { "kind": "PERSON", "start": 0, "end": 5 } ] }
    GET  /health -> 200

GLiNER is zero-shot: veil passes the kinds it wants as `labels` (uppercase
canonical kinds = pseudonym prefixes), this server maps them to GLiNER's label
strings, runs the model, and maps results back. Offsets returned to veil are
UTF-8 *byte* offsets (GLiNER yields Python char offsets — converted here; this
matters for non-ASCII input like Turkish).

Modes:
  - real  (default): loads a GLiNER PII model via the `gliner` package.
  - stub  (GLINER_STUB=1, or auto-fallback if the model can't load): a small
    deterministic gazetteer, so the veil↔detector wire is testable without the
    ~1GB model download. NOT for production — it only knows a few names.

Run:
  GLINER_STUB=1 python3 server.py            # no deps, for testing the wire
  python3 server.py                          # real model (pip install gliner)
Env: VEIL_DETECTOR_BIND (default 127.0.0.1:8808), GLINER_MODEL, GLINER_THRESHOLD
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# veil canonical prefix  <->  GLiNER natural-language label
PREFIX_TO_GLINER = {
    "PERSON": "person",
    "LOCATION": "location",
    "ORG": "organization",
    "EMAIL": "email",
    "PATH": "file path",
    "IP": "ip address",
    "URL": "url",
    "UUID": "uuid",
}
GLINER_TO_PREFIX = {v: k for k, v in PREFIX_TO_GLINER.items()}

# Deterministic stub gazetteer (stub mode only): exact substrings → kind.
# Enough to demo the freeform kinds regex can't do, and to drive the wire test.
STUB_GAZETTEER = {
    "PERSON": ["Alice", "Bob", "Dr. Smith", "Smith", "Ayşe"],
    "LOCATION": ["Bangkok", "London", "Paris", "İstanbul"],
    "ORG": ["Acme", "OpenAI", "Anthropic", "Google"],
}

DEFAULT_LABELS = ["PERSON", "LOCATION", "ORG"]


def char_to_byte(text: str, char_idx: int) -> int:
    """Unicode codepoint index -> UTF-8 byte offset (CONTRACT.md §8)."""
    return len(text[:char_idx].encode("utf-8"))


class Detector:
    """Real GLiNER detector."""

    def __init__(self) -> None:
        from gliner import GLiNER  # imported lazily so stub mode needs no deps

        model_id = os.environ.get("GLINER_MODEL", "knowledgator/gliner-pii-base-v1.0")
        self.threshold = float(os.environ.get("GLINER_THRESHOLD", "0.5"))
        self.model = GLiNER.from_pretrained(model_id)
        self.name = f"gliner:{model_id}"

    def detect(self, text: str, prefixes: list[str]) -> list[dict]:
        labels = [PREFIX_TO_GLINER.get(p, p.lower()) for p in prefixes]
        out = []
        for ent in self.model.predict_entities(text, labels, threshold=self.threshold):
            prefix = GLINER_TO_PREFIX.get(ent["label"])
            if prefix is None:
                continue
            out.append(
                {
                    "kind": prefix,
                    "start": char_to_byte(text, ent["start"]),
                    "end": char_to_byte(text, ent["end"]),
                }
            )
        return out


class StubDetector:
    """Deterministic gazetteer — testing only."""

    name = "stub"

    def detect(self, text: str, prefixes: list[str]) -> list[dict]:
        wanted = set(prefixes) or set(DEFAULT_LABELS)
        hits = []
        for kind, names in STUB_GAZETTEER.items():
            if kind not in wanted:
                continue
            for name in names:
                start = 0
                while True:
                    idx = text.find(name, start)
                    if idx == -1:
                        break
                    hits.append((idx, idx + len(name), kind))
                    start = idx + len(name)
        # Sort by start, drop overlaps (keep first/longer), convert to bytes.
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        kept = []
        for s, e, kind in hits:
            if kept and s < kept[-1][1]:
                continue
            kept.append((s, e, kind))
        return [
            {"kind": kind, "start": char_to_byte(text, s), "end": char_to_byte(text, e)}
            for (s, e, kind) in kept
        ]


def build_detector():
    if os.environ.get("GLINER_STUB") == "1":
        return StubDetector()
    try:
        return Detector()
    except Exception as err:  # noqa: BLE001 — fall back so the wire still works
        print(f"gliner-detector: model load failed ({err}); using stub", flush=True)
        return StubDetector()


def make_handler(detector):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, obj) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                self._json(200, {"ok": True, "detector": detector.name})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path != "/detect":
                self._json(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("content-length", "0"))
                req = json.loads(self.rfile.read(length) or "{}")
                text = req.get("text", "")
                labels = req.get("labels") or DEFAULT_LABELS
                entities = detector.detect(text, labels)
                self._json(200, {"entities": entities})
            except Exception as err:  # noqa: BLE001
                # Per the contract, the Rust side treats any error as "no spans"
                # and degrades to regex — but return a clean 500 for visibility.
                self._json(500, {"error": str(err)})

        def log_message(self, format, *args):  # noqa: A002 — silence request logging
            pass

    return Handler


def main() -> None:
    bind = os.environ.get("VEIL_DETECTOR_BIND", "127.0.0.1:8808")
    host, _, port = bind.rpartition(":")
    detector = build_detector()
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(detector))
    print(
        f"gliner-detector: listening on http://{bind} (detector={detector.name})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
