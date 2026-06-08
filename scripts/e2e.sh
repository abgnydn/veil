#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Full-stack smoke: the Rust engine wired to the GLiNER stub detector. Asserts
# that learned kinds (person/location/org) AND regex kinds flow through
# /v1/pseudonymize, that reverse-map restores them, and that /v1/cohort yields k
# indistinguishable prompts. Runnable locally and in CI — no model download
# (stub mode), only python3 stdlib + cargo.
#
#   ./scripts/e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DET=8808
ENG=8787

GD="" ; VS=""
cleanup() { [ -n "$GD" ] && kill "$GD" 2>/dev/null || true; [ -n "$VS" ] && kill "$VS" 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

# 1. GLiNER stub detector (deterministic gazetteer, no model).
GLINER_STUB=1 VEIL_DETECTOR_BIND=127.0.0.1:$DET python3 "$ROOT/examples/gliner-detector/server.py" &
GD=$!

# 2. Engine, wired to the detector.
cargo build --quiet --manifest-path "$ROOT/rust/Cargo.toml" --bin veil_server
VEIL_BIND=127.0.0.1:$ENG VEIL_SESSION_TTL_SECS=0 VEIL_DETECTOR_URL=http://127.0.0.1:$DET \
  "$ROOT/rust/target/debug/veil_server" &
VS=$!

# 3. Wait for both to answer health.
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:$DET/health" >/dev/null 2>&1 \
     && curl -sf "http://127.0.0.1:$ENG/v1/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -sf "http://127.0.0.1:$ENG/v1/health" >/dev/null || fail "engine never came up"

post() { curl -s -X POST "http://127.0.0.1:$ENG$1" -H 'content-type: application/json' -d "$2"; }

# 4. pseudonymize: learned (person/location/org) + regex (email) unioned.
P=$(post /v1/pseudonymize '{"session_id":"e2e","text":"Alice emailed bob@acme.com from Bangkok at Acme Corp"}')
echo "pseudonymize -> $P"
echo "$P" | grep -q '"PERSON_1"'        || fail "no PERSON_1 (learned detector not wired)"
echo "$P" | grep -q '"EMAIL_1"'         || fail "no EMAIL_1 (regex)"
echo "$P" | grep -q '"LOCATION_1"'      || fail "no LOCATION_1"
echo "$P" | grep -q '"source":"ner"'    || fail "learned spans not tagged ner"
echo "$P" | grep -q '"source":"regex"'  || fail "regex spans not tagged regex"

# 5. reverse-map restores both a learned and a regex entity.
R=$(post /v1/reverse-map '{"session_id":"e2e","text":"PERSON_1 at EMAIL_1"}')
echo "reverse-map -> $R"
echo "$R" | grep -q 'Alice'         || fail "reverse-map lost the person"
echo "$R" | grep -q 'bob@acme.com'  || fail "reverse-map lost the email"

# 6. cohort: k kind-shape-identical prompts.
C=$(post /v1/cohort '{"session_id":"c","text":"remind alice@acme.com about /Users/x/q.pdf","k":4}')
echo "cohort -> $C"
echo "$C" | grep -q '"achieved_k":4' || fail "cohort did not achieve k=4"

echo "PASS: full-stack e2e (engine + GLiNER stub: pseudonymize, reverse-map, cohort)"
