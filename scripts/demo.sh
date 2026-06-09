#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# "Watch the wire." Boots the local engine and drives the real VeilEnforcer with
# a stand-in cloud provider that records the exact bytes it receives. Shows your
# private identifiers gone from the wire, and a credential blocked outright.
# Nothing is sent to any third party; no API key needed.
#
#   ./scripts/demo.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; ENG=8799; VS=""
trap '[ -n "$VS" ] && kill "$VS" 2>/dev/null || true' EXIT

cargo build --quiet --manifest-path "$ROOT/rust/Cargo.toml" --bin veil_server
VEIL_BIND=127.0.0.1:$ENG VEIL_SESSION_TTL_SECS=0 "$ROOT/rust/target/debug/veil_server" >/dev/null 2>&1 &
VS=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$ENG/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done

bun "$ROOT/scripts/demo.ts"
echo "└────────────────────────────────────────────────────────────────┘"
