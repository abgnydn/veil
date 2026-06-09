#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LIVE: a real Claude (your `claude` login, no API token) fixes the bug seeing
# only veil-sanitized code. Makes one real model call.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; ENG=8801; VS=""
trap '[ -n "$VS" ] && kill "$VS" 2>/dev/null || true' EXIT
command -v claude >/dev/null || { echo "needs the \`claude\` CLI (claude.ai/code)"; exit 1; }
cargo build --quiet --manifest-path "$ROOT/rust/Cargo.toml" --bin veil_server
VEIL_BIND=127.0.0.1:$ENG VEIL_SESSION_TTL_SECS=0 "$ROOT/rust/target/debug/veil_server" >/dev/null 2>&1 &
VS=$!
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$ENG/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done
bun "$(dirname "$0")/demo-live.ts"
