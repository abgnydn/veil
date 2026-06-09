// SPDX-License-Identifier: Apache-2.0
// "Watch the wire." Drives the REAL VeilEnforcer with a stand-in remote that
// records the exact bytes it receives — so what's shown is captured, not
// narrated. Boot the engine first (scripts/demo.sh does this).

import {
  RustPipelineClient,
  VeilEnforcer,
  classifyTierHeuristic,
  argmaxTier,
  collectText,
} from "../ts/index.ts";
import type { Msg, TierScores, Token, VeilBackend } from "../ts/interface.ts";

const engine = new RustPipelineClient({ baseUrl: "http://127.0.0.1:8799" });

// Stand-in for a cloud provider (Anthropic). Records every message it's handed
// — that recording IS the wire — and echoes the content back as the "reply".
const wire: string[][] = [];
const remote: VeilBackend = {
  id: "anthropic",
  displayName: "anthropic",
  capabilities: { chat: true, embed: false, classify: false, pii: false, streaming: true, jsonMode: false, tools: false, maxTiersAllowed: ["public", "internal"], runsLocally: false },
  async init() {}, isReady: () => true,
  async classifyTier() { throw 0; }, async detectPII() { return []; }, async embed() { throw 0; },
  async *chat(messages: Msg[]): AsyncIterable<Token> {
    wire.push(messages.map((m) => m.content));
    const u = messages.find((m) => m.role === "user")?.content ?? "";
    yield { text: `Done — ${u}`, done: true, finishReason: "stop" };
  },
};

// Route by what's actually in the text: credentials → secret (caught by the
// heuristic via the env/key patterns); otherwise, if the engine finds any PII
// entity → private (pseudonymize); else internal. This is PII-presence routing,
// stronger than keywords alone for the privacy goal.
async function classify(text: string): Promise<TierScores> {
  const h = classifyTierHeuristic(text);
  if (argmaxTier(h) === "secret") return h;
  const { spans } = await engine.pseudonymize("classify-probe", text);
  return spans.length ? { public: 0, internal: 0, private: 1, secret: 0 } : h;
}

const enforcer = new VeilEnforcer({ engine, sessionId: "demo", remote, classify });
// no local backend wired → secret tier has nowhere safe to go → withheld.

const B = "\x1b[1m", D = "\x1b[2m", R = "\x1b[31m", G = "\x1b[32m", Y = "\x1b[33m", C = "\x1b[36m", X = "\x1b[0m";

async function show(label: string, prompt: string) {
  const before = wire.length;
  const res = await enforcer.enforce(prompt);
  console.log(`${B}You type:${X}`);
  console.log(`  ${C}${prompt}${X}\n`);
  if (res.withheld) {
    console.log(`${B}What the cloud receives:${X}`);
    console.log(`  ${R}✗ nothing.${X}  ${Y}${res.tier}-tier → withheld, fail-closed.${X}`);
    console.log(`  ${D}  (run it on a local model, or not at all — never a third party.)${X}`);
  } else {
    // Drain the stream first — the wrapped chat is lazy; it only hits the
    // remote (and records the wire) when iterated.
    const back = await collectText(res.stream);
    const sentToCloud = wire[before]?.find((c) => c) ?? "";
    console.log(`${B}What the cloud actually receives:${X}  ${D}(captured off the wire, tier=${res.tier})${X}`);
    console.log(`  ${G}${sentToCloud}${X}\n`);
    console.log(`${B}What you get back:${X}  ${D}(real values restored locally)${X}`);
    console.log(`  ${C}${back}${X}`);
  }
  console.log(`${B}────────────────────────────────────────────────────────────────${X}\n`);
}

console.log(`\n${B}┌─ veil ─ watch the wire ────────────────────────────────────────┐${X}\n`);
await show(
  "private",
  "Email the Q3 deck at /Users/baris/q3.pdf to alice@acme.com, CC bob@acme.com (my manager); staging is https://internal.acme.dev",
);
await show(
  "secret",
  "deploy prod with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
);
console.log(`${D}  engine: localhost only · open source · github.com/abgnydn/veil${X}\n`);
