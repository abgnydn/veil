// SPDX-License-Identifier: Apache-2.0
//
// The LIVE version: a real Claude fixes the bug while seeing only veil-sanitized
// code. Uses the local `claude` CLI (your existing login) — no API token. Tools
// are disabled, so the model can ONLY use the sanitized text we hand it; it
// cannot read the real files itself. Makes one real (billed) model call.
//
// Boot the engine first (demo-live.sh does it).

import { resolve } from "node:path";
import { readFile } from "node:fs/promises";

import { RustPipelineClient } from "../../ts/index.ts";

const B = "\x1b[1m", D = "\x1b[2m", G = "\x1b[32m", C = "\x1b[36m", Y = "\x1b[33m", X = "\x1b[0m";
const repoRoot = resolve(import.meta.dir, "repo");
const engine = new RustPipelineClient({ baseUrl: "http://127.0.0.1:8801" });
const session = "live-task";

async function sanitize(rel: string): Promise<string> {
  const { text } = await engine.pseudonymize(session, await readFile(resolve(repoRoot, rel), "utf8"));
  return text;
}

const auth = await sanitize("src/auth.ts");
const config = await sanitize("src/config.ts");

const prompt = `You are a senior engineer. Below is code from a repo, with identifiers replaced by opaque tokens (EMAIL_1, PATH_1, URL_1, IP_1) — treat them as given, don't ask for real values. Auth tokens expire after 15 minutes instead of 24 hours. Find the bug and give the corrected line. Be concise — 2 to 3 sentences.

=== src/auth.ts ===
${auth}

=== src/config.ts ===
${config}

(.env was withheld — it contains credentials.)`;

console.log(`\n${B}┌─ a REAL Claude fixes your bug — seeing only pseudonyms ──────────┐${X}\n`);
console.log(`${B}What we send to Claude${X} ${D}(via your \`claude\` login — no API token; tools off)${X}`);
console.log(`${D}  the model receives this, not your repo:${X}`);
for (const line of auth.split("\n").filter((l) => l.includes("EMAIL_") || l.includes("TOKEN_TTL") || l.includes("BUG"))) {
  console.log(`  ${G}${line.trim()}${X}`);
}
console.log(`  ${G}…${X}  ${D}(config.ts → URL_1 / IP_1 / PATH_1; .env withheld)${X}\n`);

console.log(`${Y}  calling the real model…${X}`);
const proc = Bun.spawn(["claude", "-p", prompt, "--allowed-tools", ""], { stdout: "pipe", stderr: "pipe" });
const answer = (await new Response(proc.stdout).text()).trim();
await proc.exited;
if (!answer) {
  console.error(`${D}  (no output — is \`claude\` logged in? try \`claude -p "hi"\`)${X}`);
  process.exit(1);
}

const restored = await engine.reverseMap(session, answer);
console.log(`\n${B}Claude's answer${X} ${D}(reverse-mapped — any pseudonyms it echoed are restored)${X}`);
console.log(`${C}${restored.split("\n").map((l) => "  " + l).join("\n")}${X}\n`);

console.log(`${B}└─────────────────────────────────────────────────────────────────┘${X}`);
console.log(`${D}  A real model fixed a real bug and never saw an email, path, URL, or your .env.${X}\n`);
