// SPDX-License-Identifier: Apache-2.0
//
// A scripted coding agent working a real task on a private repo — every file it
// reads goes through the veil MCP filesystem server first. Prints exactly what
// the cloud model receives (sanitized) so you can see your repo never leaves
// intact. No model is called; nothing is sent anywhere. Boot the engine first
// (demo.sh does it).

import { resolve } from "node:path";
import { readFile } from "node:fs/promises";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { RustPipelineClient } from "../../ts/index.ts";
import { createVeilFsServer } from "./fs-server.ts";

const B = "\x1b[1m", D = "\x1b[2m", R = "\x1b[31m", G = "\x1b[32m", Y = "\x1b[33m", C = "\x1b[36m", X = "\x1b[0m";
const repoRoot = resolve(import.meta.dir, "repo");

const engine = new RustPipelineClient({ baseUrl: "http://127.0.0.1:8801" });
const server = createVeilFsServer({ engine, sessionId: "task-fix-auth-ttl", repoRoot });
const [clientT, serverT] = InMemoryTransport.createLinkedPair();
await server.connect(serverT);
const client = new Client({ name: "coding-agent", version: "0.0.0" });
await client.connect(clientT);

type Res = { text: string; meta?: Record<string, unknown> };
async function call(tool: string, args: Record<string, unknown>): Promise<Res> {
  const r = (await client.callTool({ name: tool, arguments: args })) as {
    content: Array<{ text?: string }>;
    _meta?: Record<string, unknown>;
  };
  return { text: r.content[0]?.text ?? "", meta: r._meta };
}

function indent(s: string): string {
  return s.split("\n").map((l) => "    " + l).join("\n");
}

console.log(`\n${B}┌─ a coding agent on your private repo — through veil ─────────────┐${X}\n`);
console.log(`${B}TASK${X}  ${C}"Auth tokens expire after 15 min instead of 24h — find and fix it."${X}`);
console.log(`${D}      the agent's model only ever sees what's printed in ${G}green${D} below.${X}\n`);

console.log(`${B}agent →${X} list_dir(${C}"src"${X})`);
console.log(`${G}${indent((await call("list_dir", { path: "src" })).text)}${X}\n`);

console.log(`${B}agent →${X} read_file(${C}"src/auth.ts"${X})   ${D}# the buggy file${X}`);
console.log(`${G}${indent((await call("read_file", { path: "src/auth.ts" })).text)}${X}\n`);

console.log(`${B}agent →${X} read_file(${C}"src/config.ts"${X})`);
const cfg = await call("read_file", { path: "src/config.ts" });
console.log(`${G}${indent(cfg.text)}${X}\n`);

console.log(`${B}agent →${X} read_file(${C}".env"${X})   ${D}# agents love to peek at .env${X}`);
const env = await call("read_file", { path: ".env" });
console.log(`${R}${indent(env.text)}${X}   ${Y}← withheld, never sent${X}\n`);

console.log(`${B}agent →${X} grep(${C}"TTL"${X})`);
console.log(`${G}${indent((await call("grep", { pattern: "TTL" })).text)}${X}\n`);

console.log(`${B}└─────────────────────────────────────────────────────────────────┘${X}\n`);

// The contrast: the real file on disk vs. what the cloud model received.
const realCfg = (await readFile(resolve(repoRoot, "src/config.ts"), "utf8")).trim();
console.log(`${B}Side by side — src/config.ts${X}\n`);
console.log(`  ${B}on your disk${X}                          ${B}what the cloud model saw${X}`);
const a = realCfg.split("\n"), b = cfg.text.trim().split("\n");
for (let i = 0; i < Math.max(a.length, b.length); i++) {
  const l = (a[i] ?? "").padEnd(40).slice(0, 40);
  const r = b[i] ?? "";
  console.log(`  ${R}${l}${X}  ${G}${r}${X}`);
}
console.log(
  `\n${D}  The model had everything it needed to find the bug (TTL in seconds,${X}` +
  `\n${D}  should be ms) — and learned no real email, path, host, or URL. The${X}` +
  `\n${D}  .env never left your machine.${X}\n`,
);

await client.close();
