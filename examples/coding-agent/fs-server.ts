// SPDX-License-Identifier: Apache-2.0

// A veil-pseudonymizing MCP filesystem server — the §3.2 "fetch checkpoint".
//
// It exposes the tools a coding agent lives on (read_file, list_dir, grep), but
// every result is run through veil before the agent (and therefore the cloud
// model) sees it: PII is replaced with stable pseudonyms, and any file that
// contains a credential is WITHHELD entirely. The model does useful work on the
// repo without ever learning a real path, email, internal URL, or secret.

import { readFile, readdir } from "node:fs/promises";
import { resolve, relative, isAbsolute, join } from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { RustPipelineClient, classifyTierArgmax } from "../../ts/index.ts";

export interface VeilFsOpts {
  engine: RustPipelineClient;
  /** Conversation key — one per task, so a file is the same PATH_1 throughout. */
  sessionId: string;
  /** The repo root. All tool paths are resolved within it; escapes are refused. */
  repoRoot: string;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "target", ".venv"]);

function safeResolve(root: string, p: string): string {
  const full = resolve(root, p || ".");
  const rel = relative(root, full);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`path escapes the repo: ${p}`);
  }
  return full;
}

async function walk(root: string, dir: string, out: string[]): Promise<void> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) await walk(root, join(dir, e.name), out);
    } else {
      out.push(relative(root, join(dir, e.name)));
    }
  }
}

export function createVeilFsServer(opts: VeilFsOpts): McpServer {
  const { engine, sessionId, repoRoot } = opts;
  const server = new McpServer(
    { name: "veil-fs", version: "0.1.0" },
    {
      capabilities: { tools: {} },
      instructions:
        "Filesystem tools for a private repo. Results are veil-pseudonymized: " +
        "real identifiers appear as EMAIL_1/PATH_1/…, and files containing " +
        "credentials are withheld. Reason over the pseudonyms; do not ask for raw values.",
    },
  );

  // Withhold a whole file when it carries a credential; otherwise pseudonymize.
  async function sanitize(label: string, content: string): Promise<{ text: string; withheld: boolean }> {
    if (classifyTierArgmax(content) === "secret") {
      return { text: `[veil withheld ${label}: contains a credential — not sent to the model]`, withheld: true };
    }
    const { text } = await engine.pseudonymize(sessionId, content);
    return { text, withheld: false };
  }

  const ok = (text: string, meta: Record<string, unknown> = {}) => ({
    content: [{ type: "text" as const, text }],
    _meta: meta,
  });

  server.registerTool(
    "read_file",
    { description: "Read a file from the repo (veil-sanitized).", inputSchema: { path: z.string() } },
    async ({ path }) => {
      const raw = await readFile(safeResolve(repoRoot, path), "utf8");
      const { text, withheld } = await sanitize(path, raw);
      return ok(text, { tier: withheld ? "secret" : "sanitized", withheld });
    },
  );

  server.registerTool(
    "list_dir",
    { description: "List a directory in the repo.", inputSchema: { path: z.string().default(".") } },
    async ({ path }) => {
      const full = safeResolve(repoRoot, path);
      const names = (await readdir(full, { withFileTypes: true }))
        .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
        .join("\n");
      const { text } = await engine.pseudonymize(sessionId, names);
      return ok(text);
    },
  );

  server.registerTool(
    "grep",
    { description: "Search the repo for a substring (veil-sanitized matches).", inputSchema: { pattern: z.string() } },
    async ({ pattern }) => {
      const files: string[] = [];
      await walk(repoRoot, repoRoot, files);
      const hits: string[] = [];
      for (const rel of files) {
        let content: string;
        try {
          content = await readFile(join(repoRoot, rel), "utf8");
        } catch {
          continue;
        }
        if (classifyTierArgmax(content) === "secret") continue; // never search into a credential file
        content.split("\n").forEach((line, i) => {
          if (line.includes(pattern)) hits.push(`${rel}:${i + 1}: ${line.trim()}`);
        });
      }
      if (hits.length === 0) return ok(`no matches for ${JSON.stringify(pattern)}`);
      const { text } = await engine.pseudonymize(sessionId, hits.join("\n"));
      return ok(text);
    },
  );

  return server;
}
