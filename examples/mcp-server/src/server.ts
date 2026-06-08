// SPDX-License-Identifier: Apache-2.0

// Runnable stdio MCP server. Register it in any MCP client (Claude Desktop,
// etc.) and prompts flow through veil's tier enforcement.
//
// Wiring:
//   engine  → RustPipelineClient at $VEIL_ENGINE_URL (default loopback 8787).
//             Start it first: `cargo run --bin veil_server` in ../../rust.
//   remote  → AnthropicAdapter (public/internal, and pseudonymized private),
//             enabled only when ANTHROPIC_API_KEY is set.
//   local   → OpenAICompatAdapter (Ollama by default) for secret-tier turns.
//
// If the engine is unreachable, private/secret prompts fail closed rather than
// leak — that is the point.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import {
  AnthropicAdapter,
  OpenAICompatAdapter,
  RustPipelineClient,
  VeilEnforcer,
  type VeilBackend,
} from "../../../ts/index.ts";
import { createVeilMcpServer } from "./veil-mcp.ts";

function buildEnforcer(): VeilEnforcer {
  const engine = new RustPipelineClient({
    baseUrl: process.env.VEIL_ENGINE_URL ?? "http://127.0.0.1:8787",
  });

  let remote: VeilBackend | undefined;
  const apiKey = process.env.ANTHROPIC_API_KEY ?? null;
  if (apiKey) {
    remote = new AnthropicAdapter({
      settings: {
        getApiKey: () => apiKey,
        getDefaultModel: () => process.env.VEIL_REMOTE_MODEL ?? "claude-sonnet-4-6",
      },
    });
  }

  // Local backend for secret-tier turns (and the private fallback). Defaults to
  // Ollama; override with VEIL_LOCAL_URL / VEIL_LOCAL_MODEL.
  const local = new OpenAICompatAdapter({
    baseURL: process.env.VEIL_LOCAL_URL ?? "http://localhost:11434/v1",
    model: process.env.VEIL_LOCAL_MODEL ?? "phi3.5:3.8b",
    skipHealthCheck: true,
  });

  // VEIL_COHORT_K > 1 enables k-anonymous fan-out for private content (costs
  // k× provider calls). Unset → pseudonymize-only.
  const cohortK = Number.parseInt(process.env.VEIL_COHORT_K ?? "1", 10);

  return new VeilEnforcer({
    engine,
    sessionId: process.env.VEIL_SESSION_ID ?? "mcp-default",
    remote,
    local,
    cohortK: Number.isFinite(cohortK) && cohortK > 1 ? cohortK : undefined,
  });
}

async function main(): Promise<void> {
  const server = createVeilMcpServer(buildEnforcer());
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Logs go to stderr — stdout is the MCP wire.
  console.error("veil-mcp: ready on stdio");
}

main().catch((err) => {
  console.error("veil-mcp: fatal", err);
  process.exit(1);
});
