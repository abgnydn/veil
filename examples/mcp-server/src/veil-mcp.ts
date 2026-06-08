// SPDX-License-Identifier: Apache-2.0

// A real MCP server that enforces veil's tier algebra on every prompt.
//
// One tool, `veil_ask`: the model behind it never sees raw PII (private content
// is pseudonymized via the Rust engine before egress and reverse-mapped on the
// way back), and secret content is withheld from remote models entirely. This
// is the "realistic end-to-end consumer" from the veil Resume — the MCP layer
// is thin; the enforcement is `VeilEnforcer` from the core library.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { VeilEnforcer, collectText } from "../../../ts/index.ts";

/**
 * Build an MCP server exposing `veil_ask`, backed by the given enforcer.
 * The caller wires the enforcer with a Rust engine client + the backends it
 * wants (remote for public/internal/pseudonymized-private, local for secret).
 */
export function createVeilMcpServer(enforcer: VeilEnforcer): McpServer {
  const server = new McpServer(
    { name: "veil-mcp", version: "0.1.0" },
    {
      capabilities: { tools: {} },
      instructions:
        "Ask LLMs through veil. Prompts are tier-classified locally; private " +
        "content is pseudonymized before it reaches a remote model and " +
        "restored in the reply, and secret content never leaves the device.",
    },
  );

  server.registerTool(
    "veil_ask",
    {
      description:
        "Ask an LLM with veil tier-enforcement. Private content (emails, paths, " +
        "names) is pseudonymized before egress and restored in the reply; " +
        "secret content (keys, credentials, IDs) is withheld from remote models.",
      inputSchema: {
        prompt: z.string().describe("The user's prompt; may contain PII."),
      },
    },
    async ({ prompt }) => {
      const result = await enforcer.enforce(prompt);

      if (result.withheld) {
        return {
          content: [
            {
              type: "text" as const,
              text: `[veil withheld this prompt — ${result.reason}]`,
            },
          ],
          // Machine-readable enforcement trace for callers that inspect it.
          _meta: { tier: result.tier, withheld: true, escalated: result.escalated },
        };
      }

      const text = await collectText(result.stream);
      return {
        content: [{ type: "text" as const, text }],
        _meta: {
          tier: result.tier,
          withheld: false,
          escalated: result.escalated,
          backendId: result.backendId,
          transformed: result.transformed,
        },
      };
    },
  );

  return server;
}
