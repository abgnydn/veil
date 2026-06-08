// SPDX-License-Identifier: Apache-2.0

// e2e.test.ts — drives the veil MCP server through a real MCP Client over the
// SDK's in-memory transport. No network, no LLM: a fake engine + fake backends
// prove the protocol round-trips AND that tier enforcement holds at the MCP
// boundary (private pseudonymized before egress; secret withheld).

import { describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  RustPipelineClient,
  VeilEnforcer,
  type Msg,
  type TierScores,
  type Token,
  type VeilBackend,
} from "../../../ts/index.ts";
import { createVeilMcpServer } from "../src/veil-mcp.ts";

// ---- fakes (mirror ts/enforce.test.ts) -------------------------------------

function fakeEngine(table: Record<string, string>): RustPipelineClient {
  const inverse = Object.fromEntries(Object.entries(table).map(([k, v]) => [v, k]));
  const fetchImpl = (async (url: string, init: RequestInit = {}) => {
    const path = url.replace(/^.*\/v1/, "/v1");
    const req = JSON.parse((init.body as string) ?? "{}");
    if (path === "/v1/pseudonymize") {
      let text = req.text;
      for (const [real, pseudo] of Object.entries(table)) text = text.split(real).join(pseudo);
      return Response.json({ text, spans: [] });
    }
    if (path === "/v1/reverse-map") {
      let text = req.text;
      for (const [pseudo, real] of Object.entries(inverse)) text = text.split(pseudo).join(real);
      return Response.json({ text });
    }
    throw new Error(`unexpected ${path}`);
  }) as unknown as typeof fetch;
  return new RustPipelineClient({ fetchImpl });
}

function recordingBackend(id: string, runsLocally: boolean, sink: { seen: Msg[][] }): VeilBackend {
  return {
    id,
    displayName: id,
    capabilities: {
      chat: true,
      embed: false,
      classify: false,
      pii: false,
      streaming: true,
      jsonMode: false,
      tools: false,
      maxTiersAllowed: runsLocally
        ? ["public", "internal", "private", "secret"]
        : ["public", "internal"],
      runsLocally,
    },
    async init() {},
    isReady: () => true,
    async classifyTier() {
      throw new Error("unused");
    },
    async detectPII() {
      return [];
    },
    async embed() {
      throw new Error("unused");
    },
    async *chat(messages: Msg[]): AsyncIterable<Token> {
      sink.seen.push(messages);
      const u = messages.find((m) => m.role === "user");
      yield { text: `reply: ${u?.content ?? ""}`, done: false };
      yield { text: "", done: true, finishReason: "stop" };
    },
  };
}

function fixedTier(tier: keyof TierScores): (t: string) => TierScores {
  const base: TierScores = { public: 0, internal: 0, private: 0, secret: 0 };
  return () => ({ ...base, [tier]: 1 });
}

/** Connect an MCP Client to a server built around `enforcer`, in-process. */
async function connect(enforcer: VeilEnforcer): Promise<Client> {
  const server = createVeilMcpServer(enforcer);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "veil-test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  return client;
}

type ToolResult = {
  content: Array<{ type: string; text?: string }>;
  _meta?: Record<string, unknown>;
};

// ---- tests -----------------------------------------------------------------

describe("veil MCP server — protocol + tier enforcement", () => {
  test("tools/list advertises veil_ask", async () => {
    const client = await connect(
      new VeilEnforcer({ engine: fakeEngine({}), sessionId: "s", classify: fixedTier("internal") }),
    );
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain("veil_ask");
    await client.close();
  });

  test("private prompt: remote sees the pseudonym, caller gets the real entity", async () => {
    const remoteSink = { seen: [] as Msg[][] };
    const client = await connect(
      new VeilEnforcer({
        engine: fakeEngine({ "alice@acme.com": "EMAIL_1" }),
        sessionId: "s",
        remote: recordingBackend("anthropic", false, remoteSink),
        classify: fixedTier("private"),
      }),
    );

    const res = (await client.callTool({
      name: "veil_ask",
      arguments: { prompt: "remind alice@acme.com" },
    })) as ToolResult;

    // Caller (the MCP client) sees the real entity, reverse-mapped.
    expect(res.content[0]?.text).toBe("reply: remind alice@acme.com");
    expect(res._meta?.tier).toBe("private");
    expect(res._meta?.transformed).toBe(true);
    expect(res._meta?.backendId).toBe("veil(anthropic)");
    // The remote model only ever saw the pseudonym.
    expect(remoteSink.seen[0]?.[0]?.content).toBe("remind EMAIL_1");
    expect(remoteSink.seen[0]?.[0]?.content).not.toContain("alice@acme.com");
    await client.close();
  });

  test("secret prompt with no local backend is WITHHELD; remote never touched", async () => {
    const remoteSink = { seen: [] as Msg[][] };
    const client = await connect(
      new VeilEnforcer({
        engine: fakeEngine({}),
        sessionId: "s",
        remote: recordingBackend("anthropic", false, remoteSink),
        classify: fixedTier("secret"),
      }),
    );

    const res = (await client.callTool({
      name: "veil_ask",
      arguments: { prompt: "API_KEY=hunter2hunter2hunter2" },
    })) as ToolResult;

    expect(res.content[0]?.text).toMatch(/withheld/i);
    expect(res._meta?.withheld).toBe(true);
    expect(res._meta?.tier).toBe("secret");
    expect(remoteSink.seen).toHaveLength(0);
    await client.close();
  });

  test("public/internal prompt passes through to the remote untransformed", async () => {
    const remoteSink = { seen: [] as Msg[][] };
    const client = await connect(
      new VeilEnforcer({
        engine: fakeEngine({}),
        sessionId: "s",
        remote: recordingBackend("anthropic", false, remoteSink),
        classify: fixedTier("internal"),
      }),
    );

    const res = (await client.callTool({
      name: "veil_ask",
      arguments: { prompt: "what is the capital of France" },
    })) as ToolResult;

    expect(res.content[0]?.text).toBe("reply: what is the capital of France");
    expect(res._meta?.transformed).toBe(false);
    expect(remoteSink.seen[0]?.[0]?.content).toBe("what is the capital of France");
    await client.close();
  });
});
