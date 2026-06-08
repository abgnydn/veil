# veil-mcp-server

An example [MCP](https://modelcontextprotocol.io) server that enforces veil's
tier algebra on every prompt. It's the end-to-end consumer of the veil stack:
classify → route → pseudonymize-via-engine → reverse-map, with the two hard
invariants enforced in code.

## What it does

Exposes one tool, **`veil_ask`** (`{ prompt: string }`). For each prompt it:

1. **Classifies** the tier locally (never on a remote model).
2. **Routes** by tier:
   - `public` / `internal` → forwarded to the remote model as-is.
   - `private` → **pseudonymized** through the Rust engine before egress (the
     model sees `EMAIL_1`, not `alice@acme.com`), then the reply is
     **reverse-mapped** back for you.
   - `secret` → sent only to a **local** model; if none is configured, the
     prompt is **withheld** — never sent to a remote LLM (Hard Invariant 1).

The `_meta` on each tool result reports the enforcement trace
(`tier`, `transformed`, `backendId`, `withheld`).

## Run it

The pseudonymization engine must be up first:

```bash
# 1. start the Rust engine (loopback)
cd ../../rust && cargo run --bin veil_server      # http://127.0.0.1:8787

# 2. start this MCP server (stdio)
cd ../examples/mcp-server && npm install && npm start
```

Configuration (env):

| var | default | purpose |
|---|---|---|
| `VEIL_ENGINE_URL` | `http://127.0.0.1:8787` | Rust engine base URL |
| `ANTHROPIC_API_KEY` | _(unset)_ | enables the remote backend |
| `VEIL_REMOTE_MODEL` | `claude-sonnet-4-6` | remote model id |
| `VEIL_LOCAL_URL` | `http://localhost:11434/v1` | local (Ollama) endpoint for secret tier |
| `VEIL_LOCAL_MODEL` | `phi3.5:3.8b` | local model id |
| `VEIL_SESSION_ID` | `mcp-default` | pseudonym session key |

Register in an MCP client (e.g. Claude Desktop `mcpServers`):

```json
{
  "mcpServers": {
    "veil": {
      "command": "bun",
      "args": ["/absolute/path/to/veil/examples/mcp-server/src/server.ts"],
      "env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
    }
  }
}
```

## Test

```bash
npm test          # drives the server through a real MCP Client over in-memory
                  # transport; fake engine + backends, no network. Proves the
                  # protocol round-trips and tier enforcement holds.
```
