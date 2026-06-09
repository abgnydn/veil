# veil-coding-agent-demo

The "holy shit" artifact: a coding agent working a real task on a private repo,
where **every file it reads is veil-sanitized before the model sees it**.

```bash
npm install
./demo.sh          # boots the engine, runs the scripted agent, prints the wire
```

It drives a real MCP filesystem server (`fs-server.ts`) — `read_file`,
`list_dir`, `grep` — through a real MCP client. No model is called and nothing
leaves your machine; the demo prints exactly what a cloud model *would* receive.

## What you see

The agent is told *"auth tokens expire after 15 min instead of 24h — fix it."*
It lists `src/`, reads `auth.ts` and `config.ts`, peeks at `.env`, greps for the
bug. What the model receives:

- `auth.ts` / `config.ts` → real values replaced with stable pseudonyms:
  `sarah.chen@acme.com` → `EMAIL_1`, `https://auth.internal.acme.dev` → `URL_1`,
  `/Users/baris/...` → `PATH_1`, `10.0.4.17` → `IP_1`.
- **`.env` → withheld entirely** — it contains an AWS key and a DB URL, so it is
  never sent to the model (`[veil withheld .env: contains a credential]`).
- The bug (`TOKEN_TTL = 15 * 60`, seconds not ms) survives untouched, so the
  model can still find and fix it.

The model does the job; your cloud provider's logs contain none of your real
identifiers, and your secrets never left the machine.

## How it works (the §3.2 fetch checkpoint)

`fs-server.ts` is an MCP server whose tool *results* pass through veil:

```
agent: read_file("src/config.ts")
   → server reads the real file
   → classify: credential? → withhold.  else → engine.pseudonymize(...)
   → returns sanitized text; the agent's model only ever sees that
```

Stable per-session pseudonyms mean a file is the same `PATH_1` across the whole
task, so the model can reason about it normally. Point this server at a real
agent (Claude Desktop, Cursor, a CLI loop) and the same protection applies live.

`repo/.env` holds **fake** credentials on purpose — it's the file the demo
withholds.
