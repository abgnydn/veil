// SPDX-License-Identifier: Apache-2.0

// RustPipelineClient — the TS shell's link to the canonical Rust engine.
//
// The pseudonymization round-trip (detect → substitute → stable session table
// → reverse-map) lives in Rust (`VeilPipeline`). This client speaks the wire
// contract in `docs/CONTRACT.md` / `docs/veil-wire.schema.json` to a loopback
// `veil_server`, so the TS side stops pretending to pseudonymize (the old
// `detectPIIHeuristic` returned `[]`) and defers to the engine that actually
// works.
//
// Determinism is the server's job: this client never mints pseudonyms or keeps
// a table. Same `sessionId` → stable `EMAIL_1` across calls, because one Rust
// pipeline backs each session. See `wrapWithVeil` in `veil-wrap.ts` for the
// chat-path integration.

import type { Tier } from "./interface";

// ---- Wire vocabulary (mirror of docs/veil-wire.schema.json) ----------------

/** Canonical entity kind on the wire. snake_case per the contract. */
export type CanonicalKind =
  | "email"
  | "url"
  | "ip"
  | "path"
  | "uuid"
  | "phone"
  | "credit_card"
  | "iban"
  | "crypto_address"
  | "api_key"
  | "ssn"
  | "national_id"
  | "dob"
  | "person"
  | "location"
  | "org"
  | "custom";

export type WireSource = "regex" | "ner" | "llm" | "context";

/** A replaced span. Offsets are UTF-8 byte offsets (CONTRACT.md §3). */
export interface WireSpan {
  start: number;
  end: number;
  kind: CanonicalKind;
  score: number;
  replacement: string;
  source: WireSource;
}

export type WireAuditReason =
  | { type: "unknown_pseudonym"; kind: CanonicalKind }
  | { type: "likely_leaked"; kind: CanonicalKind };

export interface WireFinding {
  start: number;
  end: number;
  text: string;
  reason: WireAuditReason;
}

export interface PseudonymizeResult {
  text: string;
  spans: WireSpan[];
}

export interface PseudonymizeJsonResult {
  value: unknown;
  spans: WireSpan[];
}

// ---- Client ----------------------------------------------------------------

export interface RustPipelineClientOpts {
  /** Engine base URL. Loopback by default — the server holds raw PII. */
  baseUrl?: string;
  /** Test seam: inject a fetch impl. Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout in ms. Default 5000. */
  timeoutMs?: number;
}

const DEFAULT_BASE_URL = "http://127.0.0.1:8787";
const DEFAULT_TIMEOUT_MS = 5000;

export class RustPipelineError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "RustPipelineError";
  }
}

export class RustPipelineClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: RustPipelineClientOpts = {}) {
    const raw = opts.baseUrl ?? DEFAULT_BASE_URL;
    this.baseUrl = raw.endsWith("/") ? raw.slice(0, -1) : raw;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** True iff the engine answers `GET /v1/health` with 2xx. Never throws —
   *  the shell uses this to decide whether to fall back to browser NER. */
  async health(): Promise<boolean> {
    try {
      const res = await this.raw("GET", "/v1/health");
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Detect + substitute. Mints/reuses pseudonyms in `sessionId`'s table. */
  async pseudonymize(sessionId: string, text: string): Promise<PseudonymizeResult> {
    return this.post<PseudonymizeResult>("/v1/pseudonymize", { session_id: sessionId, text });
  }

  /** Rewrite pseudonyms this session minted back to real entities. Unknown
   *  pseudonyms pass through unchanged (the engine never guesses). */
  async reverseMap(sessionId: string, text: string): Promise<string> {
    const res = await this.post<{ text: string }>("/v1/reverse-map", {
      session_id: sessionId,
      text,
    });
    return res.text;
  }

  /** Audit a RAW model reply (call before reverse-map) for re-ID signal. */
  async audit(sessionId: string, reply: string): Promise<WireFinding[]> {
    const res = await this.post<{ findings: WireFinding[] }>("/v1/audit", {
      session_id: sessionId,
      reply,
    });
    return res.findings;
  }

  /** Pseudonymize every string leaf of a tool-call JSON value. */
  async pseudonymizeJson(sessionId: string, value: unknown): Promise<PseudonymizeJsonResult> {
    return this.post<PseudonymizeJsonResult>("/v1/pseudonymize-json", {
      session_id: sessionId,
      value,
    });
  }

  /** Reverse-map every string leaf of a tool-call JSON value. */
  async reverseMapJson(sessionId: string, value: unknown): Promise<unknown> {
    const res = await this.post<{ value: unknown }>("/v1/reverse-map-json", {
      session_id: sessionId,
      value,
    });
    return res.value;
  }

  /** Audit every string leaf of a tool-call JSON value. */
  async auditJson(sessionId: string, value: unknown): Promise<WireFinding[]> {
    const res = await this.post<{ findings: WireFinding[] }>("/v1/audit-json", {
      session_id: sessionId,
      value,
    });
    return res.findings;
  }

  /** Drop a session's table (and its ability to reverse-map). Call on end. */
  async deleteSession(sessionId: string): Promise<void> {
    await this.raw("DELETE", `/v1/session/${encodeURIComponent(sessionId)}`);
  }

  // ---- transport ----------------------------------------------------------

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await this.raw("POST", path, body);
    if (!res.ok) {
      const detail = await safeText(res);
      throw new RustPipelineError(
        `veil_server ${path} → HTTP ${res.status}: ${detail}`,
        res.status,
      );
    }
    return (await res.json()) as T;
  }

  private async raw(method: string, path: string, body?: unknown): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers: body !== undefined ? { "content-type": "application/json" } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      throw new RustPipelineError(
        `veil_server ${method} ${path} unreachable at ${this.baseUrl}: ${String(err)}`,
      );
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Map a wire `CanonicalKind` to the tier its presence most implies. Used by
 *  callers that want a quick "this text has secrets" signal from spans without
 *  a separate classify call. `api_key`/`ssn`/`credit_card`/`iban` read as
 *  `secret`; identifying-but-not-credential kinds read as `private`. */
export function kindFloorTier(kind: CanonicalKind): Tier {
  switch (kind) {
    case "api_key":
    case "ssn":
    case "credit_card":
    case "iban":
    case "crypto_address":
    case "national_id":
      return "secret";
    default:
      return "private";
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "<unreadable body>";
  }
}
