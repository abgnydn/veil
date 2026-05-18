// SPDX-License-Identifier: Apache-2.0

// Veil — pluggable backend interface (the host application)
//
// One TypeScript surface, every adapter implements it. The router programs
// against this and only this. See ~/the host application/veil/VEIL.md §1 for the
// canonical spec; this file is the code mirror of that contract.
//
// Hard invariants (enforced in adapter constructors / router, NOT at call sites):
//   1. `secret` content NEVER reaches a remote LLM.       (runsLocally === true)
//   2. `private` content NEVER reaches a remote LLM raw.  (cohort-blended only)
// See AnthropicAdapter for the in-code enforcement of (1) on the chat path.

// ---- Tier ladder -----------------------------------------------------------

/** Four-rung sensitivity ladder; matches ~/brain/.brain/CLAUDE.md convention. */
export type Tier = "public" | "internal" | "private" | "secret";

/**
 * Probabilistic classifier output. The brain (router) decides escalation, not
 * the classifier. Sum is ~1.0 within fp tolerance — the runtime audit harness
 * enforces this on the boundary.
 */
export interface TierScores {
  public: number;
  internal: number;
  private: number;
  secret: number;
}

// ---- PII -------------------------------------------------------------------

export type PIIKind =
  | "EMAIL"
  | "PHONE"
  | "PERSON"
  | "LOCATION"
  | "ORG"
  | "URL"
  | "IP_ADDRESS"
  | "CREDIT_CARD"
  | "IBAN"
  | "CRYPTO_ADDRESS"
  | "PATH"
  | "API_KEY"
  | "SSN"
  | "NATIONAL_ID"
  | "DOB"
  | "CUSTOM";

export interface PIISpan {
  /** utf-16 char offset, inclusive. */
  start: number;
  /** utf-16 char offset, exclusive. */
  end: number;
  kind: PIIKind;
  /** detector confidence in [0, 1]. */
  score: number;
  /** Presidio-shaped pseudonym, e.g. "EMAIL_1". */
  replacement: string;
  source: "regex" | "ner" | "llm" | "context";
}

// ---- Chat surface ----------------------------------------------------------

export interface ToolCall {
  id: string;
  name: string;
  /** JSON-serializable arguments. */
  arguments: unknown;
}

export interface ToolSchema {
  name: string;
  description?: string;
  /** JSON-Schema for arguments. */
  parameters: Record<string, unknown>;
}

export interface Msg {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  toolCallId?: string;
  toolCalls?: ToolCall[];
  /**
   * Veil-internal: tier tag attached upstream by the router or fetch checkpoint.
   * Adapters MAY inspect this to enforce hard invariants; the AnthropicAdapter
   * does so unconditionally on chat() entry.
   */
  veilTier?: Tier;
}

export interface ChatOpts {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  stop?: string[];
  jsonMode?: boolean;
  tools?: ToolSchema[];
  signal?: AbortSignal;
  /** Telemetry / audit trail tag. */
  veilTag?: string;
  /** If true, refuse fallback escalation; fail rather than reach a remote backend. */
  forceLocal?: boolean;
}

export interface Token {
  text: string;
  done: boolean;
  toolCalls?: ToolCall[];
  finishReason?: "stop" | "length" | "tool_use" | "aborted" | "error";
}

// ---- Capability matrix ----------------------------------------------------

export interface BackendCapabilities {
  chat: boolean;
  embed: boolean;
  classify: boolean;
  pii: boolean;
  streaming: boolean;
  jsonMode: boolean;
  tools: boolean;
  /**
   * Tiers this adapter is permitted to handle. Anthropic is locked to
   * ['public','internal']; local adapters carry the full ladder.
   * The router's adapter-selection step filters on this BEFORE dispatch.
   */
  maxTiersAllowed: Tier[];
  /** True iff data never leaves the device. Hard-invariant gate for `secret`. */
  runsLocally: boolean;
  /** Vector dimension for embed(); undefined when embed is unsupported. */
  embeddingDim?: number;
}

// ---- The interface every adapter implements -------------------------------

export interface VeilBackend {
  readonly id: string;
  readonly displayName: string;
  readonly capabilities: BackendCapabilities;

  init(): Promise<void>;
  isReady(): boolean;

  classifyTier(text: string): Promise<TierScores>;
  detectPII(text: string): Promise<PIISpan[]>;
  chat(messages: Msg[], opts?: ChatOpts): AsyncIterable<Token>;
  embed(text: string): Promise<Float32Array>;

  dispose?(): Promise<void>;
}

// ---- Errors ---------------------------------------------------------------

export class BackendUnsupported extends Error {
  constructor(method: string, backendId?: string) {
    super(
      backendId
        ? `Backend "${backendId}" does not support method "${method}".`
        : `Backend does not support method "${method}".`,
    );
    this.name = "BackendUnsupported";
  }
}

export class VeilRoutingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VeilRoutingError";
  }
}

/**
 * Thrown by an adapter when a hard invariant fires at call site — e.g.
 * AnthropicAdapter.chat() receiving a Msg tagged `secret`.
 */
export class VeilInvariantViolation extends Error {
  constructor(invariant: 1 | 2, detail: string) {
    super(`Veil hard-invariant ${invariant} violated: ${detail}`);
    this.name = "VeilInvariantViolation";
  }
}

// ---- Helpers --------------------------------------------------------------

/** argmax over a TierScores object. Stable: ties break in ladder order. */
export function argmaxTier(scores: TierScores): Tier {
  // Ladder order matters: when two are tied, prefer the more-cautious tier.
  const ladder: Tier[] = ["secret", "private", "internal", "public"];
  let best: Tier = "public";
  let bestScore = -Infinity;
  for (const t of ladder) {
    const s = scores[t];
    if (s > bestScore) {
      bestScore = s;
      best = t;
    }
  }
  return best;
}

/** Margin between the top tier and the runner-up. Used by the escalation rule. */
export function tierMargin(scores: TierScores): number {
  const tiers: Tier[] = ["public", "internal", "private", "secret"];
  const sorted = tiers.map((t) => scores[t]).sort((a, b) => b - a);
  const top = sorted[0] ?? 0;
  const second = sorted[1] ?? 0;
  return top - second;
}

/**
 * Strict ladder ordering. Used for `tier = max(frontmatter, classified)` in the
 * fetch checkpoint and for "bump one rung up" in the escalation rule.
 */
export function tierRank(t: Tier): 0 | 1 | 2 | 3 {
  switch (t) {
    case "public":
      return 0;
    case "internal":
      return 1;
    case "private":
      return 2;
    case "secret":
      return 3;
  }
}

export function maxTier(a: Tier, b: Tier): Tier {
  return tierRank(a) >= tierRank(b) ? a : b;
}

/** Bump one rung up the ladder. `secret` is the top — it stays at `secret`. */
export function bumpTier(t: Tier): Tier {
  switch (t) {
    case "public":
      return "internal";
    case "internal":
      return "private";
    case "private":
      return "secret";
    case "secret":
      return "secret";
  }
}
