// SPDX-License-Identifier: Apache-2.0

// Heuristic-only first-pass tier classifier.
//
// Cheap and predictable. Returns probabilistic scores summing to ~1.0 so the
// router can apply its escalation rule (`marginal < 0.2 → bump one rung`).
// Replaced later by an LLM-backed classifier (transformers.js distilled head)
// once that ships. The heuristic stays as the warm-up classifier (used while
// WebLLM is still downloading weights) and as a fallback when the model fails.
//
// Heuristics, in priority order:
//   1. `.env`-style content or YAML `sensitivity: secret` frontmatter → secret.
//   2. API-key / token-shaped strings → secret.
//   3. Medical / legal / financial keywords → private.
//   4. Personal-life keywords (family, relationships, mental health) → private.
//   5. Default → internal.
//
// `public` is intentionally never the heuristic's argmax — the brain values
// false-positive caution. Promotion to `public` happens only via explicit
// frontmatter on stored docs or via a more expressive classifier.

import type { PIISpan, Tier, TierScores } from "./interface";
import { BackendUnsupported } from "./interface";

// ---- Keyword catalogues ---------------------------------------------------

const PRIVATE_KEYWORDS_MEDICAL = [
  "diagnosis",
  "diagnosed",
  "prescription",
  "medication",
  "doctor",
  "therapist",
  "therapy",
  "depression",
  "anxiety",
  "mental health",
  "panic attack",
  "hospital",
  "patient",
  "symptom",
  "dosage",
  "mg ",
  "mri",
  "x-ray",
  "blood test",
  "biopsy",
];

const PRIVATE_KEYWORDS_LEGAL = [
  "lawsuit",
  "lawyer",
  "attorney",
  "court",
  "settlement",
  "deposition",
  "subpoena",
  "plaintiff",
  "defendant",
  "litigation",
  "legal advice",
  "confidential",
  "non-disclosure",
  "nda",
  "indictment",
  "case number",
];

const PRIVATE_KEYWORDS_FINANCIAL = [
  "bank account",
  "iban",
  "routing number",
  "credit card",
  "social security",
  "ssn",
  "tax return",
  "salary",
  "income",
  "net worth",
  "loan",
  "mortgage",
  "balance is",
  "account balance",
  "wire transfer",
];

const PRIVATE_KEYWORDS_PERSONAL = [
  "my sister",
  "my brother",
  "my mother",
  "my father",
  "my mom",
  "my dad",
  "my wife",
  "my husband",
  "my partner",
  "my girlfriend",
  "my boyfriend",
  "my son",
  "my daughter",
  "my child",
  "my kids",
  "my family",
  "fight with",
  "argued with",
  "broke up",
  "divorce",
  "miscarriage",
  "addiction",
];

const PRIVATE_KEYWORDS = [
  ...PRIVATE_KEYWORDS_MEDICAL,
  ...PRIVATE_KEYWORDS_LEGAL,
  ...PRIVATE_KEYWORDS_FINANCIAL,
  ...PRIVATE_KEYWORDS_PERSONAL,
];

const SECRET_KEYWORDS = [
  "api_key",
  "api key",
  "secret_key",
  "secret key",
  "private_key",
  "private key",
  "access_token",
  "access token",
  "bearer ",
  "password:",
  "passwd:",
  "pwd:",
];

// ---- Patterns -------------------------------------------------------------

/** YAML frontmatter `sensitivity: secret` (case-insensitive). */
const FRONTMATTER_SECRET_RE = /^---[\s\S]*?\n\s*sensitivity\s*:\s*secret\s*\n[\s\S]*?---/im;

/** YAML frontmatter `sensitivity: private`. */
const FRONTMATTER_PRIVATE_RE = /^---[\s\S]*?\n\s*sensitivity\s*:\s*private\s*\n[\s\S]*?---/im;

/** A line shaped like `KEY=value` or `KEY="value"` — .env / shell export. */
const ENV_STYLE_RE = /(^|\n)\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}=\s*["']?[^\s"'\n]{6,}/m;

/** API-key-shaped tokens: long base64-ish or `sk-`/`pk-` prefixed strings. */
const API_KEY_RE = /\b(?:sk-[A-Za-z0-9_-]{20,}|pk_[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|[A-Za-z0-9_-]{40,})\b/;

// ---- Scoring --------------------------------------------------------------

interface RawSignal {
  matched: number; // count of distinct matched keywords/patterns
  weight: number; // accumulated weight
}

function countKeywords(haystack: string, needles: string[]): RawSignal {
  let matched = 0;
  let weight = 0;
  for (const n of needles) {
    if (haystack.includes(n)) {
      matched += 1;
      weight += n.length >= 8 ? 2 : 1; // longer phrases are stronger evidence
    }
  }
  return { matched, weight };
}

/**
 * Heuristic tier classifier. Always returns scores summing to 1.0 within
 * fp tolerance — see `interface.ts` for the contract.
 */
export function classifyTierHeuristic(text: string): TierScores {
  const lower = text.toLowerCase();

  // ---- Step 1: hard signals for SECRET ------------------------------------
  if (FRONTMATTER_SECRET_RE.test(text)) {
    return { public: 0.0, internal: 0.05, private: 0.1, secret: 0.85 };
  }

  if (ENV_STYLE_RE.test(text) || API_KEY_RE.test(text)) {
    return { public: 0.0, internal: 0.05, private: 0.15, secret: 0.8 };
  }

  const secretKw = countKeywords(lower, SECRET_KEYWORDS);
  if (secretKw.matched >= 1) {
    return { public: 0.02, internal: 0.08, private: 0.2, secret: 0.7 };
  }

  // ---- Step 2: PRIVATE signals -------------------------------------------
  if (FRONTMATTER_PRIVATE_RE.test(text)) {
    return { public: 0.02, internal: 0.08, private: 0.8, secret: 0.1 };
  }

  const privateKw = countKeywords(lower, PRIVATE_KEYWORDS);
  if (privateKw.matched >= 1) {
    // More matches → more confident. Cap so margin stays interpretable.
    const conf = Math.min(0.55 + privateKw.matched * 0.07, 0.85);
    const remainder = 1 - conf;
    return {
      public: remainder * 0.05,
      internal: remainder * 0.6,
      private: conf,
      secret: remainder * 0.35,
    };
  }

  // ---- Step 3: default to INTERNAL ---------------------------------------
  // Mild margin so the escalation rule (`marginal < 0.2`) doesn't fire on
  // every neutral sentence and bump everything to private.
  return { public: 0.25, internal: 0.55, private: 0.15, secret: 0.05 };
}

/**
 * No-op PII detector for the heuristic path. Real detection is the regex
 * kernel (`pii-regex.ts`, future) + Presidio sidecar / transformers.js NER.
 * Adapters that lack PII detection delegate here so the call doesn't throw —
 * they advertise `capabilities.pii: false` and the router checks before use.
 */
export function detectPIIHeuristic(_text: string): PIISpan[] {
  return [];
}

/** Convenience: argmax-style tier from heuristic scores. */
export function classifyTierArgmax(text: string): Tier {
  const scores = classifyTierHeuristic(text);
  let best: Tier = "internal";
  let bestScore = -Infinity;
  const tiers: Tier[] = ["secret", "private", "internal", "public"];
  for (const t of tiers) {
    if (scores[t] > bestScore) {
      bestScore = scores[t];
      best = t;
    }
  }
  return best;
}

/**
 * Helper for adapters whose `classifyTier`/`detectPII` is "unsupported, use
 * the heuristic fallback". Keeps the BackendUnsupported throw centralized.
 */
export function unsupported(method: string, backendId?: string): never {
  throw new BackendUnsupported(method, backendId);
}
