// SPDX-License-Identifier: Apache-2.0

// the host application Veil — privacy layer (sensitivity routing + cohort blending + adapters).
// Per Talos's VEIL.md spec; canonized 2026-04-26 in _pantheon/talos.md.

// Interface + tier algebra + errors
export {
  type Tier,
  type TierScores,
  type PIIKind,
  type PIISpan,
  type ToolCall,
  type ToolSchema,
  type Msg,
  type ChatOpts,
  type Token,
  type BackendCapabilities,
  type VeilBackend,
  BackendUnsupported,
  VeilRoutingError,
  VeilInvariantViolation,
  argmaxTier,
  tierMargin,
  tierRank,
  maxTier,
  bumpTier,
} from "./interface";

// Heuristic classifier (warm-up path, replaced by WebLLM after init)
export {
  classifyTierHeuristic,
  detectPIIHeuristic,
  classifyTierArgmax,
  unsupported,
} from "./classifier";

// Phase 8 cohort blender (k-anon)
export {
  cohortBlend,
  flattenCohort,
  type VaultRef,
  type VaultNeighbor,
  type CohortBlendOpts,
  type CohortPlan,
} from "./cohort";

// Router (input-side checkpoint, fetch-side checkpoint, hard invariants)
export {
  routeMessage,
  type Ctx,
  type RouteResult,
} from "./router";

// Adapter — WebLLM (in-browser, default zero-install backend)
export {
  WebLLMAdapter,
  type WebLLMAdapterOpts,
} from "./webllm";

// Adapter — Anthropic (remote; hard-blocks secret + raw private at constructor + chat entry)
export {
  AnthropicAdapter,
  type AnthropicSettings,
  type AnthropicAdapterOpts,
  type SecretGuard,
} from "./anthropic";

// Adapter — Zero-TVM (the experimental, secret-tier-eligible showcase backend;
// wraps github.com/abgnydn/zero-tvm via a git submodule. See zerotvm.ts for the
// one-time setup command and ZeroTVMCard.tsx for the in-product showcase copy.)
export {
  ZeroTVMAdapter,
  ZERO_TVM_DESCRIPTION,
  splitForCompleteAPI,
  type ZeroTVMAdapterOpts,
} from "./zerotvm";

// Adapter — OpenAI-compat HTTP (lingua-franca local-server backend; covers
// Ollama, LM Studio, llamafile, vLLM, llama.cpp via the /v1 surface)
export {
  OpenAICompatAdapter,
  type OpenAICompatAdapterOpts,
} from "./openai-compat";

// Adapter — transformers.js (in-tab embed + zero-shot tier classifier + NER
// for PII; chat is intentionally unsupported — that's WebLLM's lane)
export {
  TransformersJSAdapter,
  TRANSFORMERS_JS_DEFAULTS,
  type TransformersJSAdapterOpts,
  type InitProgressEvent,
} from "./transformers-js";

// KVKK profile — Themis's regulated-domain bundle for the Example sibling
// deployment. Locks the tool surface, forces per-doc approval, pins TR locale.
// See _pantheon/themis.md.
export {
  KVKK_PROFILE,
  KVKKLockedError,
  assertNotLocked,
  isLockedTool,
  type KVKKProfile,
  type ForcedTierPolicy,
  type AuditVisibility,
  type KVKKLocale,
} from "./kvkk-profile";

// KVKK consent-log PDF formatter — Themis's bar-association-grade export.
// Pure function: takes audit rows + opts, returns a jsPDF doc the caller
// triggers `.save()` on. See `apps/web/src/components/app/KVKKConsentExport.tsx`
// for the SPA wiring.
export {
  formatConsentLog,
  computeRowsHash,
  canonicalizeRow,
  canonicalizeRows,
  consentLogFilename,
  type KVKKAuditRow,
  type KVKKPdfOptions,
} from "./kvkk-pdf";

// KVKK Madde 11 right-to-be-forgotten engine — Themis's deletion flow for
// the Example sibling deployment. Pure async function with a
// dependency-injected I/O surface (Dexie / Yjs / embeddings / audit are
// all caller-supplied). The SPA component
// `apps/web/src/components/app/DataDeletionRequest.tsx` is the
// surface; live wiring to storage is owned by Hephaestus 2/3.
export {
  executeKVKKDeletion,
  computeArgsHash,
  canonicalizeRecord,
  KVKK_DELETE_TOOL,
  KVKK_DELETE_PREVIEW,
  type KVKKGrounds,
  type DeletionRequest,
  type DeletionRecord,
  type DeletionContext,
  type DeletionCandidate,
  type AuditRow,
} from "./kvkk-deletion";

// KVKK Madde 11(b)+(c) Subject Access Request engine — Themis's read-only
// "show me what we have on this subject" flow. Pure async with a
// dependency-injected I/O surface (findDocsBySubject + findConsentRecords
// + appendAuditRow). The SPA component
// `apps/web/src/components/app/DataAccessRequest.tsx` is the
// surface; live wiring to storage is owned by Hephaestus 3.
export {
  executeKVKKSAR,
  computeSARArgsHash,
  canonicalizeSARRecord,
  truncateExcerpt,
  KVKK_SAR_TOOL,
  KVKK_SAR_PREVIEW,
  type SARRequest,
  type SARRecord,
  type SARContext,
  type SARDocMatch,
  type SARConsentRecord,
  type ProcessingPurpose,
  type AuditRow as KVKKSARAuditRow,
} from "./kvkk-sar";

// KVKK SAR PDF formatter — Section 1 - 6 layout, bilingual headings, TR/EN
// cover-sheet language toggle. Companion to kvkk-pdf.ts (consent-log).
export {
  formatSARPdf,
  sarPdfFilename,
  sarJsonFilename,
  type KVKKSARPdfOptions,
} from "./kvkk-sar-pdf";

// Controller-level KVKK Madde 11(c) declarations — purposes, categories,
// recipients, retention, controller contact. Static config Example
// ships with; SAR engine inlines these into every record.
export {
  EXAMPLE_CONTROLLER_CONFIG,
  type KVKKControllerConfig,
} from "./kvkk-controller-config";
