// SPDX-License-Identifier: Apache-2.0

// veil — privacy layer (sensitivity routing + cohort blending + adapters).

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

// Cohort blender (k-anon for the `private` tier)
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

// Rust engine client — the shell's link to the canonical pseudonymizer
export {
  RustPipelineClient,
  RustPipelineError,
  kindFloorTier,
  type RustPipelineClientOpts,
  type CanonicalKind,
  type WireSource,
  type WireSpan,
  type WireAuditReason,
  type WireFinding,
  type PseudonymizeResult,
  type PseudonymizeJsonResult,
} from "./rust-client";

// Veil wrapper — runs the pseudonymization round-trip around any backend's chat
export {
  wrapWithVeil,
  reverseMapStream,
  type WrapOpts,
} from "./veil-wrap";

// Enforcer — tier-enforcement hook a consumer (MCP server) calls end-to-end
export {
  VeilEnforcer,
  collectText,
  type VeilEnforcerOpts,
  type EnforceResult,
  type Dispatched,
  type Withheld,
} from "./enforce";

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

// Adapter — Zero-TVM (experimental, secret-tier-eligible local backend)
export {
  ZeroTVMAdapter,
  ZERO_TVM_DESCRIPTION,
  splitForCompleteAPI,
  type ZeroTVMAdapterOpts,
} from "./zerotvm";

// Adapter — OpenAI-compat HTTP (covers Ollama, LM Studio, llamafile, vLLM,
// llama.cpp via the /v1 surface)
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
