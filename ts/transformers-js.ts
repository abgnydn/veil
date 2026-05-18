// SPDX-License-Identifier: Apache-2.0

// TransformersJSAdapter — embeddings + zero-shot tier classification +
// in-browser NER for PII detection. Backed by `@huggingface/transformers`
// (already in apps/web deps), running on the ONNX Runtime Web WebGPU EP.
//
// This is NOT a chat backend. `chat()` throws BackendUnsupported. WebLLM owns
// the in-tab chat lane; this adapter owns the lane WebLLM doesn't cover —
// embeddings, NER, and classifier heads — which run faster on ONNX with
// smaller models than spinning up a full WebLLM session.
//
// Hard invariant note: runs in-tab, so `runsLocally: true`. We set
// `secretTierAllowed` semantics differently from a chat adapter: the
// capability matrix advertises full tier coverage for embed/classify/PII (those
// methods don't egress data), but the adapter does not chat at all — so the
// VEIL.md §3 router still routes secret-tier *chat* turns to a chat-capable
// local backend (Zero-TVM / WebLLM / OpenAI-compat).
//
// Model defaults (picked per the briefing's spec, all hosted on Hugging Face):
//   - embedding:  "Xenova/multilingual-e5-small"          → 384-dim
//   - classifier: "Xenova/mDeBERTa-v3-base-mnli-xnli"     → zero-shot, multilingual
//   - NER:        "Xenova/bert-base-multilingual-cased-ner-hrl"
//
// The ner default leans on the Xenova HRL multilingual NER (PER / ORG / LOC
// out of the box, plus we map the regex kernel for emails / phones / API
// keys). GLiNER would be an upgrade once verified at April 2026 (see VEIL.md
// §7 decision 6).

import type {
  BackendCapabilities,
  ChatOpts,
  Msg,
  PIIKind,
  PIISpan,
  Tier,
  TierScores,
  Token,
  VeilBackend,
} from "./interface";
import { BackendUnsupported } from "./interface";

// ---- Duck-typed pipeline shapes ------------------------------------------
//
// We describe only what we use, so the adapter typechecks without
// `@huggingface/transformers` installed in the veil package itself (the dep
// lives in apps/web; the dynamic import happens at init() time).

interface Tensor {
  /** Float32Array data buffer for feature-extraction outputs. */
  data: Float32Array | number[];
  dims: number[];
}

type FeatureExtractionPipeline = (
  text: string,
  opts?: { pooling?: "mean" | "cls"; normalize?: boolean },
) => Promise<Tensor>;

interface ZeroShotResult {
  sequence: string;
  labels: string[];
  scores: number[];
}

type ZeroShotPipeline = (
  text: string,
  candidateLabels: string[],
  opts?: { multi_label?: boolean; hypothesis_template?: string },
) => Promise<ZeroShotResult>;

interface NEREntity {
  /** Some pipelines return aggregated entity_group; others return per-token entity. */
  entity_group?: string;
  entity?: string;
  score: number;
  word: string;
  /** UTF-8 byte offsets in the input string (transformers.js exposes char offsets). */
  start?: number;
  end?: number;
}

type TokenClassificationPipeline = (
  text: string,
  opts?: { aggregation_strategy?: "simple" | "first" | "max" | "average" },
) => Promise<NEREntity[]>;

type AnyPipeline =
  | FeatureExtractionPipeline
  | ZeroShotPipeline
  | TokenClassificationPipeline;

interface PipelineFactory {
  (
    task: string,
    model?: string,
    opts?: { device?: "webgpu" | "wasm" | "cpu"; dtype?: string },
  ): Promise<AnyPipeline>;
}

interface TransformersModuleShape {
  pipeline?: PipelineFactory;
}

// ---- Adapter options ------------------------------------------------------

export interface TransformersJSAdapterOpts {
  /** Default: "Xenova/multilingual-e5-small" (384-dim, multilingual). */
  embedModel?: string;

  /** Default: "Xenova/mDeBERTa-v3-base-mnli-xnli" (multilingual zero-shot). */
  classifyModel?: string;

  /** Default: "Xenova/bert-base-multilingual-cased-ner-hrl". */
  nerModel?: string;

  /** Module specifier for the dynamic import. Tests pass `moduleOverride`. */
  moduleSpecifier?: string;

  /** Test seam: inject a pre-built module so the dynamic import never fires. */
  moduleOverride?: TransformersModuleShape;

  /** Optional override of the device hint; default 'webgpu'. */
  device?: "webgpu" | "wasm" | "cpu";

  /** Init-progress callback — emits {type:'init_progress', percent} events. */
  onInitProgress?: (event: InitProgressEvent) => void;
}

export interface InitProgressEvent {
  type: "init_progress";
  /** 0..1 across the full set of pipelines we initialize. */
  percent: number;
  /** Which pipeline is currently being prepared. */
  stage: "embed" | "classify" | "ner" | "done";
}

// ---- Defaults -------------------------------------------------------------

const DEFAULT_EMBED_MODEL = "Xenova/multilingual-e5-small";
const DEFAULT_CLASSIFY_MODEL = "Xenova/mDeBERTa-v3-base-mnli-xnli";
const DEFAULT_NER_MODEL = "Xenova/bert-base-multilingual-cased-ner-hrl";
const DEFAULT_MODULE_SPECIFIER = "@huggingface/transformers";
const E5_SMALL_DIM = 384;

// ---- Tier hypothesis templates (zero-shot NLI) ---------------------------
//
// Each label is a natural-language hypothesis. The XNLI head scores
// entailment between the input text and the hypothesis; the softmax over
// hypotheses gives us TierScores. Templates are intentionally short so
// classification stays fast on a small mDeBERTa model.

const TIER_LABELS: Tier[] = ["public", "internal", "private", "secret"];

const TIER_HYPOTHESES: Record<Tier, string> = {
  public: "publicly shareable information",
  internal: "internal work content",
  private: "personal or confidential information",
  secret: "secrets, credentials, or API keys",
};

const HYPOTHESIS_TEMPLATE = "This text is about {}.";

// ---- NER → PII kind mapping ----------------------------------------------
//
// The HRL multilingual NER model emits PER / ORG / LOC / MISC. We map each
// to the closest PIIKind. Email / phone / IP / API-key detection lives in
// the regex kernel (future) — this adapter focuses on entity-level NER.

function nerLabelToPIIKind(label: string): PIIKind | null {
  // Strip BIO prefix ("B-PER" → "PER").
  const tag = label.replace(/^[BI]-/, "").toUpperCase();
  switch (tag) {
    case "PER":
    case "PERSON":
      return "PERSON";
    case "ORG":
    case "ORGANIZATION":
      return "ORG";
    case "LOC":
    case "LOCATION":
      return "LOCATION";
    case "MISC":
      // Skip MISC — too noisy to flag as PII without context.
      return null;
    default:
      return null;
  }
}

// ---- Adapter --------------------------------------------------------------

export class TransformersJSAdapter implements VeilBackend {
  readonly id = "transformers-js";
  readonly displayName = "transformers.js (in-tab embed + NER + zero-shot)";
  readonly capabilities: BackendCapabilities = {
    chat: false, // not our lane — that's WebLLM's
    embed: true,
    classify: true, // model-backed (zero-shot NLI)
    pii: true, // model-backed (NER) plus future regex kernel layer
    streaming: false,
    jsonMode: false,
    tools: false,
    // The model methods (embed / classify / pii) don't egress; advertise full
    // tier coverage so the router can pick this adapter for any tier's
    // embedding or PII pass. Chat-tier routing is independent (chat=false
    // means the router will never send a chat turn here).
    maxTiersAllowed: ["public", "internal", "private", "secret"],
    runsLocally: true,
    embeddingDim: E5_SMALL_DIM,
  };

  private readonly embedModel: string;
  private readonly classifyModel: string;
  private readonly nerModel: string;
  private readonly moduleSpecifier: string;
  private readonly moduleOverride: TransformersModuleShape | undefined;
  private readonly device: "webgpu" | "wasm" | "cpu";
  private readonly onInitProgress: (event: InitProgressEvent) => void;

  private mod: TransformersModuleShape | null = null;
  private embedPipe: FeatureExtractionPipeline | null = null;
  private classifyPipe: ZeroShotPipeline | null = null;
  private nerPipe: TokenClassificationPipeline | null = null;
  private ready = false;

  /** Test-only: counts dynamic-import invocations. */
  private dynamicImportCount = 0;

  constructor(opts: TransformersJSAdapterOpts = {}) {
    this.embedModel = opts.embedModel ?? DEFAULT_EMBED_MODEL;
    this.classifyModel = opts.classifyModel ?? DEFAULT_CLASSIFY_MODEL;
    this.nerModel = opts.nerModel ?? DEFAULT_NER_MODEL;
    this.moduleSpecifier = opts.moduleSpecifier ?? DEFAULT_MODULE_SPECIFIER;
    this.moduleOverride = opts.moduleOverride;
    this.device = opts.device ?? "webgpu";
    this.onInitProgress = opts.onInitProgress ?? (() => {});
  }

  /**
   * Lazy-loads the three pipelines. First call to embed() / classifyTier() /
   * detectPII() triggers init() automatically; tests call init() explicitly
   * to assert progress events. Each pipeline emits a progress event as it
   * completes so the chat UI can render "downloading model…".
   */
  async init(): Promise<void> {
    if (this.ready) return;

    const mod = this.moduleOverride
      ? this.moduleOverride
      : await this.loadModule();

    this.mod = mod;

    if (typeof mod.pipeline !== "function") {
      throw new Error(
        `TransformersJSAdapter: module "${this.moduleSpecifier}" does not export pipeline().`,
      );
    }

    // Embedding pipeline. e5-small is the default — small, multilingual,
    // 384-dim. The model card recommends mean-pooling + L2-normalize.
    this.embedPipe = (await mod.pipeline("feature-extraction", this.embedModel, {
      device: this.device,
    })) as FeatureExtractionPipeline;
    this.onInitProgress({ type: "init_progress", percent: 1 / 3, stage: "embed" });

    // Zero-shot classifier. mDeBERTa-v3 XNLI is multilingual and small.
    this.classifyPipe = (await mod.pipeline("zero-shot-classification", this.classifyModel, {
      device: this.device,
    })) as ZeroShotPipeline;
    this.onInitProgress({ type: "init_progress", percent: 2 / 3, stage: "classify" });

    // NER pipeline. HRL multilingual NER ships PER / ORG / LOC / MISC.
    this.nerPipe = (await mod.pipeline("token-classification", this.nerModel, {
      device: this.device,
    })) as TokenClassificationPipeline;
    this.onInitProgress({ type: "init_progress", percent: 1, stage: "done" });

    this.ready = true;
  }

  private async loadModule(): Promise<TransformersModuleShape> {
    this.dynamicImportCount += 1;
    return (await import(/* @vite-ignore */ this.moduleSpecifier)) as TransformersModuleShape;
  }

  isReady(): boolean {
    return this.ready;
  }

  /** Test-only accessor: did the dynamic import fire? */
  _dynamicImportCount(): number {
    return this.dynamicImportCount;
  }

  // ---- chat: explicitly unsupported ---------------------------------------

  // eslint-disable-next-line require-yield
  async *chat(_messages: Msg[], _opts?: ChatOpts): AsyncIterable<Token> {
    // transformers.js can run small chat models (Phi-3.5, SmolLM, etc.) but
    // that's WebLLM's lane — bigger models, KV-cache reuse, OpenAI-shaped
    // streaming. This adapter exists for embed / classify / NER. Refusing
    // here is the contract; the router checks capabilities.chat first.
    throw new BackendUnsupported("chat", this.id);
  }

  // ---- embed: feature-extraction -------------------------------------------

  async embed(text: string): Promise<Float32Array> {
    if (!this.ready) await this.init();
    if (!this.embedPipe) {
      throw new Error("TransformersJSAdapter: embed pipeline not ready.");
    }

    const tensor = await this.embedPipe(text, {
      pooling: "mean",
      normalize: true,
    });

    const data = tensor.data;
    if (data instanceof Float32Array) return data;
    return new Float32Array(data);
  }

  // ---- classifyTier: zero-shot NLI ----------------------------------------

  async classifyTier(text: string): Promise<TierScores> {
    if (!this.ready) await this.init();
    if (!this.classifyPipe) {
      throw new Error("TransformersJSAdapter: classify pipeline not ready.");
    }

    const candidateLabels = TIER_LABELS.map((t) => TIER_HYPOTHESES[t]);
    const result = await this.classifyPipe(text, candidateLabels, {
      hypothesis_template: HYPOTHESIS_TEMPLATE,
      multi_label: false,
    });

    // Reverse-map labels back to tiers and copy scores. Pipeline returns
    // labels sorted by score descending, so we look up by label string.
    const scores: TierScores = {
      public: 0,
      internal: 0,
      private: 0,
      secret: 0,
    };
    for (let i = 0; i < result.labels.length; i++) {
      const label = result.labels[i];
      const score = result.scores[i] ?? 0;
      if (label === undefined) continue;
      const tier = TIER_LABELS.find((t) => TIER_HYPOTHESES[t] === label);
      if (tier) scores[tier] = score;
    }

    // Renormalize defensively — multi_label:false should already softmax to
    // sum=1, but rounding errors creep in across pipeline versions.
    const total = scores.public + scores.internal + scores.private + scores.secret;
    if (total > 0 && Math.abs(total - 1) > 1e-3) {
      scores.public /= total;
      scores.internal /= total;
      scores.private /= total;
      scores.secret /= total;
    }

    return scores;
  }

  // ---- detectPII: NER + entity → PIIKind mapping --------------------------

  async detectPII(text: string): Promise<PIISpan[]> {
    if (!this.ready) await this.init();
    if (!this.nerPipe) {
      throw new Error("TransformersJSAdapter: NER pipeline not ready.");
    }

    const entities = await this.nerPipe(text, {
      aggregation_strategy: "simple",
    });

    const counters: Partial<Record<PIIKind, number>> = {};
    const spans: PIISpan[] = [];

    for (const ent of entities) {
      const label = ent.entity_group ?? ent.entity ?? "";
      const kind = nerLabelToPIIKind(label);
      if (!kind) continue;

      const start = ent.start;
      const end = ent.end;
      if (
        typeof start !== "number" ||
        typeof end !== "number" ||
        end <= start ||
        start < 0 ||
        end > text.length
      ) {
        // Drop entities without a valid char span — we can't redact what we
        // can't locate. The regex kernel layer will catch obvious patterns
        // (emails / phones) the model missed.
        continue;
      }

      counters[kind] = (counters[kind] ?? 0) + 1;
      spans.push({
        start,
        end,
        kind,
        score: ent.score,
        replacement: `${kind}_${counters[kind]}`,
        source: "ner",
      });
    }

    return spans;
  }

  async dispose(): Promise<void> {
    this.embedPipe = null;
    this.classifyPipe = null;
    this.nerPipe = null;
    this.mod = null;
    this.ready = false;
  }
}

// ---- Re-exported model defaults (Settings UI reads these to label the radios) ---

export const TRANSFORMERS_JS_DEFAULTS = {
  embedModel: DEFAULT_EMBED_MODEL,
  classifyModel: DEFAULT_CLASSIFY_MODEL,
  nerModel: DEFAULT_NER_MODEL,
  embeddingDim: E5_SMALL_DIM,
} as const;
