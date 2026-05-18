//! Ternary Veil — privacy-preserving pseudonymization pipeline.
//!
//! Phase 0 shipped a regex-stub `Detector` plus a stable `SessionTable`
//! wired through `VeilPipeline::pseudonymize` and `VeilPipeline::reverse_map`.
//! Phase 1 adds `BitnetDetector` (HTTP → a local `BitNet` inference server)
//! and `FallbackDetector` to compose it with `RegexDetector` as a safety
//! net. Phase 2 promotes the flat table to a session entity graph — surface
//! forms of the same underlying entity (e.g. `Dr. Smith` and `Smith`)
//! collapse onto one `EntityId` — and introduces `EntityKind::Person`.
//! Per-session pipeline isolation lives above this crate in
//! `api::ProviderClient::Veil`, keyed by `MessageRequest.session_id`.
//! Phase 3 adds the `audit` module and `VeilPipeline::audit_reply` — a
//! re-ID auditor that flags pseudonym-shaped tokens this pipeline never
//! minted, plus raw entities that leaked back in the model's reply.

pub mod audit;
pub mod bitnet;
pub mod cohort;
pub mod entities;
pub mod llama;
pub mod pipeline;
pub mod session_table;

pub use audit::{
    apply_redaction, AuditFinding, AuditReason, AuditVerdict, UnknownPseudonymPolicy, VeilPolicy,
    REDACTION_SENTINEL,
};
pub use bitnet::{AnyDetector, BitnetDetector, FallbackDetector, MergeFallback};
pub use cohort::{
    substitute_pseudonyms, CohortError, CohortFailure, CohortPolicy, CohortSynthesizer,
    PromptEntities, StaticPoolSynthesizer,
};
pub use entities::{DetectedEntity, Detector, EntityKind, RegexDetector};
pub use llama::LlamaCompletionDetector;
pub use pipeline::VeilPipeline;
pub use session_table::{EntityId, SessionTable};
