// SPDX-License-Identifier: Apache-2.0

//! Phase 7: the loopback HTTP seam.
//!
//! Wraps one [`VeilPipeline`] per `session_id` behind the wire contract in
//! `docs/CONTRACT.md`. This is the component the TypeScript shell calls — the
//! canonical engine exposed over HTTP. It is the one place that holds raw PII
//! *and* the real↔pseudonym mapping, so it MUST stay bound to `127.0.0.1`
//! (the binary enforces this default; see `bin/veil_server.rs`).
//!
//! Wire types here are the serde mirror of `docs/veil-wire.schema.json`:
//! `CanonicalKind` serializes snake_case (`credit_card`), `WireAuditReason` is
//! an internally-tagged union (`{ "type": "likely_leaked", "kind": ... }`).
//! The internal [`EntityKind`]/[`AuditReason`] types map onto these at the
//! boundary so the engine stays decoupled from the wire format.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::audit::{AuditFinding, AuditReason};
use crate::bitnet::AnyDetector;
use crate::cohort::{
    substitute_pseudonyms, CohortSynthesizer, PromptEntities, StaticPoolSynthesizer,
};
use crate::entities::{EntityKind, RegexDetector};
use crate::pipeline::{Replacement, VeilPipeline};

// ---- Wire vocabulary (mirror of docs/veil-wire.schema.json) ----------------

/// Canonical entity kind on the wire. Serializes snake_case per the contract
/// (`credit_card`, `crypto_address`, `national_id`, `api_key`). The crate's
/// `RegexDetector` mints six of these today; the rest are reserved so the TS
/// shell and a future learned detector share one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalKind {
    Email,
    Url,
    Ip,
    Path,
    Uuid,
    Phone,
    CreditCard,
    Iban,
    CryptoAddress,
    ApiKey,
    Ssn,
    NationalId,
    Dob,
    Person,
    Location,
    Org,
    Custom,
}

impl From<EntityKind> for CanonicalKind {
    fn from(k: EntityKind) -> Self {
        match k {
            EntityKind::Email => Self::Email,
            EntityKind::Path => Self::Path,
            EntityKind::Ip => Self::Ip,
            EntityKind::Url => Self::Url,
            EntityKind::Uuid => Self::Uuid,
            EntityKind::Person => Self::Person,
            EntityKind::Location => Self::Location,
            EntityKind::Org => Self::Org,
        }
    }
}

/// Which detector produced a span. Regex spans are deterministic; `ner`/`llm`
/// are best-effort. The current server emits only `regex`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireSource {
    Regex,
    Ner,
    Llm,
    Context,
}

/// A replaced span on the wire (`docs/CONTRACT.md` §5).
#[derive(Debug, Clone, Serialize)]
pub struct WireSpan {
    pub start: usize,
    pub end: usize,
    pub kind: CanonicalKind,
    pub score: f32,
    pub replacement: String,
    pub source: WireSource,
}

impl From<Replacement> for WireSpan {
    fn from(r: Replacement) -> Self {
        // Source by construction: `RegexDetector` only emits the structural
        // kinds; person/location/org can only come from the learned NER
        // detector (regex has no pattern for names). So kind → source is exact.
        let source = match r.kind {
            EntityKind::Person | EntityKind::Location | EntityKind::Org => WireSource::Ner,
            _ => WireSource::Regex,
        };
        Self {
            start: r.start,
            end: r.end,
            kind: r.kind.into(),
            // No probabilistic score is plumbed through yet; deterministic = 1.0.
            score: 1.0,
            replacement: r.pseudonym,
            source,
        }
    }
}

/// Internally-tagged audit reason: `{ "type": "...", "kind": "..." }`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireAuditReason {
    UnknownPseudonym { kind: CanonicalKind },
    LikelyLeaked { kind: CanonicalKind },
}

/// An audit finding on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct WireFinding {
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub reason: WireAuditReason,
}

impl From<AuditFinding> for WireFinding {
    fn from(f: AuditFinding) -> Self {
        let reason = match f.reason {
            AuditReason::UnknownPseudonym { kind } => {
                WireAuditReason::UnknownPseudonym { kind: kind.into() }
            }
            AuditReason::LikelyLeaked { kind } => {
                WireAuditReason::LikelyLeaked { kind: kind.into() }
            }
        };
        Self {
            start: f.start,
            end: f.end,
            text: f.text,
            reason,
        }
    }
}

// ---- Request / response bodies ---------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TextReq {
    pub session_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct ReplyReq {
    pub session_id: String,
    pub reply: String,
}

#[derive(Debug, Deserialize)]
pub struct JsonReq {
    pub session_id: String,
    pub value: Value,
}

#[derive(Debug, Deserialize)]
pub struct CohortReq {
    pub session_id: String,
    pub text: String,
    /// Cohort size. k<=1 is a no-op (returns the real prompt only).
    pub k: usize,
    /// When true, siblings are topic-diverse decoy sentences (content-hiding)
    /// instead of renumbered copies of the real prompt — for entity profiles
    /// the decoy corpus covers; falls back to renumbered copies otherwise.
    #[serde(default)]
    pub content_hiding: bool,
}

#[derive(Debug, Serialize)]
pub struct PseudonymizeRes {
    pub text: String,
    pub spans: Vec<WireSpan>,
}

#[derive(Debug, Serialize)]
pub struct ReverseMapRes {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct AuditRes {
    pub findings: Vec<WireFinding>,
}

#[derive(Debug, Serialize)]
pub struct PseudonymizeJsonRes {
    pub value: Value,
    pub spans: Vec<WireSpan>,
}

#[derive(Debug, Serialize)]
pub struct ReverseMapJsonRes {
    pub value: Value,
}

#[derive(Debug, Serialize)]
pub struct CohortRes {
    /// k kind-shape-identical prompts: `cohort[real_index]` carries the real
    /// session pseudonyms; the rest are pool-disjoint siblings. The caller fans
    /// out all k, keeps `cohort[real_index]`'s response, drops the rest.
    pub cohort: Vec<String>,
    /// Index of the real prompt within `cohort` (0 in v1 — the caller may
    /// shuffle for positional unlinkability, see docs/CONTRACT.md §9).
    pub real_index: usize,
    /// Cohort size the caller asked for.
    pub requested_k: usize,
    /// Cohort size actually produced. Falls below `requested_k` (down to 1)
    /// when the synthesizer can't build enough disjoint siblings — fail-open,
    /// so the real prompt always ships. log2(achieved_k) bits of entropy.
    pub achieved_k: usize,
}

// ---- Session store ---------------------------------------------------------

struct Session {
    pipeline: VeilPipeline<AnyDetector>,
    last_used_ms: u64,
}

/// In-memory map of `session_id` → pipeline. One pipeline per conversation so
/// pseudonym numbering stays stable within a session and isolated across them.
///
/// `detector` is the template cloned into each new session's pipeline — regex
/// by default, or regex unioned with a learned NER detector (GLiNER via
/// `HttpNerDetector`, set by the binary from `VEIL_DETECTOR_URL`). One config
/// for the whole server; each session still gets its own session table.
pub struct SessionStore {
    sessions: HashMap<String, Session>,
    detector: AnyDetector,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    /// Store backed by the regex-only detector (no learned NER).
    #[must_use]
    pub fn new() -> Self {
        Self::with_detector(AnyDetector::Regex(RegexDetector::new()))
    }

    /// Store backed by a specific detector template, cloned per session.
    #[must_use]
    pub fn with_detector(detector: AnyDetector) -> Self {
        Self {
            sessions: HashMap::new(),
            detector,
        }
    }

    /// Get-or-create the pipeline for `id`, stamping its last-used time.
    fn touch(&mut self, id: &str, now_ms: u64) -> &mut VeilPipeline<AnyDetector> {
        let detector = self.detector.clone();
        let entry = self.sessions.entry(id.to_string()).or_insert_with(|| Session {
            pipeline: VeilPipeline::new(detector),
            last_used_ms: now_ms,
        });
        entry.last_used_ms = now_ms;
        &mut entry.pipeline
    }

    /// Drop a session (and its ability to reverse-map). Returns whether it existed.
    pub fn remove(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Evict sessions idle for at least `ttl_ms` as of `now_ms`. Returns the
    /// count evicted. `now_ms` is injected (not read from the clock) so this is
    /// testable without sleeping. The binary's reaper calls this on a timer;
    /// explicit `DELETE /v1/session/{id}` is the primary cleanup path.
    pub fn evict_idle(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| now_ms.saturating_sub(s.last_used_ms) < ttl_ms);
        before - self.sessions.len()
    }
}

/// Shared, lock-guarded session store handed to every handler.
pub type AppState = Arc<Mutex<SessionStore>>;

/// Wall-clock milliseconds since the Unix epoch. Exposed so the binary's
/// idle-reaper uses the same clock the handlers stamp with.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ---- Handlers --------------------------------------------------------------

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn pseudonymize(
    State(state): State<AppState>,
    Json(req): Json<TextReq>,
) -> Json<PseudonymizeRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());
    let (text, spans) = pipe.pseudonymize_with_spans(&req.text);
    Json(PseudonymizeRes {
        text,
        spans: spans.into_iter().map(WireSpan::from).collect(),
    })
}

async fn reverse_map(
    State(state): State<AppState>,
    Json(req): Json<TextReq>,
) -> Json<ReverseMapRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());
    Json(ReverseMapRes {
        text: pipe.reverse_map(&req.text),
    })
}

async fn audit(State(state): State<AppState>, Json(req): Json<ReplyReq>) -> Json<AuditRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());
    let findings = pipe.audit_reply_async(&req.reply).await;
    Json(AuditRes {
        findings: findings.into_iter().map(WireFinding::from).collect(),
    })
}

async fn pseudonymize_json(
    State(state): State<AppState>,
    Json(req): Json<JsonReq>,
) -> Json<PseudonymizeJsonRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());
    let mut value = req.value;
    let spans = pipe.pseudonymize_json_in_place_collect(&mut value);
    Json(PseudonymizeJsonRes {
        value,
        spans: spans.into_iter().map(WireSpan::from).collect(),
    })
}

async fn reverse_map_json(
    State(state): State<AppState>,
    Json(req): Json<JsonReq>,
) -> Json<ReverseMapJsonRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());
    let mut value = req.value;
    pipe.reverse_map_json_in_place(&mut value);
    Json(ReverseMapJsonRes { value })
}

async fn audit_json(State(state): State<AppState>, Json(req): Json<JsonReq>) -> Json<AuditRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());
    let findings = pipe.audit_json_async(&req.value).await;
    Json(AuditRes {
        findings: findings.into_iter().map(WireFinding::from).collect(),
    })
}

async fn cohort(State(state): State<AppState>, Json(req): Json<CohortReq>) -> Json<CohortRes> {
    let mut store = state.lock().await;
    let pipe = store.touch(&req.session_id, now_ms());

    // 1. Pseudonymize the real prompt (mints into the session table).
    let (real_text, _spans) = pipe.pseudonymize_with_spans(&req.text);

    // 2. Extract its pseudonym set, in first-seen order.
    let real_entities = PromptEntities::from_sanitized_text(&real_text);

    // 3. Synthesize k-1 pool-disjoint siblings. Fail-open: any synth error
    //    (pool exhausted/unsupported, or a pool↔session collision) degrades to
    //    the real prompt only rather than blocking the turn.
    let synth = StaticPoolSynthesizer::with_default_pool();
    let siblings = if req.k <= 1 || synth.assert_disjoint_from_session(pipe.table()).is_err() {
        Vec::new()
    } else {
        synth.synthesize(&real_entities, req.k).unwrap_or_default()
    };

    // 4. Build the cohort: real first, then the siblings. With content-hiding,
    //    siblings are topic-diverse decoy sentences (when the corpus covers the
    //    entity profile); otherwise renumbered copies of the real prompt.
    let mut cohort = Vec::with_capacity(siblings.len() + 1);
    cohort.push(real_text.clone());
    let decoys = if req.content_hiding {
        crate::decoy::decoy_siblings(&real_entities, &siblings)
    } else {
        None
    };
    match decoys {
        Some(texts) => cohort.extend(texts),
        None => {
            for sib in &siblings {
                cohort.push(substitute_pseudonyms(&real_text, &real_entities, sib));
            }
        }
    }

    let achieved_k = cohort.len();
    Json(CohortRes {
        cohort,
        real_index: 0,
        requested_k: req.k,
        achieved_k,
    })
}

async fn delete_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> StatusCode {
    state.lock().await.remove(&session_id);
    StatusCode::NO_CONTENT
}

/// Build the router for the wire contract. The caller owns the `AppState` so
/// it (and tests) can inspect the store and run the idle reaper.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/pseudonymize", post(pseudonymize))
        .route("/v1/reverse-map", post(reverse_map))
        .route("/v1/audit", post(audit))
        .route("/v1/pseudonymize-json", post(pseudonymize_json))
        .route("/v1/reverse-map-json", post(reverse_map_json))
        .route("/v1/audit-json", post(audit_json))
        .route("/v1/cohort", post(cohort))
        .route("/v1/session/{session_id}", delete(delete_session))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pure unit tests (no HTTP) ----

    #[test]
    fn session_store_touch_creates_then_reuses() {
        let mut s = SessionStore::new();
        assert!(s.is_empty());
        let _ = s.touch("a", 100).pseudonymize("mail a@b.com");
        assert_eq!(s.len(), 1);
        // Same id reuses the pipeline → stable pseudonym, no second mint.
        let out = s.touch("a", 200).pseudonymize("again a@b.com");
        assert_eq!(out, "again EMAIL_1");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn session_store_isolates_distinct_sessions() {
        let mut s = SessionStore::new();
        let a = s.touch("a", 0).pseudonymize("x@y.com");
        let b = s.touch("b", 0).pseudonymize("p@q.com");
        // Each session numbers from 1 — isolation.
        assert_eq!(a, "EMAIL_1");
        assert_eq!(b, "EMAIL_1");
    }

    #[test]
    fn evict_idle_drops_only_stale_sessions() {
        let mut s = SessionStore::new();
        let _ = s.touch("old", 1_000);
        let _ = s.touch("fresh", 5_000);
        // now=6000, ttl=2000: old idle 5000 (>=2000) evicted; fresh idle 1000 kept.
        let evicted = s.evict_idle(6_000, 2_000);
        assert_eq!(evicted, 1);
        assert!(s.remove("fresh"));
        assert!(!s.remove("old"));
    }

    /// Spawn a stub learned-NER `/detect` server that flags "Alice" (bytes
    /// 0..5) as a PERSON regardless of input — the kind regex can never find.
    async fn spawn_detect_stub() -> String {
        let app = Router::new().route(
            "/detect",
            post(|| async {
                Json(serde_json::json!({
                    "entities": [{ "kind": "PERSON", "start": 0, "end": 5 }]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn session_store_uses_configured_learned_detector() {
        // With a learned detector wired in (MergeFallback over regex), the
        // store must surface BOTH the learned PERSON and the regex EMAIL —
        // proving the detector template reaches each session's pipeline.
        use crate::{HttpNerDetector, MergeFallback, RegexDetector};
        let detect_url = spawn_detect_stub().await;
        let detector = AnyDetector::BitnetMergeRegex(MergeFallback::new(
            HttpNerDetector::new(detect_url),
            RegexDetector::new(),
        ));
        let mut store = SessionStore::with_detector(detector);
        let out = store.touch("s", 0).pseudonymize("Alice emails a@b.com");
        assert_eq!(out, "PERSON_1 emails EMAIL_1");
    }

    #[test]
    fn canonical_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&CanonicalKind::CreditCard).unwrap(),
            "\"credit_card\""
        );
        assert_eq!(
            serde_json::to_string(&CanonicalKind::from(EntityKind::Ip)).unwrap(),
            "\"ip\""
        );
        assert_eq!(
            serde_json::to_string(&CanonicalKind::NationalId).unwrap(),
            "\"national_id\""
        );
    }

    #[test]
    fn wire_span_source_reflects_detector_by_kind() {
        use crate::Replacement;
        let person = WireSpan::from(Replacement {
            start: 0,
            end: 5,
            kind: EntityKind::Person,
            pseudonym: "PERSON_1".to_string(),
        });
        assert!(matches!(person.source, WireSource::Ner), "person → ner");
        let email = WireSpan::from(Replacement {
            start: 0,
            end: 7,
            kind: EntityKind::Email,
            pseudonym: "EMAIL_1".to_string(),
        });
        assert!(matches!(email.source, WireSource::Regex), "email → regex");
    }

    #[test]
    fn wire_audit_reason_is_internally_tagged() {
        let r = WireAuditReason::LikelyLeaked {
            kind: CanonicalKind::Email,
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({ "type": "likely_leaked", "kind": "email" })
        );
    }

    // ---- HTTP integration (boots the server on an ephemeral loopback port) ----

    async fn spawn_server() -> String {
        let state = Arc::new(Mutex::new(SessionStore::new()));
        let app = build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_text_round_trip_and_session_lifecycle() {
        let base = spawn_server().await;
        let client = reqwest::Client::new();

        // pseudonymize → {text, spans}
        let res: Value = client
            .post(format!("{base}/v1/pseudonymize"))
            .json(&serde_json::json!({"session_id":"s1","text":"email alice@acme.com please"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res["text"], "email EMAIL_1 please");
        assert_eq!(res["spans"][0]["kind"], "email");
        assert_eq!(res["spans"][0]["replacement"], "EMAIL_1");
        assert_eq!(res["spans"][0]["source"], "regex");

        // reverse-map in the same session restores the real entity
        let res: Value = client
            .post(format!("{base}/v1/reverse-map"))
            .json(&serde_json::json!({"session_id":"s1","text":"sent to EMAIL_1"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res["text"], "sent to alice@acme.com");

        // audit flags a raw leak in a reply
        let res: Value = client
            .post(format!("{base}/v1/audit"))
            .json(&serde_json::json!({"session_id":"s1","reply":"I'll email leak@x.com now"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res["findings"][0]["reason"]["type"], "likely_leaked");
        assert_eq!(res["findings"][0]["text"], "leak@x.com");

        // DELETE drops the session
        let resp = client
            .delete(format!("{base}/v1/session/s1"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 204);

        // after delete, EMAIL_1 is unknown → passes through unchanged
        let res: Value = client
            .post(format!("{base}/v1/reverse-map"))
            .json(&serde_json::json!({"session_id":"s1","text":"sent to EMAIL_1"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res["text"], "sent to EMAIL_1");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_cohort_produces_k_indistinguishable_prompts() {
        let base = spawn_server().await;
        let client = reqwest::Client::new();

        let res: Value = client
            .post(format!("{base}/v1/cohort"))
            .json(&serde_json::json!({
                "session_id": "c1",
                "text": "remind alice@acme.com about /Users/baris/notes.md",
                "k": 4
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let cohort = res["cohort"].as_array().unwrap();
        assert_eq!(res["achieved_k"], 4);
        assert_eq!(cohort.len(), 4);
        // Real prompt (index 0) carries the session pseudonyms.
        assert_eq!(cohort[0], "remind EMAIL_1 about PATH_1");
        // Every prompt is kind-shape identical: "remind EMAIL_x about PATH_y".
        let re = regex::Regex::new(r"^remind EMAIL_\d+ about PATH_\d+$").unwrap();
        for p in cohort {
            assert!(re.is_match(p.as_str().unwrap()), "shape mismatch: {p}");
        }
        // The k pseudonym sets must be distinct — else entropy < log2(k).
        let emails: std::collections::HashSet<_> = cohort
            .iter()
            .map(|p| p.as_str().unwrap().split(' ').nth(1).unwrap())
            .collect();
        assert_eq!(emails.len(), 4, "cohort EMAIL slots must be distinct");

        // The real prompt reverse-maps; a sibling's pool pseudonym does not
        // (never minted) — so dropping siblings leaks nothing.
        let real: Value = client
            .post(format!("{base}/v1/reverse-map"))
            .json(&serde_json::json!({"session_id":"c1","text":"done EMAIL_1"}))
            .send().await.unwrap().json().await.unwrap();
        assert_eq!(real["text"], "done alice@acme.com");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_cohort_content_hiding_uses_decoy_sentences() {
        let base = spawn_server().await;
        let client = reqwest::Client::new();
        let res: Value = client
            .post(format!("{base}/v1/cohort"))
            .json(&serde_json::json!({
                "session_id":"ch","text":"remind alice@acme.com now","k":4,"content_hiding":true
            }))
            .send().await.unwrap().json().await.unwrap();
        let cohort = res["cohort"].as_array().unwrap();
        assert_eq!(cohort.len(), 4);
        // The real prompt (index 0) keeps the user's own phrasing.
        assert_eq!(cohort[0], "remind EMAIL_1 now");
        // Siblings are decoy sentences carrying pool pseudonyms — NOT renumbered
        // copies of the real template.
        for sib in &cohort[1..] {
            let s = sib.as_str().unwrap();
            assert!(s.contains("EMAIL_"), "decoy must carry an email pseudonym: {s}");
            assert!(
                !s.starts_with("remind EMAIL_"),
                "sibling should be a decoy, not a renumbered copy: {s}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_cohort_k1_is_real_only() {
        let base = spawn_server().await;
        let client = reqwest::Client::new();
        let res: Value = client
            .post(format!("{base}/v1/cohort"))
            .json(&serde_json::json!({"session_id":"c2","text":"email a@b.com","k":1}))
            .send().await.unwrap().json().await.unwrap();
        assert_eq!(res["achieved_k"], 1);
        assert_eq!(res["cohort"].as_array().unwrap().len(), 1);
        assert_eq!(res["cohort"][0], "email EMAIL_1");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_json_tool_call_round_trip() {
        let base = spawn_server().await;
        let client = reqwest::Client::new();

        // pseudonymize a tool-call argument object
        let res: Value = client
            .post(format!("{base}/v1/pseudonymize-json"))
            .json(&serde_json::json!({
                "session_id":"j1",
                "value": {"to":"alice@acme.com","body":"ship to /Users/baris/out"}
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res["value"]["to"], "EMAIL_1");
        assert_eq!(res["value"]["body"], "ship to PATH_1");
        assert_eq!(res["spans"].as_array().unwrap().len(), 2);

        // reverse-map-json restores both leaves in the same session
        let res: Value = client
            .post(format!("{base}/v1/reverse-map-json"))
            .json(&serde_json::json!({
                "session_id":"j1",
                "value": {"to":"EMAIL_1","note":"path was PATH_1"}
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(res["value"]["to"], "alice@acme.com");
        assert_eq!(res["value"]["note"], "path was /Users/baris/out");
    }
}
