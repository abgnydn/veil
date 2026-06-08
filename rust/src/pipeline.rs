//! The public pipeline. Owns a `Detector` + `SessionTable` and exposes
//! two operations: pseudonymize an outbound prompt, reverse-map an inbound
//! reply.

use regex::Regex;
use serde_json::Value;

use crate::audit::{AuditFinding, AuditReason};
use crate::entities::{Detector, EntityKind, RegexDetector};
use crate::session_table::SessionTable;

/// One entity replaced during pseudonymization: where it was in the input
/// (UTF-8 byte offsets, per `docs/CONTRACT.md` §3) and the pseudonym it became.
/// Returned by [`VeilPipeline::pseudonymize_with_spans`] so the HTTP seam can
/// report `{ text, spans }` without re-running detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// Byte offset (inclusive) of the original entity in the input.
    pub start: usize,
    /// Byte offset (exclusive) of the original entity in the input.
    pub end: usize,
    pub kind: EntityKind,
    /// The minted-or-reused pseudonym, e.g. `EMAIL_1`.
    pub pseudonym: String,
}

/// Guard against pathological nesting when walking tool-call JSON. Most
/// real tool inputs are shallow (two or three levels); 32 leaves plenty of
/// headroom without risk of stack-blowing on a crafted payload.
const MAX_JSON_DEPTH: usize = 32;

/// Keys inside a tool's JSON input whose VALUES should be left untouched
/// by the walker. `system` and `role` are Anthropic wire-protocol names;
/// a well-behaved tool shouldn't embed one, but if it does, those values
/// are control keywords (`"user"`, `"assistant"`) rather than user PII,
/// and rewriting them could confuse downstream consumers.
const RESERVED_JSON_KEYS: &[&str] = &["system", "role"];

/// Two-direction pipeline. Generic over the detector so Phase 1 can plug
/// in a BitNet-backed one without touching this type.
#[derive(Debug)]
pub struct VeilPipeline<D: Detector = RegexDetector> {
    detector: D,
    table: SessionTable,
    /// Compiled once, used by `reverse_map` to find pseudonyms in a reply.
    pseudonym_pattern: Regex,
}

impl VeilPipeline<RegexDetector> {
    /// Convenience: build a pipeline with the default regex detector.
    #[must_use]
    pub fn with_default_regex() -> Self {
        Self::new(RegexDetector::new())
    }
}

impl<D: Detector> VeilPipeline<D> {
    /// Build a pipeline around the given detector with an empty session table.
    pub fn new(detector: D) -> Self {
        // Single-sourced from `EntityKind::ALL` so a new kind needs no second
        // edit here. Deliberately the *known* prefixes, not an open
        // `[A-Z]+_\d+`: the audit scanner flags unknown pseudonyms, and an
        // open pattern would mis-flag natural tokens like `ROOM_101`.
        let alternation = EntityKind::ALL
            .iter()
            .map(|k| k.as_prefix())
            .collect::<Vec<_>>()
            .join("|");
        let pseudonym_pattern = Regex::new(&format!(r"\b({alternation})_\d+\b"))
            .expect("pseudonym pattern must compile");
        Self {
            detector,
            table: SessionTable::new(),
            pseudonym_pattern,
        }
    }

    /// Read-only access to the session table — useful for tests and
    /// inspection.
    #[must_use]
    pub fn table(&self) -> &SessionTable {
        &self.table
    }

    /// Replace detected entities in `input` with stable pseudonyms drawn
    /// from the session table. Entities seen in a prior call reuse the
    /// same pseudonym.
    pub fn pseudonymize(&mut self, input: &str) -> String {
        self.pseudonymize_with_spans(input).0
    }

    /// Like [`Self::pseudonymize`] but also returns the [`Replacement`] spans
    /// it applied — what the HTTP `/v1/pseudonymize` endpoint reports as
    /// `{ text, spans }` (see `docs/CONTRACT.md` §4.1). Span offsets are
    /// UTF-8 byte offsets into `input`.
    pub fn pseudonymize_with_spans(&mut self, input: &str) -> (String, Vec<Replacement>) {
        let detections = self.detector.detect(input);
        if detections.is_empty() {
            return (input.to_string(), Vec::new());
        }

        // Detections are already sorted and non-overlapping.
        let mut out = String::with_capacity(input.len());
        let mut spans = Vec::with_capacity(detections.len());
        let mut cursor = 0usize;
        for det in detections {
            out.push_str(&input[cursor..det.start]);
            let pseudo = self.table.pseudonymize(&det.text, det.kind);
            spans.push(Replacement {
                start: det.start,
                end: det.end,
                kind: det.kind,
                pseudonym: pseudo.clone(),
            });
            out.push_str(&pseudo);
            cursor = det.end;
        }
        out.push_str(&input[cursor..]);
        (out, spans)
    }

    /// Walk `input`, replace any pseudonym (e.g. `EMAIL_1`) that this
    /// pipeline minted back with its real entity. Pseudonyms this pipeline
    /// did not mint are left untouched — safer than guessing.
    #[must_use]
    pub fn reverse_map(&self, input: &str) -> String {
        self.pseudonym_pattern
            .replace_all(input, |caps: &regex::Captures<'_>| {
                let m = caps.get(0).expect("whole match always present").as_str();
                self.table
                    .real_for(m)
                    .map_or_else(|| m.to_string(), str::to_string)
            })
            .into_owned()
    }

    /// Phase 3: scan the raw model reply for two kinds of re-ID signal.
    ///
    /// 1. Pseudonym-shaped tokens (e.g. `EMAIL_99`) that this pipeline did
    ///    not mint — `AuditReason::UnknownPseudonym`. Either a hallucination
    ///    or a cross-session reference; either way, silently passing it
    ///    through hands the user a fake-looking token.
    /// 2. Raw entities matched by the detector — `AuditReason::LikelyLeaked`.
    ///    The model saw pseudonyms, not real entities, so any raw entity in
    ///    the reply is the model writing a real-looking entity directly.
    ///    Note: this uses the *fixed* `RegexDetector`, not the pipeline's
    ///    configured detector — because the configured detector is
    ///    potentially a `BitnetDetector` (HTTP), and we don't want the
    ///    audit path to become async / fallible. Regex-level leak detection
    ///    is a deliberate floor, not a ceiling; a later phase can swap in
    ///    the learned detector.
    ///
    /// IMPORTANT: call this on the *raw* reply, before `reverse_map`.
    /// After reverse-mapping, known pseudonyms become their real entities,
    /// which the leak detector would then flag as false positives.
    ///
    /// Returned findings are sorted by `start` and non-overlapping.
    #[must_use]
    pub fn audit_reply(&self, reply: &str) -> Vec<AuditFinding> {
        let mut findings: Vec<AuditFinding> = Vec::new();

        // (1) Unknown pseudonyms.
        for m in self.pseudonym_pattern.find_iter(reply) {
            let text = m.as_str();
            if self.table.real_for(text).is_some() {
                continue;
            }
            let kind = text
                .split('_')
                .next()
                .and_then(EntityKind::from_prefix)
                // pseudonym_pattern only matches the six known prefixes, so
                // failure here is a programmer error (pattern out of sync
                // with `EntityKind::from_prefix`). Defend anyway by skipping.
                .unwrap_or(EntityKind::Email);
            findings.push(AuditFinding {
                text: text.to_string(),
                start: m.start(),
                end: m.end(),
                reason: AuditReason::UnknownPseudonym { kind },
            });
        }

        // (2) Likely-leaked raw entities. The regex detector already
        // returns non-overlapping spans and handles URL-vs-email shadowing.
        let detector = RegexDetector::new();
        for det in detector.detect(reply) {
            findings.push(AuditFinding {
                text: det.text,
                start: det.start,
                end: det.end,
                reason: AuditReason::LikelyLeaked { kind: det.kind },
            });
        }

        // Sort by start. Unknown-pseudonym and leaked-entity spans cannot
        // overlap (pseudonym_pattern matches `PREFIX_\d+`; the regex
        // detector matches raw entity shapes — disjoint grammars), so a
        // single stable sort is enough.
        findings.sort_by_key(|f| f.start);
        findings
    }

    /// Phase 5: pseudonymize every string leaf of a `serde_json::Value` in
    /// place. Designed for agentic traffic — the Anthropic wire protocol
    /// carries tool arguments as JSON (`InputContentBlock::ToolUse.input`,
    /// `ToolResultContentBlock::Json`) which is where the bulk of PII
    /// flows in practice. The walker descends into arrays and objects,
    /// rewrites each string leaf with `pseudonymize`, and leaves numbers,
    /// booleans, and nulls alone.
    ///
    /// Bounded by `MAX_JSON_DEPTH` so a crafted nesting can't blow the
    /// stack. Values under `RESERVED_JSON_KEYS` are skipped — those keys
    /// are Anthropic wire-protocol identifiers, not user content.
    pub fn pseudonymize_json_in_place(&mut self, value: &mut Value) {
        pseudonymize_json_depth(value, self, MAX_JSON_DEPTH);
    }

    /// Span-collecting counterpart of [`Self::pseudonymize_json_in_place`] —
    /// what `/v1/pseudonymize-json` reports as `{ value, spans }`. Each
    /// span's `start`/`end` are byte offsets **within the string leaf** it was
    /// found in, not the serialized document (cross-leaf offset math is not
    /// meaningful — same rule as the JSON auditor, `docs/CONTRACT.md` §4.2).
    pub fn pseudonymize_json_in_place_collect(&mut self, value: &mut Value) -> Vec<Replacement> {
        let mut spans = Vec::new();
        pseudonymize_json_collect_depth(value, self, MAX_JSON_DEPTH, &mut spans);
        spans
    }

    /// Reverse counterpart: walk the same shape, rewrite pseudonyms in
    /// string leaves back to their real entities. Pseudonyms the pipeline
    /// didn't mint are left alone (same policy as [`Self::reverse_map`]).
    pub fn reverse_map_json_in_place(&self, value: &mut Value) {
        reverse_map_json_depth(value, self, MAX_JSON_DEPTH);
    }

    /// Phase 6: audit every string leaf of a `serde_json::Value` the same
    /// way [`Self::audit_reply_async`] audits a text block. Without this,
    /// a model that emits `{"to": "alice@acme.com"}` inside a tool call
    /// would slip past the auditor — the text pass never sees it, and the
    /// reverse-map JSON walker only *translates*, it doesn't inspect.
    ///
    /// The returned findings are flat (one `Vec<AuditFinding>`). Their
    /// `start`/`end` offsets are relative to the *string leaf* they were
    /// found in, not to any serialized form of `value` — cross-leaf offset
    /// math is not meaningful. That's enough for the policy layer
    /// ([`AuditVerdict`]) and for logging, which is Phase 6's target
    /// acceptance (log-only). Redaction inside tool-call JSON is not
    /// covered here — splicing in-place requires carrying the JSON
    /// pointer alongside each finding, which a later phase can layer on
    /// without changing this signature.
    ///
    /// Walk rules mirror [`Self::pseudonymize_json_in_place`]: bounded by
    /// `MAX_JSON_DEPTH` and skipping values under `RESERVED_JSON_KEYS`
    /// (`"system"`, `"role"`).
    pub async fn audit_json_async(&self, value: &Value) -> Vec<AuditFinding> {
        let mut leaves: Vec<&str> = Vec::new();
        collect_string_leaves(value, &mut leaves, MAX_JSON_DEPTH);
        let mut findings = Vec::new();
        for leaf in leaves {
            let mut leaf_findings = self.audit_reply_async(leaf).await;
            findings.append(&mut leaf_findings);
        }
        findings
    }

    /// Phase 4: async superset of [`Self::audit_reply`]. Starts from the
    /// sync regex floor, then asks the configured detector (via
    /// [`Detector::detect_async`]) for additional leaks. The key win over
    /// the sync version: when `D` is a learned detector like
    /// `BitnetDetector`, this picks up entity kinds regex cannot
    /// reliably find — notably `EntityKind::Person`.
    ///
    /// Merge policy:
    /// - Learned detections that are themselves pseudonym-shaped
    ///   (`PREFIX_\d+`) are skipped. Either the pipeline already minted
    ///   them (sync path saw no finding — correct) or it didn't (sync
    ///   path already flagged them as `UnknownPseudonym`). Either way,
    ///   the learned detector shouldn't get a second opinion.
    /// - Learned detections that overlap an existing finding are
    ///   skipped — avoids double-flagging a raw entity the regex floor
    ///   already saw.
    ///
    /// Safety properties carried over from the sync version: findings
    /// are returned sorted by `start` and non-overlapping, and the
    /// caller must invoke this on the *raw* reply before `reverse_map`.
    pub async fn audit_reply_async(&self, reply: &str) -> Vec<AuditFinding> {
        let mut findings = self.audit_reply(reply);

        let learned = self.detector.detect_async(reply).await;
        for det in learned {
            if self.pseudonym_pattern.is_match(&det.text) {
                continue;
            }
            let overlap = findings
                .iter()
                .any(|f| !(det.end <= f.start || det.start >= f.end));
            if overlap {
                continue;
            }
            findings.push(AuditFinding {
                text: det.text,
                start: det.start,
                end: det.end,
                reason: AuditReason::LikelyLeaked { kind: det.kind },
            });
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
}

/// Recursive walker for [`VeilPipeline::pseudonymize_json_in_place`]. Split
/// out so depth is tracked locally without forcing every public entry
/// point to take it as a parameter.
fn pseudonymize_json_depth<D: Detector>(
    value: &mut Value,
    pipeline: &mut VeilPipeline<D>,
    depth: usize,
) {
    if depth == 0 {
        return;
    }
    match value {
        Value::String(s) => {
            *s = pipeline.pseudonymize(s);
        }
        Value::Array(items) => {
            for item in items {
                pseudonymize_json_depth(item, pipeline, depth - 1);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if RESERVED_JSON_KEYS.contains(&k.as_str()) {
                    continue;
                }
                pseudonymize_json_depth(v, pipeline, depth - 1);
            }
        }
        _ => {}
    }
}

/// Span-collecting walker for [`VeilPipeline::pseudonymize_json_in_place_collect`].
/// Mirrors `pseudonymize_json_depth` but runs the with-spans text pass on each
/// leaf and accumulates the replacements (offsets relative to each leaf).
fn pseudonymize_json_collect_depth<D: Detector>(
    value: &mut Value,
    pipeline: &mut VeilPipeline<D>,
    depth: usize,
    spans: &mut Vec<Replacement>,
) {
    if depth == 0 {
        return;
    }
    match value {
        Value::String(s) => {
            let (rewritten, mut leaf_spans) = pipeline.pseudonymize_with_spans(s);
            *s = rewritten;
            spans.append(&mut leaf_spans);
        }
        Value::Array(items) => {
            for item in items {
                pseudonymize_json_collect_depth(item, pipeline, depth - 1, spans);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if RESERVED_JSON_KEYS.contains(&k.as_str()) {
                    continue;
                }
                pseudonymize_json_collect_depth(v, pipeline, depth - 1, spans);
            }
        }
        _ => {}
    }
}

/// Gather every string leaf in `value` (depth-bounded, skipping values under
/// `RESERVED_JSON_KEYS`). Separated from [`VeilPipeline::audit_json_async`]
/// so the async method body stays flat — recursing across an `.await` would
/// force a `Box::pin` dance on the future.
fn collect_string_leaves<'v>(value: &'v Value, out: &mut Vec<&'v str>, depth: usize) {
    if depth == 0 {
        return;
    }
    match value {
        Value::String(s) => out.push(s.as_str()),
        Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, out, depth - 1);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                if RESERVED_JSON_KEYS.contains(&k.as_str()) {
                    continue;
                }
                collect_string_leaves(v, out, depth - 1);
            }
        }
        _ => {}
    }
}

/// Recursive counterpart for reverse-mapping. Takes `&VeilPipeline` since
/// `reverse_map` doesn't mutate the session table.
fn reverse_map_json_depth<D: Detector>(
    value: &mut Value,
    pipeline: &VeilPipeline<D>,
    depth: usize,
) {
    if depth == 0 {
        return;
    }
    match value {
        Value::String(s) => {
            *s = pipeline.reverse_map(s);
        }
        Value::Array(items) => {
            for item in items {
                reverse_map_json_depth(item, pipeline, depth - 1);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if RESERVED_JSON_KEYS.contains(&k.as_str()) {
                    continue;
                }
                reverse_map_json_depth(v, pipeline, depth - 1);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::VeilPipeline;
    use crate::audit::{AuditReason, UnknownPseudonymPolicy, VeilPolicy};
    use crate::entities::{DetectedEntity, Detector, EntityKind};

    #[test]
    fn passes_through_text_with_no_entities() {
        let mut p = VeilPipeline::with_default_regex();
        let out = p.pseudonymize("nothing here, move along");
        assert_eq!(out, "nothing here, move along");
        assert!(p.table().is_empty());
    }

    #[test]
    fn reverse_map_is_identity_on_unknown_pseudonyms() {
        let p = VeilPipeline::with_default_regex();
        // Pseudonym pattern matches but was never minted — leave alone.
        let out = p.reverse_map("reference EMAIL_42 and PATH_99");
        assert_eq!(out, "reference EMAIL_42 and PATH_99");
    }

    /// A fake detector that lets us exercise the pipeline independently of
    /// the regex rules — useful for Phase-1 readiness.
    struct FakeDetector {
        spans: Vec<DetectedEntity>,
    }
    impl Detector for FakeDetector {
        fn detect(&self, _input: &str) -> Vec<DetectedEntity> {
            self.spans.clone()
        }
    }

    #[test]
    fn pipeline_works_with_custom_detector() {
        let fake = FakeDetector {
            spans: vec![DetectedEntity {
                kind: EntityKind::Email,
                start: 7,
                end: 14,
                text: "x@y.com".to_string(),
            }],
        };
        let mut p = VeilPipeline::new(fake);
        let out = p.pseudonymize("email: x@y.com!");
        assert_eq!(out, "email: EMAIL_1!");
    }

    /// Phase 2 coref smoke test. Two turns, same underlying person, two
    /// different surface forms — both should share a pseudonym, and
    /// reverse-mapping should restore the first-seen form.
    #[test]
    fn pipeline_coref_collapses_honorific_across_turns() {
        // Fresh detector per call so detection offsets are relative to the
        // turn-specific input.
        struct HonorificThenBare;
        impl Detector for HonorificThenBare {
            fn detect(&self, input: &str) -> Vec<DetectedEntity> {
                if let Some(idx) = input.find("Dr. Smith") {
                    vec![DetectedEntity {
                        kind: EntityKind::Person,
                        start: idx,
                        end: idx + "Dr. Smith".len(),
                        text: "Dr. Smith".to_string(),
                    }]
                } else if let Some(idx) = input.find("Smith") {
                    vec![DetectedEntity {
                        kind: EntityKind::Person,
                        start: idx,
                        end: idx + "Smith".len(),
                        text: "Smith".to_string(),
                    }]
                } else {
                    Vec::new()
                }
            }
        }
        let mut p = VeilPipeline::new(HonorificThenBare);
        let turn1 = p.pseudonymize("met Dr. Smith today");
        let turn2 = p.pseudonymize("Smith was friendly");
        assert_eq!(turn1, "met PERSON_1 today");
        assert_eq!(turn2, "PERSON_1 was friendly");
        assert_eq!(p.table().len(), 1);
        // Reverse-map uses the first-seen canonical surface.
        assert_eq!(p.reverse_map("saw PERSON_1 again"), "saw Dr. Smith again");
    }

    // ---------- Phase 3: re-ID audit ----------

    #[test]
    fn audit_flags_unknown_pseudonym() {
        let p = VeilPipeline::with_default_regex();
        // Pipeline never minted anything — every pseudonym-shaped token is unknown.
        let findings = p.audit_reply("reference EMAIL_42 and PATH_99");
        assert_eq!(findings.len(), 2);
        assert!(matches!(
            findings[0].reason,
            AuditReason::UnknownPseudonym {
                kind: EntityKind::Email
            }
        ));
        assert_eq!(findings[0].text, "EMAIL_42");
        assert!(matches!(
            findings[1].reason,
            AuditReason::UnknownPseudonym {
                kind: EntityKind::Path
            }
        ));
        assert_eq!(findings[1].text, "PATH_99");
    }

    #[test]
    fn audit_passes_known_pseudonym_through() {
        let mut p = VeilPipeline::with_default_regex();
        // Prime so EMAIL_1 is a pseudonym this pipeline minted.
        let _ = p.pseudonymize("email a@b.com please");
        let findings = p.audit_reply("will ping EMAIL_1 shortly");
        assert!(
            findings.is_empty(),
            "known pseudonym must not fire audit, got: {findings:?}"
        );
    }

    #[test]
    fn audit_flags_raw_email_as_likely_leaked() {
        let p = VeilPipeline::with_default_regex();
        let findings = p.audit_reply("the model wrote leak@example.com in its reply");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "leak@example.com");
        assert!(matches!(
            findings[0].reason,
            AuditReason::LikelyLeaked {
                kind: EntityKind::Email
            }
        ));
    }

    #[test]
    fn audit_fires_on_reply_containing_real_entity_even_when_pipeline_minted_same_one() {
        // If the user asked about a@b.com and we minted EMAIL_1 → a@b.com,
        // the model should emit EMAIL_1 in its reply. If it emits a@b.com
        // directly, THAT is the leak — the auditor must flag it on the raw
        // reply (before reverse_map) so we can distinguish "model emitted
        // pseudonym, we restored it" from "model emitted real entity".
        let mut p = VeilPipeline::with_default_regex();
        let _ = p.pseudonymize("user's email is a@b.com");
        let findings = p.audit_reply("I'll email a@b.com right now");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "a@b.com");
        assert!(matches!(
            findings[0].reason,
            AuditReason::LikelyLeaked {
                kind: EntityKind::Email
            }
        ));
    }

    #[test]
    fn audit_findings_are_sorted_by_start_offset() {
        let p = VeilPipeline::with_default_regex();
        // Interleave unknown pseudonym and raw entity so sort actually matters.
        let reply = "raw 1.2.3.4 then unknown EMAIL_5 then another /Users/x/y";
        let findings = p.audit_reply(reply);
        assert!(findings.len() >= 3);
        for pair in findings.windows(2) {
            assert!(
                pair[0].start <= pair[1].start,
                "findings must be sorted, got {pair:?}"
            );
        }
    }

    #[test]
    fn audit_is_silent_on_clean_reply() {
        let p = VeilPipeline::with_default_regex();
        assert!(p
            .audit_reply("all clear, nothing sensitive here")
            .is_empty());
    }

    // ---------- Phase 4: learned async audit ----------

    /// Fake async-aware detector: returns the configured spans from BOTH
    /// `detect` and `detect_async`. Exists so tests can exercise the async
    /// merge path without standing up an HTTP server. If we only tested
    /// with `RegexDetector`, `audit_reply_async` would be indistinguishable
    /// from `audit_reply` and the merge logic would be untested.
    struct StubAsyncDetector {
        spans: Vec<DetectedEntity>,
    }
    impl Detector for StubAsyncDetector {
        fn detect(&self, _input: &str) -> Vec<DetectedEntity> {
            self.spans.clone()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_reply_async_surfaces_learned_person_leak() {
        // "Dr. Smith" in the reply — regex cannot flag persons, only the
        // learned detector can. audit_reply (sync) returns empty; audit_reply_async
        // returns one LikelyLeaked(Person) finding. This is the core Phase 4
        // promise: person leaks are now caught.
        let stub = StubAsyncDetector {
            spans: vec![DetectedEntity {
                kind: EntityKind::Person,
                start: 0,
                end: 9,
                text: "Dr. Smith".to_string(),
            }],
        };
        let p = VeilPipeline::new(stub);
        assert!(
            p.audit_reply("Dr. Smith called back").is_empty(),
            "sync path cannot see persons — regression if this fails"
        );
        let findings = p.audit_reply_async("Dr. Smith called back").await;
        assert_eq!(findings.len(), 1, "async path must flag the person leak");
        assert_eq!(findings[0].text, "Dr. Smith");
        assert!(matches!(
            findings[0].reason,
            AuditReason::LikelyLeaked {
                kind: EntityKind::Person
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_reply_async_skips_learned_detections_overlapping_sync_findings() {
        // Regex floor flags a@b.com; stub detector "independently" also
        // returns the same span with a different kind. Must not be
        // double-counted — merge policy is "sync wins for overlapping spans".
        let stub = StubAsyncDetector {
            spans: vec![DetectedEntity {
                kind: EntityKind::Person, // deliberately wrong kind to make sure we drop this
                start: "leak from ".len(),
                end: "leak from a@b.com".len(),
                text: "a@b.com".to_string(),
            }],
        };
        let p = VeilPipeline::new(stub);
        let findings = p.audit_reply_async("leak from a@b.com").await;
        assert_eq!(findings.len(), 1, "must not double-flag the same span");
        assert!(matches!(
            findings[0].reason,
            AuditReason::LikelyLeaked {
                kind: EntityKind::Email
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_reply_async_skips_pseudonym_shaped_learned_detections() {
        // If the learned detector mistakes a pseudonym like `PERSON_1`
        // for a person name, the merge policy must drop the detection
        // outright. Here `PERSON_1` is UNKNOWN to the pipeline (never
        // minted), so the sync pass flags it as UnknownPseudonym; the
        // pseudonym-shaped learned detection over the same span must NOT
        // produce a second LikelyLeaked finding.
        let stub = StubAsyncDetector {
            spans: vec![DetectedEntity {
                kind: EntityKind::Person,
                start: 5,
                end: 13,
                text: "PERSON_1".to_string(),
            }],
        };
        let p = VeilPipeline::new(stub);
        let findings = p.audit_reply_async("ping PERSON_1 soon").await;
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        assert!(
            matches!(findings[0].reason, AuditReason::UnknownPseudonym { .. }),
            "expected only the sync UnknownPseudonym, got {findings:?}"
        );
    }

    // ---------- Phase 5: JSON walker ----------

    #[test]
    fn pseudonymize_json_rewrites_strings_under_nested_keys() {
        // NOTE: `serde_json::Map` without `preserve_order` is a `BTreeMap`,
        // so the walker visits keys alphabetically: `body` then `meta` then
        // `to`. Pseudonym numbering follows that visit order.
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let mut value = json!({
            "to": "alice@acme.com",
            "body": "ping me at bob@corp.com",
            "meta": {
                "from_path": "/Users/baris/notes.md",
                "count": 3
            }
        });
        p.pseudonymize_json_in_place(&mut value);
        // body first → EMAIL_1; meta.from_path → PATH_1; to last → EMAIL_2.
        assert_eq!(value["body"].as_str(), Some("ping me at EMAIL_1"));
        assert_eq!(value["meta"]["from_path"].as_str(), Some("PATH_1"));
        assert_eq!(value["to"].as_str(), Some("EMAIL_2"));
        // Non-string leaves pass through.
        assert_eq!(value["meta"]["count"].as_i64(), Some(3));
    }

    #[test]
    fn pseudonymize_json_walks_into_arrays() {
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let mut value = json!({
            "recipients": ["a@b.com", "c@d.com", {"bcc": "e@f.com"}]
        });
        p.pseudonymize_json_in_place(&mut value);
        assert_eq!(value["recipients"][0].as_str(), Some("EMAIL_1"));
        assert_eq!(value["recipients"][1].as_str(), Some("EMAIL_2"));
        assert_eq!(value["recipients"][2]["bcc"].as_str(), Some("EMAIL_3"));
    }

    #[test]
    fn pseudonymize_json_round_trips_through_reverse_map() {
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let mut value = json!({
            "to": "alice@acme.com",
            "body": "ship to /Users/baris/out"
        });
        p.pseudonymize_json_in_place(&mut value);
        assert_eq!(value["to"].as_str(), Some("EMAIL_1"));
        assert_eq!(value["body"].as_str(), Some("ship to PATH_1"));
        p.reverse_map_json_in_place(&mut value);
        assert_eq!(value["to"].as_str(), Some("alice@acme.com"));
        assert_eq!(value["body"].as_str(), Some("ship to /Users/baris/out"));
    }

    #[test]
    fn pseudonymize_json_skips_reserved_wire_keys() {
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let mut value = json!({
            "role": "user@special.com",
            "system": "admin@special.com",
            "to": "alice@acme.com"
        });
        p.pseudonymize_json_in_place(&mut value);
        // "role" / "system" values are skipped — their literal strings survive.
        assert_eq!(value["role"].as_str(), Some("user@special.com"));
        assert_eq!(value["system"].as_str(), Some("admin@special.com"));
        // Regular keys are still rewritten.
        assert_eq!(value["to"].as_str(), Some("EMAIL_1"));
    }

    #[test]
    fn pseudonymize_json_is_identity_on_non_string_leaves() {
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let mut value = json!({
            "count": 42,
            "ratio": 0.5,
            "enabled": true,
            "missing": null,
            "tags": []
        });
        let before = value.clone();
        p.pseudonymize_json_in_place(&mut value);
        assert_eq!(value, before);
    }

    #[test]
    fn pseudonymize_json_reuses_pseudonyms_already_minted_by_text_pass() {
        // Critical property for mixed agentic traffic: a request can carry
        // both a text block and a tool-call with the same entity. If the
        // text pass ran first and minted EMAIL_1 for a@b.com, the JSON walker
        // MUST reuse EMAIL_1 rather than mint EMAIL_2.
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let _ = p.pseudonymize("please email a@b.com");
        let mut value = json!({ "to": "a@b.com" });
        p.pseudonymize_json_in_place(&mut value);
        assert_eq!(value["to"].as_str(), Some("EMAIL_1"));
    }

    #[test]
    fn pseudonymize_json_stops_at_max_depth() {
        // Build a deeply-nested structure: 40 arrays each containing the next.
        // MAX_JSON_DEPTH = 32, so depth 33+ strings should be left untouched.
        use serde_json::{json, Value};
        let mut leaf = Value::String("a@b.com".to_string());
        for _ in 0..40 {
            leaf = json!([leaf]);
        }
        let mut p = VeilPipeline::with_default_regex();
        p.pseudonymize_json_in_place(&mut leaf);
        // Find the innermost value; since depth stopped early, it should
        // still be the raw email. If the walker recursed without bound, it
        // would have been pseudonymized.
        let mut cursor = &leaf;
        let mut levels = 0;
        while let Some(first) = cursor.as_array().and_then(|a| a.first()) {
            cursor = first;
            levels += 1;
            if levels > 45 {
                break;
            }
        }
        assert_eq!(
            cursor.as_str(),
            Some("a@b.com"),
            "innermost string (below MAX_JSON_DEPTH) must not be rewritten"
        );
    }

    // ---------- Phase 6: JSON-aware audit ----------

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_json_async_flags_raw_email_in_string_leaf() {
        // The core Phase 6 promise: a raw email hidden inside a tool-call
        // argument must trip the auditor, not slip past it. audit_reply
        // never sees this value — the text pass only walks text/thinking.
        use serde_json::json;
        let p = VeilPipeline::with_default_regex();
        let value = json!({
            "to": "leak@example.com",
            "body": "ok"
        });
        let findings = p.audit_json_async(&value).await;
        assert_eq!(findings.len(), 1, "expected one leak, got: {findings:?}");
        assert_eq!(findings[0].text, "leak@example.com");
        assert!(matches!(
            findings[0].reason,
            AuditReason::LikelyLeaked {
                kind: EntityKind::Email
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_json_async_walks_into_arrays_and_nested_objects() {
        // A leak nested two levels deep must still surface. This is not
        // theoretical — real tool schemas have `recipients: [{address: ...}]`
        // or `meta.from` shapes.
        use serde_json::json;
        let p = VeilPipeline::with_default_regex();
        let value = json!({
            "recipients": [
                {"address": "clean@ok.com"},
                {"address": "also@ok.com"},
            ],
            "meta": {
                "from": "real@leaker.io"
            }
        });
        let findings = p.audit_json_async(&value).await;
        // All three emails are raw and un-pseudonymized; all three should
        // surface as likely-leaked.
        assert_eq!(findings.len(), 3, "got findings: {findings:?}");
        let kinds: Vec<_> = findings.iter().map(|f| f.reason.clone()).collect();
        assert!(kinds.iter().all(|r| matches!(
            r,
            AuditReason::LikelyLeaked {
                kind: EntityKind::Email
            }
        )));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_json_async_flags_unknown_pseudonym_inside_tool_arg() {
        // Model hallucinates `EMAIL_99` inside a tool argument instead of
        // a real address. The reverse-map pass would silently pass it
        // through (pipeline didn't mint it); the audit must flag it.
        use serde_json::json;
        let p = VeilPipeline::with_default_regex();
        let value = json!({ "to": "EMAIL_99", "subject": "hi" });
        let findings = p.audit_json_async(&value).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "EMAIL_99");
        assert!(matches!(
            findings[0].reason,
            AuditReason::UnknownPseudonym {
                kind: EntityKind::Email
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_json_async_is_silent_on_clean_tool_input() {
        use serde_json::json;
        let p = VeilPipeline::with_default_regex();
        let value = json!({
            "count": 3,
            "enabled": true,
            "tags": ["alpha", "beta"],
            "meta": { "label": "nothing sensitive" }
        });
        assert!(p.audit_json_async(&value).await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_json_async_skips_reserved_wire_keys() {
        // Mirrors pseudonymize_json_skips_reserved_wire_keys: values under
        // `role`/`system` are wire-protocol control keywords and the
        // walker must not audit them (keeps rules consistent across
        // pseudonymize and audit passes).
        use serde_json::json;
        let p = VeilPipeline::with_default_regex();
        let value = json!({
            "role": "user@special.com",
            "system": "admin@special.com",
            "to": "real@leaker.io"
        });
        let findings = p.audit_json_async(&value).await;
        assert_eq!(findings.len(), 1, "reserved keys must be skipped");
        assert_eq!(findings[0].text, "real@leaker.io");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_json_async_does_not_flag_known_pseudonyms() {
        // If the pipeline earlier minted EMAIL_1 for a@b.com, a tool call
        // arg containing "EMAIL_1" is the model doing the right thing —
        // not a leak. Must not produce findings.
        use serde_json::json;
        let mut p = VeilPipeline::with_default_regex();
        let _ = p.pseudonymize("please email a@b.com");
        let value = json!({ "to": "EMAIL_1" });
        assert!(p.audit_json_async(&value).await.is_empty());
    }

    #[test]
    fn policy_verdict_on_unknown_respects_unknown_pseudonym_axis() {
        let p = VeilPipeline::with_default_regex();
        let findings = p.audit_reply("EMAIL_99 is suspicious");
        assert!(!findings.is_empty());

        // Log-only default: observability only.
        let policy = VeilPolicy {
            on_unknown_pseudonym: UnknownPseudonymPolicy::Log,
        };
        assert_eq!(
            policy.verdict(&findings),
            crate::audit::AuditVerdict::LogOnly
        );

        // Reject escalates.
        let policy = VeilPolicy {
            on_unknown_pseudonym: UnknownPseudonymPolicy::Reject,
        };
        assert_eq!(
            policy.verdict(&findings),
            crate::audit::AuditVerdict::Reject
        );
    }
}
