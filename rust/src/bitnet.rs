//! HTTP-backed detector that delegates entity recognition to a local `BitNet`
//! inference server. Phase 1 of the Ternary Veil roadmap — drops into the
//! stable [`Detector`] boundary, with [`FallbackDetector`] providing a
//! regex-stub safety net when the server is unreachable or returns garbage.
//!
//! Wire protocol (`POST {endpoint}/detect`):
//! ```json
//! // request
//! { "text": "..." }
//! // response
//! { "entities": [ { "kind": "EMAIL", "start": 0, "end": 5 }, ... ] }
//! ```
//! `kind` must match an [`EntityKind::as_prefix`] value. `start`/`end` are
//! byte offsets into the input; any entity whose span is out of bounds,
//! not on char boundaries, or carrying an unknown `kind` is dropped.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::entities::{DetectedEntity, Detector, EntityKind};

/// Default timeout for a single detect HTTP call. Chosen small enough to
/// not stall a turn if the server hangs — the fallback detector takes over.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Detector that POSTs the input to a `BitNet` inference server's `/detect`
/// endpoint and parses the returned spans.
///
/// Errors (HTTP failure, timeout, malformed JSON, invalid spans) are
/// swallowed to an empty result — pair with [`FallbackDetector`] to keep
/// regex coverage when the server is down.
#[derive(Debug, Clone)]
pub struct BitnetDetector {
    endpoint: String,
    http: reqwest::Client,
}

impl BitnetDetector {
    /// Build a detector pointing at `endpoint` (e.g. `http://127.0.0.1:8080`).
    /// The `/detect` path is appended at call time.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("reqwest client with rustls-tls must build");
        Self {
            endpoint: endpoint.into(),
            http,
        }
    }

    /// Override the default per-call timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client with rustls-tls must build");
        self
    }

    /// Private async body. Named `_impl` so the public async interface
    /// goes through the [`Detector`] trait's `detect_async` — keeps one
    /// canonical entry point for every caller.
    async fn detect_impl(&self, input: &str) -> Vec<DetectedEntity> {
        let url = format!("{}/detect", self.endpoint.trim_end_matches('/'));
        let body = DetectRequest { text: input };
        let Ok(response) = self.http.post(&url).json(&body).send().await else {
            return Vec::new();
        };
        if !response.status().is_success() {
            return Vec::new();
        }
        let Ok(parsed) = response.json::<DetectResponse>().await else {
            return Vec::new();
        };
        validate_spans(parsed.entities, input)
    }
}

impl Detector for BitnetDetector {
    /// Must be called from within a multi-threaded tokio runtime — that is
    /// the caller contract for every veil pipeline that uses the sync
    /// path, since the surrounding `ProviderClient` is async. If called
    /// outside one, this panics. Phase 4 audit paths prefer `detect_async`
    /// to avoid the `block_in_place` hop entirely.
    fn detect(&self, input: &str) -> Vec<DetectedEntity> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.detect_impl(input))
        })
    }

    /// Native async path. No `block_in_place`, so safe to call from any
    /// tokio runtime flavor — single-threaded included.
    fn detect_async<'a>(
        &'a self,
        input: &'a str,
    ) -> impl std::future::Future<Output = Vec<DetectedEntity>> + Send + 'a {
        self.detect_impl(input)
    }
}

/// Two-stage detector: run `primary` first; if it returns no entities,
/// run `secondary` as a safety net. This lets `BitnetDetector` be the
/// primary path while `RegexDetector` catches the case where the server
/// is down (swallowed to empty) or genuinely missed obvious PII.
///
/// This is asymmetric on purpose: when primary finds >=1 entity we trust
/// it — merging with secondary is deferred to a later phase.
#[derive(Debug, Clone)]
pub struct FallbackDetector<P, S> {
    primary: P,
    secondary: S,
}

impl<P, S> FallbackDetector<P, S> {
    pub const fn new(primary: P, secondary: S) -> Self {
        Self { primary, secondary }
    }
}

impl<P: Detector, S: Detector> Detector for FallbackDetector<P, S> {
    fn detect(&self, input: &str) -> Vec<DetectedEntity> {
        let primary = self.primary.detect(input);
        if primary.is_empty() {
            self.secondary.detect(input)
        } else {
            primary
        }
    }

    /// Override the default so the primary's native async path runs when it
    /// has one. Phase 5: with `primary = BitnetDetector`, the default impl
    /// would fall through to `self.detect` → `BitnetDetector::detect`, which
    /// re-enters `block_in_place`. That defeats the whole point of using
    /// `detect_async` from `audit_reply_async` and the session pipeline.
    async fn detect_async(&self, input: &str) -> Vec<DetectedEntity> {
        let primary = self.primary.detect_async(input).await;
        if primary.is_empty() {
            self.secondary.detect_async(input).await
        } else {
            primary
        }
    }
}

/// Phase 7: two-stage detector that *merges* primary + secondary instead of
/// running secondary only as a safety net. Fixes the asymmetry E27
/// surfaced: when spaCy returns a PERSON, [`FallbackDetector`] never runs
/// regex, so `"Dr. Smith emailed baris@example.com"` leaves the email raw.
/// With [`MergeFallback`], both stages run and their spans union.
///
/// Merge rule: keep every primary span + every secondary span that does
/// not overlap a primary span. Primary wins on overlap — same precedence
/// as `audit_reply_async`'s sync/learned merge, so behavior is uniform
/// across the codebase. No attempt is made to reconcile *which kind* a
/// span belongs to when both stages agree on offsets; the primary's label
/// stands.
#[derive(Debug, Clone)]
pub struct MergeFallback<P, S> {
    primary: P,
    secondary: S,
}

impl<P, S> MergeFallback<P, S> {
    pub const fn new(primary: P, secondary: S) -> Self {
        Self { primary, secondary }
    }
}

impl<P: Detector, S: Detector> Detector for MergeFallback<P, S> {
    fn detect(&self, input: &str) -> Vec<DetectedEntity> {
        let primary = self.primary.detect(input);
        let secondary = self.secondary.detect(input);
        merge_spans(primary, secondary)
    }

    async fn detect_async(&self, input: &str) -> Vec<DetectedEntity> {
        let primary = self.primary.detect_async(input).await;
        let secondary = self.secondary.detect_async(input).await;
        merge_spans(primary, secondary)
    }
}

/// Keep every `primary` span; append every `secondary` span whose byte
/// range does not overlap any primary span. Output is sorted by `start`,
/// non-overlapping (preserved invariant that every downstream walker
/// relies on). O(n*m) but n and m are small — a typical sentence produces
/// <10 spans per stage.
fn merge_spans(
    primary: Vec<DetectedEntity>,
    secondary: Vec<DetectedEntity>,
) -> Vec<DetectedEntity> {
    let mut out = primary;
    for s in secondary {
        let overlaps = out.iter().any(|p| !(s.end <= p.start || s.start >= p.end));
        if !overlaps {
            out.push(s);
        }
    }
    out.sort_by(|a, b| a.start.cmp(&b.start));
    out
}

/// Phase 5: a single closed-form detector type that the api crate can wrap
/// a per-session [`VeilPipeline`] around. Necessary because the [`Detector`]
/// trait uses return-position-impl-trait on `detect_async` and so is not
/// object-safe — `Box<dyn Detector>` doesn't compile. Enum dispatch keeps
/// every variant's future type concrete while letting the construction
/// site pick the shape at runtime (regex-only today, regex + `BitNet` when
/// `VEIL_BITNET_ENDPOINT` is set, bare `BitNet` in tests).
///
/// Phase 7 adds [`Self::BitnetMergeRegex`] — the merging variant is now
/// the production default when `VEIL_BITNET_ENDPOINT` is set. The
/// asymmetric [`Self::BitnetWithRegexFallback`] stays available for
/// callers that explicitly want the older behavior (no existing test
/// depends on it, but keeping it costs nothing and documents intent).
#[derive(Debug, Clone)]
pub enum AnyDetector {
    Regex(crate::entities::RegexDetector),
    Bitnet(BitnetDetector),
    BitnetWithRegexFallback(FallbackDetector<BitnetDetector, crate::entities::RegexDetector>),
    BitnetMergeRegex(MergeFallback<BitnetDetector, crate::entities::RegexDetector>),
}

impl Detector for AnyDetector {
    fn detect(&self, input: &str) -> Vec<DetectedEntity> {
        match self {
            Self::Regex(d) => d.detect(input),
            Self::Bitnet(d) => d.detect(input),
            Self::BitnetWithRegexFallback(d) => d.detect(input),
            Self::BitnetMergeRegex(d) => d.detect(input),
        }
    }

    async fn detect_async(&self, input: &str) -> Vec<DetectedEntity> {
        match self {
            Self::Regex(d) => d.detect_async(input).await,
            Self::Bitnet(d) => d.detect_async(input).await,
            Self::BitnetWithRegexFallback(d) => d.detect_async(input).await,
            Self::BitnetMergeRegex(d) => d.detect_async(input).await,
        }
    }
}

#[derive(Serialize)]
struct DetectRequest<'a> {
    text: &'a str,
}

#[derive(Deserialize)]
struct DetectResponse {
    entities: Vec<WireEntity>,
}

#[derive(Deserialize)]
struct WireEntity {
    kind: String,
    start: usize,
    end: usize,
}

/// Drop any entity with an unknown kind, a span that is out of bounds or
/// not on UTF-8 char boundaries, or that overlaps a previously-kept one.
/// Re-extracts `text` from the input so the server can't lie about
/// content while claiming valid spans.
fn validate_spans(raw: Vec<WireEntity>, input: &str) -> Vec<DetectedEntity> {
    let mut kept: Vec<DetectedEntity> = Vec::with_capacity(raw.len());
    let mut filtered: Vec<DetectedEntity> = raw
        .into_iter()
        .filter_map(|e| {
            let kind = EntityKind::from_prefix(&e.kind)?;
            if e.start >= e.end || e.end > input.len() {
                return None;
            }
            if !input.is_char_boundary(e.start) || !input.is_char_boundary(e.end) {
                return None;
            }
            Some(DetectedEntity {
                kind,
                start: e.start,
                end: e.end,
                text: input[e.start..e.end].to_string(),
            })
        })
        .collect();
    filtered.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    for det in filtered {
        let overlaps = kept.last().is_some_and(|last| last.end > det.start);
        if !overlaps {
            kept.push(det);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::{BitnetDetector, FallbackDetector, MergeFallback};
    use crate::entities::{Detector, EntityKind, RegexDetector};

    struct TestServer {
        base_url: String,
        _join: JoinHandle<()>,
    }

    /// Byte-for-byte copy of the working pattern from
    /// `api/tests/client_integration.rs::spawn_server`, kept narrow:
    /// this helper answers exactly one request with `response` and exits.
    async fn spawn_server(response: String) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have local addr");
        let join = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = Vec::new();
            let mut header_end = None;
            loop {
                let mut chunk = [0_u8; 1024];
                let Ok(read) = socket.read(&mut chunk).await else {
                    return;
                };
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(pos);
                    break;
                }
            }
            let Some(header_end) = header_end else {
                return;
            };
            let (header_bytes, remaining) = buffer.split_at(header_end);
            let headers = String::from_utf8(header_bytes.to_vec()).unwrap_or_default();
            let mut content_length = 0_usize;
            for line in headers.split("\r\n").skip(1) {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = remaining[4..].to_vec();
            while body.len() < content_length {
                let mut chunk = vec![0_u8; content_length - body.len()];
                let Ok(read) = socket.read(&mut chunk).await else {
                    return;
                };
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            let _ = socket.write_all(response.as_bytes()).await;
        });
        TestServer {
            base_url: format!("http://{address}"),
            _join: join,
        }
    }

    fn http_ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn http_status(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parses_valid_response() {
        let body = r#"{"entities":[{"kind":"EMAIL","start":7,"end":14},{"kind":"PATH","start":18,"end":28}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let input = "email: x@y.com at /Users/foo end";
        let found = detector.detect(input);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].kind, EntityKind::Email);
        assert_eq!(found[0].text, "x@y.com");
        assert_eq!(found[1].kind, EntityKind::Path);
        assert_eq!(found[1].text, "/Users/foo");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn returns_empty_on_http_500() {
        let server = spawn_server(http_status("500 Internal Server Error", "{}")).await;
        let detector = BitnetDetector::new(server.base_url);
        assert!(detector.detect("anything").is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn returns_empty_on_malformed_json() {
        let server = spawn_server(http_ok("not json {{{")).await;
        let detector = BitnetDetector::new(server.base_url);
        assert!(detector.detect("anything").is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn filters_out_of_bounds_spans() {
        let body = r#"{"entities":[{"kind":"EMAIL","start":0,"end":9999}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let found = detector.detect("short input");
        assert!(found.is_empty(), "out-of-bounds span should be dropped");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn filters_unknown_entity_kind() {
        let body = r#"{"entities":[{"kind":"BANANA","start":0,"end":3}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let found = detector.detect("abc def");
        assert!(found.is_empty(), "unknown kind should be dropped");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn filters_non_char_boundary_spans() {
        // "héllo" has a 2-byte é (offsets 0,1,3,4,5). Span 2..3 is mid-char.
        let body = r#"{"entities":[{"kind":"PATH","start":2,"end":3}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let found = detector.detect("héllo");
        assert!(found.is_empty(), "mid-char span should be dropped");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolves_overlaps_keeping_longest() {
        // Two overlapping spans covering "x@y.com"; longer should win.
        let body =
            r#"{"entities":[{"kind":"EMAIL","start":0,"end":3},{"kind":"URL","start":0,"end":7}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let found = detector.detect("x@y.com");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Url);
        assert_eq!(found[0].end, 7);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pipeline_with_bitnet_pseudonymizes_span_regex_misses() {
        // BitNet server claims "Alice" (0..5) is PII — a token no regex
        // in `RegexDetector` would ever flag. This is the Phase 1 smoke
        // test: the pipeline wires BitnetDetector output through
        // pseudonymize + reverse_map end-to-end.
        let body = r#"{"entities":[{"kind":"EMAIL","start":0,"end":5}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let mut pipeline = crate::VeilPipeline::new(detector);
        let out = pipeline.pseudonymize("Alice writes code");
        assert_eq!(out, "EMAIL_1 writes code");
        assert_eq!(pipeline.reverse_map(&out), "Alice writes code");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn returns_empty_on_connection_refused() {
        // Port 1 on localhost is reserved and refuses connections.
        let detector = BitnetDetector::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        assert!(detector.detect("a@b.com").is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_reply_async_flags_person_leak_via_bitnet() {
        // Phase 4 acceptance: prime a pipeline that routes through a real
        // BitnetDetector (HTTP), audit a reply containing a person name the
        // pipeline never minted. The sync `audit_reply` floor cannot see
        // persons (regex has no person pattern); `audit_reply_async` must
        // pick it up via the learned detector and emit
        // `AuditReason::LikelyLeaked { kind: Person }`.
        let body = r#"{"entities":[{"kind":"PERSON","start":0,"end":9}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = BitnetDetector::new(server.base_url);
        let pipeline = crate::VeilPipeline::new(detector);

        // Sanity: sync path is blind to persons.
        assert!(
            pipeline.audit_reply("Dr. Smith called back").is_empty(),
            "sync audit_reply must not flag a person leak — regression if this fails"
        );

        let findings = pipeline.audit_reply_async("Dr. Smith called back").await;
        assert_eq!(
            findings.len(),
            1,
            "async audit must flag the person leak, got: {findings:?}"
        );
        assert_eq!(findings[0].text, "Dr. Smith");
        assert!(matches!(
            findings[0].reason,
            crate::audit::AuditReason::LikelyLeaked {
                kind: EntityKind::Person
            }
        ));
    }

    #[test]
    fn fallback_uses_primary_when_non_empty() {
        // Simple fakes — no HTTP, no tokio needed.
        struct Stub(Vec<super::DetectedEntity>);
        impl Detector for Stub {
            fn detect(&self, _input: &str) -> Vec<super::DetectedEntity> {
                self.0.clone()
            }
        }
        let primary = Stub(vec![super::DetectedEntity {
            kind: EntityKind::Email,
            start: 0,
            end: 5,
            text: "a@b.c".to_string(),
        }]);
        let secondary = RegexDetector::new();
        let fallback = FallbackDetector::new(primary, secondary);
        let out = fallback.detect("a@b.c and x@y.org");
        assert_eq!(out.len(), 1, "primary non-empty, secondary must not run");
        assert_eq!(out[0].text, "a@b.c");
    }

    #[test]
    fn fallback_uses_secondary_when_primary_empty() {
        struct Empty;
        impl Detector for Empty {
            fn detect(&self, _input: &str) -> Vec<super::DetectedEntity> {
                Vec::new()
            }
        }
        let fallback = FallbackDetector::new(Empty, RegexDetector::new());
        let out = fallback.detect("contact a@b.com");
        assert!(
            out.iter().any(|e| e.kind == EntityKind::Email),
            "regex fallback should have found the email"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fallback_regex_kicks_in_when_bitnet_server_down() {
        // Primary points nowhere; fallback should pick up the email.
        let primary = BitnetDetector::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        let fallback = FallbackDetector::new(primary, RegexDetector::new());
        let out = fallback.detect("ping me at eng@example.com please");
        assert!(
            out.iter().any(|e| e.kind == EntityKind::Email),
            "regex fallback should trigger when BitNet is unreachable"
        );
    }

    // ---------- Phase 5: FallbackDetector::detect_async + AnyDetector ----------

    #[tokio::test(flavor = "multi_thread")]
    async fn fallback_detect_async_prefers_primary_without_secondary_hit() {
        struct OnePerson;
        impl Detector for OnePerson {
            fn detect(&self, _input: &str) -> Vec<super::DetectedEntity> {
                vec![super::DetectedEntity {
                    kind: EntityKind::Person,
                    start: 0,
                    end: 5,
                    text: "Alice".to_string(),
                }]
            }
        }
        // Regex secondary would flag a@b.com. If `detect_async` short-circuits
        // correctly, only the primary's `Person` span comes back.
        let fb = FallbackDetector::new(OnePerson, RegexDetector::new());
        let found = fb.detect_async("Alice pinged a@b.com").await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Person);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fallback_detect_async_falls_through_to_secondary_when_primary_empty() {
        // Primary server is down (connection refused) → primary returns empty
        // via its native async path; secondary (regex) catches the email.
        let primary = BitnetDetector::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        let fb = FallbackDetector::new(primary, RegexDetector::new());
        let found = fb.detect_async("reach me at ops@example.com").await;
        assert!(found.iter().any(|e| e.kind == EntityKind::Email));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn any_detector_bitnet_variant_round_trips_through_pipeline() {
        let body = r#"{"entities":[{"kind":"PERSON","start":0,"end":9}]}"#;
        let server = spawn_server(http_ok(body)).await;
        let detector = super::AnyDetector::Bitnet(BitnetDetector::new(server.base_url));
        let mut pipeline = crate::VeilPipeline::new(detector);
        let out = pipeline.pseudonymize("Dr. Smith signed off");
        assert_eq!(out, "PERSON_1 signed off");
        assert_eq!(pipeline.reverse_map(&out), "Dr. Smith signed off");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn any_detector_bitnet_with_regex_fallback_composes() {
        // Primary BitNet server is unreachable; the AnyDetector variant's
        // async path must still surface the regex-detected email.
        let primary = BitnetDetector::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        let detector = super::AnyDetector::BitnetWithRegexFallback(FallbackDetector::new(
            primary,
            RegexDetector::new(),
        ));
        let found = detector.detect_async("email: a@b.com").await;
        assert!(
            found.iter().any(|e| e.kind == EntityKind::Email),
            "regex fallback under AnyDetector must still fire on BitNet outage"
        );
    }

    // ---------- Phase 7: MergeFallback ----------

    /// Stub that returns a fixed set of spans regardless of input.
    /// Used to isolate `MergeFallback` behavior from any live detector.
    struct StubDetector(Vec<super::DetectedEntity>);
    impl Detector for StubDetector {
        fn detect(&self, _input: &str) -> Vec<super::DetectedEntity> {
            self.0.clone()
        }
    }

    #[test]
    fn merge_fallback_unions_non_overlapping_spans_from_both_stages() {
        // The Phase 7 acceptance: E27's live smoke showed FallbackDetector
        // drops the email when spaCy returns a PERSON in the same
        // sentence. MergeFallback must keep both.
        let primary = StubDetector(vec![super::DetectedEntity {
            kind: EntityKind::Person,
            start: 4,
            end: 9,
            text: "Smith".to_string(),
        }]);
        let secondary = RegexDetector::new();
        let merge = MergeFallback::new(primary, secondary);
        let out = merge.detect("Dr. Smith emailed baris@example.com");
        assert_eq!(out.len(), 2, "expected PERSON + EMAIL, got {out:?}");
        // Sorted by start.
        assert_eq!(out[0].kind, EntityKind::Person);
        assert_eq!(out[0].text, "Smith");
        assert_eq!(out[1].kind, EntityKind::Email);
        assert_eq!(out[1].text, "baris@example.com");
    }

    #[test]
    fn merge_fallback_primary_wins_on_overlap() {
        // Both stages claim the same span. Keep primary's label, drop
        // secondary — same precedence as `audit_reply_async`'s sync/learned
        // merge so behavior is uniform across the codebase.
        let primary = StubDetector(vec![super::DetectedEntity {
            kind: EntityKind::Person,
            // Intentionally mis-labeling an email span as Person to prove
            // primary's label stands on overlap.
            start: 0,
            end: 7,
            text: "a@b.com".to_string(),
        }]);
        let secondary = RegexDetector::new();
        let merge = MergeFallback::new(primary, secondary);
        let out = merge.detect("a@b.com and nothing else");
        assert_eq!(out.len(), 1, "overlap must dedup, got {out:?}");
        assert_eq!(
            out[0].kind,
            EntityKind::Person,
            "primary label must win on overlap"
        );
    }

    #[test]
    fn merge_fallback_degrades_to_secondary_when_primary_empty() {
        // With an empty primary, MergeFallback and FallbackDetector
        // produce the same output — regex catches what the learned stage
        // missed. This preserves the safety-net behavior E27's writeup
        // flagged as a reason to keep around.
        struct Empty;
        impl Detector for Empty {
            fn detect(&self, _input: &str) -> Vec<super::DetectedEntity> {
                Vec::new()
            }
        }
        let merge = MergeFallback::new(Empty, RegexDetector::new());
        let out = merge.detect("contact a@b.com");
        assert!(
            out.iter().any(|e| e.kind == EntityKind::Email),
            "regex must still fire when primary is empty, got {out:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn merge_fallback_detect_async_unions_both_stages() {
        // Exact async analogue of the sync union test — guards against a
        // regression where the override on `detect_async` drifts from the
        // sync path (Phase 5 hit exactly this kind of bug).
        let primary = StubDetector(vec![super::DetectedEntity {
            kind: EntityKind::Person,
            start: 4,
            end: 9,
            text: "Smith".to_string(),
        }]);
        let merge = MergeFallback::new(primary, RegexDetector::new());
        let out = merge
            .detect_async("Dr. Smith emailed baris@example.com")
            .await;
        assert_eq!(out.len(), 2, "async path must also union, got {out:?}");
        assert_eq!(out[0].kind, EntityKind::Person);
        assert_eq!(out[1].kind, EntityKind::Email);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn any_detector_bitnet_merge_regex_variant_composes() {
        // Variant-level wiring: AnyDetector::BitnetMergeRegex exists and
        // routes to MergeFallback. Use unreachable BitNet to force the
        // primary-empty path and confirm regex still surfaces.
        let primary = BitnetDetector::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        let detector =
            super::AnyDetector::BitnetMergeRegex(MergeFallback::new(primary, RegexDetector::new()));
        let found = detector
            .detect_async("ping me at support@example.com please")
            .await;
        assert!(
            found.iter().any(|e| e.kind == EntityKind::Email),
            "regex safety net must fire under AnyDetector::BitnetMergeRegex too"
        );
    }
}
