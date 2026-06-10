//! Entity detection — regex stub for Phase 0; swapped for `BitNet` in Phase 1.
//!
//! The `Detector` trait is the stable boundary: the rest of the pipeline
//! does not care whether spans come from regex, an SLM, or something else.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// The kind of a detected entity. Drives pseudonym namespacing
/// (`EMAIL_1`, `PATH_2`, …) and reverse-mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKind {
    Email,
    Path,
    Ip,
    Url,
    Uuid,
    /// Personal name. Regex alone cannot reliably find names, so this kind
    /// only reaches the session table via the learned detector
    /// ([`crate::HttpNerDetector`], typically GLiNER).
    Person,
    /// Place name (city, country, address). Learned-detector only — same
    /// rationale as [`Self::Person`].
    Location,
    /// Organization / company name. Learned-detector only.
    Org,
    /// Catch-all for any other PII a learned/LLM detector flags that has no
    /// dedicated kind yet — phone, date of birth, account/ID number, address,
    /// SSN, etc. Pseudonym prefix is `PII`. Lets an LLM detector cover the long
    /// tail of identifiers (where the leakage hides) while staying reversible.
    Custom,
}

impl EntityKind {
    /// Every kind this crate currently mints, in pseudonym-counter order.
    /// Single source of truth for the reverse-map / audit scanner pattern
    /// (`pipeline.rs` builds its alternation from these prefixes) so adding a
    /// kind here is the only edit needed — no second regex to keep in sync.
    /// See `docs/CONTRACT.md` §2 for the canonical kind↔prefix table.
    pub const ALL: [EntityKind; 9] = [
        Self::Email,
        Self::Path,
        Self::Ip,
        Self::Url,
        Self::Uuid,
        Self::Person,
        Self::Location,
        Self::Org,
        Self::Custom,
    ];

    /// Upper-case prefix used in generated pseudonyms.
    #[must_use]
    pub const fn as_prefix(self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::Path => "PATH",
            Self::Ip => "IP",
            Self::Url => "URL",
            Self::Uuid => "UUID",
            Self::Person => "PERSON",
            Self::Location => "LOCATION",
            Self::Org => "ORG",
            Self::Custom => "PII",
        }
    }

    /// Parse the prefix produced by `as_prefix`, for reverse-mapping.
    #[must_use]
    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "EMAIL" => Some(Self::Email),
            "PATH" => Some(Self::Path),
            "IP" => Some(Self::Ip),
            "URL" => Some(Self::Url),
            "UUID" => Some(Self::Uuid),
            "PERSON" => Some(Self::Person),
            "LOCATION" => Some(Self::Location),
            "ORG" => Some(Self::Org),
            "PII" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// A single detection: where the entity is in the input string and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedEntity {
    pub kind: EntityKind,
    /// Byte offset (inclusive) of the entity start within the input.
    pub start: usize,
    /// Byte offset (exclusive) of the entity end within the input.
    pub end: usize,
    /// The actual text of the entity.
    pub text: String,
}

/// Abstract entity detector. Phase 0 ships `RegexDetector`; Phase 1 adds
/// a `BitnetDetector` that speaks HTTP to a local `BitNet` server.
pub trait Detector: Send + Sync {
    /// Return non-overlapping detections in `input`, sorted by `start`.
    fn detect(&self, input: &str) -> Vec<DetectedEntity>;

    /// Async counterpart. Default delegates to the sync version so
    /// lightweight detectors (e.g. [`RegexDetector`]) don't need to
    /// override. Detectors with a native async path (e.g. HTTP-backed
    /// `BitnetDetector`) override this to avoid a `block_in_place` hop —
    /// critical on the Phase 4 `audit_reply_async` path, where the whole
    /// point is running the learned detector inside an existing async
    /// call without blocking a runtime worker.
    fn detect_async<'a>(
        &'a self,
        input: &'a str,
    ) -> impl std::future::Future<Output = Vec<DetectedEntity>> + Send + 'a {
        async move { self.detect(input) }
    }
}

/// Regex-based detector covering five common entity kinds. Deliberately
/// coarse — Phase 1 replaces this with a learned sanitizer.
#[derive(Debug, Clone)]
pub struct RegexDetector {
    patterns: Vec<(EntityKind, Regex)>,
}

impl RegexDetector {
    /// Build a detector covering email, filesystem path, IPv4, URL, UUID.
    ///
    /// # Panics
    /// Only on programmer error if the embedded patterns fail to compile,
    /// which is covered by the regression test below.
    #[must_use]
    pub fn new() -> Self {
        // Order matters: URL is checked before email so that an `@` inside
        // a URL does not get carved out as an email span.
        // URL/PATH exclude trailing delimiters — quotes, commas, brackets,
        // braces, angle brackets, backtick — so a value in code or JSON
        // (`"https://x.dev",`) doesn't swallow the closing `"`/`,`. Without
        // this the span eats surrounding syntax and mangles the round-trip.
        let raw: &[(EntityKind, &str)] = &[
            (EntityKind::Url, "https?://[^\\s)\\]}>\"',`<]+"),
            (
                EntityKind::Email,
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ),
            (
                EntityKind::Path,
                "/(?:Users|home|tmp|var|opt|etc|usr)/[^\\s)\\]}>\"',`<]+",
            ),
            (EntityKind::Ip, r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            (
                EntityKind::Uuid,
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            ),
        ];
        let patterns = raw
            .iter()
            .map(|(kind, pat)| {
                (
                    *kind,
                    Regex::new(pat).expect("embedded detector pattern must compile"),
                )
            })
            .collect();
        Self { patterns }
    }
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexDetector {
    fn detect(&self, input: &str) -> Vec<DetectedEntity> {
        let mut all: Vec<DetectedEntity> = Vec::new();
        for (kind, re) in &self.patterns {
            for m in re.find_iter(input) {
                all.push(DetectedEntity {
                    kind: *kind,
                    start: m.start(),
                    end: m.end(),
                    text: m.as_str().to_string(),
                });
            }
        }
        resolve_overlaps(all)
    }
}

/// Sort detections by `start`, then drop any that overlap with a
/// previously-kept one. Tie on start: keep the longer span.
fn resolve_overlaps(mut all: Vec<DetectedEntity>) -> Vec<DetectedEntity> {
    all.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<DetectedEntity> = Vec::with_capacity(all.len());
    for det in all {
        let overlaps = out.last().is_some_and(|last| last.end > det.start);
        if !overlaps {
            out.push(det);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Detector, EntityKind, RegexDetector};

    #[test]
    fn detector_compiles_every_pattern() {
        let _ = RegexDetector::new();
    }

    #[test]
    fn finds_email_path_ip_url_uuid() {
        let d = RegexDetector::new();
        let input =
            "a@b.com /Users/x/y 10.0.0.1 https://example.com/x 550e8400-e29b-41d4-a716-446655440000";
        let found = d.detect(input);
        let kinds: Vec<_> = found.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&EntityKind::Email));
        assert!(kinds.contains(&EntityKind::Path));
        assert!(kinds.contains(&EntityKind::Ip));
        assert!(kinds.contains(&EntityKind::Url));
        assert!(kinds.contains(&EntityKind::Uuid));
    }

    #[test]
    fn url_and_path_do_not_swallow_trailing_quote_or_comma() {
        // The agentic case: a URL/path as a value in code or JSON. The span
        // must stop at the closing quote, not eat it (or the surrounding
        // syntax breaks when pseudonymized).
        let d = RegexDetector::new();
        let input = r#"{"authUrl": "https://auth.internal.acme.dev", "doc": "/Users/x/run.md"}"#;
        let found = d.detect(input);
        let url = found.iter().find(|e| e.kind == EntityKind::Url).unwrap();
        assert_eq!(url.text, "https://auth.internal.acme.dev");
        let path = found.iter().find(|e| e.kind == EntityKind::Path).unwrap();
        assert_eq!(path.text, "/Users/x/run.md");
    }

    #[test]
    fn url_shadows_embedded_email_shape() {
        // "https://user@host/…" contains an `@` but URL should consume it
        // so we don't emit a stray email span inside the URL.
        let d = RegexDetector::new();
        let input = "see https://user@host.example.com/x for details";
        let found = d.detect(input);
        let emails: Vec<_> = found
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .collect();
        assert!(
            emails.is_empty(),
            "no email should be emitted inside a URL span, got: {emails:?}"
        );
    }

    #[test]
    fn detections_are_sorted_and_non_overlapping() {
        let d = RegexDetector::new();
        let input = "emails a@b.com and c@d.org plus /tmp/x";
        let found = d.detect(input);
        for pair in found.windows(2) {
            assert!(pair[0].end <= pair[1].start, "overlapping spans: {pair:?}");
        }
    }

    #[test]
    fn entity_kind_prefix_round_trip() {
        for k in EntityKind::ALL {
            assert_eq!(EntityKind::from_prefix(k.as_prefix()), Some(k));
        }
        assert_eq!(EntityKind::from_prefix("UNKNOWN"), None);
    }
}
