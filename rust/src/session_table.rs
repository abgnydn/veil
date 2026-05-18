//! Session-scoped entity graph: surface forms ↔ stable pseudonym.
//!
//! Phase 0 shipped a flat `(real, kind) → pseudonym` map — good enough for
//! exact-match recall across turns. Phase 2 promotes it to a small entity
//! graph so that distinct surface forms for the same underlying entity
//! (e.g. `Dr. Smith` and `Smith`) collapse to a single pseudonym. The
//! collapsing rule is intentionally crude and local: normalize the surface
//! (lowercase + strip honorifics for `Person`) and look the normalized form
//! up in a `surface_index`. Discourse-level anaphora (`she` → `Dr. Smith`)
//! is out of scope here — the "Say Something Else" benchmark lives at
//! Phase 3.
//!
//! The `pseudonymize` / `real_for` / `pseudo_for` / `len` / `is_empty`
//! surface is preserved from Phase 0 so downstream callers don't move.

use std::collections::HashMap;

use crate::entities::EntityKind;

/// Opaque identifier for one entity inside a session. Stable for the life
/// of the `SessionTable` — surface forms collapse onto the same `EntityId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityId(u64);

#[derive(Debug, Clone)]
struct Entry {
    pseudonym: String,
    /// The first surface form we saw for this entity — what reverse-mapping
    /// restores. Keeping "first seen" (rather than "most recent") means
    /// round-tripping is deterministic and testable.
    canonical: String,
}

#[derive(Debug, Default, Clone)]
pub struct SessionTable {
    entries: HashMap<EntityId, Entry>,
    /// Normalized surface → entity id. See `normalize_surface` for the rule
    /// that decides which surfaces collapse.
    surface_index: HashMap<String, EntityId>,
    pseudonym_index: HashMap<String, EntityId>,
    counters: HashMap<EntityKind, u32>,
    next_id: u64,
}

impl SessionTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a stable pseudonym for `real`, minting a new one the first
    /// time we see the underlying entity and reusing the existing one every
    /// time after — including for distinct surface forms that normalize to
    /// the same entity (e.g. `Dr. Smith` and `Smith` both yield `PERSON_1`).
    pub fn pseudonymize(&mut self, real: &str, kind: EntityKind) -> String {
        let normalized = normalize_surface(real, kind);
        if let Some(id) = self.surface_index.get(&normalized) {
            if let Some(entry) = self.entries.get(id) {
                return entry.pseudonym.clone();
            }
        }
        // Mint a fresh entity.
        let id = EntityId(self.next_id);
        self.next_id += 1;
        let counter = self.counters.entry(kind).or_insert(0);
        *counter += 1;
        let pseudonym = format!("{}_{}", kind.as_prefix(), counter);
        self.entries.insert(
            id,
            Entry {
                pseudonym: pseudonym.clone(),
                canonical: real.to_string(),
            },
        );
        self.surface_index.insert(normalized, id);
        self.pseudonym_index.insert(pseudonym.clone(), id);
        pseudonym
    }

    /// Look up the real entity behind a pseudonym we minted. Returns the
    /// canonical (first-seen) surface form so reverse-mapping is stable
    /// regardless of which surface variant arrived last.
    #[must_use]
    pub fn real_for(&self, pseudo: &str) -> Option<&str> {
        let id = self.pseudonym_index.get(pseudo)?;
        self.entries.get(id).map(|e| e.canonical.as_str())
    }

    /// Look up the pseudonym for a real entity, if we've seen it.
    /// Tries an exact match first (covers identity-normalized kinds) and
    /// falls back to the Person normalization so `pseudo_for("Dr. Smith")`
    /// resolves when the entity was stored as bare `Smith`.
    #[must_use]
    pub fn pseudo_for(&self, real: &str) -> Option<&str> {
        let id = self
            .surface_index
            .get(real)
            .or_else(|| self.surface_index.get(&normalize_person(real)))?;
        self.entries.get(id).map(|e| e.pseudonym.as_str())
    }

    /// Number of distinct entities we have pseudonyms for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Surface-form coreference normalization.
///
/// - `Person`: lowercase, strip a leading honorific (`Dr.`, `Mr.`, `Mrs.`,
///   `Ms.`, `Prof.`, `Miss`), and trim whitespace. This is the rule that
///   makes `Dr. Smith` and `Smith` collapse onto the same pseudonym.
/// - Every other kind: treat the surface as already canonical. Emails are
///   technically case-insensitive but Phase 0 tests assume exact-match
///   semantics, so we leave them alone — emails rarely change case within
///   one conversation and the regression cost outweighs the benefit.
fn normalize_surface(real: &str, kind: EntityKind) -> String {
    match kind {
        EntityKind::Person => normalize_person(real),
        EntityKind::Email
        | EntityKind::Path
        | EntityKind::Ip
        | EntityKind::Url
        | EntityKind::Uuid => real.to_string(),
    }
}

// Honorifics stripped by `normalize_person`. Order matters when one is a
// prefix of another ("mr." before "mr") so the longer match wins.
const HONORIFICS: &[&str] = &[
    "dr.", "dr", "mr.", "mr", "mrs.", "mrs", "ms.", "ms", "prof.", "prof", "miss",
];

fn normalize_person(real: &str) -> String {
    let trimmed = real.trim();
    let lower = trimmed.to_lowercase();
    // Strip a single leading honorific + the punctuation/whitespace after
    // it. We only strip one — "dr. mr. smith" is already weird input.
    for honor in HONORIFICS {
        if let Some(rest) = lower.strip_prefix(honor) {
            // Must be followed by whitespace to count as a title, not a
            // prefix of a longer name (e.g. "Mrsomething" is not "Mrs" +
            // "omething").
            if let Some(stripped) = rest.strip_prefix(char::is_whitespace) {
                return stripped.trim().to_string();
            }
        }
    }
    lower
}

#[cfg(test)]
mod tests {
    use super::{normalize_person, EntityKind, SessionTable};

    #[test]
    fn stable_across_repeated_calls() {
        let mut t = SessionTable::new();
        let p1 = t.pseudonymize("a@b.com", EntityKind::Email);
        let p2 = t.pseudonymize("a@b.com", EntityKind::Email);
        assert_eq!(p1, p2);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn distinct_entities_get_distinct_pseudonyms() {
        let mut t = SessionTable::new();
        let p1 = t.pseudonymize("a@b.com", EntityKind::Email);
        let p2 = t.pseudonymize("c@d.com", EntityKind::Email);
        assert_ne!(p1, p2);
        assert_eq!(p1, "EMAIL_1");
        assert_eq!(p2, "EMAIL_2");
    }

    #[test]
    fn counters_are_per_kind() {
        let mut t = SessionTable::new();
        let e = t.pseudonymize("a@b.com", EntityKind::Email);
        let p = t.pseudonymize("/Users/x/y", EntityKind::Path);
        assert_eq!(e, "EMAIL_1");
        assert_eq!(p, "PATH_1");
    }

    #[test]
    fn reverse_lookup_round_trips() {
        let mut t = SessionTable::new();
        let p = t.pseudonymize("a@b.com", EntityKind::Email);
        assert_eq!(t.real_for(&p), Some("a@b.com"));
        assert_eq!(t.pseudo_for("a@b.com"), Some(p.as_str()));
        assert_eq!(t.real_for("NONEXISTENT_99"), None);
    }

    #[test]
    fn person_coref_groups_honorific_surface_forms() {
        let mut t = SessionTable::new();
        let p1 = t.pseudonymize("Dr. Smith", EntityKind::Person);
        let p2 = t.pseudonymize("Smith", EntityKind::Person);
        assert_eq!(p1, p2, "honorific + bare name should share a pseudonym");
        assert_eq!(p1, "PERSON_1");
        assert_eq!(t.len(), 1, "only one entity should be minted");
    }

    #[test]
    fn person_reverse_returns_first_seen_surface() {
        let mut t = SessionTable::new();
        // First surface wins — this is what lets a consistent reply
        // reverse-map back to the way the user originally phrased it.
        let _ = t.pseudonymize("Dr. Smith", EntityKind::Person);
        let _ = t.pseudonymize("Smith", EntityKind::Person);
        assert_eq!(t.real_for("PERSON_1"), Some("Dr. Smith"));
    }

    #[test]
    fn person_coref_respects_distinct_names() {
        let mut t = SessionTable::new();
        let p1 = t.pseudonymize("Dr. Smith", EntityKind::Person);
        let p2 = t.pseudonymize("Dr. Jones", EntityKind::Person);
        assert_ne!(p1, p2);
        assert_eq!(p1, "PERSON_1");
        assert_eq!(p2, "PERSON_2");
    }

    #[test]
    fn person_coref_is_case_insensitive() {
        let mut t = SessionTable::new();
        let p1 = t.pseudonymize("SMITH", EntityKind::Person);
        let p2 = t.pseudonymize("smith", EntityKind::Person);
        assert_eq!(p1, p2);
    }

    #[test]
    fn non_person_kinds_skip_normalization() {
        // Phase 0 semantics: exact match for emails. "A@b.com" and
        // "a@b.com" stay distinct — we do not want to pretend to canonicalize
        // without a proper email parser.
        let mut t = SessionTable::new();
        let p1 = t.pseudonymize("A@b.com", EntityKind::Email);
        let p2 = t.pseudonymize("a@b.com", EntityKind::Email);
        assert_ne!(p1, p2);
    }

    #[test]
    fn normalize_person_strips_common_honorifics() {
        assert_eq!(normalize_person("Dr. Smith"), "smith");
        assert_eq!(normalize_person("Mr. Smith"), "smith");
        assert_eq!(normalize_person("Mrs. Smith"), "smith");
        assert_eq!(normalize_person("Ms. Smith"), "smith");
        assert_eq!(normalize_person("Prof. Smith"), "smith");
        assert_eq!(normalize_person("Miss Smith"), "smith");
        assert_eq!(normalize_person("Smith"), "smith");
        // No false positive: "Mrsomething" is not "Mrs" + "omething".
        assert_eq!(normalize_person("Mrsomething"), "mrsomething");
    }
}
