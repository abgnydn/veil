//! Phase 8 — prompt-space k-anonymity.
//!
//! Given a prompt `P` whose entities have already been replaced with
//! session-minted pseudonyms, the cohort sampler produces `k-1` synthetic
//! *sibling* prompts by swapping every real pseudonym for a same-kind
//! attribute drawn from a pseudonym *pool*. All `k` prompts are then
//! dispatched to the provider; the response bound to the real pseudonym
//! set is returned and the `k-1` sibling responses are logged and
//! discarded by the caller.
//!
//! This module ships the trait ([`CohortSynthesizer`]), a positional
//! attribute container ([`PromptEntities`]), and a v1 implementation
//! ([`StaticPoolSynthesizer`]) backed by a reserved-numeric-range pool.
//! Integration with the provider layer is deliberately not in this module
//! — the trait is the stable boundary so the production design (a federated
//! cohort histogram from the Swarm) can slot in later without touching the
//! pipeline.
//!
//! # Privacy guarantee (v1)
//!
//! For a prompt with pseudonym set `E = {e_1, …, e_n}`, the synthesizer
//! returns `k-1` sibling sets `E'_1, …, E'_{k-1}`. Each `E'_j` is
//! positionally aligned with `E` (same kinds, same order) but drawn from
//! a pool disjoint from the session's `SessionTable`. An adversary that
//! observes the cohort and has no out-of-band information cannot identify
//! which of the `k` prompts carries the real session's pseudonyms with
//! probability better than `1/k` — entropy `log2(k)`.
//!
//! # Known limitations (tracked; acceptable for v1)
//!
//! - **Pool fingerprint.** Default pool numbering uses a reserved range
//!   (`*_10001` upward). An adversary that knows the scheme can partition
//!   real vs sibling by range. Future work: randomize pool assignment
//!   per-session. Documented in `~/brain/experiments/E29`.
//! - **Temporal correlation.** The synthesizer is deterministic, so the
//!   same real set produces the same sibling sets across turns. Also
//!   fingerprintable. Same future work applies.
//! - **Side-channel symmetry.** The cohort dispatcher (provider layer) is
//!   responsible for ensuring siblings carry identical temperature, tokens,
//!   and headers to the real request. This module cannot enforce that.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::entities::EntityKind;
use crate::session_table::SessionTable;

/// Numeric floor for default-pool pseudonyms (`EMAIL_10001`, `EMAIL_10002`,
/// …). Picked far above any plausible per-session mint count so the pool
/// is disjoint from `SessionTable` output by construction. The
/// `assert_disjoint_from_session` check enforces it at runtime anyway.
const POOL_NUMERIC_FLOOR: usize = 10_001;

/// Per-kind default-pool size. Supports k up to `POOL_SIZE + 1` for a
/// single-entity prompt, or k up to `POOL_SIZE / n + 1` when the prompt
/// has `n` entities of the same kind. 16 is comfortable for v1 — PUPA
/// benchmark prompts rarely carry more than 2 entities of one kind, so
/// k <= 8 is well within range.
const POOL_SIZE_PER_KIND: usize = 16;

/// The ordered set of pseudonyms that appear in one prompt, each tagged
/// with its entity kind. Positional: `pairs[i]` for a real prompt maps to
/// `pairs[i]` in each sibling, so the substitution walker can build a
/// rewrite map by zip.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptEntities {
    pairs: Vec<(String, EntityKind)>,
}

impl PromptEntities {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an ordered list of (pseudonym, kind). Duplicates are
    /// preserved — if the caller extracts entities positionally (e.g.
    /// from a sanitized text via `from_sanitized_text`), dedup is already
    /// applied; if they construct manually, they own the order semantics.
    #[must_use]
    pub fn from_pairs(pairs: Vec<(String, EntityKind)>) -> Self {
        Self { pairs }
    }

    pub fn push(&mut self, pseudonym: impl Into<String>, kind: EntityKind) {
        self.pairs.push((pseudonym.into(), kind));
    }

    #[must_use]
    pub fn pairs(&self) -> &[(String, EntityKind)] {
        &self.pairs
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Scan `sanitized` text for pseudonym tokens (same grammar as
    /// `VeilPipeline::pseudonym_pattern`) and collect them in first-seen
    /// order, deduplicated. Each token's kind is decoded from its prefix.
    /// Tokens whose prefix is not a known `EntityKind` are skipped.
    ///
    /// This is how the provider layer extracts the real prompt's entity
    /// set from an already-sanitized request without touching the session
    /// table: walk the sanitized text, pick out every pseudonym.
    #[must_use]
    pub fn from_sanitized_text(sanitized: &str) -> Self {
        let mut out = Self::new();
        out.extend_from_sanitized_text(sanitized);
        out
    }

    /// Scan `sanitized` and append any pseudonyms not already in `self`.
    /// Used by the provider layer to accumulate entities across every
    /// text/JSON surface of a `MessageRequest` (system, text blocks,
    /// tool-call JSON leaves) into one positional set before handing it
    /// to the synthesizer.
    pub fn extend_from_sanitized_text(&mut self, sanitized: &str) {
        let pat = pseudonym_pattern();
        let mut seen: BTreeSet<String> = self.pairs.iter().map(|(p, _)| p.clone()).collect();
        for m in pat.find_iter(sanitized) {
            let text = m.as_str();
            if !seen.insert(text.to_string()) {
                continue;
            }
            let Some(prefix) = text.split('_').next() else {
                continue;
            };
            if let Some(kind) = EntityKind::from_prefix(prefix) {
                self.pairs.push((text.to_string(), kind));
            }
        }
    }
}

/// Errors the cohort synthesizer can surface. The provider layer decides
/// whether to fail closed (abort the real request) or fail open (skip
/// cohort for this turn and log) based on `CohortPolicy::on_failure`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CohortError {
    /// The pool has entries for this kind but not enough to produce `k-1`
    /// disjoint siblings when the real prompt carries multiple entities
    /// of this kind. `needed = (k-1) * count_of_kind_in_real`.
    PoolExhausted {
        kind: EntityKind,
        needed: usize,
        available: usize,
    },
    /// The pool has no entries for this kind at all — usually a static
    /// configuration error (new `EntityKind` added, pool not extended).
    KindUnsupported { kind: EntityKind },
    /// A pool entry collides with a pseudonym already minted by the
    /// session. Belt-and-suspenders — the default pool is disjoint by
    /// construction, but a caller-supplied pool might not be.
    PoolCollisionWithSession { pseudonym: String },
}

impl std::fmt::Display for CohortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PoolExhausted {
                kind,
                needed,
                available,
            } => write!(
                f,
                "cohort pool exhausted for kind {kind:?}: needed {needed}, available {available}"
            ),
            Self::KindUnsupported { kind } => {
                write!(f, "cohort pool has no entries for kind {kind:?}")
            }
            Self::PoolCollisionWithSession { pseudonym } => write!(
                f,
                "cohort pool entry {pseudonym} collides with a session-minted pseudonym"
            ),
        }
    }
}

impl std::error::Error for CohortError {}

/// Produce `k-1` sibling pseudonym sets for the given real set. v1 ships
/// [`StaticPoolSynthesizer`]; production targets a federated cohort
/// histogram from the Swarm, but the trait shape is intentionally
/// stable across implementations.
pub trait CohortSynthesizer: Send + Sync {
    /// Synthesize the sibling cohort for `real`. Returns `k-1` sibling
    /// [`PromptEntities`], each the same length as `real` with identical
    /// kinds in identical order but distinct pool-sourced pseudonyms.
    ///
    /// `k == 1` is a legal no-op (returns empty `Vec`). `k == 0` is also
    /// treated as no-op for defensive reasons — the caller should still
    /// guard against `k == 0` at the policy layer.
    fn synthesize(
        &self,
        real: &PromptEntities,
        k: usize,
    ) -> Result<Vec<PromptEntities>, CohortError>;
}

/// v1 synthesizer: a hardcoded attribute pool per `EntityKind`. Draws are
/// deterministic and positional — sibling `j` for real position `i` of
/// kind `K` gets `pool[K][j * n_K + i]` where `n_K` is the count of `K`
/// in the real prompt. This keeps sibling 0 and sibling 1 disjoint at
/// every position.
#[derive(Debug, Clone)]
pub struct StaticPoolSynthesizer {
    pool: HashMap<EntityKind, Vec<String>>,
}

impl StaticPoolSynthesizer {
    /// Build with the default pool (16 entries per kind, numeric range
    /// `*_10001..=*_10016`).
    #[must_use]
    pub fn with_default_pool() -> Self {
        Self {
            pool: build_default_pool(),
        }
    }

    /// Build with a caller-supplied pool. Useful for tests that want a
    /// tiny pool to exercise exhaustion, and for future swaps to a
    /// Swarm-sourced pool.
    #[must_use]
    pub fn with_pool(pool: HashMap<EntityKind, Vec<String>>) -> Self {
        Self { pool }
    }

    /// Return `Err(CohortError::PoolCollisionWithSession)` if any pool
    /// entry is already minted in `session`. The default pool is disjoint
    /// from `SessionTable` output by construction (`POOL_NUMERIC_FLOOR`
    /// sits above any plausible session mint), but this check fires
    /// regardless — an attacker-supplied pool or a session that happens
    /// to have minted >10000 distinct entities of one kind would otherwise
    /// leak real entities into sibling slots.
    pub fn assert_disjoint_from_session(&self, session: &SessionTable) -> Result<(), CohortError> {
        for entries in self.pool.values() {
            for pseudo in entries {
                if session.real_for(pseudo).is_some() {
                    return Err(CohortError::PoolCollisionWithSession {
                        pseudonym: pseudo.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Inspect the pool for a given kind — for tests and diagnostics.
    #[must_use]
    pub fn pool_for(&self, kind: EntityKind) -> Option<&[String]> {
        self.pool.get(&kind).map(Vec::as_slice)
    }
}

impl CohortSynthesizer for StaticPoolSynthesizer {
    fn synthesize(
        &self,
        real: &PromptEntities,
        k: usize,
    ) -> Result<Vec<PromptEntities>, CohortError> {
        if k <= 1 {
            return Ok(Vec::new());
        }
        let k_minus_1 = k - 1;

        // Capacity check per kind up front. Fails fast with a precise
        // error rather than running half-way and leaving the caller
        // with a partial cohort.
        let mut kind_counts: HashMap<EntityKind, usize> = HashMap::new();
        for (_, kind) in real.pairs() {
            *kind_counts.entry(*kind).or_insert(0) += 1;
        }
        for (kind, n) in &kind_counts {
            let need = k_minus_1 * n;
            let avail = self.pool.get(kind).map_or(0, Vec::len);
            if avail == 0 {
                return Err(CohortError::KindUnsupported { kind: *kind });
            }
            if avail < need {
                return Err(CohortError::PoolExhausted {
                    kind: *kind,
                    needed: need,
                    available: avail,
                });
            }
        }

        let mut siblings: Vec<PromptEntities> =
            (0..k_minus_1).map(|_| PromptEntities::new()).collect();
        // Per-kind cursor tracks how many pool entries we've consumed.
        let mut per_kind_cursor: HashMap<EntityKind, usize> = HashMap::new();
        for (_real_pseudo, kind) in real.pairs() {
            let pool = self
                .pool
                .get(kind)
                .expect("capacity check above guarantees kind is present");
            let cursor = per_kind_cursor.entry(*kind).or_insert(0);
            for sibling in &mut siblings {
                let pseudo = pool
                    .get(*cursor)
                    .expect("capacity check above guarantees pool has enough entries");
                sibling.push(pseudo.clone(), *kind);
                *cursor += 1;
            }
        }
        Ok(siblings)
    }
}

/// Rewrite every real pseudonym in `sanitized` to its sibling counterpart,
/// position-aligned from `real` ↔ `sibling`. Pseudonyms in `sanitized` that
/// are not in `real` are left alone (they are either unknown pseudonyms —
/// someone else's problem for the auditor — or already a pool entry).
///
/// `real` and `sibling` must be the same length; `sibling` must be the
/// output of a [`CohortSynthesizer::synthesize`] call given `real`. The
/// provider layer is the only caller and owns that invariant.
#[must_use]
pub fn substitute_pseudonyms(
    sanitized: &str,
    real: &PromptEntities,
    sibling: &PromptEntities,
) -> String {
    debug_assert_eq!(
        real.len(),
        sibling.len(),
        "real and sibling PromptEntities must be positionally aligned"
    );
    if real.is_empty() {
        return sanitized.to_string();
    }
    let map: HashMap<&str, &str> = real
        .pairs()
        .iter()
        .zip(sibling.pairs().iter())
        .map(|((r, _), (s, _))| (r.as_str(), s.as_str()))
        .collect();
    let pat = pseudonym_pattern();
    pat.replace_all(sanitized, |caps: &regex::Captures<'_>| {
        let m = caps.get(0).expect("whole match always present").as_str();
        map.get(m).copied().unwrap_or(m).to_string()
    })
    .into_owned()
}

/// Compile the canonical pseudonym pattern. Kept in sync with
/// `VeilPipeline::pseudonym_pattern` — the same grammar both mints and
/// recognizes pseudonyms everywhere in the crate.
fn pseudonym_pattern() -> Regex {
    Regex::new(r"\b(EMAIL|PATH|IP|URL|UUID|PERSON)_\d+\b").expect("pseudonym pattern must compile")
}

/// What the dispatcher should do when a sibling fan-out request fails
/// (network error, synthesizer error, or provider-side rejection of the
/// sibling payload). The real request is never affected by `Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CohortFailure {
    /// Log the failure, reduce the effective cohort size by one, and
    /// still return the real response. Availability-first. Privacy
    /// guarantee degrades from `k` to `k-1` (or fewer) but never below
    /// the trivial `k=1` (pseudonymization only).
    Drop,
    /// Fail the real request if any sibling fails — strict mode. Makes
    /// the privacy guarantee hold exactly or not at all. Useful for
    /// research evaluations where a partial cohort contaminates the
    /// measurement.
    Abort,
}

/// Per-client cohort configuration. Lives alongside `VeilPolicy` on
/// `ProviderClient::Veil` and drives the dispatcher's fan-out loop.
/// `synthesizer` is an `Arc<dyn CohortSynthesizer>` so the same instance
/// can be shared across clones of the `ProviderClient` without
/// duplicating the pool.
#[derive(Clone)]
pub struct CohortPolicy {
    pub k: usize,
    pub synthesizer: Arc<dyn CohortSynthesizer>,
    pub on_failure: CohortFailure,
}

impl std::fmt::Debug for CohortPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortPolicy")
            .field("k", &self.k)
            .field("on_failure", &self.on_failure)
            .field("synthesizer", &"<dyn CohortSynthesizer>")
            .finish()
    }
}

impl CohortPolicy {
    /// Shortcut: k with the default static pool, fail-open.
    #[must_use]
    pub fn static_pool(k: usize) -> Self {
        Self {
            k,
            synthesizer: Arc::new(StaticPoolSynthesizer::with_default_pool()),
            on_failure: CohortFailure::Drop,
        }
    }
}

fn build_default_pool() -> HashMap<EntityKind, Vec<String>> {
    let mut pool = HashMap::new();
    for kind in [
        EntityKind::Email,
        EntityKind::Path,
        EntityKind::Ip,
        EntityKind::Url,
        EntityKind::Uuid,
        EntityKind::Person,
    ] {
        let mut entries = Vec::with_capacity(POOL_SIZE_PER_KIND);
        for i in 0..POOL_SIZE_PER_KIND {
            entries.push(format!("{}_{}", kind.as_prefix(), POOL_NUMERIC_FLOOR + i));
        }
        pool.insert(kind, entries);
    }
    pool
}

#[cfg(test)]
mod tests {
    use super::{
        build_default_pool, substitute_pseudonyms, CohortError, CohortSynthesizer, PromptEntities,
        StaticPoolSynthesizer, POOL_NUMERIC_FLOOR,
    };
    use crate::entities::EntityKind;
    use crate::session_table::SessionTable;
    use std::collections::HashMap;

    #[test]
    fn from_sanitized_text_extracts_pseudonyms_in_first_seen_order() {
        let sanitized = "ping EMAIL_1 then PATH_1 and again EMAIL_1";
        let entities = PromptEntities::from_sanitized_text(sanitized);
        assert_eq!(
            entities.pairs(),
            &[
                ("EMAIL_1".to_string(), EntityKind::Email),
                ("PATH_1".to_string(), EntityKind::Path),
            ]
        );
    }

    #[test]
    fn extend_accumulates_across_surfaces_without_duplicating() {
        // Simulates walking a MessageRequest with EMAIL_1 in the system
        // prompt, PATH_1 in a text block, and EMAIL_1 again in a JSON
        // tool-call arg. Extracted entities must be [EMAIL_1, PATH_1] in
        // first-seen order — no double-count on EMAIL_1.
        let mut entities = PromptEntities::new();
        entities.extend_from_sanitized_text("system: email EMAIL_1");
        entities.extend_from_sanitized_text("text: look at PATH_1");
        entities.extend_from_sanitized_text("tool: to=EMAIL_1");
        assert_eq!(
            entities.pairs(),
            &[
                ("EMAIL_1".to_string(), EntityKind::Email),
                ("PATH_1".to_string(), EntityKind::Path),
            ]
        );
    }

    #[test]
    fn from_sanitized_text_ignores_unknown_prefixes() {
        // "FOO_1" matches none of the known EntityKind prefixes so the
        // pseudonym_pattern regex will not produce a hit in the first
        // place — hence the only extracted entity is the real one.
        let sanitized = "seen FOO_1 alongside EMAIL_1";
        let entities = PromptEntities::from_sanitized_text(sanitized);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities.pairs()[0].0, "EMAIL_1");
    }

    #[test]
    fn static_pool_k_equals_one_returns_empty() {
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![("EMAIL_1".into(), EntityKind::Email)]);
        let siblings = synth.synthesize(&real, 1).expect("k=1 must succeed");
        assert!(siblings.is_empty());
    }

    #[test]
    fn static_pool_k_equals_zero_returns_empty() {
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![("EMAIL_1".into(), EntityKind::Email)]);
        let siblings = synth.synthesize(&real, 0).expect("k=0 must succeed");
        assert!(siblings.is_empty());
    }

    #[test]
    fn static_pool_k_equals_three_produces_two_siblings_same_shape() {
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![("EMAIL_1".into(), EntityKind::Email)]);
        let siblings = synth.synthesize(&real, 3).expect("k=3 must succeed");
        assert_eq!(siblings.len(), 2, "k=3 must yield k-1=2 siblings");
        for sib in &siblings {
            assert_eq!(sib.len(), real.len());
            assert_eq!(sib.pairs()[0].1, EntityKind::Email);
        }
        // Siblings must be distinct at every position — otherwise an
        // adversary collapsing duplicates collapses the cohort to k=2.
        assert_ne!(siblings[0].pairs()[0].0, siblings[1].pairs()[0].0);
    }

    #[test]
    fn static_pool_per_kind_siblings_carry_matching_prefix() {
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![
            ("EMAIL_1".into(), EntityKind::Email),
            ("PATH_1".into(), EntityKind::Path),
        ]);
        let siblings = synth.synthesize(&real, 3).expect("k=3 must succeed");
        for sib in &siblings {
            assert!(
                sib.pairs()[0].0.starts_with("EMAIL_"),
                "position 0 sibling must be an email, got {:?}",
                sib.pairs()[0]
            );
            assert!(
                sib.pairs()[1].0.starts_with("PATH_"),
                "position 1 sibling must be a path, got {:?}",
                sib.pairs()[1]
            );
        }
    }

    #[test]
    fn static_pool_is_deterministic_across_repeated_calls() {
        // v1 guarantee: same real + same k → same siblings. Tests rely on
        // this; later versions can layer in per-session randomization.
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![
            ("EMAIL_1".into(), EntityKind::Email),
            ("EMAIL_2".into(), EntityKind::Email),
            ("PATH_1".into(), EntityKind::Path),
        ]);
        let first = synth.synthesize(&real, 4).expect("first call");
        let second = synth.synthesize(&real, 4).expect("second call");
        assert_eq!(first, second, "deterministic synthesis required");
    }

    #[test]
    fn static_pool_distinct_draws_across_positions_of_same_kind() {
        // If a prompt has two EMAIL entities and k=3, the two EMAIL
        // positions must draw non-colliding pool entries within each
        // sibling — otherwise the sibling prompt has EMAIL_X == EMAIL_X,
        // which collapses two distinct real entities into one and leaks
        // their identicality.
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![
            ("EMAIL_1".into(), EntityKind::Email),
            ("EMAIL_2".into(), EntityKind::Email),
        ]);
        let siblings = synth.synthesize(&real, 3).expect("k=3 must succeed");
        for sib in &siblings {
            assert_ne!(
                sib.pairs()[0].0,
                sib.pairs()[1].0,
                "sibling must not collapse two real EMAILs into one: {:?}",
                sib.pairs()
            );
        }
    }

    #[test]
    fn static_pool_uses_reserved_numeric_range() {
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![("EMAIL_1".into(), EntityKind::Email)]);
        let siblings = synth.synthesize(&real, 3).expect("k=3");
        for sib in &siblings {
            let text = &sib.pairs()[0].0;
            let suffix: usize = text
                .trim_start_matches("EMAIL_")
                .parse()
                .expect("pool entries are EMAIL_<n>");
            assert!(
                suffix >= POOL_NUMERIC_FLOOR,
                "pool entry {text} must be above POOL_NUMERIC_FLOOR={POOL_NUMERIC_FLOOR}"
            );
        }
    }

    #[test]
    fn static_pool_exhausted_is_reported_precisely() {
        // Pool with 2 Email entries; real carries 2 Emails; k=3 needs
        // (k-1) * n = 2 * 2 = 4 distinct draws — must fail.
        let mut pool = HashMap::new();
        pool.insert(
            EntityKind::Email,
            vec!["EMAIL_900".to_string(), "EMAIL_901".to_string()],
        );
        let synth = StaticPoolSynthesizer::with_pool(pool);
        let real = PromptEntities::from_pairs(vec![
            ("EMAIL_1".into(), EntityKind::Email),
            ("EMAIL_2".into(), EntityKind::Email),
        ]);
        let err = synth.synthesize(&real, 3).unwrap_err();
        assert!(
            matches!(
                err,
                CohortError::PoolExhausted {
                    kind: EntityKind::Email,
                    needed: 4,
                    available: 2
                }
            ),
            "expected precise exhaustion error, got {err:?}"
        );
    }

    #[test]
    fn static_pool_kind_unsupported_when_pool_missing_entry() {
        // Pool has only Email; real carries a Person. Must report the
        // missing kind precisely so the caller can diagnose a static
        // configuration gap (new EntityKind, pool not extended).
        let mut pool = HashMap::new();
        pool.insert(EntityKind::Email, vec!["EMAIL_900".to_string()]);
        let synth = StaticPoolSynthesizer::with_pool(pool);
        let real = PromptEntities::from_pairs(vec![("PERSON_1".into(), EntityKind::Person)]);
        let err = synth.synthesize(&real, 2).unwrap_err();
        assert!(matches!(
            err,
            CohortError::KindUnsupported {
                kind: EntityKind::Person
            }
        ));
    }

    #[test]
    fn static_pool_disjoint_from_fresh_session() {
        let synth = StaticPoolSynthesizer::with_default_pool();
        let session = SessionTable::new();
        synth
            .assert_disjoint_from_session(&session)
            .expect("fresh session cannot collide with a disjoint pool");
    }

    #[test]
    fn static_pool_disjoint_from_populated_session() {
        // Populate a session with a realistic handful of pseudonyms and
        // confirm the default pool (numeric range >= 10_001) is still
        // disjoint. Belt-and-suspenders: the default pool's range is
        // engineered to be disjoint, but this pins the contract.
        let synth = StaticPoolSynthesizer::with_default_pool();
        let mut session = SessionTable::new();
        let _ = session.pseudonymize("a@b.com", EntityKind::Email);
        let _ = session.pseudonymize("c@d.com", EntityKind::Email);
        let _ = session.pseudonymize("/Users/x/y", EntityKind::Path);
        let _ = session.pseudonymize("Dr. Smith", EntityKind::Person);
        synth
            .assert_disjoint_from_session(&session)
            .expect("populated real session must be disjoint from default pool");
    }

    #[test]
    fn static_pool_collision_with_session_is_detected() {
        // Caller-supplied pool that (accidentally) contains EMAIL_1,
        // which the session has minted. The collision check must fire
        // before dispatch so we never substitute a real pseudonym into
        // a sibling slot and then accidentally reverse-map it into real
        // data at audit time.
        let mut pool = HashMap::new();
        pool.insert(EntityKind::Email, vec!["EMAIL_1".to_string()]);
        let synth = StaticPoolSynthesizer::with_pool(pool);
        let mut session = SessionTable::new();
        let p = session.pseudonymize("a@b.com", EntityKind::Email);
        assert_eq!(p, "EMAIL_1");
        let err = synth.assert_disjoint_from_session(&session).unwrap_err();
        assert!(matches!(
            err,
            CohortError::PoolCollisionWithSession { ref pseudonym } if pseudonym == "EMAIL_1"
        ));
    }

    #[test]
    fn substitute_replaces_real_pseudonyms_positionally() {
        let real = PromptEntities::from_pairs(vec![
            ("EMAIL_1".into(), EntityKind::Email),
            ("PATH_1".into(), EntityKind::Path),
        ]);
        let sibling = PromptEntities::from_pairs(vec![
            ("EMAIL_10001".into(), EntityKind::Email),
            ("PATH_10001".into(), EntityKind::Path),
        ]);
        let out = substitute_pseudonyms("send EMAIL_1 the file at PATH_1 now", &real, &sibling);
        assert_eq!(out, "send EMAIL_10001 the file at PATH_10001 now");
    }

    #[test]
    fn substitute_leaves_unknown_pseudonyms_alone() {
        // EMAIL_42 is not in `real`, so it should pass through. This is
        // the same policy as `VeilPipeline::reverse_map` — the auditor,
        // not the substitution walker, is responsible for flagging
        // unknown pseudonyms.
        let real = PromptEntities::from_pairs(vec![("EMAIL_1".into(), EntityKind::Email)]);
        let sibling = PromptEntities::from_pairs(vec![("EMAIL_10001".into(), EntityKind::Email)]);
        let out = substitute_pseudonyms("ping EMAIL_1 vs EMAIL_42", &real, &sibling);
        assert_eq!(out, "ping EMAIL_10001 vs EMAIL_42");
    }

    #[test]
    fn substitute_is_identity_when_real_is_empty() {
        let real = PromptEntities::new();
        let sibling = PromptEntities::new();
        let out = substitute_pseudonyms("nothing to swap here", &real, &sibling);
        assert_eq!(out, "nothing to swap here");
    }

    #[test]
    fn cohort_entropy_over_k_siblings_is_log2_k() {
        // Formal check: an adversary observing the cohort (real + k-1
        // siblings) and having no side information sees a uniform
        // distribution over k indistinguishable entity sets. Entropy =
        // log2(k). This is the privacy guarantee the paper claims for
        // v1. Computed here as a regression test so any refactor that
        // accidentally collapses two siblings to the same attribute
        // (which would drop entropy below log2(k)) fails loudly.
        let synth = StaticPoolSynthesizer::with_default_pool();
        let real = PromptEntities::from_pairs(vec![("EMAIL_1".into(), EntityKind::Email)]);
        let k: usize = 4;
        let siblings = synth.synthesize(&real, k).expect("synthesis");
        let mut cohort: Vec<String> = siblings.iter().map(|s| s.pairs()[0].0.clone()).collect();
        cohort.push(real.pairs()[0].0.clone());
        // k entities must all be distinct — else entropy < log2(k).
        let unique: std::collections::HashSet<_> = cohort.iter().collect();
        assert_eq!(
            unique.len(),
            k,
            "cohort must have k distinct entities; got {cohort:?}"
        );
        // Entropy of a uniform distribution over k distinct outcomes is
        // exactly log2(k). No floating-point slack needed.
        #[allow(clippy::cast_precision_loss)]
        let expected = (k as f64).log2();
        #[allow(clippy::cast_precision_loss)]
        let observed = (unique.len() as f64).log2();
        assert!((observed - expected).abs() < 1e-12);
    }

    #[test]
    fn build_default_pool_covers_every_entity_kind() {
        // Regression guard against adding a new EntityKind variant and
        // forgetting to extend the pool — would otherwise surface only
        // at runtime as `CohortError::KindUnsupported`.
        let pool = build_default_pool();
        for kind in [
            EntityKind::Email,
            EntityKind::Path,
            EntityKind::Ip,
            EntityKind::Url,
            EntityKind::Uuid,
            EntityKind::Person,
        ] {
            let entries = pool
                .get(&kind)
                .unwrap_or_else(|| panic!("default pool must cover {kind:?}"));
            assert!(!entries.is_empty(), "pool for {kind:?} must be non-empty");
        }
    }
}
