// SPDX-License-Identifier: Apache-2.0

//! Content-hiding decoy synthesis for cohort blending (opt-in).
//!
//! The default cohort synthesizer ([`crate::cohort::StaticPoolSynthesizer`])
//! makes siblings that are *renumbered copies* of the real prompt — so all k
//! prompts share the same words and only the pseudonym numbers differ. That
//! hides which entity set is real but reveals the prompt's template/topic.
//!
//! This module instead fills **decoy templates** — realistic, topic-diverse
//! prompts indexed by entity-kind profile — with the sibling pseudonyms, so the
//! k prompts are *different sentences about different things*. A wire adversary
//! learns much less about the real prompt's subject.
//!
//! # Honest limitation
//!
//! Decoys come from a fixed corpus; the real prompt is the user's own phrasing.
//! A style-aware adversary could still single out the user-shaped sentence among
//! corpus-shaped decoys. True content-indistinguishability needs decoys drawn
//! from the user's *own* distribution (the vault-neighbor approach of VEIL.md
//! §4.1: embeddings + K-NN over a local note store — not built). This is a
//! topic-hiding improvement, not a complete solution. Falls back to renumbered
//! copies for any entity profile the corpus doesn't cover.

use std::collections::{HashMap, VecDeque};

use crate::cohort::PromptEntities;
use crate::entities::EntityKind;

/// Profile key for a prompt: its entity-kind prefixes, sorted and `|`-joined
/// (e.g. `"EMAIL"`, `"EMAIL|PATH"`). Decoy templates are indexed by this.
fn profile_key(entities: &PromptEntities) -> String {
    let mut prefixes: Vec<&str> = entities.pairs().iter().map(|(_, k)| k.as_prefix()).collect();
    prefixes.sort_unstable();
    prefixes.join("|")
}

/// Generate decoy prompts for the given `siblings`, matching `real`'s entity
/// profile. Returns `None` if the corpus has no template for that profile —
/// the caller then falls back to renumbered copies. Each sibling gets a
/// different template (cycled) so two siblings aren't the same sentence.
#[must_use]
pub fn decoy_siblings(real: &PromptEntities, siblings: &[PromptEntities]) -> Option<Vec<String>> {
    if siblings.is_empty() {
        return Some(Vec::new());
    }
    let templates = templates_for(&profile_key(real))?;
    let out = siblings
        .iter()
        .enumerate()
        .map(|(i, sib)| fill_template(templates[i % templates.len()], sib))
        .collect();
    Some(out)
}

/// Fill a template's `{PREFIX}` placeholders with the sibling's pseudonyms,
/// matched by kind in first-seen order. Assumes the template's placeholders
/// match the sibling's kind multiset (guaranteed by profile lookup).
fn fill_template(template: &str, sibling: &PromptEntities) -> String {
    let mut queues: HashMap<EntityKind, VecDeque<&str>> = HashMap::new();
    for (pseudo, kind) in sibling.pairs() {
        queues.entry(*kind).or_default().push_back(pseudo.as_str());
    }
    let mut result = template.to_string();
    for kind in EntityKind::ALL {
        let placeholder = format!("{{{}}}", kind.as_prefix());
        while result.contains(&placeholder) {
            let Some(pseudo) = queues.get_mut(&kind).and_then(VecDeque::pop_front) else {
                break;
            };
            result = result.replacen(&placeholder, pseudo, 1);
        }
    }
    result
}

/// Built-in decoy corpus. Keys are sorted-prefix profiles (see `profile_key`).
/// Single-kind and common two-kind profiles are covered; anything else falls
/// back to renumbered copies. Templates are realistic assistant prompts.
fn templates_for(profile: &str) -> Option<&'static [&'static str]> {
    let templates: &[&str] = match profile {
        "EMAIL" => &[
            "draft a reply to {EMAIL}",
            "did {EMAIL} get back to us",
            "add {EMAIL} to the invite",
            "follow up with {EMAIL} tomorrow",
        ],
        "PATH" => &[
            "review the diff in {PATH}",
            "the backup is at {PATH}",
            "archive {PATH} when done",
            "what changed in {PATH}",
        ],
        "PERSON" => &[
            "sync with {PERSON} this week",
            "{PERSON} approved the plan",
            "ask {PERSON} for an update",
            "{PERSON} is out of office",
        ],
        "URL" => &[
            "the spec is at {URL}",
            "{URL} is returning errors",
            "summarize {URL} for me",
            "is {URL} still live",
        ],
        "IP" => &[
            "{IP} is unreachable",
            "add {IP} to the allowlist",
            "trace traffic from {IP}",
            "ping {IP} and report back",
        ],
        "LOCATION" => &[
            "the {LOCATION} office is closed today",
            "roll out to {LOCATION} next",
            "book a room in {LOCATION}",
            "the team in {LOCATION} is blocked",
        ],
        "ORG" => &[
            "the {ORG} renewal is due",
            "{ORG} raised a support ticket",
            "draft a proposal for {ORG}",
            "{ORG} wants a demo",
        ],
        "UUID" => &[
            "look up record {UUID}",
            "{UUID} failed validation",
            "retry job {UUID}",
            "trace request {UUID}",
        ],
        "EMAIL|PATH" => &[
            "send {PATH} to {EMAIL}",
            "{EMAIL} asked for the file at {PATH}",
            "attach {PATH} and email {EMAIL}",
        ],
        "EMAIL|PERSON" => &[
            "tell {PERSON} to email {EMAIL}",
            "cc {PERSON} at {EMAIL}",
            "{PERSON} can be reached at {EMAIL}",
        ],
        "LOCATION|PERSON" => &[
            "{PERSON} is flying to {LOCATION}",
            "meet {PERSON} in {LOCATION}",
            "{PERSON} relocated to {LOCATION}",
        ],
        "ORG|PERSON" => &[
            "{PERSON} just joined {ORG}",
            "{PERSON} handles the {ORG} account",
            "introduce {PERSON} to {ORG}",
        ],
        "EMAIL|URL" => &[
            "email the link {URL} to {EMAIL}",
            "{EMAIL} shared {URL}",
        ],
        "IP|URL" => &[
            "{URL} resolves to {IP}",
            "{IP} is hosting {URL}",
        ],
        _ => return None,
    };
    Some(templates)
}

#[cfg(test)]
mod tests {
    use super::{decoy_siblings, fill_template, profile_key};
    use crate::cohort::{PromptEntities, StaticPoolSynthesizer};
    use crate::entities::EntityKind;

    fn real(pairs: &[(&str, EntityKind)]) -> PromptEntities {
        PromptEntities::from_pairs(pairs.iter().map(|(p, k)| ((*p).to_string(), *k)).collect())
    }

    #[test]
    fn profile_key_sorts_prefixes() {
        let e = real(&[("PATH_1", EntityKind::Path), ("EMAIL_1", EntityKind::Email)]);
        assert_eq!(profile_key(&e), "EMAIL|PATH");
    }

    #[test]
    fn fill_template_substitutes_by_kind() {
        let sib = real(&[("EMAIL_10001", EntityKind::Email), ("PATH_10001", EntityKind::Path)]);
        assert_eq!(fill_template("send {PATH} to {EMAIL}", &sib), "send PATH_10001 to EMAIL_10001");
    }

    #[test]
    fn decoy_siblings_produce_distinct_sentences_for_known_profile() {
        use crate::cohort::CohortSynthesizer;
        let r = real(&[("EMAIL_1", EntityKind::Email)]);
        let synth = StaticPoolSynthesizer::with_default_pool();
        let siblings = synth.synthesize(&r, 4).unwrap(); // k=4 → 3 siblings
        let decoys = decoy_siblings(&r, &siblings).expect("EMAIL profile is covered");
        assert_eq!(decoys.len(), 3);
        // Each decoy carries a pool pseudonym and is NOT a copy of any other
        // (cycled templates → different sentences).
        for d in &decoys {
            assert!(d.contains("EMAIL_"), "decoy must carry an email pseudonym: {d}");
        }
        assert_eq!(decoys.iter().collect::<std::collections::HashSet<_>>().len(), 3);
    }

    #[test]
    fn decoy_siblings_returns_none_for_uncovered_profile() {
        use crate::cohort::CohortSynthesizer;
        // Two emails + a uuid is not in the corpus → fall back signal.
        let r = real(&[
            ("EMAIL_1", EntityKind::Email),
            ("EMAIL_2", EntityKind::Email),
            ("UUID_1", EntityKind::Uuid),
        ]);
        let synth = StaticPoolSynthesizer::with_default_pool();
        let siblings = synth.synthesize(&r, 3).unwrap();
        assert!(decoy_siblings(&r, &siblings).is_none());
    }

    #[test]
    fn decoy_siblings_empty_when_no_siblings() {
        let r = real(&[("EMAIL_1", EntityKind::Email)]);
        assert_eq!(decoy_siblings(&r, &[]), Some(Vec::new()));
    }
}
