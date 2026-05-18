//! End-to-end round-trip test: pseudonymize an outbound prompt, simulate
//! a model echoing those pseudonyms, reverse-map the echo back to the
//! original real entities. This is the "prove the loop" criterion for
//! Phase 0.
//!
//! The `mock-anthropic-service` is intentionally not used here. Phase 0.5
//! will add the `ProviderClient::Veil` wrapping variant with the mock
//! integration; Phase 0 proves the pipeline on its own so review burden
//! stays small.

use veil::VeilPipeline;

#[test]
fn round_trips_multiple_entity_kinds() {
    let mut pipeline = VeilPipeline::with_default_regex();

    let original = "contact me at baris@example.com about /Users/baris/secret.txt \
                    at https://api.example.com/v1/users — box is 10.0.0.1";
    let sanitized = pipeline.pseudonymize(original);

    // Real entities must not appear in the sanitized form.
    assert!(
        !sanitized.contains("baris@example.com"),
        "email leaked: {sanitized}"
    );
    assert!(
        !sanitized.contains("/Users/baris"),
        "path leaked: {sanitized}"
    );
    assert!(
        !sanitized.contains("api.example.com"),
        "url leaked: {sanitized}"
    );
    assert!(!sanitized.contains("10.0.0.1"), "ip leaked: {sanitized}");

    // Pseudonyms should be present.
    assert!(sanitized.contains("EMAIL_"));
    assert!(sanitized.contains("PATH_"));
    assert!(sanitized.contains("URL_"));
    assert!(sanitized.contains("IP_"));

    // Model "reply" that echoes the pseudonyms — the kind of response we'd
    // get from Claude in a real run.
    let model_reply = "Looked at PATH_1. Sent a note to EMAIL_1. Verified URL_1 resolves to IP_1.";
    let restored = pipeline.reverse_map(model_reply);

    // Real entities restored.
    assert!(
        restored.contains("/Users/baris/secret.txt"),
        "path not restored: {restored}"
    );
    assert!(
        restored.contains("baris@example.com"),
        "email not restored: {restored}"
    );
    assert!(
        restored.contains("api.example.com"),
        "url not restored: {restored}"
    );
    assert!(restored.contains("10.0.0.1"), "ip not restored: {restored}");
}

#[test]
fn same_entity_gets_same_pseudonym_across_calls() {
    let mut pipeline = VeilPipeline::with_default_regex();

    let first = pipeline.pseudonymize("reach me at baris@example.com");
    let second = pipeline.pseudonymize("again, mail baris@example.com please");

    // The pseudonym must be identical across turns — this is what lets
    // multi-turn model reasoning stay coherent.
    let first_pseudo = first
        .split_whitespace()
        .find(|t| t.starts_with("EMAIL_"))
        .expect("first turn should contain a pseudonym");
    let second_pseudo = second
        .split_whitespace()
        .find(|t| t.starts_with("EMAIL_"))
        // may end with trailing punctuation; trim it
        .map(|t| t.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_'))
        .expect("second turn should contain a pseudonym");
    assert_eq!(first_pseudo, second_pseudo);
    assert_eq!(pipeline.table().len(), 1);
}

#[test]
fn unseen_pseudonyms_are_not_rewritten() {
    let pipeline = VeilPipeline::with_default_regex();
    // Model hallucinates a pseudonym we never minted — we must NOT silently
    // invent a value for it. Phase 3 (re-ID auditor) will flag these;
    // Phase 0 just leaves them alone.
    let reply = "Per EMAIL_99 the answer is yes";
    assert_eq!(pipeline.reverse_map(reply), reply);
}
