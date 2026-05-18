//! Live smoke test for the spaCy FastAPI shim sitting at
//! `~/veil-ner-shims/spacy/server.py`. Launch the shim separately:
//!
//! ```bash
//! cd ~/veil-ner-shims/spacy
//! source .venv/bin/activate
//! uvicorn server:app --host 127.0.0.1 --port 8080
//! ```
//!
//! Then:
//!
//! ```bash
//! cargo run -p veil --example smoke_spacy_shim
//! ```
//!
//! Unlike `smoke_llama`, this exercises the native `/detect` contract
//! through `BitnetDetector` — no JSON coaxing, no prompt engineering.
//! The shim maps spaCy's `PERSON` label to veil's `EntityKind::Person`
//! and drops everything else (ORG/GPE/LOC/…), leaving EMAIL / PATH / IP
//! / URL / UUID to the regex fallback.

use std::env;
use std::time::Duration;

use veil::{BitnetDetector, Detector, FallbackDetector, RegexDetector, VeilPipeline};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let endpoint =
        env::var("VEIL_SPACY_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    eprintln!("[smoke] endpoint = {endpoint}");

    let spacy = BitnetDetector::new(&endpoint).with_timeout(Duration::from_secs(10));

    eprintln!("\n=== Test 1: direct detector on PERSON-rich input ===");
    let input = "Dr. Smith and Alice Chen met with Bob on Tuesday.";
    eprintln!("input:  {input:?}");
    let start = std::time::Instant::now();
    let found = spacy.detect_async(input).await;
    eprintln!("took:   {:?}", start.elapsed());
    for ent in &found {
        eprintln!(
            "  - {:?} at {}..{} = {:?}",
            ent.kind, ent.start, ent.end, ent.text
        );
    }
    if found.is_empty() {
        eprintln!("  (shim returned no entities — model may not recognize these as PERSON)");
    }

    eprintln!("\n=== Test 2: pipeline with FallbackDetector<Spacy, Regex> ===");
    // FallbackDetector: primary is spaCy (finds persons), secondary is
    // regex (finds emails/paths/IPs/URLs/UUIDs). Because FallbackDetector
    // is asymmetric (only runs secondary when primary returns nothing),
    // this ordering means on a PERSON-only input we get spaCy; on an
    // EMAIL-only input we get regex; on a MIXED input we get ONLY what
    // spaCy returned. That's a known limitation — Phase 5 work may want
    // a merging fallback.
    let fallback = FallbackDetector::new(
        BitnetDetector::new(&endpoint).with_timeout(Duration::from_secs(10)),
        RegexDetector::new(),
    );
    let mut pipeline = VeilPipeline::new(fallback);

    let prompts = [
        "Dr. Smith emailed baris@example.com about the deploy.",
        "Alice Chen reviewed /Users/bob/notes.md",
        "Contact support@example.com if 10.0.0.1 is unreachable.",
        "No PII here, just prose.",
    ];
    for prompt in prompts {
        let sanitized = pipeline.pseudonymize(prompt);
        let restored = pipeline.reverse_map(&sanitized);
        eprintln!("\n  in:  {prompt:?}");
        eprintln!("  out: {sanitized:?}");
        eprintln!("  rev: {restored:?}");
        if restored != prompt {
            eprintln!("  WARN: reverse_map did not round-trip!");
        }
    }
    eprintln!("\n  final table size: {} entities", pipeline.table().len());

    eprintln!("\n=== Test 3: audit_reply_async catches leaked person via spaCy ===");
    // Build a fresh pipeline where the detector IS spaCy (not the
    // fallback), so audit_reply_async's learned pass uses spaCy and can
    // flag PERSON leaks regex cannot.
    let pipeline =
        VeilPipeline::new(BitnetDetector::new(&endpoint).with_timeout(Duration::from_secs(10)));
    let reply = "Dr. Smith called back about the meeting.";
    let findings = pipeline.audit_reply_async(reply).await;
    eprintln!("reply:    {reply:?}");
    eprintln!("findings: {}", findings.len());
    for f in &findings {
        eprintln!(
            "  - {:?} at {}..{} = {:?}",
            f.reason, f.start, f.end, f.text
        );
    }
    if findings.is_empty() {
        eprintln!("  (no findings — shim did not recognize the person)");
    }
}
