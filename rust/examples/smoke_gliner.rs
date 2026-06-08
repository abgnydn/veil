//! Live smoke for Phase 1's learned detector against the GLiNER server.
//!
//! ```bash
//! # in one shell — stub mode needs no model download:
//! GLINER_STUB=1 python3 examples/gliner-detector/server.py
//! # in another:
//! cargo run -q -p veil --example smoke_gliner
//! ```
//!
//! Purpose: prove end-to-end that `HttpNerDetector` (GLiNER backend) +
//! `MergeFallback(RegexDetector)` does what regex alone cannot — pseudonymize
//! the freeform `PERSON`/`LOCATION`/`ORG` kinds — while regex still handles the
//! structured `EMAIL`, all unioned into one pass and reverse-mapped cleanly.

use std::env;
use std::time::Duration;

use veil::{HttpNerDetector, MergeFallback, RegexDetector, VeilPipeline};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let endpoint =
        env::var("VEIL_DETECTOR_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8808".to_string());
    eprintln!("[smoke-gliner] endpoint = {endpoint}");

    let input = "Alice emailed bob@acme.com from Bangkok about the Acme deal.";
    eprintln!("\ninput: {input:?}\n");

    // Learned (GLiNER) for freeform kinds + regex for structured kinds, unioned.
    let detector = MergeFallback::new(
        HttpNerDetector::new(&endpoint).with_timeout(Duration::from_secs(10)),
        RegexDetector::new(),
    );
    let mut pipeline = VeilPipeline::new(detector);

    let pseudonymized = pipeline.pseudonymize(input);
    eprintln!("pseudonymized: {pseudonymized:?}");
    eprintln!("  — expect PERSON_1 (Alice), EMAIL_1 (bob@acme.com), LOCATION_1");
    eprintln!("    (Bangkok), ORG_1 (Acme) — regex got the email, GLiNER the rest.");

    let restored = pipeline.reverse_map(&pseudonymized);
    eprintln!("\nreverse-mapped: {restored:?}");
    assert_eq!(restored, input, "round-trip must restore the original exactly");
    eprintln!("\n[smoke-gliner] round-trip OK");
}
