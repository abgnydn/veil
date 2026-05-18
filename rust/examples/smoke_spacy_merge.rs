//! Live smoke for Phase 7's [`MergeFallback`] against the spaCy shim.
//!
//! Same setup as `smoke_spacy_shim`:
//!
//! ```bash
//! ./rust/scripts/serve-spacy-shim.sh
//! # in another shell:
//! cargo run -q -p veil --example smoke_spacy_merge
//! ```
//!
//! Purpose: prove end-to-end that the E27 asymmetry is closed. Input
//! `"Dr. Smith emailed baris@example.com"` must pseudonymize BOTH the
//! person AND the email under `MergeFallback`; under the older
//! `FallbackDetector` it would leave the email raw.

use std::env;
use std::time::Duration;

use veil::{BitnetDetector, FallbackDetector, MergeFallback, RegexDetector, VeilPipeline};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let endpoint =
        env::var("VEIL_SPACY_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    eprintln!("[smoke-merge] endpoint = {endpoint}");

    let input = "Dr. Smith emailed baris@example.com about the deploy.";
    eprintln!("\ninput: {input:?}\n");

    // Baseline: the asymmetric variant. Primary = spaCy, secondary = regex.
    // Because spaCy returns a PERSON, secondary never runs, so the email
    // stays raw. This is the bug Phase 7 fixes.
    let fallback = FallbackDetector::new(
        BitnetDetector::new(&endpoint).with_timeout(Duration::from_secs(10)),
        RegexDetector::new(),
    );
    let mut p_fallback = VeilPipeline::new(fallback);
    let out_fallback = p_fallback.pseudonymize(input);
    eprintln!("FallbackDetector (Phase 1/5 asymmetric):");
    eprintln!("  out: {out_fallback:?}");
    eprintln!("  — note: email stays RAW because spaCy fired first.\n");

    // Phase 7: MergeFallback runs BOTH and unions spans.
    let merge = MergeFallback::new(
        BitnetDetector::new(&endpoint).with_timeout(Duration::from_secs(10)),
        RegexDetector::new(),
    );
    let mut p_merge = VeilPipeline::new(merge);
    let out_merge = p_merge.pseudonymize(input);
    eprintln!("MergeFallback (Phase 7):");
    eprintln!("  out: {out_merge:?}");
    eprintln!("  — expected: both PERSON_1 and EMAIL_1 (order by offset — PERSON_1 first).");
}
