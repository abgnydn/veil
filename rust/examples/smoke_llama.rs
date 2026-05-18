//! Live smoke test for `LlamaCompletionDetector` against a running
//! `llama-server` (`BitNet` or otherwise).
//!
//! ```bash
//! # In one shell: launch the llama.cpp server
//! ~/BitNet/build/bin/llama-server \
//!   -m ~/BitNet/models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf \
//!   -c 2048 -t 4 --host 127.0.0.1 --port 8089 -ngl 0
//!
//! # In another shell:
//! cargo run -p veil --example smoke_llama
//! ```
//!
//! Not a unit test — deliberately depends on a running server. Exists
//! so we can see what the model actually produces on realistic prompts,
//! not what we imagine it might produce in a mock.

use std::env;
use std::time::Duration;

use veil::{
    AuditReason, Detector, FallbackDetector, LlamaCompletionDetector, RegexDetector, VeilPipeline,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let endpoint =
        env::var("VEIL_LLAMA_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8089".to_string());
    eprintln!("[smoke] endpoint = {endpoint}");

    let llama = LlamaCompletionDetector::new(&endpoint).with_timeout(Duration::from_secs(60));

    eprintln!("\n=== Test 1: direct detector on text with PERSON + EMAIL ===");
    let input = "Dr. Smith and Alice Chen both emailed alice@acme.com about the deploy.";
    eprintln!("input:  {input:?}");
    let start = std::time::Instant::now();
    let found = llama.detect_async(input).await;
    eprintln!("took:   {:?}", start.elapsed());
    for ent in &found {
        eprintln!(
            "  - {:?} at {}..{} = {:?}",
            ent.kind, ent.start, ent.end, ent.text
        );
    }
    if found.is_empty() {
        eprintln!("  (model returned no entities)");
    }

    eprintln!("\n=== Test 2: pipeline with FallbackDetector<Llama, Regex> ===");
    let fallback = FallbackDetector::new(
        LlamaCompletionDetector::new(&endpoint).with_timeout(Duration::from_secs(60)),
        RegexDetector::new(),
    );
    let mut pipeline = VeilPipeline::new(fallback);
    let prompt = "Please email baris@example.com about the Dr. Smith report.";
    eprintln!("prompt: {prompt:?}");
    let sanitized = pipeline.pseudonymize(prompt);
    eprintln!("sanitized: {sanitized:?}");
    eprintln!("table size: {} entities", pipeline.table().len());
    let restored = pipeline.reverse_map(&sanitized);
    eprintln!("reverse-mapped: {restored:?}");

    eprintln!("\n=== Test 3: audit_reply_async on a reply containing a leaked name ===");
    // Reply contains "Dr. Smith" raw — the audit should flag it as a
    // person leak even though the pipeline never minted that pseudonym.
    let reply = "Dr. Smith called back";
    let findings = pipeline.audit_reply_async(reply).await;
    eprintln!("reply:    {reply:?}");
    eprintln!("findings: {}", findings.len());
    for f in &findings {
        let kind = match &f.reason {
            AuditReason::UnknownPseudonym { kind } => format!("UnknownPseudonym({kind:?})"),
            AuditReason::LikelyLeaked { kind } => format!("LikelyLeaked({kind:?})"),
        };
        eprintln!("  - {kind}: {:?} at {}..{}", f.text, f.start, f.end);
    }
}
