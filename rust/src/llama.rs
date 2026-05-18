//! Detector that prompts any `OpenAI`-compatible chat-completion endpoint
//! (llama.cpp `llama-server`, Ollama, vLLM, LM Studio, …) to extract
//! sensitive entities and returns them as `DetectedEntity` spans.
//!
//! Unlike [`crate::BitnetDetector`], which expects a dedicated `/detect`
//! endpoint speaking our native JSON contract, this variant works against
//! any generative model already serving the standard `OpenAI`
//! `/v1/chat/completions` API. The first reason it exists: the
//! `~/BitNet/run_inference_server.py` setup launches
//! `llama-server`, which speaks exactly that API — so this is the
//! shortest path from "we have a local model running" to "our pipeline
//! uses it."
//!
//! ## Wire protocol
//!
//! ```json
//! // POST {endpoint}/v1/chat/completions
//! { "model": "...", "messages": [...], "temperature": 0.0, "max_tokens": 512 }
//! // response (only the first choice is read)
//! { "choices": [ { "message": { "content": "[{\"kind\":\"PERSON\",\"text\":\"Alice\"}]" } } ] }
//! ```
//!
//! ## Why we don't trust model-reported offsets
//!
//! Generative LLMs are unreliable at offset arithmetic — they'll report
//! `"start": 14, "end": 20` for a token that actually lives at 12..18.
//! Instead we prompt the model for `{kind, text}` pairs only and recover
//! offsets locally via `str::find`, skipping byte ranges already claimed
//! by a prior match. This trades some redundancy for robustness: as long
//! as the model echoes the right substring, we'll find it.
//!
//! Every failure mode (HTTP error, timeout, malformed JSON, hallucinated
//! entities that don't appear in the input) collapses to an empty
//! `Vec<DetectedEntity>` — pair with `FallbackDetector` for graceful
//! degradation to regex.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::entities::{DetectedEntity, Detector, EntityKind};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MODEL: &str = "bitnet";

/// System prompt. Deliberately bossy about format — any prose around the
/// JSON is still recoverable (see `extract_json_array`), but fewer words
/// means fewer tokens means faster inference.
const SYSTEM_PROMPT: &str = "You are a precise privacy sanitizer. Given user text, \
identify every sensitive entity: person names (PERSON), email addresses (EMAIL), \
filesystem paths (PATH), IP addresses (IP), URLs (URL), UUIDs (UUID). Reply with \
ONLY a JSON array, no prose, no markdown fences. Each element has exactly two \
fields: \"kind\" (one of PERSON, EMAIL, PATH, IP, URL, UUID) and \"text\" (the \
exact substring copied from the input). If nothing sensitive is found, reply [].";

fn user_prompt(input: &str) -> String {
    format!("Text:\n{input}\n\nJSON:")
}

/// Detector backed by an `OpenAI`-compatible chat-completions endpoint.
///
/// Uses `reqwest` (the same HTTP client `BitnetDetector` uses) and a
/// carefully-engineered system prompt. The response is parsed defensively:
/// markdown fences and any prose are stripped, the JSON array is
/// extracted, and entity offsets are recovered by searching the input
/// text rather than trusting the model.
#[derive(Debug, Clone)]
pub struct LlamaCompletionDetector {
    endpoint: String,
    model: String,
    http: reqwest::Client,
}

impl LlamaCompletionDetector {
    /// Build a detector pointing at an `OpenAI`-compatible endpoint
    /// (llama.cpp server, Ollama, etc.). Uses the default model name
    /// `"bitnet"` — appropriate for `llama-server` where the name is
    /// largely decorative but must be present in the request body.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::with_model(endpoint, DEFAULT_MODEL)
    }

    /// Build with an explicit model identifier. Needed for Ollama (`"llama3:8b"`,
    /// etc.) and vLLM where the server dispatches on model name.
    #[must_use]
    pub fn with_model(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("reqwest client with rustls-tls must build");
        Self {
            endpoint: endpoint.into(),
            model: model.into(),
            http,
        }
    }

    /// Override the default 30-second timeout. Local llama.cpp on CPU can
    /// take tens of seconds on long prompts; remote endpoints are
    /// typically faster. The 30-second default is pragmatic for CPU
    /// `BitNet` but aggressively slow compared to `BitnetDetector`'s
    /// 1.5-second default — generative inference is inherently slow.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client with rustls-tls must build");
        self
    }

    async fn detect_impl(&self, input: &str) -> Vec<DetectedEntity> {
        let debug = std::env::var("VEIL_LLAMA_DEBUG").is_ok();
        let url = format!(
            "{}/v1/chat/completions",
            self.endpoint.trim_end_matches('/')
        );
        let user_msg = user_prompt(input);
        let body = ChatRequest {
            model: &self.model,
            messages: vec![
                ChatMessageReq {
                    role: "system",
                    content: SYSTEM_PROMPT,
                },
                ChatMessageReq {
                    role: "user",
                    content: &user_msg,
                },
            ],
            temperature: 0.0,
            max_tokens: 512,
        };
        let response = match self.http.post(&url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                if debug {
                    eprintln!("[veil.llama.debug] send error: {e}");
                }
                return Vec::new();
            }
        };
        if !response.status().is_success() {
            if debug {
                eprintln!(
                    "[veil.llama.debug] non-success status: {}",
                    response.status()
                );
            }
            return Vec::new();
        }
        let raw_body = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                if debug {
                    eprintln!("[veil.llama.debug] body read error: {e}");
                }
                return Vec::new();
            }
        };
        if debug {
            eprintln!("[veil.llama.debug] raw body: {raw_body}");
        }
        let parsed: ChatCompletionResponse = match serde_json::from_str(&raw_body) {
            Ok(p) => p,
            Err(e) => {
                if debug {
                    eprintln!("[veil.llama.debug] json parse error: {e}");
                }
                return Vec::new();
            }
        };
        let Some(content) = parsed.choices.first().map(|c| c.message.content.as_str()) else {
            if debug {
                eprintln!("[veil.llama.debug] no choices in response");
            }
            return Vec::new();
        };
        if debug {
            eprintln!("[veil.llama.debug] model content: {content:?}");
        }
        parse_and_locate(content, input)
    }
}

impl Detector for LlamaCompletionDetector {
    /// Sync path — requires a multi-thread tokio runtime, same as
    /// `BitnetDetector::detect`. Prefer `detect_async` on new code.
    fn detect(&self, input: &str) -> Vec<DetectedEntity> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.detect_impl(input))
        })
    }

    fn detect_async<'a>(
        &'a self,
        input: &'a str,
    ) -> impl std::future::Future<Output = Vec<DetectedEntity>> + Send + 'a {
        self.detect_impl(input)
    }
}

/// Parse the model's response content into locatable spans.
///
/// Three defenses against generative-LLM noise:
/// 1. Strip markdown fences and surrounding prose — `extract_json_array`
///    finds the outermost `[...]` range and ignores everything else.
/// 2. Unknown `kind` values are dropped (same policy as `bitnet::validate_spans`).
/// 3. Entity `text` values that don't appear in the input are dropped —
///    the model cannot invent new entities; it can only echo ones from
///    the input.
fn parse_and_locate(content: &str, input: &str) -> Vec<DetectedEntity> {
    let Some(array_str) = extract_json_array(content) else {
        return Vec::new();
    };
    let Ok(entities) = serde_json::from_str::<Vec<LlmEntity>>(array_str) else {
        return Vec::new();
    };
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    let mut out: Vec<DetectedEntity> = Vec::new();
    for e in entities {
        let Some(kind) = EntityKind::from_prefix(&e.kind) else {
            continue;
        };
        if e.text.is_empty() {
            continue;
        }
        // Walk through every occurrence of `e.text` in the input, keeping
        // the first that doesn't overlap a prior claim. This handles the
        // case where the model returns the same name twice (e.g. "Dr.
        // Smith" reported once but appearing three times in the input)
        // without double-counting any single occurrence.
        let mut cursor = 0usize;
        while let Some(idx_rel) = input[cursor..].find(&e.text) {
            let start = cursor + idx_rel;
            let end = start + e.text.len();
            let overlaps = claimed.iter().any(|(s, ee)| !(end <= *s || start >= *ee));
            if overlaps {
                cursor = start + 1;
                continue;
            }
            // UTF-8 boundary sanity — same invariant `bitnet::validate_spans` enforces.
            if !input.is_char_boundary(start) || !input.is_char_boundary(end) {
                cursor = start + 1;
                continue;
            }
            claimed.push((start, end));
            out.push(DetectedEntity {
                kind,
                start,
                end,
                text: e.text,
            });
            break;
        }
    }
    // Sort + drop any residual overlaps (claim-tracking above should
    // already prevent them; this is belt + suspenders).
    out.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut kept: Vec<DetectedEntity> = Vec::with_capacity(out.len());
    for det in out {
        let overlaps = kept.last().is_some_and(|last| last.end > det.start);
        if !overlaps {
            kept.push(det);
        }
    }
    kept
}

/// Find the outermost `[...]` array in the model's content. Handles
/// markdown fences (` ```json ... ``` `), leading/trailing prose, and
/// empty arrays. Returns `None` if no `[` / `]` pair is found.
fn extract_json_array(content: &str) -> Option<&str> {
    let start = content.find('[')?;
    let end = content.rfind(']')?;
    if end < start {
        return None;
    }
    Some(&content[start..=end])
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessageReq<'a>>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize)]
struct ChatMessageReq<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

#[derive(Deserialize)]
struct LlmEntity {
    kind: String,
    text: String,
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::{extract_json_array, LlamaCompletionDetector};
    use crate::entities::{Detector, EntityKind};

    struct TestServer {
        base_url: String,
        _join: JoinHandle<()>,
    }

    /// Copy of the `spawn_server` pattern from `bitnet::tests` — same
    /// single-shot HTTP mock. Duplicated rather than extracted because
    /// sharing test-only helpers across sibling modules is fiddly in
    /// Rust's module system and the helper is ~60 lines.
    async fn spawn_server(response: String) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("local addr");
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
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn chat_response(content: &str) -> String {
        // Escape the content for JSON.
        let escaped = serde_json::to_string(content).expect("content must serialize");
        format!(r#"{{"choices":[{{"message":{{"role":"assistant","content":{escaped}}}}}]}}"#)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn happy_path_extracts_person_name() {
        let model_output = r#"[{"kind":"PERSON","text":"Dr. Smith"}]"#;
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let input = "I spoke with Dr. Smith yesterday";
        let found = detector.detect_async(input).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Person);
        assert_eq!(found[0].text, "Dr. Smith");
        assert_eq!(&input[found[0].start..found[0].end], "Dr. Smith");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handles_markdown_code_fences() {
        // LLMs love wrapping JSON in ```json ... ``` — we must ignore the fences.
        let model_output = "```json\n[{\"kind\":\"EMAIL\",\"text\":\"a@b.com\"}]\n```";
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let found = detector
            .detect_async("email me at a@b.com when ready")
            .await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Email);
        assert_eq!(found[0].text, "a@b.com");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handles_prose_before_and_after_json() {
        let model_output =
            "Sure! Here are the entities I found: [{\"kind\":\"PATH\",\"text\":\"/Users/x\"}] Let me know if you need more.";
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let found = detector.detect_async("check /Users/x please").await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drops_entity_not_appearing_in_input() {
        // Model hallucinates — it returns an entity that doesn't exist in
        // the input. `str::find` won't locate it and we drop it silently.
        let model_output = r#"[{"kind":"PERSON","text":"Alice"}]"#;
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let found = detector
            .detect_async("this input contains no names at all")
            .await;
        assert!(
            found.is_empty(),
            "hallucinated entity must be dropped, got: {found:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drops_unknown_entity_kind() {
        let model_output = r#"[{"kind":"BANANA","text":"Smith"}]"#;
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let found = detector.detect_async("met Smith today").await;
        assert!(found.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_entity_text_claims_different_occurrences() {
        // Model reports "Smith" twice; the input has "Smith" appearing
        // twice too. Both should be located at different offsets without
        // overlap.
        let model_output = r#"[{"kind":"PERSON","text":"Smith"},{"kind":"PERSON","text":"Smith"}]"#;
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let input = "Smith and also Smith again";
        let found = detector.detect_async(input).await;
        assert_eq!(found.len(), 2, "both occurrences should be located");
        assert_ne!(
            found[0].start, found[1].start,
            "must claim different offsets: {found:?}"
        );
        assert_eq!(&input[found[0].start..found[0].end], "Smith");
        assert_eq!(&input[found[1].start..found[1].end], "Smith");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_array_yields_empty_result() {
        let server = spawn_server(http_ok(&chat_response("[]"))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        assert!(detector.detect_async("clean input").await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_json_in_content_yields_empty() {
        let server = spawn_server(http_ok(&chat_response("not json at all {{{"))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        assert!(detector.detect_async("anything").await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_error_yields_empty() {
        let body = r#"{"error":"oops"}"#;
        let server = spawn_server(format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
        .await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        assert!(detector.detect_async("anything").await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connection_refused_yields_empty() {
        let detector = LlamaCompletionDetector::new("http://127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        assert!(detector.detect_async("a@b.com").await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pipeline_integration_with_llama_detector() {
        // End-to-end smoke: pipeline uses LlamaCompletionDetector to
        // pseudonymize, then reverse-map. Same shape as the Phase 1 bitnet
        // pipeline test, but exercises the prompt-based path.
        let model_output = r#"[{"kind":"PERSON","text":"Alice"}]"#;
        let server = spawn_server(http_ok(&chat_response(model_output))).await;
        let detector = LlamaCompletionDetector::new(server.base_url);
        let mut pipeline = crate::VeilPipeline::new(detector);
        let out = pipeline.pseudonymize("Alice writes Rust");
        assert_eq!(out, "PERSON_1 writes Rust");
        assert_eq!(pipeline.reverse_map(&out), "Alice writes Rust");
    }

    #[test]
    fn extract_json_array_finds_array_between_prose() {
        assert_eq!(
            extract_json_array("prose [1,2,3] more prose"),
            Some("[1,2,3]")
        );
        assert_eq!(
            extract_json_array("```json\n[\"a\",\"b\"]\n```"),
            Some("[\"a\",\"b\"]")
        );
        assert_eq!(extract_json_array("no brackets here"), None);
        assert_eq!(extract_json_array("][ wrong order"), None);
    }
}
