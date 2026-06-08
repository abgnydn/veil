// SPDX-License-Identifier: Apache-2.0

//! `veil_server` — the loopback HTTP entry point for the Rust pseudonymization
//! engine. Exposes the wire contract in `docs/CONTRACT.md` so the TypeScript
//! shell (and any other consumer) can detect / pseudonymize / reverse-map /
//! audit over HTTP, one [`SessionStore`] entry per conversation.
//!
//! Binds `127.0.0.1` by design: this process holds raw PII *and* the
//! real↔pseudonym mapping. Do not expose it off-host.
//!
//! Env knobs:
//!   VEIL_BIND               default 127.0.0.1:8787  (loopback host:port)
//!   VEIL_SESSION_TTL_SECS   default 3600; 0 disables the idle reaper

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use veil::server::{build_router, now_ms, SessionStore};
use veil::{AnyDetector, HttpNerDetector, MergeFallback, RegexDetector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("VEIL_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let ttl_secs = std::env::var("VEIL_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);

    // Refuse a non-loopback bind: this server is the one place that sees raw
    // PII and the mapping. A typo that exposes it off-host is a leak, not a
    // convenience — fail closed.
    if !is_loopback_bind(&bind) {
        return Err(format!(
            "VEIL_BIND={bind} is not loopback. veil_server holds raw PII + the \
             pseudonym mapping and must bind 127.0.0.1/::1 only."
        )
        .into());
    }

    // Detector: regex-only by default. When VEIL_DETECTOR_URL points at a
    // learned-NER server (GLiNER — see examples/gliner-detector/), union it
    // with regex via MergeFallback so the freeform PERSON/LOCATION/ORG kinds
    // are caught too. If that server is down, MergeFallback degrades to regex.
    let detector = match std::env::var("VEIL_DETECTOR_URL") {
        Ok(url) if !url.is_empty() => {
            eprintln!("veil_server: learned detector at {url} (regex + GLiNER)");
            AnyDetector::BitnetMergeRegex(MergeFallback::new(
                HttpNerDetector::new(url),
                RegexDetector::new(),
            ))
        }
        _ => {
            eprintln!("veil_server: regex-only detector (set VEIL_DETECTOR_URL for learned NER)");
            AnyDetector::Regex(RegexDetector::new())
        }
    };
    let state: Arc<Mutex<SessionStore>> = Arc::new(Mutex::new(SessionStore::with_detector(detector)));

    // Idle reaper: the safety net for clients that forget to DELETE. Explicit
    // DELETE /v1/session/{id} is the primary cleanup path.
    if ttl_secs > 0 {
        let reaper = state.clone();
        let ttl_ms = ttl_secs.saturating_mul(1000);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let evicted = reaper.lock().await.evict_idle(now_ms(), ttl_ms);
                if evicted > 0 {
                    eprintln!("veil_server: evicted {evicted} idle session(s)");
                }
            }
        });
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!(
        "veil_server: listening on http://{} (loopback only, session TTL {}s)",
        listener.local_addr()?,
        ttl_secs
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// True iff `bind` targets a loopback host. Accepts `127.0.0.0/8`, `::1`
/// (optionally bracketed), and `localhost`.
fn is_loopback_bind(bind: &str) -> bool {
    let host = bind.rsplit_once(':').map_or(bind, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host == "::1" {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("veil_server: shutting down");
}
