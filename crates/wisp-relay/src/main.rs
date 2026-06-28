//! Wisp blind relay — WAN rendezvous for peer-to-peer transfers.
//!
//! The relay is structurally blind: it sees only the code *commitment* (a
//! 16-byte BLAKE3 hash of the code), the TLS fingerprint (public), and the
//! sender's observed public IP. File content and metadata never touch it.
//!
//! Routes:
//!   GET /pub/{ch}/{fp}/{port}  — sender announces; relay records observed IP
//!   GET /sub/{ch}              — receiver queries; relay waits up to 30s
//!
//! Usage: wisp-relay [port]     (default 7777)

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::{routing::get, Json, Router};
use dashmap::DashMap;
use serde_json::{json, Value};
use tokio::sync::Notify;

#[derive(Debug, Clone)]
struct Entry {
    ip: String,
    port: u16,
    fp: String,
    expires: Instant,
}

/// Shared relay state.
///
/// `store`   — settled sender entries keyed by `ch`.
/// `waiters` — per-ch Notify handles: a receiver that arrives before the
///             sender parks here; handle_pub calls notify_waiters() on insert.
struct AppState {
    store:   DashMap<String, Entry>,
    waiters: DashMap<String, Arc<Notify>>,
}

type Store = Arc<AppState>;

fn valid_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7777);

    let state: Store = Arc::new(AppState {
        store:   DashMap::new(),
        waiters: DashMap::new(),
    });

    // Purge expired entries every 15s.
    tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                state.store.retain(|_, v| v.expires > Instant::now());
            }
        }
    });

    let app = Router::new()
        .route("/pub/:ch/:fp/:port", get(handle_pub))
        .route("/sub/:ch", get(handle_sub))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("wisp-relay listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Sender announces itself. The relay records the *observed* public IP.
async fn handle_pub(
    Path((ch, fp, port_str)): Path<(String, String, String)>,
    State(state): State<Store>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, Json<Value>) {
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid port"})),
            )
        }
    };
    if port == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid port"})),
        );
    }
    if !valid_hex(&ch, 32) || !valid_hex(&fp, 64) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ch must be 32 hex chars, fp must be 64 hex chars"})),
        );
    }
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "IPv6 not supported"})),
                )
            }
        },
    };
    tracing::info!(ch = %ch.get(..8).unwrap_or(&ch), %ip, port, "sender announced");
    state.store.insert(
        ch.clone(),
        Entry {
            ip: ip.clone(),
            port,
            fp,
            expires: Instant::now() + Duration::from_secs(60),
        },
    );
    // Wake any receiver that arrived before us.
    if let Some(n) = state.waiters.get(&ch) {
        n.notify_waiters();
    }
    (StatusCode::OK, Json(json!({"observed_ip": ip})))
}

/// Receiver queries. Waits up to 30s for the sender to announce.
///
/// Parks on a `Notify` handle instead of polling every 500ms, so idle
/// receivers consume no CPU and wake immediately when the sender arrives.
async fn handle_sub(
    Path(ch): Path<String>,
    State(state): State<Store>,
) -> (StatusCode, Json<Value>) {
    // Get-or-create the Notify for this ch so handle_pub can wake us.
    let notify = state
        .waiters
        .entry(ch.clone())
        .or_insert_with(|| Arc::new(Notify::new()))
        .clone();

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // Create the Notified future BEFORE checking the store so that a
        // notify_waiters() call that races between the check and the await
        // is not lost. If the sender fires between notified() creation and
        // the first poll, Tokio marks the future immediately ready.
        let notified = notify.notified();

        let found = state.store.get(&ch).and_then(|e| {
            if e.expires > Instant::now() {
                Some((e.ip.clone(), e.port, e.fp.clone()))
            } else {
                None
            }
        });
        if let Some((ip, port, fp)) = found {
            state.waiters.remove(&ch);
            tracing::info!(ch = %ch.get(..8).unwrap_or(&ch), %ip, port, "receiver found sender");
            return (
                StatusCode::OK,
                Json(json!({"ip": ip, "port": port, "fp": fp})),
            );
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Park until the sender notifies us or the timeout fires.
        let _ = tokio::time::timeout(remaining, notified).await;
    }

    state.waiters.remove(&ch);
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no sender found within timeout"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hex_accepts_correct_lengths() {
        let ch = "a".repeat(32);
        let fp = "f".repeat(64);
        assert!(valid_hex(&ch, 32));
        assert!(valid_hex(&fp, 64));
    }

    #[test]
    fn valid_hex_rejects_wrong_length() {
        assert!(!valid_hex(&"a".repeat(31), 32));
        assert!(!valid_hex(&"a".repeat(33), 32));
        assert!(!valid_hex(&"f".repeat(63), 64));
    }

    #[test]
    fn valid_hex_rejects_non_hex_chars() {
        assert!(!valid_hex(&"g".repeat(32), 32));
        assert!(!valid_hex(&"z".repeat(64), 64));
        assert!(!valid_hex(&" ".repeat(32), 32));
    }
}
