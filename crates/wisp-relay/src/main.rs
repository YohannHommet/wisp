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

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Spin up a real axum relay on a random loopback port. Returns the port.
    async fn spawn_relay() -> u16 {
        let state: Store = Arc::new(AppState {
            store: DashMap::new(),
            waiters: DashMap::new(),
        });
        let app = Router::new()
            .route("/pub/:ch/:fp/:port", get(handle_pub))
            .route("/sub/:ch", get(handle_sub))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        port
    }

    /// Make a raw HTTP/1.1 GET and return `(status_code, full_response_text)`.
    ///
    /// Sends `Connection: close` so hyper/axum closes after the response —
    /// allowing `read_to_end` to return without a separate shutdown step.
    async fn http_get(port: u16, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf).into_owned();
        let status: u16 = response
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, response)
    }

    // ── Happy path: pub then sub ───────────────────────────────────────────────

    #[tokio::test]
    async fn relay_pub_then_sub() {
        let port = spawn_relay().await;
        let ch = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(); // 32 hex chars
        let fp = "f".repeat(64);

        let (pub_status, pub_body) =
            http_get(port, &format!("/pub/{ch}/{fp}/9999")).await;
        assert_eq!(pub_status, 200, "pub body: {pub_body}");
        assert!(pub_body.contains("observed_ip"), "pub body: {pub_body}");

        let (sub_status, sub_body) =
            http_get(port, &format!("/sub/{ch}")).await;
        assert_eq!(sub_status, 200, "sub body: {sub_body}");
        assert!(sub_body.contains("9999"), "sub body should contain port: {sub_body}");
        assert!(sub_body.contains("fp"), "sub body should contain fp: {sub_body}");
    }

    // ── Subscriber arrives before sender; must wake quickly ───────────────────

    #[tokio::test]
    async fn relay_sub_before_pub_wakes_quickly() {
        let port = spawn_relay().await;
        let ch = "b".repeat(32);
        let fp = "e".repeat(64);

        // Launch subscriber first — handle_sub will park on its Notify
        let ch_for_sub = ch.clone();
        let sub_task = tokio::spawn(async move {
            http_get(port, &format!("/sub/{ch_for_sub}")).await
        });

        // Give the request 100ms to connect and reach handle_sub's Notify park point.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let t0 = Instant::now();
        // Sender announces — notify_waiters() must wake the parked subscriber
        http_get(port, &format!("/pub/{ch}/{fp}/8888")).await;

        let (sub_status, sub_body) =
            tokio::time::timeout(Duration::from_secs(3), sub_task)
                .await
                .expect("sub must return quickly after pub announces — not after 30s timeout")
                .unwrap();

        assert_eq!(sub_status, 200, "sub body: {sub_body}");
        assert!(sub_body.contains("8888"), "sub body should contain port 8888: {sub_body}");
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "subscriber must not wait for the full 30s poll timeout"
        );
    }

    // ── Malformed inputs must be rejected with 400 ────────────────────────────

    #[tokio::test]
    async fn relay_invalid_input_rejected() {
        let port = spawn_relay().await;
        let ch = "a".repeat(32);
        let fp = "f".repeat(64);

        // ch too short
        let (status, body) =
            http_get(port, &format!("/pub/{}/{fp}/9000", "a".repeat(31))).await;
        assert_eq!(status, 400, "31-char ch: {body}");

        // ch with non-hex character
        let (status, body) =
            http_get(port, &format!("/pub/{}/{fp}/9000", "g".repeat(32))).await;
        assert_eq!(status, 400, "non-hex ch: {body}");

        // fp too short
        let (status, body) =
            http_get(port, &format!("/pub/{ch}/{}/9000", "f".repeat(63))).await;
        assert_eq!(status, 400, "63-char fp: {body}");

        // port = 0
        let (status, body) =
            http_get(port, &format!("/pub/{ch}/{fp}/0")).await;
        assert_eq!(status, 400, "port 0: {body}");
    }
}
