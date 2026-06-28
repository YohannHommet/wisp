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

#[derive(Debug, Clone)]
struct Entry {
    ip: String,
    port: u16,
    fp: String,
    expires: Instant,
}

type Store = Arc<DashMap<String, Entry>>;

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

    let store: Store = Arc::new(DashMap::new());

    // Purge expired entries every 15s.
    tokio::spawn({
        let store = store.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                store.retain(|_, v| v.expires > Instant::now());
            }
        }
    });

    let app = Router::new()
        .route("/pub/:ch/:fp/:port", get(handle_pub))
        .route("/sub/:ch", get(handle_sub))
        .with_state(store);

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
    State(store): State<Store>,
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
    tracing::info!(ch = %&ch[..8], %ip, port, "sender announced");
    store.insert(
        ch,
        Entry {
            ip: ip.clone(),
            port,
            fp,
            expires: Instant::now() + Duration::from_secs(60),
        },
    );
    (StatusCode::OK, Json(json!({"observed_ip": ip})))
}

/// Receiver queries. Waits up to 30s for the sender to announce.
async fn handle_sub(
    Path(ch): Path<String>,
    State(store): State<Store>,
) -> (StatusCode, Json<Value>) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let found = store.get(&ch).and_then(|e| {
            if e.expires > Instant::now() {
                Some((e.ip.clone(), e.port, e.fp.clone()))
            } else {
                None
            }
        });
        if let Some((ip, port, fp)) = found {
            tracing::info!(ch = %&ch[..8], %ip, port, "receiver found sender");
            return (
                StatusCode::OK,
                Json(json!({"ip": ip, "port": port, "fp": fp})),
            );
        }
        if Instant::now() >= deadline {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "no sender found within timeout"})),
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
