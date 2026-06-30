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
use std::time::Duration;
use tokio::time::Instant;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Json, Router};
use dashmap::DashMap;
use serde_json::{json, Value};
use tokio::sync::Notify;

const MAX_CAPACITY: usize = 10000;

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
    store_cleanup_running: std::sync::atomic::AtomicBool,
    waiters_cleanup_running: std::sync::atomic::AtomicBool,
    rate_limits: DashMap<IpAddr, (u32, Instant)>,
    trust_proxy: bool,
}

type Store = Arc<AppState>;

struct CleanupGuard<'a>(&'a std::sync::atomic::AtomicBool);
impl<'a> Drop for CleanupGuard<'a> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

struct WaiterGuard {
    ch: String,
    state: Store,
    notify: Arc<Notify>,
}
impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.state.waiters.remove_if(&self.ch, |_, notify| {
            std::sync::Arc::strong_count(notify) <= 2
        });
    }
}

fn valid_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn extract_ip(headers: &HeaderMap, peer_addr: SocketAddr, trust_proxy: bool) -> IpAddr {
    let mut ip = peer_addr.ip();
    if trust_proxy {
        // Check X-Forwarded-For first
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            if let Some(first_ip) = xff.split(',').next().map(|s| s.trim()) {
                if let Ok(parsed) = first_ip.parse::<IpAddr>() {
                    ip = parsed;
                }
            }
        } else if let Some(xri) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
            // Fall back to X-Real-IP
            if let Ok(parsed) = xri.trim().parse::<IpAddr>() {
                ip = parsed;
            }
        }
    }

    // Normalise IPv6-mapped IPv4 addresses to standard IpAddr::V4
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            ip = IpAddr::V4(v4);
        }
    }

    ip
}

fn check_rate_limit(state: &Store, ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut entry = state.rate_limits.entry(ip).or_insert((0, now));
    let (count, start_time) = entry.value_mut();
    
    if now.duration_since(*start_time) >= Duration::from_secs(60) {
        *count = 1;
        *start_time = now;
        true
    } else {
        *count += 1;
        *count <= 30
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // CLI Help Check
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("Usage: wisp-relay [port] [--trust-proxy]   (default 7777)");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let trust_proxy = args.iter().any(|arg| arg == "--trust-proxy");
    let port: u16 = args
        .iter()
        .skip(1)
        .filter(|&s| s != "--trust-proxy")
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7777);

    let state: Store = Arc::new(AppState {
        store:   DashMap::new(),
        waiters: DashMap::new(),
        store_cleanup_running: std::sync::atomic::AtomicBool::new(false),
        waiters_cleanup_running: std::sync::atomic::AtomicBool::new(false),
        rate_limits: DashMap::new(),
        trust_proxy,
    });

    // Purge expired store entries, rate limit records, and orphaned waiters every 15s.
    tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let now = Instant::now();
                state.store.retain(|_, v| v.expires > now);
                state.waiters.retain(|_, notify| Arc::strong_count(notify) > 1);
                state.rate_limits.retain(|_, (_, time)| now.duration_since(*time) < Duration::from_secs(60));
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
    headers: HeaderMap,
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

    let ch = ch.to_lowercase();
    let fp = fp.to_lowercase();

    if !valid_hex(&ch, 32) || !valid_hex(&fp, 64) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ch must be 32 hex chars, fp must be 64 hex chars"})),
        );
    }

    let ip_addr = extract_ip(&headers, addr, state.trust_proxy);

    if !check_rate_limit(&state, ip_addr) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate limit exceeded"})),
        );
    }

    // Capacity limit check
    if state.store.len() >= MAX_CAPACITY {
        if state.store_cleanup_running.compare_exchange(
            false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed
        ).is_ok() {
            let _guard = CleanupGuard(&state.store_cleanup_running);
            state.store.retain(|_, v| v.expires > Instant::now());
        }
        if state.store.len() >= MAX_CAPACITY {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "relay capacity exceeded"})),
            );
        }
    }

    let ip = ip_addr.to_string();

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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let ch = ch.to_lowercase();

    if !valid_hex(&ch, 32) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ch must be 32 hex chars"})),
        );
    }

    let ip_addr = extract_ip(&headers, addr, state.trust_proxy);

    if !check_rate_limit(&state, ip_addr) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate limit exceeded"})),
        );
    }

    // Capacity limit check for waiters
    if state.waiters.len() >= MAX_CAPACITY {
        if state.waiters_cleanup_running.compare_exchange(
            false, true, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed
        ).is_ok() {
            let _guard = CleanupGuard(&state.waiters_cleanup_running);
            state.waiters.retain(|_, notify| Arc::strong_count(notify) > 1);
        }
        if state.waiters.len() >= MAX_CAPACITY {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "relay waiter capacity exceeded"})),
            );
        }
    }

    // Get-or-create the Notify for this ch so handle_pub can wake us.
    let guard = WaiterGuard {
        ch: ch.clone(),
        state: state.clone(),
        notify: state
            .waiters
            .entry(ch.clone())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone(),
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut result = None;

    loop {
        // Create the Notified future BEFORE checking the store so that a
        // notify_waiters() call that races between the check and the await
        // is not lost. If the sender fires between notified() creation and
        // the first poll, Tokio marks the future immediately ready.
        let notified = guard.notify.notified();

        let found = state.store.get(&ch).and_then(|e| {
            if e.expires > Instant::now() {
                Some((e.ip.clone(), e.port, e.fp.clone()))
            } else {
                None
            }
        });
        if let Some((ip, port, fp)) = found {
            tracing::info!(ch = %ch.get(..8).unwrap_or(&ch), %ip, port, "receiver found sender");
            result = Some((
                StatusCode::OK,
                Json(json!({"ip": ip, "port": port, "fp": fp})),
            ));
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Park until the sender notifies us or the timeout fires.
        let _ = tokio::time::timeout(remaining, notified).await;
    }

    drop(guard);

    result.unwrap_or((
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no sender found within timeout"})),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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

    #[test]
    fn test_extract_ipv4_direct() {
        let headers = HeaderMap::new();
        let peer_addr = SocketAddr::from(([192, 168, 1, 50], 12345));
        let ip = extract_ip(&headers, peer_addr, true);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn test_extract_ipv4_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178".parse().unwrap());
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let ip = extract_ip(&headers, peer_addr, true);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 195)));
    }

    #[test]
    fn test_extract_ipv4_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.196".parse().unwrap());
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let ip = extract_ip(&headers, peer_addr, true);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 196)));
    }

    #[test]
    fn test_extract_ipv4_v6_mapped() {
        let headers = HeaderMap::new();
        // IPv4-mapped IPv6 address: ::ffff:192.168.1.50
        let v6_mapped = SocketAddr::new(
            IpAddr::V6("::ffff:192.168.1.50".parse().unwrap()),
            12345,
        );
        let ip = extract_ip(&headers, v6_mapped, true);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn test_extract_ip_v6_raw() {
        let headers = HeaderMap::new();
        let v6_raw = SocketAddr::new(
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            12345,
        );
        let ip = extract_ip(&headers, v6_raw, true);
        assert_eq!(ip, IpAddr::V6("2001:db8::1".parse().unwrap()));
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
            store_cleanup_running: std::sync::atomic::AtomicBool::new(false),
            waiters_cleanup_running: std::sync::atomic::AtomicBool::new(false),
            rate_limits: DashMap::new(),
            trust_proxy: true,
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

    // ── Rate Limiting test ────────────────────────────────────────────────────

    #[tokio::test]
    async fn relay_rate_limiting() {
        let port = spawn_relay().await;
        let ch = "c".repeat(32);
        let fp = "f".repeat(64);

        // 1. Perform 30 requests. They should not get HTTP 429.
        for _ in 0..30 {
            let (status, _) = http_get(port, &format!("/pub/{ch}/{fp}/9000")).await;
            assert_eq!(status, 200);
        }

        // 2. The 31st request should be rejected with 429.
        let (status, body) = http_get(port, &format!("/pub/{ch}/{fp}/9000")).await;
        assert_eq!(status, 429, "Expected HTTP 429, got {status} ({body})");
    }

    #[tokio::test]
    async fn test_direct_handler_abort_bug() {
        tokio::time::pause();

        let state: Store = Arc::new(AppState {
            store: DashMap::new(),
            waiters: DashMap::new(),
            store_cleanup_running: std::sync::atomic::AtomicBool::new(false),
            waiters_cleanup_running: std::sync::atomic::AtomicBool::new(false),
            rate_limits: DashMap::new(),
            trust_proxy: true,
        });
        
        let ch = "e".repeat(32);
        let fp = "f".repeat(64);
        
        println!("[TEST] Start Sub1 at t = {:?}", tokio::time::Instant::now());
        let state_clone1 = state.clone();
        let ch_clone1 = ch.clone();
        let sub1 = tokio::spawn(async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
            handle_sub(
                Path(ch_clone1),
                State(state_clone1),
                ConnectInfo(addr),
                HeaderMap::new(),
            ).await
        });
        
        // Advance to t = 15s
        tokio::time::sleep(Duration::from_secs(15)).await;
        
        println!("[TEST] Start Sub2 at t = {:?}", tokio::time::Instant::now());
        let state_clone2 = state.clone();
        let ch_clone2 = ch.clone();
        let sub2 = tokio::spawn(async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
            handle_sub(
                Path(ch_clone2),
                State(state_clone2),
                ConnectInfo(addr),
                HeaderMap::new(),
            ).await
        });
        
        // Let Sub2 register (t = 15.1s)
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        println!("[TEST] Waiters count before Sub1 timeout: {}", state.waiters.len());
        
        // Advance to t = 31s (Sub1 timed out at t = 30s)
        tokio::time::sleep(Duration::from_secs(16)).await;
        println!("[TEST] Time now: {:?}", tokio::time::Instant::now());
        
        println!("[TEST] Waiters count after Sub1 timeout: {}", state.waiters.len());
        
        // Publisher announces at t = 31.1s
        println!("[TEST] Publisher announcing...");
        let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
        let (pub_status, pub_body) = handle_pub(
            Path((ch.clone(), fp.clone(), "7777".to_string())),
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
        ).await;
        println!("[TEST] Publisher response: {:?}, body: {:?}", pub_status, pub_body);
        
        println!("[TEST] Awaiting Sub2 (expecting immediate wake)...");
        // We use a 1-second timeout in mock time. If Sub2 wakes up immediately, the time will still be 31.1s.
        // If the bug is present, Sub2 will not wake up and will time out (mock time would advance to its timeout).
        let sub2_res = tokio::time::timeout(Duration::from_secs(1), sub2).await;
        println!("[TEST] Sub2 raw result: {:?}", sub2_res);
        
        let (sub2_status, sub2_body) = match sub2_res {
            Ok(Ok(res)) => res,
            _ => panic!("Sub2 did NOT wake up immediately when publisher announced at t=31s! It is delayed/orphaned!"),
        };
            
        println!("[TEST] Sub2 finished with status {:?}, body: {:?}", sub2_status, sub2_body);
        assert_eq!(sub2_status, StatusCode::OK);
        
        // Cleanup sub1 task
        let _ = sub1.await;
    }
}



