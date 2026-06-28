//! WAN rendezvous client — talks to a `wisp-relay` server over plain HTTP/1.0.
//!
//! Security note: the relay HTTP channel is unauthenticated. This is intentional
//! and safe because the receiver independently pins the TLS certificate fingerprint
//! obtained from the relay, and the PAKE handshake authenticates both parties via
//! the pairing code. An attacker who corrupts the relay response cannot complete
//! the PAKE or pass the fingerprint check.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RELAY_TIMEOUT: Duration = Duration::from_secs(35);

#[derive(Deserialize)]
struct AnnounceResp {
    observed_ip: String,
}

#[derive(Deserialize)]
struct FindResp {
    ip: String,
    port: u16,
    fp: String,
}

/// Register this transfer with the relay. Returns the observed public IP.
///
/// `relay_host` — e.g. `relay.example.com:7777` (no scheme)
pub async fn announce(relay_host: &str, ch: &str, fp_hex: &str, port: u16) -> Result<Ipv4Addr> {
    let path = format!("/pub/{ch}/{fp_hex}/{port}");
    let body = http_get(relay_host, &path)
        .await
        .context("relay announce failed")?;
    let resp: AnnounceResp =
        serde_json::from_str(&body).context("parsing relay announce response")?;
    resp.observed_ip
        .parse()
        .context("parsing observed IP from relay")
}

/// Look up a sender by code. Waits up to 30 s for the sender to appear.
///
/// Returns `(public_ip, port, fingerprint)`.
pub async fn find_wan(relay_host: &str, code: &str) -> Result<(Ipv4Addr, u16, [u8; 32])> {
    let ch = crate::code_commitment(code);
    let path = format!("/sub/{ch}");
    let body = http_get(relay_host, &path)
        .await
        .context("relay find failed")?;
    let resp: FindResp = serde_json::from_str(&body).context("parsing relay find response")?;
    let ip: Ipv4Addr = resp.ip.parse().context("parsing sender IP")?;
    let fp_vec = hex::decode(&resp.fp).context("decoding fingerprint from relay")?;
    let fingerprint: [u8; 32] = fp_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("relay returned fingerprint of wrong length"))?;
    Ok((ip, resp.port, fingerprint))
}

/// Minimal HTTP/1.0 GET — reads the full response body after a 200 OK.
async fn http_get(host: &str, path: &str) -> Result<String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(host))
        .await
        .context("relay connection timed out")?
        .with_context(|| format!("connecting to relay {host}"))?;

    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    tokio::time::timeout(RELAY_TIMEOUT, stream.read_to_end(&mut buf))
        .await
        .context("relay response timed out")??;

    let raw = String::from_utf8_lossy(&buf);
    let status_line = raw.lines().next().unwrap_or("");

    // Split headers / body on the blank line.
    let body = raw
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| raw.split("\n\n").nth(1))
        .unwrap_or("")
        .trim()
        .to_string();

    if !status_line.contains("200") {
        let err_msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_else(|| status_line.to_string());
        return Err(anyhow!("relay: {err_msg}"));
    }

    Ok(body)
}

/// Strip `http://` / `https://` scheme from a URL to get `host:port`.
pub fn strip_scheme(url: &str) -> &str {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
}
