//! WAN rendezvous client — talks to a `wisp-relay` server over plain HTTP/1.0.
//!
//! Security note: the relay HTTP channel is unauthenticated. This is intentional
//! and safe because the receiver independently pins the TLS certificate fingerprint
//! obtained from the relay, and the PAKE handshake authenticates both parties via
//! the pairing code. An attacker who corrupts the relay response cannot complete
//! the PAKE or pass the fingerprint check.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

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
/// `relay_url` — e.g. `https://relay.example.com:7777` or just `relay.example.com:7777`
pub async fn announce(relay_url: &str, ch: &str, fp_hex: &str, port: u16) -> Result<IpAddr> {
    let path = format!("/pub/{ch}/{fp_hex}/{port}");
    let body = http_get(relay_url, &path)
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
pub async fn find_wan(relay_url: &str, code: &str) -> Result<(IpAddr, u16, [u8; 32])> {
    let ch = crate::code_commitment(code);
    let path = format!("/sub/{ch}");
    let body = http_get(relay_url, &path)
        .await
        .context("relay find failed")?;
    let resp: FindResp = serde_json::from_str(&body).context("parsing relay find response")?;
    let ip: IpAddr = resp.ip.parse().context("parsing sender IP")?;
    let fp_vec = hex::decode(&resp.fp).context("decoding fingerprint from relay")?;
    let fingerprint: [u8; 32] = fp_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("relay returned fingerprint of wrong length"))?;
    Ok((ip, resp.port, fingerprint))
}

/// Minimal HTTPS client using reqwest
async fn http_get(relay_url_or_host: &str, path: &str) -> Result<String> {
    let url = if relay_url_or_host.starts_with("http://") || relay_url_or_host.starts_with("https://") {
        format!("{}{}", relay_url_or_host.trim_end_matches('/'), path)
    } else {
        format!("https://{}{}", relay_url_or_host.trim_end_matches('/'), path)
    };

    let client = reqwest::Client::builder()
        .timeout(RELAY_TIMEOUT)
        .build()
        .context("building HTTP client")?;

    let resp = client.get(&url)
        .send()
        .await
        .with_context(|| format!("HTTP GET request to {url} failed"))?;

    let status = resp.status();
    let body = resp.text().await.context("reading response body")?;

    if !status.is_success() {
        let err_msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_else(|| format!("HTTP status {status}"));
        return Err(anyhow!("relay: {err_msg}"));
    }

    Ok(body)
}

/// Strip `http://` / `https://` scheme from a URL to get `host:port`.
/// Any path after the host is dropped so `TcpStream::connect` gets a bare `host:port`.
pub fn strip_scheme(url: &str) -> &str {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    without_scheme.split('/').next().unwrap_or(without_scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_scheme_http() {
        assert_eq!(strip_scheme("http://relay.example.com:7777"), "relay.example.com:7777");
    }

    #[test]
    fn strip_scheme_https() {
        assert_eq!(strip_scheme("https://relay.example.com:7777"), "relay.example.com:7777");
    }

    #[test]
    fn strip_scheme_with_path() {
        assert_eq!(strip_scheme("http://relay.example.com:7777/api/v1"), "relay.example.com:7777");
    }

    #[test]
    fn strip_scheme_no_scheme() {
        assert_eq!(strip_scheme("relay.example.com:7777"), "relay.example.com:7777");
    }

    #[test]
    fn strip_scheme_trailing_slash() {
        assert_eq!(strip_scheme("http://relay.example.com:7777/"), "relay.example.com:7777");
    }
}
