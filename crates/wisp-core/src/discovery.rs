//! LAN discovery via mDNS (`_wisp._udp.local.`).
//!
//! Phase 2 change: instead of advertising the pairing code in cleartext, we
//! advertise a 16-byte BLAKE3 commitment (`ch`). A passive LAN observer cannot
//! extract the code from the advertisement; only the receiver, who already
//! knows the code, can compute the same commitment and match it.
//!
//! TXT records advertised:
//!   `ch`  — hex(BLAKE3(code)[..16])  code commitment (32 hex chars)
//!   `fp`  — hex(cert fingerprint)    BLAKE3 hash of the DER certificate
//!
//! File metadata (name, size, hash) is no longer in mDNS; it is sent inside
//! the PAKE-authenticated, TLS-encrypted QUIC stream (see `transfer.rs`).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

pub const SERVICE_TYPE: &str = "_wisp._udp.local.";

/// Resolved sender endpoint.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub addr: Ipv4Addr,
    pub port: u16,
    pub fingerprint: [u8; 32],
}

/// Active advertisement; unregisters on drop.
pub struct Advert {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for Advert {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Advertise a transfer on the LAN under `code` (commitment only).
pub fn advertise(code: &str, ip: Ipv4Addr, port: u16, fingerprint_hex: &str) -> Result<Advert> {
    let ch = code_commitment(code);
    let daemon = ServiceDaemon::new().context("starting mDNS daemon")?;
    let host = format!("wisp-{port}.local.");
    let props: [(&str, &str); 2] = [("ch", &ch), ("fp", fingerprint_hex)];
    let info = ServiceInfo::new(SERVICE_TYPE, code, &host, IpAddr::V4(ip), port, &props[..])
        .context("building mDNS service info")?;
    let fullname = info.get_fullname().to_string();
    daemon.register(info).context("registering mDNS service")?;
    Ok(Advert { daemon, fullname })
}

/// Browse the LAN for `code` (matched via its commitment) until found or timeout.
pub fn find(code: &str, timeout: Duration) -> Result<Resolved> {
    let ch_expected = code_commitment(code);
    let daemon = ServiceDaemon::new().context("starting mDNS daemon")?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .context("starting mDNS browse")?;
    let deadline = Instant::now() + timeout;

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| anyhow!("no sender found for code `{code}` on the local network"))?;

        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if info.get_property_val_str("ch") != Some(ch_expected.as_str()) {
                    continue;
                }
                let Some(addr) = info.get_addresses().iter().find_map(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                }) else {
                    continue;
                };
                let fingerprint = parse_fingerprint(&info)?;
                let port = info.get_port();
                let _ = daemon.shutdown();
                return Ok(Resolved {
                    addr,
                    port,
                    fingerprint,
                });
            }
            Ok(_) => continue,
            Err(_) => {
                return Err(anyhow!(
                    "no sender found for code `{code}` on the local network"
                ))
            }
        }
    }
}

/// BLAKE3(code)[..16] encoded as hex — 32-char string.
fn code_commitment(code: &str) -> String {
    hex::encode(&blake3::hash(code.as_bytes()).as_bytes()[..16])
}

fn parse_fingerprint(info: &ServiceInfo) -> Result<[u8; 32]> {
    let fp_hex = info.get_property_val_str("fp").unwrap_or("");
    let fp_vec = hex::decode(fp_hex).context("decoding certificate fingerprint")?;
    fp_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("advertised fingerprint has wrong length"))
}
