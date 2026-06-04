//! LAN discovery via mDNS (`_wisp._udp.local.`).
//!
//! The sender advertises a service whose instance name is the pairing code,
//! carrying the file metadata and the certificate fingerprint in TXT records.
//! The receiver browses for the matching code and resolves the address/port.
//!
//! Note (Phase 1): metadata here is in cleartext on the LAN. Phase 2 moves all
//! metadata inside the PAKE-authenticated, encrypted channel.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

pub const SERVICE_TYPE: &str = "_wisp._udp.local.";

/// Metadata advertised about a transfer.
#[derive(Debug, Clone)]
pub struct TransferMeta {
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub fingerprint: [u8; 32],
}

/// Resolved sender endpoint plus advertised metadata.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub addr: Ipv4Addr,
    pub port: u16,
    pub meta: TransferMeta,
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

/// Advertise a transfer on the LAN under `code`.
#[allow(clippy::too_many_arguments)]
pub fn advertise(
    code: &str,
    ip: Ipv4Addr,
    port: u16,
    name: &str,
    size: u64,
    hash: &str,
    fingerprint_hex: &str,
) -> Result<Advert> {
    let daemon = ServiceDaemon::new().context("starting mDNS daemon")?;
    let host = format!("wisp-{port}.local.");
    let size_s = size.to_string();
    let props: [(&str, &str); 5] = [
        ("code", code),
        ("name", name),
        ("size", &size_s),
        ("hash", hash),
        ("fp", fingerprint_hex),
    ];
    let info = ServiceInfo::new(SERVICE_TYPE, code, &host, IpAddr::V4(ip), port, &props[..])
        .context("building mDNS service info")?;
    let fullname = info.get_fullname().to_string();
    daemon.register(info).context("registering mDNS service")?;
    Ok(Advert { daemon, fullname })
}

/// Browse the LAN for `code` until found or `timeout` elapses.
pub fn find(code: &str, timeout: Duration) -> Result<Resolved> {
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
                if info.get_property_val_str("code") != Some(code) {
                    continue;
                }
                let Some(addr) = info.get_addresses().iter().find_map(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                }) else {
                    continue;
                };
                let meta = parse_meta(&info)?;
                let port = info.get_port();
                let _ = daemon.shutdown();
                return Ok(Resolved { addr, port, meta });
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

fn parse_meta(info: &ServiceInfo) -> Result<TransferMeta> {
    let name = info
        .get_property_val_str("name")
        .unwrap_or("file")
        .to_string();
    let size = info
        .get_property_val_str("size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let hash = info.get_property_val_str("hash").unwrap_or("").to_string();
    let fp_hex = info.get_property_val_str("fp").unwrap_or("");
    let fp_vec = hex::decode(fp_hex).context("decoding certificate fingerprint")?;
    let fingerprint: [u8; 32] = fp_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("advertised fingerprint has wrong length"))?;
    Ok(TransferMeta {
        name,
        size,
        hash,
        fingerprint,
    })
}
