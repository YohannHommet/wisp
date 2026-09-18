//! mDNS carries a public locator and ephemeral TLS fingerprint, never a password hash.
use crate::PairingCode;
use anyhow::{bail, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

pub const SERVICE_TYPE: &str = "_wisp2._udp.local.";

pub struct Advertisement(ServiceDaemon);
impl Drop for Advertisement {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

#[derive(Debug)]
pub struct Resolved {
    pub address: SocketAddr,
    pub fingerprint: [u8; 32],
}

pub fn advertise(
    code: &PairingCode,
    ip: Ipv4Addr,
    port: u16,
    fingerprint: &[u8; 32],
) -> Result<Advertisement> {
    let daemon = ServiceDaemon::new().context("starting local discovery")?;
    let guard = Advertisement(daemon);
    let fp = hex::encode(fingerprint);
    let props = [("id", code.locator()), ("fp", fp.as_str()), ("v", "2")];
    let host = format!("wisp-{}-{port}.local.", code.locator());
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        code.locator(),
        &host,
        IpAddr::V4(ip),
        port,
        &props[..],
    )?;
    guard.0.register(info).context("advertising the transfer")?;
    Ok(guard)
}

/// Async polling keeps discovery cancellation bounded and drops the daemon immediately.
pub async fn find(code: &PairingCode, duration: Duration) -> Result<Resolved> {
    let guard = Advertisement(ServiceDaemon::new().context("starting local discovery")?);
    let receiver = guard
        .0
        .browse(SERVICE_TYPE)
        .context("browsing the local network")?;
    let search = async {
        loop {
            // Bound work per tick so a noisy network cannot starve cancellation or the timeout.
            for _ in 0..64 {
                let Ok(event) = receiver.try_recv() else {
                    break;
                };
                if let ServiceEvent::ServiceResolved(info) = event {
                    if info.get_property_val_str("id") != Some(code.locator())
                        || info.get_property_val_str("v") != Some("2")
                    {
                        continue;
                    }
                    let Some(fp) = info
                        .get_property_val_str("fp")
                        .and_then(|s| hex::decode(s).ok())
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    else {
                        continue;
                    };
                    let Some(ip) = info.get_addresses().iter().find_map(|ip| match ip {
                        IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_multicast() => Some(*v4),
                        _ => None,
                    }) else {
                        continue;
                    };
                    if info.get_port() == 0 {
                        continue;
                    }
                    return Resolved {
                        address: SocketAddr::new(ip.into(), info.get_port()),
                        fingerprint: fp,
                    };
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    match tokio::time::timeout(duration, search).await {
        Ok(resolved) => Ok(resolved),
        Err(_) => bail!("no sender found on this network; check the code and Wi-Fi, or use --address with the address printed by the sender"),
    }
}
