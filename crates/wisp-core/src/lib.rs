//! Wisp core protocol.
//!
//! Phase 3 (LAN + WAN): mDNS discovery (LAN) or relay rendezvous (WAN) +
//! SPAKE2 mutual authentication + QUIC (TLS 1.3) with fingerprint pinning +
//! BLAKE3 verify-before-rename. File metadata is inside the encrypted channel.
//!
//! See `docs/THREAT_MODEL.md` for the exact security guarantees of this phase.

pub mod code;
pub mod discovery;
pub mod pake;
pub mod relay;
pub mod transfer;
pub mod transport;

pub use transfer::{receive_file, send_file};

/// On-the-wire protocol identifier (ALPN + branding).
pub const PROTOCOL: &str = "wsp/1";

/// BLAKE3(first_two_parts_of_code)[..16] as hex — the mDNS / relay commitment.
pub(crate) fn code_commitment(code: &str) -> String {
    let parts: Vec<&str> = code.split('-').collect();
    let commitment_input = if parts.len() >= 2 {
        format!("{}-{}", parts[0], parts[1])
    } else {
        code.to_string()
    };
    hex::encode(&blake3::hash(commitment_input.as_bytes()).as_bytes()[..16])
}

