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
pub mod config;
pub mod error;
pub mod pairing;

pub use transfer::{receive_file, send_file, sanitize, ProgressCallback};
pub use error::{Error, Result};

/// On-the-wire protocol identifier (ALPN + branding).
pub const PROTOCOL: &str = "wsp/1";

/// BLAKE3(first_two_parts_of_code)[..16] as hex — the mDNS / relay commitment.
pub fn code_commitment(code: &str) -> String {
    let commitment_input = match code.match_indices('-').nth(1) {
        Some((idx, _)) => &code[..idx],
        None => code,
    };
    hex::encode(&blake3::hash(commitment_input.as_bytes()).as_bytes()[..16])
}

