//! Wisp core protocol.
//!
//! Phase 1 (LAN): mDNS discovery + QUIC (TLS 1.3) transport with certificate
//! fingerprint pinning + BLAKE3 verify-before-rename integrity.
//!
//! See `docs/THREAT_MODEL.md` for the exact security guarantees of this phase.

pub mod code;
pub mod discovery;
pub mod transfer;
pub mod transport;

pub use transfer::{receive_file, send_file};

/// On-the-wire protocol identifier (ALPN + branding).
pub const PROTOCOL: &str = "wsp/1";
