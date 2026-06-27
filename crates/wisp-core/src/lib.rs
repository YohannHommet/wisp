//! Wisp core protocol.
//!
//! Phase 2 (LAN, PAKE-authenticated): mDNS discovery with code commitment +
//! SPAKE2 mutual authentication + QUIC (TLS 1.3) with fingerprint pinning +
//! BLAKE3 verify-before-rename. File metadata is inside the encrypted channel.
//!
//! See `docs/THREAT_MODEL.md` for the exact security guarantees of this phase.

pub mod code;
pub mod discovery;
pub mod pake;
pub mod transfer;
pub mod transport;

pub use transfer::{receive_file, send_file};

/// On-the-wire protocol identifier (ALPN + branding).
pub const PROTOCOL: &str = "wsp/1";
