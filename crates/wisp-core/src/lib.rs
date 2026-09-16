//! Wisp: one file, one receiver, one local-network session.
//! The library performs no terminal output and never loads configuration implicitly.
#![forbid(unsafe_code)]

pub mod code;
pub mod config;
pub mod discovery;
mod pake;
mod storage;
pub mod transfer;
mod transport;

pub use code::PairingCode;
pub use storage::sanitize;
pub use transfer::{
    receive_file, send_file, Event, EventHandler, ReceiveOptions, SendOptions, TransferReceipt,
};

/// Incompatible with the prototype: independent discovery and verified receipts.
pub const PROTOCOL: &str = "wsp/2";
