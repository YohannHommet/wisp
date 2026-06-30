use thiserror::Error;
use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid file: {0}")]
    InvalidFile(PathBuf),

    #[error("Config error: {0}")]
    Config(String),

    #[error("SPAKE2 PAKE handshake failed: {0}")]
    Pake(String),

    #[error("Discovery timed out or failed: {0}")]
    Discovery(String),

    #[error("QUIC network transport error: {0}")]
    Transport(String),

    #[error("File integrity check FAILED: corrupt or tampered transfer (received {received} of {expected} bytes, hash mismatch)")]
    Integrity {
        received: u64,
        expected: u64,
    },

    #[error("Relay error: {0}")]
    Relay(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),

    #[error("QUIC write error: {0}")]
    QuicWrite(#[from] quinn::WriteError),

    #[error("QUIC read error: {0}")]
    QuicRead(#[from] quinn::ReadError),

    #[error("QUIC connection error: {0}")]
    QuicConnection(#[from] quinn::ConnectionError),

    #[error("QUIC connect error: {0}")]
    QuicConnect(#[from] quinn::ConnectError),

    #[error("JSON serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Generic error: {0}")]
    Generic(#[from] anyhow::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
