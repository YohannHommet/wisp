//! Out-of-band device pairing handshake.
//!
//! Using an ephemeral SPAKE2 code to authenticate, two devices establish a secure
//! connection and exchange their persistent certificate fingerprints and friendly names.
//! Once successfully authenticated and confirmed by the user, the peer is saved
//! in the trusted_peers configuration registry.

use anyhow::{anyhow, Context, Result};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchange {
    pub friendly_name: String,
    pub certificate_fingerprint: String,
}

/// Run pairing exchange as the sender/host (Role A in SPAKE2).
pub async fn run_pairing_host(
    code: &str,
    friendly_name: &str,
    local_fingerprint: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
) -> Result<PeerExchange> {
    // 1. Authenticate using SPAKE2
    crate::pake::sender_handshake(code, send, recv, tls_unique)
        .await
        .context("SPAKE2 host handshake failed")?;

    // 2. Send local peer info
    let local_info = PeerExchange {
        friendly_name: friendly_name.to_string(),
        certificate_fingerprint: local_fingerprint.to_string(),
    };
    let payload = serde_json::to_vec(&local_info)?;
    write_prefixed_frame(send, &payload).await?;

    // 3. Receive remote peer info
    let remote_payload = read_prefixed_frame(recv).await?;
    let remote_info: PeerExchange = serde_json::from_slice(&remote_payload)
        .context("failed to parse remote peer exchange payload")?;

    Ok(remote_info)
}

/// Run pairing exchange as the client/receiver (Role B in SPAKE2).
pub async fn run_pairing_client(
    code: &str,
    friendly_name: &str,
    local_fingerprint: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
) -> Result<PeerExchange> {
    // 1. Authenticate using SPAKE2
    crate::pake::receiver_handshake(code, send, recv, tls_unique)
        .await
        .context("SPAKE2 client handshake failed")?;

    // 2. Receive remote peer info
    let remote_payload = read_prefixed_frame(recv).await?;
    let remote_info: PeerExchange = serde_json::from_slice(&remote_payload)
        .context("failed to parse remote peer exchange payload")?;

    // 3. Send local peer info
    let local_info = PeerExchange {
        friendly_name: friendly_name.to_string(),
        certificate_fingerprint: local_fingerprint.to_string(),
    };
    let payload = serde_json::to_vec(&local_info)?;
    write_prefixed_frame(send, &payload).await?;

    Ok(remote_info)
}

async fn write_prefixed_frame(send: &mut SendStream, msg: &[u8]) -> Result<()> {
    let len = u32::try_from(msg.len()).map_err(|_| anyhow!("pairing message too long"))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(msg).await?;
    Ok(())
}

async fn read_prefixed_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1024 * 1024 {
        return Err(anyhow!("invalid pairing message size: {len}"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Endpoint;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    async fn quic_loopback() -> (quinn::Connection, quinn::Connection) {
        let setup = crate::transport::make_server_config().unwrap();
        let fingerprint = setup.fingerprint;
        let server_ep = Endpoint::server(
            setup.config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let port = server_ep.local_addr().unwrap().port();

        tokio::join!(
            async {
                let inc = server_ep.accept().await.unwrap();
                inc.await.unwrap()
            },
            async {
                let cfg = crate::transport::make_client_config(fingerprint).unwrap();
                let mut ep =
                    Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                        .unwrap();
                ep.set_default_client_config(cfg);
                ep.connect(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    "wisp",
                )
                .unwrap()
                .await
                .unwrap()
            }
        )
    }

    #[tokio::test]
    async fn test_pairing_exchange_happy_path() {
        let code = "9-bear-mars";
        let host_name = "Host Laptop";
        let host_fp = "sha256-host-fingerprint";
        let client_name = "Client Desktop";
        let client_fp = "sha256-client-fingerprint";

        let (server_conn, client_conn) = quic_loopback().await;

        let host_handle = tokio::spawn({
            let sc = server_conn.clone();
            let code = code.to_string();
            async move {
                let (mut s, mut r) = sc.accept_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                sc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                run_pairing_host(&code, host_name, host_fp, &mut s, &mut r, &tls_unique).await
            }
        });

        let client_handle = tokio::spawn({
            let cc = client_conn.clone();
            let code = code.to_string();
            async move {
                let (mut s, mut r) = cc.open_bi().await.unwrap();
                let mut tls_unique = [0u8; 32];
                cc.export_keying_material(&mut tls_unique, b"wisp-channel-binding", &[]).unwrap();
                run_pairing_client(&code, client_name, client_fp, &mut s, &mut r, &tls_unique).await
            }
        });

        let (host_res, client_res) = tokio::join!(host_handle, client_handle);
        let host_exchange = host_res.unwrap().unwrap();
        let client_exchange = client_res.unwrap().unwrap();

        // Host received client info
        assert_eq!(host_exchange.friendly_name, client_name);
        assert_eq!(host_exchange.certificate_fingerprint, client_fp);

        // Client received host info
        assert_eq!(client_exchange.friendly_name, host_name);
        assert_eq!(client_exchange.certificate_fingerprint, host_fp);
    }
}
