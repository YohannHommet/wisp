//! SPAKE2 key exchange with role-specific confirmation bound to the QUIC TLS session.
//! Authentication completes before metadata or file bytes are exchanged. See the
//! threat model for the distinction between this composition and the SPAKE2 RFC.

use anyhow::{anyhow, Result};
use quinn::{RecvStream, SendStream};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;

const ID_SENDER: &[u8] = b"wisp-v2-sender";
const ID_RECEIVER: &[u8] = b"wisp-v2-receiver";

/// Sender (SPAKE2 role A). Call immediately after `accept_bi()`.
pub async fn sender_handshake(
    code: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
) -> Result<()> {
    let (state, msg_a) = Spake2::<Ed25519Group>::start_a(
        &Password::new(code.as_bytes()),
        &Identity::new(ID_SENDER),
        &Identity::new(ID_RECEIVER),
    );

    // Receiver speaks first: read B message, then send A message.
    let msg_b = read_frame(recv).await?;
    write_frame(send, &msg_a).await?;

    let key = state
        .finish(&msg_b)
        .map_err(|e| anyhow!("PAKE key derivation failed: {:?}", e))?;

    // Send our confirmation, then verify theirs.
    send.write_all(&mac(&key, b"wisp:v2:confirm:a", tls_unique))
        .await?;

    let mut got_b = [0u8; 32];
    recv.read_exact(&mut got_b).await?;
    if got_b
        .ct_eq(&mac(&key, b"wisp:v2:confirm:b", tls_unique))
        .unwrap_u8()
        == 0
    {
        return Err(anyhow!(
            "authentication failed — wrong code or active network attack"
        ));
    }

    Ok(())
}

/// Receiver (SPAKE2 role B). Call immediately after `open_bi()`.
pub async fn receiver_handshake(
    code: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
) -> Result<()> {
    let (state, msg_b) = Spake2::<Ed25519Group>::start_b(
        &Password::new(code.as_bytes()),
        &Identity::new(ID_SENDER),
        &Identity::new(ID_RECEIVER),
    );

    // Receiver speaks first: send B message, then receive A message.
    write_frame(send, &msg_b).await?;
    let msg_a = read_frame(recv).await?;

    let key = state
        .finish(&msg_a)
        .map_err(|e| anyhow!("PAKE key derivation failed: {:?}", e))?;

    // Verify sender's confirmation, then send ours.
    let mut got_a = [0u8; 32];
    recv.read_exact(&mut got_a).await?;
    if got_a
        .ct_eq(&mac(&key, b"wisp:v2:confirm:a", tls_unique))
        .unwrap_u8()
        == 0
    {
        return Err(anyhow!(
            "authentication failed — wrong code or active network attack"
        ));
    }

    send.write_all(&mac(&key, b"wisp:v2:confirm:b", tls_unique))
        .await?;

    Ok(())
}

fn mac(key: &[u8], label: &[u8], tls_unique: &[u8; 32]) -> [u8; 32] {
    let mut k = [0u8; 32];
    let len = key.len().min(32);
    k[..len].copy_from_slice(&key[..len]);
    let mut hasher = blake3::Hasher::new_keyed(&k);
    hasher.update(label);
    hasher.update(tls_unique);
    *hasher.finalize().as_bytes()
}

async fn write_frame(send: &mut SendStream, msg: &[u8]) -> Result<()> {
    let len = u8::try_from(msg.len()).map_err(|_| anyhow!("PAKE message too long"))?;
    send.write_all(&[len]).await?;
    send.write_all(msg).await?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 1];
    recv.read_exact(&mut len_buf).await?;
    let len = len_buf[0] as usize;
    if len == 0 {
        return Err(anyhow!("empty PAKE message"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_deterministic_and_32_bytes() {
        let key = [0xabu8; 64];
        let dummy = [0u8; 32];
        let out = mac(&key, b"wisp:v2:confirm:a", &dummy);
        assert_eq!(out.len(), 32);
        assert_eq!(out, mac(&key, b"wisp:v2:confirm:a", &dummy));
    }

    #[test]
    fn mac_differs_by_label() {
        let key = [0x01u8; 64];
        let dummy = [0u8; 32];
        assert_ne!(
            mac(&key, b"wisp:v2:confirm:a", &dummy),
            mac(&key, b"wisp:v2:confirm:b", &dummy)
        );
    }

    #[test]
    fn mac_differs_by_key() {
        let key_a = [0x01u8; 64];
        let key_b = [0x02u8; 64];
        let dummy = [0u8; 32];
        assert_ne!(
            mac(&key_a, b"wisp:v2:confirm:a", &dummy),
            mac(&key_b, b"wisp:v2:confirm:a", &dummy)
        );
    }

    #[test]
    fn ct_eq_correct_vs_wrong() {
        let key = [0xffu8; 64];
        let label = b"wisp:v2:confirm:a";
        let dummy = [0u8; 32];
        let correct = mac(&key, label, &dummy);
        let mut wrong = correct;
        wrong[0] ^= 1;
        assert_eq!(correct.ct_eq(&correct).unwrap_u8(), 1);
        assert_eq!(correct.ct_eq(&wrong).unwrap_u8(), 0);
    }
}
