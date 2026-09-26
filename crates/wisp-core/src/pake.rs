//! SPAKE2 key exchange with role-specific confirmation bound to the QUIC TLS session.
//! Authentication completes before metadata or file bytes are exchanged. See the
//! threat model for the distinction between this composition and the SPAKE2 RFC.

use quinn::{RecvStream, SendStream};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::time::Duration;
use subtle::ConstantTimeEq;

const ID_SENDER: &[u8] = b"wisp-v2-sender";
const ID_RECEIVER: &[u8] = b"wisp-v2-receiver";

/// Errors that can occur during the PAKE and intent handshake.
#[derive(Debug)]
pub enum HandshakeError {
    /// Peer did not supply a valid locator proof of intent. This occurs during
    /// network port scans, spurious connections, or mismatched session identifiers.
    /// Crucially, this error does NOT consume a password guess attempt.
    InvalidIntent,
    /// SPAKE2 authentication failed: wrong password/code or active network attack.
    AuthFailed,
    /// Connection or protocol failure before authentication could complete.
    Protocol(String),
    /// Underlying I/O error during handshake.
    Io(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIntent => write!(f, "invalid session locator token"),
            Self::AuthFailed => {
                write!(
                    f,
                    "authentication failed — wrong code or active network attack"
                )
            }
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Io(err) => write!(f, "I/O error during handshake: {err}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Compute a domain-separated, TLS-channel-bound locator intent token.
///
/// Because `tls_unique` is derived from the TLS 1.3 key exporter for the specific
/// QUIC connection, this token cannot be replayed across connections, even if an
/// eavesdropper observes mDNS packets or network metadata.
pub fn locator_token(locator: &str, tls_unique: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wisp:v2:client-intent\0");
    hasher.update(locator.as_bytes());
    hasher.update(tls_unique);
    *hasher.finalize().as_bytes()
}

/// Extract the 8-digit public locator from a pairing code or return the input slice.
pub fn extract_locator(code: &str) -> &str {
    if let Some((loc, _)) = code.split_once('-') {
        if loc.len() == 8 && loc.bytes().all(|b| b.is_ascii_digit()) {
            return loc;
        }
    }
    if code.len() >= 8 {
        &code[..8]
    } else {
        code
    }
}

/// Sender (SPAKE2 role A). Call immediately after `accept_bi()`.
pub async fn sender_handshake(
    code: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
) -> Result<(), HandshakeError> {
    let res = async {
        // Phase 1: Verify client proof of intent before running SPAKE2 or counting attempts.
        // Use 5s timeout so stalled network probes do not hold the loop.
        let mut client_token = [0u8; 32];
        if tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut client_token))
            .await
            .map_err(|_| HandshakeError::InvalidIntent)?
            .is_err()
        {
            return Err(HandshakeError::InvalidIntent);
        }
        let expected_token = locator_token(extract_locator(code), tls_unique);
        if client_token.ct_eq(&expected_token).unwrap_u8() == 0 {
            return Err(HandshakeError::InvalidIntent);
        }

        // Phase 2: SPAKE2 handshake.
        let (state, msg_a) = Spake2::<Ed25519Group>::start_a(
            &Password::new(code.as_bytes()),
            &Identity::new(ID_SENDER),
            &Identity::new(ID_RECEIVER),
        );

        // Receiver speaks first: read B message. Bounded to 5s.
        let msg_b = match tokio::time::timeout(Duration::from_secs(5), read_frame(recv)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(HandshakeError::Protocol(
                    "timeout waiting for client SPAKE2 message".into(),
                ))
            }
        };
        write_frame(send, &msg_a).await?;

        let key = state
            .finish(&msg_b)
            .map_err(|_| HandshakeError::AuthFailed)?;

        // Send our confirmation. Once this is sent, the client has enough info to verify its guess offline!
        send.write_all(&mac(&key, b"wisp:v2:confirm:a", tls_unique))
            .await
            .map_err(|e| HandshakeError::Protocol(e.to_string()))?;

        // Read client confirmation. Any failure or timeout here MUST be counted as AuthFailed
        // to prevent an attacker from testing password guesses offline and withholding got_b.
        let mut got_b = [0u8; 32];
        let read_res =
            tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut got_b)).await;
        match read_res {
            Ok(Ok(())) => {
                if got_b
                    .ct_eq(&mac(&key, b"wisp:v2:confirm:b", tls_unique))
                    .unwrap_u8()
                    == 0
                {
                    return Err(HandshakeError::AuthFailed);
                }
            }
            _ => return Err(HandshakeError::AuthFailed),
        }

        Ok(())
    }
    .await;

    if res.is_err() {
        let _ = send.reset(0u32.into());
    }
    res
}

/// Receiver (SPAKE2 role B). Call immediately after `open_bi()`.
pub async fn receiver_handshake(
    code: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
    tls_unique: &[u8; 32],
) -> Result<(), HandshakeError> {
    let res = async {
        // Phase 1: Transmit client intent token bound to this TLS session.
        let token = locator_token(extract_locator(code), tls_unique);
        send.write_all(&token)
            .await
            .map_err(|e| HandshakeError::Protocol(e.to_string()))?;

        // Phase 2: SPAKE2 handshake.
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
            .map_err(|_| HandshakeError::AuthFailed)?;

        // Verify sender's confirmation, then send ours.
        let mut got_a = [0u8; 32];
        recv.read_exact(&mut got_a)
            .await
            .map_err(|e| HandshakeError::Protocol(e.to_string()))?;
        if got_a
            .ct_eq(&mac(&key, b"wisp:v2:confirm:a", tls_unique))
            .unwrap_u8()
            == 0
        {
            return Err(HandshakeError::AuthFailed);
        }

        send.write_all(&mac(&key, b"wisp:v2:confirm:b", tls_unique))
            .await
            .map_err(|e| HandshakeError::Protocol(e.to_string()))?;

        Ok(())
    }
    .await;

    if res.is_err() {
        let _ = send.reset(0u32.into());
    }
    res
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

async fn write_frame(send: &mut SendStream, msg: &[u8]) -> Result<(), HandshakeError> {
    let len = u8::try_from(msg.len())
        .map_err(|_| HandshakeError::Protocol("PAKE message too long".into()))?;
    send.write_all(&[len])
        .await
        .map_err(|e| HandshakeError::Protocol(e.to_string()))?;
    send.write_all(msg)
        .await
        .map_err(|e| HandshakeError::Protocol(e.to_string()))?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, HandshakeError> {
    let mut len_buf = [0u8; 1];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| HandshakeError::Protocol(e.to_string()))?;
    let len = len_buf[0] as usize;
    if len == 0 {
        return Err(HandshakeError::Protocol("empty PAKE message".into()));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| HandshakeError::Protocol(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_token_is_deterministic_and_unique() {
        let binding = [42u8; 32];
        let t1 = locator_token("12345678", &binding);
        let t2 = locator_token("12345678", &binding);
        assert_eq!(t1, t2);

        let t3 = locator_token("87654321", &binding);
        assert_ne!(t1, t3);

        let mut other_binding = binding;
        other_binding[0] ^= 1;
        let t4 = locator_token("12345678", &other_binding);
        assert_ne!(t1, t4);
    }

    #[test]
    fn extract_locator_handles_codes_and_fallbacks() {
        assert_eq!(
            extract_locator("12345678-amber-river-moss-lunar"),
            "12345678"
        );
        assert_eq!(extract_locator("99998888-word1"), "99998888");
        assert_eq!(extract_locator("short"), "short");
        assert_eq!(extract_locator("abcdefghij"), "abcdefgh");
    }

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
