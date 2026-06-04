//! QUIC transport setup: self-signed certificate generation on the sender, and
//! certificate-fingerprint *pinning* on the receiver.
//!
//! The sender mints a fresh self-signed certificate per run. Its BLAKE3
//! fingerprint is advertised out-of-band (mDNS in Phase 1) and pinned by the
//! receiver's custom verifier — so a passive eavesdropper cannot read the
//! stream, and the receiver only talks to the advertised endpoint.
//!
//! Phase 2 binds this channel to a PAKE secret to defeat *active* spoofers.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::PROTOCOL;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A server config plus the fingerprint a receiver must pin.
pub struct ServerSetup {
    pub config: ServerConfig,
    pub fingerprint: [u8; 32],
}

/// Build a QUIC server config with a fresh self-signed certificate.
pub fn make_server_config() -> Result<ServerSetup> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["wisp".to_string()])
            .context("generating self-signed certificate")?;

    let cert_der: CertificateDer<'static> = cert.der().clone();
    let fingerprint = *blake3::hash(cert_der.as_ref()).as_bytes();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .context("rustls single cert")?;
    crypto.alpn_protocols = vec![PROTOCOL.as_bytes().to_vec()];

    let quic = QuicServerConfig::try_from(crypto).context("quic server config")?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(0u8.into());
    config.transport_config(Arc::new(transport));

    Ok(ServerSetup {
        config,
        fingerprint,
    })
}

/// Build a QUIC client config that pins the sender's certificate fingerprint.
pub fn make_client_config(expected_fingerprint: [u8; 32]) -> Result<ClientConfig> {
    let verifier = Arc::new(PinnedVerifier {
        fingerprint: expected_fingerprint,
        provider: provider(),
    });

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![PROTOCOL.as_bytes().to_vec()];

    let quic = QuicClientConfig::try_from(crypto).context("quic client config")?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

/// Verifier that accepts exactly one certificate: the one whose BLAKE3
/// fingerprint matches the value advertised by the sender.
#[derive(Debug)]
struct PinnedVerifier {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = blake3::hash(end_entity.as_ref());
        if got.as_bytes() == &self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "wisp: certificate fingerprint mismatch (possible MITM)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
