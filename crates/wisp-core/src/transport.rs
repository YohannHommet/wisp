//! Ephemeral QUIC/TLS connections; discovery fingerprints are pinned when available.
//! Fingerprints alone are not identities. Every connection must complete the
//! channel-bound PAKE before metadata or file bytes are exchanged.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::PROTOCOL;

use std::sync::OnceLock;

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
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
    transport.max_concurrent_bidi_streams(1u8.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
    config.transport_config(Arc::new(transport));

    Ok(ServerSetup {
        config,
        fingerprint,
    })
}

/// Pin the discovery fingerprint when available. With an explicit address, TLS
/// verifies certificate possession and PAKE authenticates the peer before metadata.
/// An unpinned TLS connection alone is NOT authenticated; never bypass PAKE.
pub fn make_client_config(expected_fingerprint: Option<[u8; 32]>) -> Result<ClientConfig> {
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
    let mut config = ClientConfig::new(Arc::new(quic));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(0u8.into());
    transport.max_concurrent_bidi_streams(1u8.into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Verifier that accepts exactly one certificate: the one whose BLAKE3
/// fingerprint matches the value advertised by the sender.
#[derive(Debug)]
struct PinnedVerifier {
    fingerprint: Option<[u8; 32]>,
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
        if self
            .fingerprint
            .is_none_or(|expected| got.as_bytes() == &expected)
        {
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
