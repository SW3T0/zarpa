// SPDX-License-Identifier: Apache-2.0
//! `Transport` over plain `quinn` + `rustls` with Ed25519 identity certificates.
//!
//! Identity model: each device has a self-signed X.509 certificate whose key is the Ed25519 key
//! derived from its 32-byte seed. There are no certificate authorities: a peer is accepted only if
//! the Ed25519 public key in its certificate is in the trust list (and, when dialing, equals the
//! expected key). The TLS 1.3 handshake signature is still verified with the crypto provider's
//! signature verification algorithms, which proves possession of the private key.

use bench_core::transport::{Connection, PeerAddr, PeerKey, Transport, TransportError};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// ALPN protocol identifier for the spike.
pub const ALPN: &[u8] = b"zarpa-spike/0";

/// SNI sent by clients. Identity is the certificate key, never the name, so this is a constant.
const SERVER_NAME: &str = "zarpa-peer";

/// PKCS#8 v1 prefix for an Ed25519 private key; the 32-byte seed follows it.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn other<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Other(e.to_string())
}

fn pkcs8_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = PKCS8_ED25519_PREFIX.to_vec();
    der.extend_from_slice(seed);
    der
}

/// Extracts the raw Ed25519 public key from a certificate's SubjectPublicKeyInfo.
/// Fails for any certificate that does not carry an Ed25519 key.
fn ed25519_key_of(cert: &CertificateDer<'_>) -> Result<PeerKey, rustls::Error> {
    use x509_parser::oid_registry::OID_SIG_ED25519;
    let (rest, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    if !rest.is_empty() {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    let spki = parsed.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
    }
    let key: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    Ok(PeerKey(key))
}

/// Shared verification logic for both directions: pin-by-key against a trust list.
#[derive(Debug)]
struct KeyPinVerifier {
    trusted: Arc<Vec<PeerKey>>,
    /// On the client: the key the dialed peer must have.
    expected: Option<PeerKey>,
    algs: WebPkiSupportedAlgorithms,
}

impl KeyPinVerifier {
    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            // Identities are single self-signed certificates; no chains.
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        let key = ed25519_key_of(end_entity)?;
        let expected_ok = self.expected.is_none_or(|e| e == key);
        if expected_ok && self.trusted.contains(&key) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn tls12(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Unreachable in practice (TLS 1.3 only), but still verified properly.
        verify_tls12_signature(m, c, d, &self.algs)
    }

    fn tls13(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Real signature verification with the provider's algorithms, using the key in `c`.
        verify_tls13_signature(m, c, d, &self.algs)
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        // Only Ed25519 identities exist; advertise only that scheme.
        vec![SignatureScheme::ED25519]
    }
}

impl ServerCertVerifier for KeyPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls12(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

impl ClientCertVerifier for KeyPinVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls12(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

/// A quinn endpoint that both listens and dials, authenticated by Ed25519 certificates.
pub struct QuinnTransport {
    endpoint: quinn::Endpoint,
    local: SocketAddr,
    key: PeerKey,
    trusted: Arc<Vec<PeerKey>>,
    provider: Arc<CryptoProvider>,
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

impl QuinnTransport {
    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }

    fn client_config(&self, expected: PeerKey) -> Result<quinn::ClientConfig, TransportError> {
        let verifier = Arc::new(KeyPinVerifier {
            trusted: Arc::clone(&self.trusted),
            expected: Some(expected),
            algs: self.provider.signature_verification_algorithms,
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(other)?
            .dangerous() // only to install a custom verifier; it pins keys and verifies signatures
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![self.cert.clone()], self.private_key())
            .map_err(other)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let quic = QuicClientConfig::try_from(tls).map_err(other)?;
        Ok(quinn::ClientConfig::new(Arc::new(quic)))
    }

    /// The key of the verified peer certificate on an established connection.
    fn verified_key(conn: &quinn::Connection) -> Option<PeerKey> {
        let identity = conn.peer_identity()?;
        let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
        ed25519_key_of(certs.first()?).ok()
    }
}

impl Transport for QuinnTransport {
    type Conn = QuinnConn;

    fn name() -> &'static str {
        "quinn"
    }

    async fn bind(secret: [u8; 32], trusted: Vec<PeerKey>) -> Result<Self, TransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let pkcs8 = pkcs8_from_seed(&secret);
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
            &rcgen::PKCS_ED25519,
        )
        .map_err(other)?;
        let params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).map_err(other)?;
        let cert = params.self_signed(&key_pair).map_err(other)?.der().clone();

        let key = bench_core::transport::public_key(&secret);
        debug_assert_eq!(ed25519_key_of(&cert).ok(), Some(key));
        let trusted = Arc::new(trusted);

        let verifier = Arc::new(KeyPinVerifier {
            trusted: Arc::clone(&trusted),
            expected: None,
            algs: provider.signature_verification_algorithms,
        });
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(other)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![cert.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone())),
            )
            .map_err(other)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let quic = QuicServerConfig::try_from(tls).map_err(other)?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));

        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let local = endpoint.local_addr()?;
        Ok(Self {
            endpoint,
            local,
            key,
            trusted,
            provider,
            cert,
            pkcs8,
        })
    }

    fn addr(&self) -> PeerAddr {
        PeerAddr {
            key: self.key,
            direct: vec![self.local],
        }
    }

    async fn accept(&self) -> Result<QuinnConn, TransportError> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| TransportError::Other("endpoint closed".into()))?;
            // A failed handshake (e.g. untrusted client certificate) is dropped; keep waiting.
            let Ok(conn) = incoming.await else { continue };
            match Self::verified_key(&conn) {
                Some(k) if self.trusted.contains(&k) => return Ok(QuinnConn { conn, remote: k }),
                _ => conn.close(1u32.into(), b"untrusted"),
            }
        }
    }

    async fn connect(&self, to: &PeerAddr) -> Result<QuinnConn, TransportError> {
        if !self.trusted.contains(&to.key) {
            return Err(TransportError::UntrustedPeer);
        }
        let mut last = TransportError::Connect("no direct addresses".into());
        for addr in &to.direct {
            let config = self.client_config(to.key)?;
            let connecting = match self.endpoint.connect_with(config, *addr, SERVER_NAME) {
                Ok(c) => c,
                Err(e) => {
                    last = TransportError::Connect(e.to_string());
                    continue;
                }
            };
            match connecting.await {
                Ok(conn) => match Self::verified_key(&conn) {
                    Some(k) if k == to.key && self.trusted.contains(&k) => {
                        return Ok(QuinnConn { conn, remote: k })
                    }
                    _ => {
                        conn.close(1u32.into(), b"untrusted");
                        return Err(TransportError::UntrustedPeer);
                    }
                },
                Err(e) => last = TransportError::Connect(e.to_string()),
            }
        }
        Err(last)
    }
}

/// An authenticated quinn connection.
pub struct QuinnConn {
    conn: quinn::Connection,
    remote: PeerKey,
}

impl Connection for QuinnConn {
    type Send = quinn::SendStream;
    type Recv = quinn::RecvStream;

    fn remote_key(&self) -> PeerKey {
        self.remote
    }

    async fn open_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream), TransportError> {
        self.conn.open_bi().await.map_err(other)
    }

    async fn accept_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), TransportError> {
        self.conn.accept_bi().await.map_err(other)
    }

    fn close(&self) {
        self.conn.close(0u32.into(), b"closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_core::transport::{public_key, test_secret};

    #[tokio::test]
    async fn certificate_carries_seed_derived_key() {
        let t = QuinnTransport::bind(test_secret(3), vec![]).await.unwrap();
        assert_eq!(
            ed25519_key_of(&t.cert).unwrap(),
            public_key(&test_secret(3))
        );
        assert_eq!(QuinnTransport::name(), "quinn");
        assert!(t.addr().direct[0].ip().is_loopback());
    }

    /// The client's refusal comes from the TLS certificate check, not from a timeout.
    #[tokio::test]
    async fn client_rejects_wrong_server_key_in_handshake() {
        let server = QuinnTransport::bind(test_secret(2), vec![public_key(&test_secret(7))])
            .await
            .unwrap();
        // Client trusts key(5) and dials server(2) pretending it is key(5).
        let client = QuinnTransport::bind(test_secret(7), vec![public_key(&test_secret(5))])
            .await
            .unwrap();
        let mut to = server.addr();
        to.key = public_key(&test_secret(5));
        let accept = tokio::spawn(async move { server.accept().await.map(|_| ()) });
        let err = match client.connect(&to).await {
            Ok(_) => panic!("connected to a server with the wrong key"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.to_lowercase().contains("certificate"),
            "unexpected error: {err}"
        );
        accept.abort();
    }

    /// `accept` survives a rejected client and then returns the next trusted one.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_keeps_waiting_after_untrusted_client() {
        let server = Arc::new(
            QuinnTransport::bind(test_secret(2), vec![public_key(&test_secret(1))])
                .await
                .unwrap(),
        );
        let to = server.addr();
        let acc = tokio::spawn({
            let server = Arc::clone(&server);
            async move { server.accept().await.map(|c| c.remote_key()) }
        });
        let intruder = QuinnTransport::bind(test_secret(9), vec![public_key(&test_secret(2))])
            .await
            .unwrap();
        let _ = intruder.connect(&to).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !acc.is_finished(),
            "accept returned after an untrusted handshake"
        );
        let friend = QuinnTransport::bind(test_secret(1), vec![public_key(&test_secret(2))])
            .await
            .unwrap();
        let _c = friend.connect(&to).await.expect("trusted connect");
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), acc)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(got, public_key(&test_secret(1)));
    }
}
