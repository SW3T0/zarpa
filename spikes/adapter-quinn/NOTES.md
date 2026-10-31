# adapter-quinn — notes

## Versions (from `spikes/Cargo.lock`, 2026-10-30)

| Crate | Version |
|---|---|
| quinn | 0.11.12 |
| quinn-proto | 0.11.19 |
| quinn-udp | 0.5.16 |
| rustls | 0.23.46 |
| rustls-pki-types | 1.15.1 |
| rustls-webpki | 0.103.16 |
| rcgen | 0.14.10 |
| x509-parser | 0.18.1 |
| ring | 0.17.14 |
| tokio | 1.54.1 |

Toolchain: Rust 1.99.x, MSVC Build Tools, Windows 11.

## Crypto provider: `ring`

`cargo add` picks defaults that pull in **aws-lc-rs** (rustls default feature `aws_lc_rs`) and
`rustls-platform-verifier` (quinn default). aws-lc-rs needs cmake/NASM on Windows, so defaults are
switched off and `ring` is used everywhere:

- `quinn`: `default-features = false`, features `runtime-tokio`, `rustls-ring`, `log`
- `rustls`: `default-features = false`, features `ring`, `std`, `logging` (no `tls12`: QUIC is TLS 1.3 only)
- `rcgen`: `default-features = false`, features `crypto`, `ring`

`cargo tree -i aws-lc-rs` confirms it is not in the graph. The provider is passed explicitly
(`rustls::crypto::ring::default_provider()` + `builder_with_provider`), no process-global default.

## API facts (non-obvious)

- **Custom verifiers** live in `rustls::client::danger::ServerCertVerifier` and
  `rustls::server::danger::ClientCertVerifier`. Installing a client-side custom verifier goes through
  `ClientConfig::builder_with_provider(..).with_protocol_versions(&[&TLS13])?.dangerous().with_custom_certificate_verifier(..)`;
  "dangerous" is only the name of that builder step. The server side needs no `dangerous()`:
  `.with_client_cert_verifier(Arc<dyn ClientCertVerifier>)`.
- **Handshake signatures** are verified with `rustls::crypto::verify_tls13_signature(msg, cert, dss, &provider.signature_verification_algorithms)`
  (also `verify_tls12_signature`). It parses the end-entity cert with webpki and checks the
  signature with the key inside it, so our verifiers only add the key-pinning decision in
  `verify_server_cert` / `verify_client_cert`; possession of the private key is still proven.
- `supported_verify_schemes()` returns only `SignatureScheme::ED25519`. On the server this goes into
  the CertificateRequest, so the client's Ed25519 cert is selected for client auth.
- `ClientCertVerifier`: `client_auth_mandatory() = true`, `root_hint_subjects() = &[]` (no CAs).
- **quinn ↔ rustls glue**: `quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig}` implement
  `TryFrom<rustls::{Client,Server}Config>`; they fail if the provider lacks
  `TLS13_AES_128_GCM_SHA256` (ring has it). Then `quinn::ClientConfig::new(Arc::new(..))` and
  `quinn::ServerConfig::with_crypto(Arc::new(..))`. ALPN is set on the rustls config (`alpn_protocols`).
- One `quinn::Endpoint::server(config, 127.0.0.1:0)` both listens and dials (`connect_with(client_config, addr, sni)`).
  A per-call client config is built in `connect` because the expected server key differs per dial.
- **Peer identity**: `Connection::peer_identity()` returns `Box<dyn Any>` that downcasts to
  `Vec<CertificateDer<'static>>` with the rustls session. `remote_key` is extracted from that verified
  certificate (and re-checked against the trust list as defence in depth).
- Server side: `Endpoint::accept()` yields `Incoming`; `incoming.await` resolves only once the TLS
  handshake (including client-certificate verification) completes, so a rejected client is just an
  `Err` there and `accept` loops.
- **Key material**: PKCS#8 v1 = `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 || seed`.
  `rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer, &rcgen::PKCS_ED25519)`, then
  `CertificateParams::new(vec!["zarpa-peer"])?.self_signed(&key_pair)?.der()`. rcgen and rustls share
  the same `rustls-pki-types`, so `CertificateDer` passes straight through.
- **SPKI extraction**: `x509_parser::parse_x509_certificate(der)` → `cert.public_key()`; require
  `algorithm.algorithm == oid_registry::OID_SIG_ED25519` (1.3.101.112) and a 32-byte
  `subject_public_key.data`. Certificate chains (intermediates) are rejected.
- The SNI name `zarpa-peer` is a constant; identity is the key, never the name. Certificate validity
  dates are not checked (rcgen's default range is very wide); identity is pinned by key.
- quinn's `SendStream`/`RecvStream` implement tokio `AsyncWrite`/`AsyncRead` directly;
  `poll_shutdown` = `finish()`.

## Results

`cargo test -p adapter-quinn`: all five conformance tests pass on the first implementation attempt
(no fix attempts needed), plus three adapter-local tests:

- `certificate_carries_seed_derived_key` — cert key equals `public_key(seed)`, name is `quinn`, address is loopback.
- `client_rejects_wrong_server_key_in_handshake` — the client error is a TLS certificate error, not a timeout.
- `accept_keeps_waiting_after_untrusted_client` — `accept` survives a rejected handshake and then
  returns the next trusted peer.

Note: `rejects_untrusted_peer` takes ~3 s because the conformance test waits out its `SHORT`
timeout on `accept` (which correctly never returns).
