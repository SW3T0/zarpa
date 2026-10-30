// SPDX-License-Identifier: Apache-2.0
//! `Transport` over `iroh` endpoints.
//!
//! Identity model: the 32-byte Ed25519 seed is the iroh `SecretKey`, so the iroh `EndpointId` *is*
//! the device's `PeerKey`. iroh authenticates the remote key in its TLS handshake (raw public keys);
//! it does not know our trust list, so this adapter enforces trust at the application level right
//! after the handshake: `accept` closes connections from untrusted keys and keeps waiting, and
//! `connect` refuses (and closes) anything that is not the expected, trusted key.
//!
//! Local-only: relay disabled, no address lookup (no DNS/pkarr publishing or resolving), net-report
//! optional probes off, portmapper feature not compiled, socket bound to `127.0.0.1:0` only.

use bench_core::transport::{Connection, PeerAddr, PeerKey, Transport, TransportError};
use iroh::endpoint::{presets, RecvStream, SendStream, VarInt};
use iroh::{
    Endpoint, EndpointAddr, NetReportConfig, PublicKey, RelayMode, SecretKey, TransportAddr,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// ALPN protocol identifier for the spike.
pub const ALPN: &[u8] = b"zarpa-spike/0";

fn other<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Other(e.to_string())
}

fn peer_key(id: &PublicKey) -> PeerKey {
    PeerKey(*id.as_bytes())
}

/// An iroh endpoint that both listens and dials, restricted to a trust list.
pub struct IrohTransport {
    endpoint: Endpoint,
    key: PeerKey,
    trusted: Arc<Vec<PeerKey>>,
}

impl IrohTransport {
    /// The endpoint's direct addresses: what iroh advertises plus the actually bound sockets.
    fn direct_addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self.endpoint.addr().ip_addrs().copied().collect();
        for s in self.endpoint.bound_sockets() {
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }
}

impl Transport for IrohTransport {
    type Conn = IrohConn;

    fn name() -> &'static str {
        "iroh"
    }

    async fn bind(secret: [u8; 32], trusted: Vec<PeerKey>) -> Result<Self, TransportError> {
        let secret_key = SecretKey::from_bytes(&secret);
        // `presets::Minimal` = empty builder (relay disabled, no address lookup) + ring provider.
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .net_report_config(NetReportConfig::minimal())
            .clear_ip_transports()
            .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(other)?
            .bind()
            .await
            .map_err(other)?;
        let key = peer_key(&endpoint.id());
        debug_assert_eq!(key, bench_core::transport::public_key(&secret));
        Ok(Self {
            endpoint,
            key,
            trusted: Arc::new(trusted),
        })
    }

    fn addr(&self) -> PeerAddr {
        PeerAddr {
            key: self.key,
            direct: self.direct_addrs(),
        }
    }

    async fn accept(&self) -> Result<IrohConn, TransportError> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| TransportError::Other("endpoint closed".into()))?;
            // A failed handshake is dropped; keep waiting.
            let Ok(conn) = incoming.await else { continue };
            let remote = peer_key(&conn.remote_id());
            if self.trusted.contains(&remote) {
                return Ok(IrohConn { conn, remote });
            }
            conn.close(VarInt::from_u32(1), b"untrusted");
        }
    }

    async fn connect(&self, to: &PeerAddr) -> Result<IrohConn, TransportError> {
        if !self.trusted.contains(&to.key) {
            return Err(TransportError::UntrustedPeer);
        }
        let id =
            PublicKey::from_bytes(&to.key.0).map_err(|e| TransportError::Connect(e.to_string()))?;
        let addr = EndpointAddr::from_parts(id, to.direct.iter().copied().map(TransportAddr::Ip));
        let conn = self
            .endpoint
            .connect(addr, ALPN)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        // iroh guarantees the handshake proved `id`; re-check against the trust list anyway.
        let remote = peer_key(&conn.remote_id());
        if remote != to.key || !self.trusted.contains(&remote) {
            conn.close(VarInt::from_u32(1), b"untrusted");
            return Err(TransportError::UntrustedPeer);
        }
        Ok(IrohConn { conn, remote })
    }
}

/// An authenticated iroh connection.
pub struct IrohConn {
    conn: iroh::endpoint::Connection,
    remote: PeerKey,
}

impl Connection for IrohConn {
    type Send = SendStream;
    type Recv = RecvStream;

    fn remote_key(&self) -> PeerKey {
        self.remote
    }

    async fn open_stream(&self) -> Result<(SendStream, RecvStream), TransportError> {
        self.conn.open_bi().await.map_err(other)
    }

    async fn accept_stream(&self) -> Result<(SendStream, RecvStream), TransportError> {
        self.conn.accept_bi().await.map_err(other)
    }

    fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_core::transport::{public_key, test_secret};

    #[tokio::test]
    async fn endpoint_id_is_seed_derived_key_and_loopback_only() {
        let t = IrohTransport::bind(test_secret(3), vec![]).await.unwrap();
        assert_eq!(t.addr().key, public_key(&test_secret(3)));
        assert_eq!(IrohTransport::name(), "iroh");
        let direct = t.addr().direct;
        assert!(!direct.is_empty());
        assert!(direct.iter().all(|a| a.ip().is_loopback()), "{direct:?}");
    }

    /// `accept` survives an untrusted (but iroh-authenticated) client and returns the next trusted one.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_keeps_waiting_after_untrusted_client() {
        let server = Arc::new(
            IrohTransport::bind(test_secret(2), vec![public_key(&test_secret(1))])
                .await
                .unwrap(),
        );
        let to = server.addr();
        let acc = tokio::spawn({
            let server = Arc::clone(&server);
            async move { server.accept().await.map(|c| c.remote_key()) }
        });
        let intruder = IrohTransport::bind(test_secret(9), vec![public_key(&test_secret(2))])
            .await
            .unwrap();
        let _ = intruder.connect(&to).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !acc.is_finished(),
            "accept returned after an untrusted handshake"
        );
        let friend = IrohTransport::bind(test_secret(1), vec![public_key(&test_secret(2))])
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

    /// Dialing a key that is not the one listening on the address fails (iroh's handshake check).
    #[tokio::test(flavor = "multi_thread")]
    async fn connect_to_wrong_key_fails() {
        let server = IrohTransport::bind(test_secret(2), vec![public_key(&test_secret(7))])
            .await
            .unwrap();
        let client = IrohTransport::bind(test_secret(7), vec![public_key(&test_secret(5))])
            .await
            .unwrap();
        let mut to = server.addr();
        to.key = public_key(&test_secret(5));
        let accept = tokio::spawn(async move { server.accept().await.map(|_| ()) });
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(15), client.connect(&to)).await;
        assert!(
            !matches!(res, Ok(Ok(_))),
            "connected to a server with the wrong key"
        );
        accept.abort();
    }
}
