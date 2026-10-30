// SPDX-License-Identifier: Apache-2.0
//! The abstraction both QUIC stacks must implement.

use std::future::Future;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// An Ed25519 public key: the identity of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey(pub [u8; 32]);

/// Everything needed to dial a peer on the local network.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    pub key: PeerKey,
    pub direct: Vec<SocketAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("peer is not trusted")]
    UntrustedPeer,
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

/// Derives the public key from a 32-byte Ed25519 secret seed.
pub fn public_key(secret: &[u8; 32]) -> PeerKey {
    PeerKey(
        ed25519_dalek::SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes(),
    )
}

/// A fixed, obviously-fake secret for tests and benchmarks.
pub fn test_secret(n: u8) -> [u8; 32] {
    [n; 32]
}

/// An authenticated endpoint that can dial and accept trusted peers.
///
/// Contract: a peer whose key is not in `trusted` MUST NOT obtain a `Conn` from `accept`, and
/// `connect` MUST fail if the remote key is not `to.key` or is not in `trusted`.
/// `Conn::remote_key` is the key proven during the handshake, never a self-reported value.
pub trait Transport: Sized + Send + Sync + 'static {
    type Conn: Connection;

    fn name() -> &'static str;

    /// `secret` is the Ed25519 seed; `trusted` lists the peers allowed to connect or be connected to.
    /// Must listen on the loopback/LAN without any relay or internet access.
    fn bind(
        secret: [u8; 32],
        trusted: Vec<PeerKey>,
    ) -> impl Future<Output = Result<Self, TransportError>> + Send;

    fn addr(&self) -> PeerAddr;

    fn accept(&self) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;

    fn connect(
        &self,
        to: &PeerAddr,
    ) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}

/// An established, mutually authenticated connection with bidirectional streams.
///
/// Note for implementers: QUIC makes a stream visible to the peer only once data is written on it.
pub trait Connection: Send + Sync + 'static {
    type Send: AsyncWrite + Unpin + Send + 'static;
    type Recv: AsyncRead + Unpin + Send + 'static;

    fn remote_key(&self) -> PeerKey;

    fn open_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::Send, Self::Recv), TransportError>> + Send;

    fn accept_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::Send, Self::Recv), TransportError>> + Send;

    /// Closes the connection immediately (used to simulate a dropped link).
    fn close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_is_deterministic_and_distinct() {
        assert_eq!(public_key(&test_secret(1)), public_key(&test_secret(1)));
        assert_ne!(public_key(&test_secret(1)), public_key(&test_secret(2)));
    }
}
