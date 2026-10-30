// SPDX-License-Identifier: Apache-2.0
//! Behavioural contract every `Transport` adapter must satisfy.

use crate::block::{gen_bytes, BLOCK_SIZE};
use crate::manifest::Manifest;
use crate::transfer::{recv, send};
use crate::transport::{public_key, test_secret, Connection, Transport};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(30);
const SHORT: Duration = Duration::from_secs(3);

/// Two endpoints (secrets 1 and 2) that trust each other.
pub async fn pair<X: Transport>() -> (X, X) {
    let (sa, sb) = (test_secret(1), test_secret(2));
    let a = X::bind(sa, vec![public_key(&sb)]).await.expect("bind a");
    let b = X::bind(sb, vec![public_key(&sa)]).await.expect("bind b");
    (a, b)
}

/// A trusted pair plus an established connection (kept together so endpoints stay alive).
pub async fn connected<X: Transport>() -> (X, X, Arc<X::Conn>, Arc<X::Conn>) {
    let (a, b) = pair::<X>().await;
    let to_b = b.addr();
    let (ca, cb) = tokio::join!(a.connect(&to_b), b.accept());
    (a, b, Arc::new(ca.expect("connect")), Arc::new(cb.expect("accept")))
}

pub async fn authenticated_roundtrip<X: Transport>() {
    let (_a, _b, ca, cb) = connected::<X>().await;
    assert_eq!(ca.remote_key(), public_key(&test_secret(2)));
    assert_eq!(cb.remote_key(), public_key(&test_secret(1)));

    let payload = gen_bytes(42, 1024 * 1024);
    let expected = payload.clone();
    let writer = {
        let ca = Arc::clone(&ca);
        tokio::spawn(async move {
            let (mut tx, _rx) = ca.open_stream().await.expect("open");
            tx.write_all(&payload).await.expect("write");
            tx.shutdown().await.expect("shutdown");
        })
    };
    let (_tx, mut rx) = timeout(T, cb.accept_stream()).await.expect("timeout").expect("accept stream");
    let mut got = Vec::new();
    timeout(T, rx.read_to_end(&mut got)).await.expect("timeout").expect("read");
    writer.await.unwrap();
    assert_eq!(got, expected);
}

/// A server must never hand out a connection to a peer outside its trust list.
pub async fn rejects_untrusted_peer<X: Transport>() {
    let (_a, b) = pair::<X>().await; // b trusts only key(1)
    let intruder = X::bind(test_secret(9), vec![public_key(&test_secret(2))])
        .await
        .expect("bind intruder");
    let to_b = b.addr();
    let (accepted, _dialed) =
        tokio::join!(timeout(SHORT, b.accept()), timeout(SHORT, intruder.connect(&to_b)));
    assert!(!matches!(accepted, Ok(Ok(_))), "server accepted an untrusted peer");
}

/// A client must refuse to talk to a server whose key it does not trust.
pub async fn rejects_unknown_server<X: Transport>() {
    let server = X::bind(test_secret(2), vec![public_key(&test_secret(7))])
        .await
        .expect("bind server");
    let client = X::bind(test_secret(7), vec![]).await.expect("bind client"); // trusts nobody
    let to_server = server.addr();
    let (_accepted, dialed) =
        tokio::join!(timeout(SHORT, server.accept()), timeout(SHORT, client.connect(&to_server)));
    assert!(!matches!(dialed, Ok(Ok(_))), "client connected to an untrusted server");
}

pub async fn transfer_verified<X: Transport>() {
    let (_a, _b, ca, cb) = connected::<X>().await;
    let data = Arc::new(gen_bytes(5, 16 * 1024 * 1024));
    let manifest = Manifest::from_bytes(&data, BLOCK_SIZE);
    let rx = tokio::spawn({
        let cb = Arc::clone(&cb);
        async move { recv(&cb, None).await }
    });
    let sent = timeout(T, send(&ca, &data, &manifest, 4, None)).await.expect("timeout").expect("send");
    let set = timeout(T, rx).await.expect("timeout").unwrap().expect("recv");
    assert_eq!(sent, manifest.block_count());
    assert!(set.is_complete());
}

/// After a dropped connection, only the missing blocks are re-sent.
pub async fn resume_after_drop<X: Transport>() {
    let (a, b, ca, cb) = connected::<X>().await;
    let data = Arc::new(gen_bytes(6, 32 * 1024 * 1024)); // 8 blocks
    let manifest = Manifest::from_bytes(&data, BLOCK_SIZE);
    assert_eq!(manifest.block_count(), 8);

    let rx = tokio::spawn({
        let cb = Arc::clone(&cb);
        async move { recv(&cb, None).await }
    });
    let first = timeout(T, send(&ca, &data, &manifest, 2, Some(3))).await.expect("timeout").expect("send 1");
    let partial = timeout(T, rx).await.expect("timeout").unwrap().expect("recv 1");
    assert_eq!(first, 3);
    assert_eq!(partial.verified_count(), 3);
    assert!(!partial.is_complete());

    ca.close();
    cb.close();

    // Reconnect and resume with the receiver's prior state.
    let to_b = b.addr();
    let (ca2, cb2) = tokio::join!(a.connect(&to_b), b.accept());
    let (ca2, cb2) = (Arc::new(ca2.expect("reconnect")), Arc::new(cb2.expect("re-accept")));
    let rx2 = tokio::spawn({
        let cb2 = Arc::clone(&cb2);
        async move { recv(&cb2, Some(partial)).await }
    });
    let second = timeout(T, send(&ca2, &data, &manifest, 2, None)).await.expect("timeout").expect("send 2");
    let done = timeout(T, rx2).await.expect("timeout").unwrap().expect("recv 2");
    assert_eq!(second, 5, "only the 5 missing blocks must be re-sent");
    assert!(done.is_complete());
}

/// Instantiates the whole suite for one adapter type, e.g.
/// `bench_core::conformance_tests!(adapter_quinn::QuinnTransport);`
#[macro_export]
macro_rules! conformance_tests {
    ($t:ty) => {
        mod conformance_suite {
            #[tokio::test(flavor = "multi_thread")]
            async fn authenticated_roundtrip() {
                $crate::conformance::authenticated_roundtrip::<$t>().await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn rejects_untrusted_peer() {
                $crate::conformance::rejects_untrusted_peer::<$t>().await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn rejects_unknown_server() {
                $crate::conformance::rejects_unknown_server::<$t>().await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn transfer_verified() {
                $crate::conformance::transfer_verified::<$t>().await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn resume_after_drop() {
                $crate::conformance::resume_after_drop::<$t>().await
            }
        }
    };
}
