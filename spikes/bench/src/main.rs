// SPDX-License-Identifier: Apache-2.0
//! M1.1 benchmarks. Usage: `bench [--mib N]` (throughput) or `bench --encoding`.

use bench_core::block::{gen_bytes, BLOCK_SIZE};
use bench_core::conformance::connected;
use bench_core::manifest::Manifest;
use bench_core::transfer::{recv, send};
use bench_core::transport::Transport;
use std::sync::Arc;
use std::time::Instant;

/// Loopback throughput in MiB/s for one transfer of `mib` MiB over `streams` parallel streams.
async fn throughput<X: Transport>(mib: usize, streams: u32) -> f64 {
    let (_a, _b, ca, cb) = connected::<X>().await;
    let data = Arc::new(gen_bytes(1, mib * 1024 * 1024));
    let manifest = Manifest::from_bytes(&data, BLOCK_SIZE); // hashing is excluded from timing
    let start = Instant::now();
    let rx = tokio::spawn({
        let cb = Arc::clone(&cb);
        async move { recv(&cb, None).await }
    });
    send(&ca, &data, &manifest, streams, None).await.expect("send");
    let set = rx.await.expect("join").expect("recv");
    assert!(set.is_complete(), "transfer incomplete");
    mib as f64 / start.elapsed().as_secs_f64()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

async fn row<X: Transport>(mib: usize, streams: u32) {
    let mut runs = Vec::new();
    for _ in 0..3 {
        runs.push(throughput::<X>(mib, streams).await);
    }
    println!("| {} | {} | {} | {:.0} |", X::name(), mib, streams, median(runs));
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mib = args
        .iter()
        .position(|a| a == "--mib")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);

    println!("| transport | MiB sent | streams | median MiB/s (3 runs, loopback) |");
    println!("|---|---|---|---|");
    for streams in [1u32, 4] {
        row::<adapter_quinn::QuinnTransport>(mib, streams).await;
        row::<adapter_iroh::IrohTransport>(mib, streams).await;
    }
}
