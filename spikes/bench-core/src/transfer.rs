// SPDX-License-Identifier: Apache-2.0
//! Offer -> want-list -> parallel block streams, over any `Connection`.

use crate::manifest::{Manifest, VerifiedSet};
use crate::transport::{Connection, TransportError};
use crate::wire::{
    read_block, read_offer, read_want, write_block, write_offer, write_want, WireError,
    STREAM_MAGIC,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn wire_err(e: WireError) -> TransportError {
    TransportError::Other(e.to_string())
}

/// Sends `data`: offer, receiver replies with the blocks it still needs, then those blocks flow over
/// `streams` parallel streams. `limit` caps how many blocks are sent (simulates an interrupted
/// transfer). Returns the number of blocks sent.
pub async fn send<C: Connection>(
    conn: &Arc<C>,
    data: &Arc<Vec<u8>>,
    manifest: &Manifest,
    streams: u32,
    limit: Option<usize>,
) -> Result<usize, TransportError> {
    let (mut ctl_tx, mut ctl_rx) = conn.open_stream().await?;
    write_offer(&mut ctl_tx, manifest, streams)
        .await
        .map_err(wire_err)?;
    let mut wanted = read_want(&mut ctl_rx, manifest.block_count())
        .await
        .map_err(wire_err)?;
    if let Some(l) = limit {
        wanted.truncate(l);
    }
    let total = wanted.len();

    let mut lanes: Vec<Vec<u32>> = vec![Vec::new(); streams as usize];
    for (i, idx) in wanted.into_iter().enumerate() {
        lanes[i % streams as usize].push(idx);
    }

    let mut tasks = Vec::new();
    for lane in lanes {
        let (mut tx, rx) = conn.open_stream().await?;
        let data = Arc::clone(data);
        let manifest = manifest.clone();
        tasks.push(tokio::spawn(async move {
            let _keep = rx;
            tx.write_all(&[STREAM_MAGIC]).await?;
            for idx in lane {
                let range = manifest
                    .block_range(idx as usize)
                    .ok_or_else(|| std::io::Error::other("bad block index"))?;
                write_block(&mut tx, idx, &data[range])
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            tx.shutdown().await?;
            Ok::<(), std::io::Error>(())
        }));
    }
    for t in tasks {
        t.await
            .map_err(|e| TransportError::Other(e.to_string()))??;
    }

    // Wait for the receiver's final ack so closing the connection cannot discard in-flight data.
    let mut ack = [0u8; 1];
    ctl_rx.read_exact(&mut ack).await?;
    Ok(total)
}

/// Receives a transfer. If `prior` holds verified blocks of the same manifest, they are kept and only
/// the missing blocks are requested (resume). Returns the resulting verified set.
pub async fn recv<C: Connection>(
    conn: &Arc<C>,
    prior: Option<VerifiedSet>,
) -> Result<VerifiedSet, TransportError> {
    let (mut ctl_tx, mut ctl_rx) = conn.accept_stream().await?;
    let (manifest, streams) = read_offer(&mut ctl_rx).await.map_err(wire_err)?;
    let set = match prior {
        Some(p) if p.manifest() == &manifest => p,
        _ => VerifiedSet::new(manifest.clone()),
    };
    write_want(&mut ctl_tx, &set.missing())
        .await
        .map_err(wire_err)?;

    let shared = Arc::new(Mutex::new(set));
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let (tx, mut rx) = conn.accept_stream().await?;
        let shared = Arc::clone(&shared);
        let max_len = manifest.block_size;
        tasks.push(tokio::spawn(async move {
            let _keep = tx;
            let mut magic = [0u8; 1];
            if rx.read_exact(&mut magic).await.is_err() || magic[0] != STREAM_MAGIC {
                return;
            }
            while let Ok(Some((idx, data))) = read_block(&mut rx, max_len).await {
                // Blocks failing verification are simply not recorded.
                let _ = shared.lock().unwrap().accept(idx as usize, &data);
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    ctl_tx.write_all(&[1]).await?;
    ctl_tx.flush().await?;

    let set = Arc::try_unwrap(shared)
        .map_err(|_| TransportError::Other("verified set still shared".into()))?
        .into_inner()
        .unwrap();
    Ok(set)
}
