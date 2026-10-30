// SPDX-License-Identifier: Apache-2.0
//! Minimal framing for the spike: offer, want-list and block frames.

use crate::manifest::Manifest;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// First byte of every data stream, so QUIC makes the stream visible to the peer.
pub const STREAM_MAGIC: u8 = 0xB1;
/// Upper bound on blocks per transfer accepted from the wire.
pub const MAX_BLOCKS: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid frame: {0}")]
    Invalid(&'static str),
}

pub async fn write_offer<W: AsyncWrite + Unpin>(
    w: &mut W,
    m: &Manifest,
    streams: u32,
) -> Result<(), WireError> {
    w.write_u64_le(m.size).await?;
    w.write_u32_le(m.block_size as u32).await?;
    w.write_u32_le(streams).await?;
    w.write_u32_le(m.hashes.len() as u32).await?;
    for h in &m.hashes {
        w.write_all(h).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_offer<R: AsyncRead + Unpin>(r: &mut R) -> Result<(Manifest, u32), WireError> {
    let size = r.read_u64_le().await?;
    let block_size = r.read_u32_le().await? as usize;
    let streams = r.read_u32_le().await?;
    let count = r.read_u32_le().await? as usize;
    if block_size == 0 || count > MAX_BLOCKS || streams == 0 || streams > 64 {
        return Err(WireError::Invalid("offer fields out of range"));
    }
    if (size as u128).div_ceil(block_size as u128) != count as u128 {
        return Err(WireError::Invalid("block count does not match size"));
    }
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut h = [0u8; 32];
        r.read_exact(&mut h).await?;
        hashes.push(h);
    }
    Ok((
        Manifest {
            size,
            block_size,
            hashes,
        },
        streams,
    ))
}

pub async fn write_want<W: AsyncWrite + Unpin>(
    w: &mut W,
    indices: &[u32],
) -> Result<(), WireError> {
    w.write_u32_le(indices.len() as u32).await?;
    for i in indices {
        w.write_u32_le(*i).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_want<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u32>, WireError> {
    let count = r.read_u32_le().await? as usize;
    if count > max {
        return Err(WireError::Invalid("want list too long"));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.read_u32_le().await?);
    }
    Ok(out)
}

pub async fn write_block<W: AsyncWrite + Unpin>(
    w: &mut W,
    index: u32,
    data: &[u8],
) -> Result<(), WireError> {
    w.write_u32_le(index).await?;
    w.write_u32_le(data.len() as u32).await?;
    w.write_all(data).await?;
    Ok(())
}

/// Reads one block frame. Returns `Ok(None)` when the stream ends at a frame boundary.
pub async fn read_block<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: usize,
) -> Result<Option<(u32, Vec<u8>)>, WireError> {
    let mut idx = [0u8; 4];
    match r.read_exact(&mut idx).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = r.read_u32_le().await? as usize;
    if len > max_len {
        return Err(WireError::Invalid("block frame too large"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(Some((u32::from_le_bytes(idx), data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::gen_bytes;
    use tokio::io::duplex;

    #[tokio::test]
    async fn offer_roundtrip() {
        let data = gen_bytes(3, 10);
        let m = Manifest::from_bytes(&data, 4);
        let (mut a, mut b) = duplex(1 << 16);
        write_offer(&mut a, &m, 3).await.unwrap();
        let (got, streams) = read_offer(&mut b).await.unwrap();
        assert_eq!(got, m);
        assert_eq!(streams, 3);
    }

    #[tokio::test]
    async fn offer_rejects_inconsistent_block_count() {
        let (mut a, mut b) = duplex(1 << 16);
        let bad = Manifest {
            size: 100,
            block_size: 4,
            hashes: vec![[0u8; 32]; 2],
        };
        write_offer(&mut a, &bad, 1).await.unwrap();
        assert!(matches!(
            read_offer(&mut b).await,
            Err(WireError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn offer_rejects_zero_block_size() {
        let (mut a, mut b) = duplex(1 << 16);
        let bad = Manifest {
            size: 0,
            block_size: 0,
            hashes: vec![],
        };
        write_offer(&mut a, &bad, 1).await.unwrap();
        assert!(matches!(
            read_offer(&mut b).await,
            Err(WireError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn want_roundtrip_and_limit() {
        let (mut a, mut b) = duplex(1 << 16);
        write_want(&mut a, &[1, 5, 9]).await.unwrap();
        assert_eq!(read_want(&mut b, 100).await.unwrap(), vec![1, 5, 9]);
        write_want(&mut a, &[1, 2, 3]).await.unwrap();
        assert!(matches!(
            read_want(&mut b, 2).await,
            Err(WireError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn block_roundtrip_then_clean_eof() {
        let (mut a, mut b) = duplex(1 << 16);
        write_block(&mut a, 7, b"hello").await.unwrap();
        drop(a);
        assert_eq!(
            read_block(&mut b, 1024).await.unwrap(),
            Some((7, b"hello".to_vec()))
        );
        assert_eq!(read_block(&mut b, 1024).await.unwrap(), None);
    }

    #[tokio::test]
    async fn block_rejects_oversized_frame() {
        let (mut a, mut b) = duplex(1 << 16);
        write_block(&mut a, 0, &[0u8; 100]).await.unwrap();
        assert!(matches!(
            read_block(&mut b, 10).await,
            Err(WireError::Invalid(_))
        ));
    }
}
