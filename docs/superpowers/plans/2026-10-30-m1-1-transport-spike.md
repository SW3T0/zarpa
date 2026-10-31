# M1.1 — Transport and Encoding Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decide, with measured data, which QUIC stack Zarpa builds on (`quinn` or `iroh`) and which wire encoding its control messages use, and record both as ADRs.

**Architecture:** A separate Cargo workspace under `spikes/` (excluded from the root workspace so root CI and `cargo-deny` stay unaffected). A shared `bench-core` crate defines a small `Transport` trait, a minimal block-transfer protocol and a conformance test suite. Two adapters (`adapter-quinn`, `adapter-iroh`) implement the trait and must pass the same suite; a `bench` binary measures throughput and encodings. ADR-0004 (encoding) and ADR-0005 (transport) are written by applying the decision rules below.

**Tech Stack:** Rust stable (1.99+), tokio, quinn + rustls + rcgen, iroh, blake3, ed25519-dalek, ciborium / postcard / rmp-serde, Python 3 (tiny helper scripts).

**Why adapter code is not pre-written here:** the QUIC crates' APIs change between releases and cannot be verified offline. The *contract* (trait, wire protocol, conformance tests, benchmarks) is fully specified below as code; each adapter task states exactly what must pass and records the crate versions and API facts it discovered. The tests are the specification.

---

## Decision rules (fixed BEFORE measuring)

**Transport (ADR-0005).** Apply in order:

1. **Eliminate** any candidate that fails a conformance test (`rejects_untrusted_peer`, `rejects_unknown_server`, `resume_after_drop`, `authenticated_roundtrip`, `transfer_verified`) after three documented fix attempts, or whose throughput (loopback, 1 GiB, 4 streams, median of 3) is below **100 MiB/s**.
2. If both survive, **prefer `iroh`** only if ALL hold: its throughput is within 20 % of the best candidate; local-network discovery works with no relay and no internet (Task 9); every license in its dependency tree is permissive (MIT, Apache-2.0, BSD, ISC, Unicode, Zlib, CC0, MPL-2.0 file-level only) — list any additions to `deny.toml`. Otherwise choose `quinn`.
3. The ADR must state the consequence that matters most to the project: with `iroh`, the public protocol rides on iroh's QUIC conventions (third-party clients need a compatible stack); with `quinn`, Zarpa must build discovery, NAT traversal and relays itself in Phase 2.
4. The ADR is written with `Status: proposed`; the project owner decides and may override the rule.

**Encoding (ADR-0004).** Third-party interoperability dominates (spec goal: others can write compatible clients). Choose **CBOR** (RFC 8949) unless encode+decode of the 256-hash manifest takes more than **1 ms** on the dev machine, or CBOR's encoded size exceeds postcard's by more than **10 %** for that manifest. If so, choose the best of MessagePack/postcard and say why.

---

## File structure (created by this plan)

| Path | Responsibility |
|---|---|
| `Cargo.toml` (modify) | Exclude `spikes/` from the root workspace |
| `.gitignore` (modify) | Ignore `target/` in any directory |
| `spikes/Cargo.toml` | Spike workspace |
| `spikes/README.md` | What the spike is, how to run it |
| `spikes/bench-core/` | `block`, `manifest`, `wire`, `transport`, `transfer`, `conformance` modules |
| `spikes/adapter-quinn/` | `QuinnTransport` + conformance test + discovery example |
| `spikes/adapter-iroh/` | `IrohTransport` + conformance test + discovery example |
| `spikes/bench/` | Throughput and encoding benchmarks |
| `docs/spikes/2026-m1-1-results.md` | Measured results |
| `docs/adr/0004-message-encoding.md`, `docs/adr/0005-transport-stack.md` | Decisions |
| `docs/protocol/README.md` (modify) | Point to ADR-0004 as accepted/proposed |

**Conventions for every task:** Git Bash on Windows, repo root `/c/Users/ernes/Dev/zarpa`. Rust commands: `export PATH="$HOME/.cargo/bin:$PATH"`. **Run `cargo` from PowerShell, not Git Bash** (Git's `link` shadows MSVC `link.exe` and linking fails there): `$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"` then `Set-Location C:\Users\ernes\Dev\zarpa\spikes`. Commit with `git commit -s`, Conventional Commits, ending with the harness `Co-Authored-By` trailer. Work on branch `spike/m1-1-transport`. Never push except in Task 12 and never merge without the user's approval (`main` is protected; changes land through PRs).

---

### Task 0: Branch and baseline

**Files:** none

- [ ] **Step 1: Branch from up-to-date main**

Run: `cd /c/Users/ernes/Dev/zarpa && git checkout main && git pull && git checkout -b spike/m1-1-transport && git branch --show-current`
Expected: `spike/m1-1-transport`

- [ ] **Step 2: Record the toolchain**

Run (PowerShell): `rustc --version; cargo --version`
Expected: `rustc 1.99.x` or newer. Save the output; it goes into the results doc.

---

### Task 1: Spike workspace skeleton

**Files:**
- Modify: `Cargo.toml`, `.gitignore`
- Create: `spikes/Cargo.toml`, `spikes/README.md`, `spikes/bench-core/Cargo.toml`, `spikes/bench-core/src/lib.rs`

- [ ] **Step 1: Exclude the spikes from the root workspace**

In `Cargo.toml`, change the `[workspace]` table so it reads:
```toml
[workspace]
resolver = "2"
members = ["core"]
exclude = ["spikes"]
```

- [ ] **Step 2: Make `.gitignore` ignore `target/` everywhere**

Replace the line `/target/` with `target/`.

- [ ] **Step 3: Write `spikes/Cargo.toml`**

Only `bench-core` exists yet; the other members are added in their own tasks.
```toml
[workspace]
resolver = "2"
members = ["bench-core"]

[workspace.package]
version = "0.0.0"
edition = "2021"
license = "Apache-2.0"
publish = false
```

- [ ] **Step 4: Write `spikes/bench-core/Cargo.toml`**

```toml
[package]
name = "bench-core"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
blake3 = "1"
ed25519-dalek = "2"
thiserror = "2"
tokio = { version = "1", features = ["io-util", "rt-multi-thread", "macros", "sync", "time"] }

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
```

- [ ] **Step 5: Write `spikes/bench-core/src/lib.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0
//! Shared building blocks for the M1.1 transport spike.
```

- [ ] **Step 6: Write `spikes/README.md`**

```markdown
# Spikes

Throwaway-but-kept experiments that inform architecture decisions. Not part of the root workspace and not
built by CI.

## M1.1 — transport and encoding

Compares `quinn` and `iroh` behind one `Transport` trait and compares control-message encodings.
Results: `docs/spikes/2026-m1-1-results.md`. Decisions: ADR-0004 and ADR-0005.

Run from PowerShell (Windows) or any shell (Linux/macOS), inside `spikes/`:

    cargo test --workspace
    cargo run -p bench --release -- --mib 1024
    cargo run -p bench --release -- --encoding
```

- [ ] **Step 7: Verify and commit**

Run (PowerShell, in `spikes`): `cargo check --workspace` then (in repo root) `cargo check --workspace`
Expected: both succeed; the root check must not mention `bench-core`.

```bash
git add Cargo.toml .gitignore spikes
git commit -s -m "chore(spikes): add M1.1 spike workspace"
```

---

### Task 2: Blocks, manifest and verified set (TDD)

**Files:**
- Create: `spikes/bench-core/src/block.rs`, `spikes/bench-core/src/manifest.rs`
- Modify: `spikes/bench-core/src/lib.rs`

- [ ] **Step 1: Declare modules**

Append to `lib.rs`:
```rust
pub mod block;
pub mod manifest;
```

- [ ] **Step 2: Write failing tests first**

`block.rs` (tests only for now):
```rust
// SPDX-License-Identifier: Apache-2.0
//! Block size, hashing and deterministic test payloads.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_bytes_is_deterministic_and_exact_length() {
        let a = gen_bytes(7, 1000);
        let b = gen_bytes(7, 1000);
        assert_eq!(a, b);
        assert_eq!(a.len(), 1000);
    }

    #[test]
    fn gen_bytes_differs_by_seed() {
        assert_ne!(gen_bytes(1, 64), gen_bytes(2, 64));
    }

    #[test]
    fn gen_bytes_zero_seed_is_valid() {
        assert_eq!(gen_bytes(0, 16).len(), 16);
        assert_ne!(gen_bytes(0, 16), vec![0u8; 16]);
    }

    #[test]
    fn hash_block_differs_for_different_data() {
        assert_ne!(hash_block(b"a"), hash_block(b"b"));
    }
}
```

`manifest.rs` (tests only for now):
```rust
// SPDX-License-Identifier: Apache-2.0
//! Transfer manifest and the receiver-side set of verified blocks.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::gen_bytes;

    #[test]
    fn manifest_counts_blocks_and_ranges() {
        let m = Manifest::from_bytes(&gen_bytes(1, 10), 4);
        assert_eq!(m.block_count(), 3);
        assert_eq!(m.block_range(0), Some(0..4));
        assert_eq!(m.block_range(2), Some(8..10));
        assert_eq!(m.block_range(3), None);
    }

    #[test]
    fn verified_set_accepts_good_block_and_rejects_bad() {
        let data = gen_bytes(2, 8);
        let mut set = VerifiedSet::new(Manifest::from_bytes(&data, 4));
        assert_eq!(set.missing(), vec![0, 1]);
        assert_eq!(set.accept(0, &data[0..4]), Ok(()));
        assert_eq!(set.accept(1, b"nope"), Err(BlockError::HashMismatch));
        assert_eq!(set.accept(9, &data[0..4]), Err(BlockError::OutOfRange));
        assert_eq!(set.missing(), vec![1]);
        assert_eq!(set.verified_count(), 1);
        assert!(!set.is_complete());
        assert_eq!(set.accept(1, &data[4..8]), Ok(()));
        assert!(set.is_complete());
    }

    #[test]
    fn empty_file_is_complete_with_zero_blocks() {
        let set = VerifiedSet::new(Manifest::from_bytes(&[], 4));
        assert_eq!(set.manifest().block_count(), 0);
        assert!(set.is_complete());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run (PowerShell, in `spikes`): `cargo test -p bench-core 2>&1 | Select-Object -Last 12`
Expected: compile errors such as "cannot find function `gen_bytes`" and "cannot find type `Manifest`".

- [ ] **Step 4: Implement `block.rs`** (insert above the `#[cfg(test)]` block)

```rust
/// Block size used by the spike (4 MiB), as in `docs/protocol/README.md`.
pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Deterministic pseudo-random bytes (xorshift64*), so tests and benchmarks need no files.
pub fn gen_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// BLAKE3 hash of one block.
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}
```

- [ ] **Step 5: Implement `manifest.rs`** (insert above the `#[cfg(test)]` block)

```rust
use crate::block::hash_block;
use std::ops::Range;

/// Describes a file as a list of fixed-size blocks and their BLAKE3 hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub size: u64,
    pub block_size: usize,
    pub hashes: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn from_bytes(data: &[u8], block_size: usize) -> Self {
        assert!(block_size > 0, "block_size must be positive");
        Self {
            size: data.len() as u64,
            block_size,
            hashes: data.chunks(block_size).map(hash_block).collect(),
        }
    }

    pub fn block_count(&self) -> usize {
        self.hashes.len()
    }

    /// Byte range of block `index` inside the file, or `None` if out of range.
    pub fn block_range(&self, index: usize) -> Option<Range<usize>> {
        if index >= self.hashes.len() {
            return None;
        }
        let start = index * self.block_size;
        let end = (start + self.block_size).min(self.size as usize);
        Some(start..end)
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("block index out of range")]
    OutOfRange,
    #[error("block hash mismatch")]
    HashMismatch,
}

/// Receiver-side record of which blocks have been received AND verified.
#[derive(Debug, Clone)]
pub struct VerifiedSet {
    manifest: Manifest,
    have: Vec<bool>,
}

impl VerifiedSet {
    pub fn new(manifest: Manifest) -> Self {
        let n = manifest.block_count();
        Self { manifest, have: vec![false; n] }
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Verifies `data` against the manifest hash and marks the block as present.
    pub fn accept(&mut self, index: usize, data: &[u8]) -> Result<(), BlockError> {
        let expected = self.manifest.hashes.get(index).ok_or(BlockError::OutOfRange)?;
        if hash_block(data) != *expected {
            return Err(BlockError::HashMismatch);
        }
        self.have[index] = true;
        Ok(())
    }

    /// Indices of blocks not yet verified.
    pub fn missing(&self) -> Vec<u32> {
        self.have
            .iter()
            .enumerate()
            .filter(|(_, h)| !**h)
            .map(|(i, _)| i as u32)
            .collect()
    }

    pub fn verified_count(&self) -> usize {
        self.have.iter().filter(|h| **h).count()
    }

    pub fn is_complete(&self) -> bool {
        self.have.iter().all(|h| *h)
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p bench-core 2>&1 | Select-String "test result|FAILED|error"`
Expected: `test result: ok. 7 passed`

- [ ] **Step 7: Commit**

```bash
git add spikes/bench-core
git commit -s -m "feat(spikes): add block hashing, manifest and verified set"
```

---

### Task 3: Spike wire format (TDD)

**Files:**
- Create: `spikes/bench-core/src/wire.rs`
- Modify: `spikes/bench-core/src/lib.rs`

This is a deliberately trivial binary framing used only to measure *transport*; it is not the product encoding (that is decided in Task 9).

- [ ] **Step 1: Declare module**

Append to `lib.rs`: `pub mod wire;`

- [ ] **Step 2: Write failing tests**

`wire.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
//! Minimal framing for the spike: offer, want-list and block frames.

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
        let bad = Manifest { size: 100, block_size: 4, hashes: vec![[0u8; 32]; 2] };
        write_offer(&mut a, &bad, 1).await.unwrap();
        assert!(matches!(read_offer(&mut b).await, Err(WireError::Invalid(_))));
    }

    #[tokio::test]
    async fn offer_rejects_zero_block_size() {
        let (mut a, mut b) = duplex(1 << 16);
        let bad = Manifest { size: 0, block_size: 0, hashes: vec![] };
        write_offer(&mut a, &bad, 1).await.unwrap();
        assert!(matches!(read_offer(&mut b).await, Err(WireError::Invalid(_))));
    }

    #[tokio::test]
    async fn want_roundtrip_and_limit() {
        let (mut a, mut b) = duplex(1 << 16);
        write_want(&mut a, &[1, 5, 9]).await.unwrap();
        assert_eq!(read_want(&mut b, 100).await.unwrap(), vec![1, 5, 9]);
        write_want(&mut a, &[1, 2, 3]).await.unwrap();
        assert!(matches!(read_want(&mut b, 2).await, Err(WireError::Invalid(_))));
    }

    #[tokio::test]
    async fn block_roundtrip_then_clean_eof() {
        let (mut a, mut b) = duplex(1 << 16);
        write_block(&mut a, 7, b"hello").await.unwrap();
        drop(a);
        assert_eq!(read_block(&mut b, 1024).await.unwrap(), Some((7, b"hello".to_vec())));
        assert_eq!(read_block(&mut b, 1024).await.unwrap(), None);
    }

    #[tokio::test]
    async fn block_rejects_oversized_frame() {
        let (mut a, mut b) = duplex(1 << 16);
        write_block(&mut a, 0, &[0u8; 100]).await.unwrap();
        assert!(matches!(read_block(&mut b, 10).await, Err(WireError::Invalid(_))));
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p bench-core wire 2>&1 | Select-Object -Last 8`
Expected: compile errors ("cannot find function `write_offer`", etc.).

- [ ] **Step 4: Implement** (insert above `#[cfg(test)]` in `wire.rs`)

```rust
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
    Ok((Manifest { size, block_size, hashes }, streams))
}

pub async fn write_want<W: AsyncWrite + Unpin>(w: &mut W, indices: &[u32]) -> Result<(), WireError> {
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
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p bench-core 2>&1 | Select-String "test result|FAILED|error"`
Expected: `test result: ok. 13 passed`

- [ ] **Step 6: Commit**

```bash
git add spikes/bench-core
git commit -s -m "feat(spikes): add spike wire framing"
```

---

### Task 4: Transport trait and key helpers (TDD)

**Files:**
- Create: `spikes/bench-core/src/transport.rs`
- Modify: `spikes/bench-core/src/lib.rs`

- [ ] **Step 1: Declare module and write failing test**

Append to `lib.rs`: `pub mod transport;`

`transport.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
//! The abstraction both QUIC stacks must implement.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_is_deterministic_and_distinct() {
        assert_eq!(public_key(&test_secret(1)), public_key(&test_secret(1)));
        assert_ne!(public_key(&test_secret(1)), public_key(&test_secret(2)));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p bench-core transport 2>&1 | Select-Object -Last 6`
Expected: compile error "cannot find function `public_key`".

- [ ] **Step 3: Implement** (above the test module)

```rust
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
    PeerKey(ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().to_bytes())
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

    fn connect(&self, to: &PeerAddr) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}

/// An established, mutually authenticated connection with bidirectional streams.
///
/// Note for implementers: QUIC makes a stream visible to the peer only once data is written on it.
pub trait Connection: Send + Sync + 'static {
    type Send: AsyncWrite + Unpin + Send + 'static;
    type Recv: AsyncRead + Unpin + Send + 'static;

    fn remote_key(&self) -> PeerKey;

    fn open_stream(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), TransportError>> + Send;

    fn accept_stream(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), TransportError>> + Send;

    /// Closes the connection immediately (used to simulate a dropped link).
    fn close(&self);
}
```
- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p bench-core 2>&1 | Select-String "test result|FAILED|error"`
Expected: `test result: ok. 14 passed`

- [ ] **Step 5: Commit**

```bash
git add spikes/bench-core
git commit -s -m "feat(spikes): add Transport trait and key helpers"
```

---

### Task 5: Transfer logic and conformance suite

**Files:**
- Create: `spikes/bench-core/src/transfer.rs`, `spikes/bench-core/src/conformance.rs`
- Modify: `spikes/bench-core/src/lib.rs`

The conformance suite is the contract for both adapters. It cannot be exercised until an adapter exists, so this task only requires that it **compiles**; Tasks 6 and 7 run it.

- [ ] **Step 1: Declare modules**

Append to `lib.rs`:
```rust
pub mod conformance;
pub mod transfer;
```

- [ ] **Step 2: Write `transfer.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0
//! Offer -> want-list -> parallel block streams, over any `Connection`.

use crate::manifest::{Manifest, VerifiedSet};
use crate::transport::{Connection, TransportError};
use crate::wire::{
    read_block, read_offer, read_want, write_block, write_offer, write_want, WireError, STREAM_MAGIC,
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
    write_offer(&mut ctl_tx, manifest, streams).await.map_err(wire_err)?;
    let mut wanted = read_want(&mut ctl_rx, manifest.block_count()).await.map_err(wire_err)?;
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
        t.await.map_err(|e| TransportError::Other(e.to_string()))??;
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
    write_want(&mut ctl_tx, &set.missing()).await.map_err(wire_err)?;

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
```

- [ ] **Step 3: Write `conformance.rs`**

```rust
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
```

- [ ] **Step 4: Verify it compiles, fix only genuine compile errors**

Run: `cargo test -p bench-core 2>&1 | Select-String "test result|FAILED|error"`
Expected: `test result: ok. 14 passed` (no new tests run here). If rustc rejects the code, make the smallest fix that keeps the same behaviour and list each fix in the commit body.

- [ ] **Step 5: Commit**

```bash
git add spikes/bench-core
git commit -s -m "feat(spikes): add transfer logic and conformance suite"
```

---

### Task 6: `quinn` adapter

**Files:**
- Create: `spikes/adapter-quinn/Cargo.toml`, `spikes/adapter-quinn/src/lib.rs`, `spikes/adapter-quinn/tests/conformance.rs`
- Modify: `spikes/Cargo.toml` (add `"adapter-quinn"` to `members`)

- [ ] **Step 1: Crate manifest and failing conformance test**

`spikes/adapter-quinn/Cargo.toml`:
```toml
[package]
name = "adapter-quinn"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
bench-core = { path = "../bench-core" }
tokio = { version = "1", features = ["full"] }

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
```
Then add the real dependencies with `cargo add -p adapter-quinn quinn rustls rcgen x509-parser` (PowerShell, in `spikes`). Pick the rustls crypto provider that compiles on Windows without extra system tools (prefer `ring`); record the exact choice.

`spikes/adapter-quinn/tests/conformance.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
bench_core::conformance_tests!(adapter_quinn::QuinnTransport);
```
`spikes/adapter-quinn/src/lib.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
//! `Transport` over plain `quinn` + `rustls` with Ed25519 identity certificates.
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p adapter-quinn 2>&1 | Select-Object -Last 8`
Expected: compile error "cannot find type `QuinnTransport` in crate `adapter_quinn`".

- [ ] **Step 3: API reconnaissance (record what you find)**

Read the current docs on docs.rs for `quinn`, `rustls` (custom `ServerCertVerifier` / `ClientCertVerifier`), `rcgen` and `x509-parser`. Write a short `spikes/adapter-quinn/NOTES.md` with: exact crate versions from `Cargo.lock`, the crypto provider used, and any API facts that were non-obvious. This file feeds the results doc.

- [ ] **Step 4: Implement `QuinnTransport`** so that all five conformance tests pass

Requirements (the tests are the contract):
- Identity: build a self-signed certificate whose key is the Ed25519 key derived from the 32-byte seed. A PKCS#8 v1 Ed25519 private key is the 16 bytes `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20` followed by the 32-byte seed; feed that to `rcgen::KeyPair`.
- Authentication: both directions require certificates (mutual TLS). Implement custom rustls verifiers that (a) extract the 32-byte Ed25519 public key from the presented certificate's SubjectPublicKeyInfo, (b) accept only if it is in `trusted` and, on the client, equals `to.key`, and (c) still verify the TLS 1.3 handshake signature with the provider's signature verification algorithms (do NOT skip signature verification). No certificate authorities.
- `Connection::remote_key` is the key extracted from the verified peer certificate.
- `bind` listens on `127.0.0.1:0` (loopback, no relay, no internet); `addr()` reports the bound socket address.
- `accept` loops: connections that fail the handshake are dropped and accept keeps waiting; it never returns a `Conn` for an untrusted peer.
- Streams: map `open_stream`/`accept_stream` to quinn bidirectional streams; `close` calls `Connection::close`.
- ALPN: `b"zarpa-spike/0"`.

- [ ] **Step 5: Run the suite until it passes**

Run: `cargo test -p adapter-quinn 2>&1 | Select-String "test |test result"`
Expected: five lines `test conformance_suite::<name> ... ok` and `test result: ok. 5 passed`.
If a test still fails after three documented attempts, do NOT mark it `#[ignore]` and do NOT weaken the test. Leave it failing, record the attempts in `NOTES.md`, and report DONE_WITH_CONCERNS (decision rule 1 then applies).

- [ ] **Step 6: Commit**

```bash
git add spikes
git commit -s -m "feat(spikes): add quinn transport adapter"
```

---

### Task 7: `iroh` adapter

**Files:**
- Create: `spikes/adapter-iroh/Cargo.toml`, `spikes/adapter-iroh/src/lib.rs`, `spikes/adapter-iroh/tests/conformance.rs`, `spikes/adapter-iroh/NOTES.md`
- Modify: `spikes/Cargo.toml` (add `"adapter-iroh"` to `members`)

- [ ] **Step 1: Crate manifest and failing conformance test**

`spikes/adapter-iroh/Cargo.toml`: same shape as the quinn adapter (name `adapter-iroh`), then `cargo add -p adapter-iroh iroh`.

`spikes/adapter-iroh/tests/conformance.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
bench_core::conformance_tests!(adapter_iroh::IrohTransport);
```
`spikes/adapter-iroh/src/lib.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
//! `Transport` over `iroh` endpoints.
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p adapter-iroh 2>&1 | Select-Object -Last 8`
Expected: compile error "cannot find type `IrohTransport` in crate `adapter_iroh`".

- [ ] **Step 3: API reconnaissance (record what you find)**

Read the current iroh docs (docs.rs and the project's examples) for: building an endpoint from a secret key, setting ALPNs, **disabling relay and any online discovery/DNS publishing for these tests**, getting the endpoint's direct addresses, dialing by key plus direct addresses, accepting connections, and reading the authenticated remote key from a connection. Write `NOTES.md` with exact versions, the feature flags enabled, and non-obvious facts.

- [ ] **Step 4: Implement `IrohTransport`** so that all five conformance tests pass

Requirements:
- The Ed25519 seed becomes the iroh secret key; `bind` uses loopback/LAN only, no relay, no network discovery services, no internet access.
- `addr()` reports the endpoint's own key and its bound direct socket addresses.
- Trust: iroh authenticates the remote key during the handshake; the adapter must enforce the trust list at the application level. `accept` loops: after accepting a connection, if the authenticated remote key is not in `trusted`, close it and keep waiting; it never returns a `Conn` for an untrusted peer. `connect` verifies the authenticated remote key equals `to.key` and is in `trusted`, else closes and returns `TransportError::UntrustedPeer`.
- Streams: map `open_stream`/`accept_stream` to the connection's bidirectional streams; `close` closes the connection.
- ALPN: `b"zarpa-spike/0"`.

- [ ] **Step 5: Run the suite until it passes**

Run: `cargo test -p adapter-iroh 2>&1 | Select-String "test |test result"`
Expected: `test result: ok. 5 passed`. Same failure policy as Task 6 Step 5.

- [ ] **Step 6: Commit**

```bash
git add spikes
git commit -s -m "feat(spikes): add iroh transport adapter"
```

---

### Task 8: Throughput benchmark

**Files:**
- Create: `spikes/bench/Cargo.toml`, `spikes/bench/src/main.rs`
- Modify: `spikes/Cargo.toml` (add `"bench"` to `members`)

- [ ] **Step 1: Manifest**

`spikes/bench/Cargo.toml`:
```toml
[package]
name = "bench"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
bench-core = { path = "../bench-core" }
adapter-quinn = { path = "../adapter-quinn" }
adapter-iroh = { path = "../adapter-iroh" }
tokio = { version = "1", features = ["full"] }
```
(Task 9 adds the encoding dependencies.)

- [ ] **Step 2: Write `main.rs`**

```rust
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
```
Each adapter's `Transport::name()` must return `"quinn"` and `"iroh"` respectively (add this to the adapters if not already done).

- [ ] **Step 3: Build and smoke-run small**

Run: `cargo run -p bench --release -- --mib 64 2>&1 | Select-Object -Last 8`
Expected: a markdown table with four rows (quinn/iroh x 1/4 streams) and positive MiB/s values.

- [ ] **Step 4: Full run, saved**

Run: `cargo run -p bench --release -- --mib 1024 2>&1 | Tee-Object -FilePath ..\bench-throughput.md`
Expected: the table with 1024 MiB rows. Keep `bench-throughput.md` uncommitted at the repo root; its content is pasted into the results doc in Task 10.

- [ ] **Step 5: Commit**

```bash
git add spikes
git commit -s -m "feat(spikes): add throughput benchmark"
```

---

### Task 9: Encoding, discovery, dependency and mobile data

**Files:**
- Create: `spikes/bench/src/encoding.rs`, `spikes/adapter-quinn/examples/discover.rs`, `spikes/adapter-iroh/examples/discover.rs`
- Modify: `spikes/bench/Cargo.toml`, `spikes/bench/src/main.rs`

#### 9a. Encoding comparison

- [ ] **Step 1: Add dependencies**

Run (PowerShell, in `spikes`): `cargo add -p bench serde --features derive; cargo add -p bench serde_bytes ciborium postcard rmp-serde`
Expected: `postcard` may need the `use-std` feature to serialize to `Vec`; enable it if `to_allocvec` is missing.

- [ ] **Step 2: Write `encoding.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0
//! Compares candidate encodings on realistic control messages.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::time::Instant;

/// 256 blocks of 4 MiB = a 1 GiB file. Hashes are one concatenated byte string.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WireManifest {
    pub size: u64,
    pub block_size: u32,
    pub hashes: ByteBuf,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Control {
    Want { indices: Vec<u32> },
    Ack,
    Error { code: String, message: String },
}

fn manifest() -> WireManifest {
    WireManifest { size: 1 << 30, block_size: 4 << 20, hashes: ByteBuf::from(vec![0xAB; 32 * 256]) }
}

fn control() -> Control {
    Control::Want { indices: (0..64).collect() }
}

fn measure<T, E, D>(name: &str, label: &str, value: &T, enc: E, dec: D)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    E: Fn(&T) -> Vec<u8>,
    D: Fn(&[u8]) -> T,
{
    const N: u32 = 5_000;
    let bytes = enc(value);
    assert_eq!(&dec(&bytes), value, "{name} roundtrip failed");
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(enc(value));
    }
    let enc_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(dec(&bytes));
    }
    let dec_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    println!("| {label} | {name} | {} | {enc_us:.2} | {dec_us:.2} |", bytes.len());
}

fn run_for<T>(label: &str, value: T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    measure(
        "CBOR (ciborium)",
        label,
        &value,
        |v| {
            let mut out = Vec::new();
            ciborium::into_writer(v, &mut out).unwrap();
            out
        },
        |b| ciborium::from_reader(b).unwrap(),
    );
    measure(
        "postcard",
        label,
        &value,
        |v| postcard::to_allocvec(v).unwrap(),
        |b| postcard::from_bytes(b).unwrap(),
    );
    measure(
        "MessagePack (rmp-serde)",
        label,
        &value,
        |v| rmp_serde::to_vec_named(v).unwrap(),
        |b| rmp_serde::from_slice(b).unwrap(),
    );
}

pub fn run() {
    println!("| message | encoding | bytes | encode µs | decode µs |");
    println!("|---|---|---|---|---|");
    run_for("manifest (256 blocks)", manifest());
    run_for("want list (64 indices)", control());
}
```
- [ ] **Step 3: Wire the subcommand**

In `main.rs` add `mod encoding;` at the top and, at the start of `main` after parsing `args`:
```rust
    if args.iter().any(|a| a == "--encoding") {
        encoding::run();
        return;
    }
```

- [ ] **Step 4: Run and save**

Run: `cargo run -p bench --release -- --encoding 2>&1 | Tee-Object -FilePath ..\bench-encoding.md`
Expected: a table with 6 rows (2 messages x 3 encodings), no panics. Keep the file uncommitted for Task 10.

#### 9b. Local-network discovery smoke test (no relay, no internet)

- [ ] **Step 5: Write `examples/discover.rs` for each adapter**

Each example: starts a transport that advertises itself on the local network using that stack's own mechanism (for iroh: its local-network discovery; for quinn: the `mdns-sd` crate, added with `cargo add -p adapter-quinn mdns-sd`), listens for other instances for 8 seconds, and prints one line `FOUND <hex public key>` per distinct peer seen, then `DONE`. Document in the example's header comment how to run it. Use secret `test_secret(n)` with `n` taken from the first CLI argument so two instances get different identities.

- [ ] **Step 6: Run two instances at once per adapter**

Run (two PowerShell windows, within 5 s of each other), for each adapter: `cargo run -p adapter-quinn --example discover -- 1` and `cargo run -p adapter-quinn --example discover -- 2`; same for `adapter-iroh`.
Expected: each instance prints `FOUND` with the other's key. If discovery does not work on loopback/multicast of this machine, record exactly what happened; do not fake the result. A two-device LAN test is optional and manual; note whether it was done.

#### 9c. Dependency weight and licenses

- [ ] **Step 7: Collect numbers for each adapter**

Run (PowerShell, in `spikes`), once for `adapter-quinn` and once for `adapter-iroh`:
```powershell
cargo tree -p adapter-quinn -e normal --prefix none | Sort-Object -Unique | Measure-Object -Line
cargo tree -p adapter-quinn -e normal --prefix none --format "{l}" | Sort-Object | Group-Object | Sort-Object Count -Descending | Select-Object Count, Name
```
Expected: the number of unique crates and a license histogram. Record both in the results doc. Also record the release size of the bench binary: `(Get-Item target\release\bench.exe).Length`.

#### 9d. Mobile feasibility (informational)

- [ ] **Step 8: Attempt an Android check**

Run: `rustup target add aarch64-linux-android; cargo check -p adapter-quinn --target aarch64-linux-android 2>&1 | Select-Object -Last 8` and the same for `adapter-iroh`.
Expected: success, or a build-script error needing the Android NDK. Either is valid data. Do not install the NDK. Record the outcome (iOS cannot be checked on Windows).

- [ ] **Step 9: Commit**

```bash
git add spikes
git commit -s -m "feat(spikes): add encoding benchmark and discovery examples"
```

---

### Task 10: Results document

**Files:**
- Create: `docs/spikes/2026-m1-1-results.md`

- [ ] **Step 1: Write the results from the measured data**

Create `docs/spikes/2026-m1-1-results.md` with these sections, filled only with numbers and observations actually produced in Tasks 6-9 (no estimates, no invented values):

1. **Environment:** OS, CPU model, RAM, `rustc --version`, date.
2. **Versions:** exact `quinn`, `rustls`, `iroh` versions from `Cargo.lock`, and the rustls crypto provider.
3. **Conformance:** a table of the five tests per adapter (pass/fail) plus the failure notes if any.
4. **Throughput:** paste `bench-throughput.md`.
5. **Encoding:** paste `bench-encoding.md`.
6. **Discovery:** what happened per adapter, including whether a two-device test was done.
7. **Dependencies:** unique crate count, license histogram and binary size per adapter, and any licenses not currently allowed by `deny.toml`.
8. **Mobile:** the Android check outcome per adapter.
9. **Caveats:** loopback is not a real LAN; numbers are from one machine; iOS not checked.

- [ ] **Step 2: Delete the temporary files and commit**

```bash
rm -f bench-throughput.md bench-encoding.md
git add docs/spikes
git commit -s -m "docs(spikes): record M1.1 transport and encoding results"
```

---

### Task 11: ADRs

**Files:**
- Create: `docs/adr/0004-message-encoding.md`, `docs/adr/0005-transport-stack.md`
- Modify: `docs/protocol/README.md`

- [ ] **Step 1: Apply the decision rules mechanically**

Using ONLY `docs/spikes/2026-m1-1-results.md`, evaluate the "Decision rules" at the top of this plan, writing down for each rule whether it passed with the number that proves it.

- [ ] **Step 2: Write `docs/adr/0004-message-encoding.md`**

Structure (same style as ADR-0001..0003): `# 4. <Decision title naming the chosen encoding>`, `- Status: proposed`, `- Date: <today>`, then `## Context` (why an encoding is needed, interoperability goal), `## Decision` (the chosen encoding and the rule-application evidence with the measured numbers), `## Consequences` (what it costs, what it enables, how to change it later), and `## Alternatives considered` (the other two, with their numbers).

- [ ] **Step 3: Write `docs/adr/0005-transport-stack.md`**

Same structure. The Decision section must show, for each of the four rules, the evidence. The Consequences section must state the point in rule 3 explicitly (protocol dependence on iroh vs Phase 2 effort with quinn) and list any `deny.toml` license additions the chosen stack needs.

- [ ] **Step 4: Update the protocol draft**

In `docs/protocol/README.md`, replace the sentence "Message encoding is selected by ADR-0004 during milestone M1; this draft therefore specifies messages semantically (fields and meaning), not byte layouts." with: "Message encoding is defined by ADR-0004 (status: proposed); this draft specifies messages semantically (fields and meaning), not byte layouts."

- [ ] **Step 5: Verify no unfinished markers and commit**

Run: `grep -nE "TBD|TODO|FIXME|XXX" docs/adr/0004-message-encoding.md docs/adr/0005-transport-stack.md docs/spikes/2026-m1-1-results.md || echo CLEAN`
Expected: `CLEAN`

```bash
git add docs
git commit -s -m "docs(adr): propose message encoding and transport stack"
```

---

### Task 12: Verify gates and open the PR (outward-facing — requires user confirmation)

**Files:** none

- [ ] **Step 1: Root gates still pass**

Run (PowerShell, repo root): `cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace`
Expected: all succeed; none of them builds `spikes/`.

- [ ] **Step 2: Spike gates**

Run (in `spikes`): `cargo fmt --all; cargo test --workspace 2>&1 | Select-String "test result|FAILED"`
Expected: all test suites report `ok` (any contract-test failure must already be documented in the ADR).

- [ ] **Step 3: Ask the user**

Show the user the two ADR decisions and the evidence tables. Ask for explicit approval to push the branch and open a PR. Do not push on silence or on a notification.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin spike/m1-1-transport
gh pr create --base main --title "feat(spikes): M1.1 transport and encoding spike" --body "Compares quinn and iroh behind one Transport trait and compares CBOR, postcard and MessagePack for control messages. Adds results and proposes ADR-0004 (encoding) and ADR-0005 (transport).

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```
Expected: a PR URL. All required checks must pass; merge only after the user approves the ADR decisions (change `Status: proposed` to `accepted` in a follow-up commit on the same branch first).

---

## Self-review (spec coverage)

| Spec requirement | Task |
|---|---|
| §14: choose `quinn` or `iroh` via a spike meeting LAN throughput and resume tests | 5-8, 11 |
| §14/protocol draft: encoding chosen in M1 via ADR-0004 | 9a, 11 |
| §7: BLAKE3 blocks, parallel streams, verified blocks, resume | 2, 3, 5 |
| §5/§12: mutual key-based authentication, no certificate authorities, untrusted peers rejected | 4, 5 (`rejects_*`), 6, 7 |
| §6: discovery works without relay/internet | 9b |
| §4.2: transport behind a trait | 4 |
| §2/§16: mobile feasibility risk | 9d |
| AGENTS.md: ADRs for decisions, signed Conventional Commits, PRs to protected `main`, no unrelated CI impact | 1 (root exclusion), 11, 12 |
| Out of scope here (later M1.x plans): persistent identity store, pairing, the real `zarpad` daemon, local API, CLI | — |
