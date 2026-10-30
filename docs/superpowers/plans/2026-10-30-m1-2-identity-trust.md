# M1.2 Device Identity and Trust Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `zarpa-core` a persistent device identity (Ed25519 key, device ID = public key), a pluggable secret store, and a persistent list of trusted (paired) devices.

**Architecture:** Three small, independent units in `core/`: `identity` (key pair, `DeviceId`), `secret_store` (a `SecretStore` trait with in-memory and owner-only-file implementations, plus an optional OS-keyring implementation behind a Cargo feature), and `trust` (a JSON-file-backed `TrustStore` with atomic writes). Nothing here touches the network: M1.3 (discovery) and M1.4 (pairing) consume these types, and the iroh transport adapter (M1.6) takes `Identity::secret()` and `TrustStore::ids()`.

**Tech Stack:** Rust 2021, `ed25519-dalek` 2, `rand_core` 0.6, `serde` + `serde_json`, `thiserror` 2, `zeroize`, `tempfile` (dev), `keyring` 3 (optional feature).

**Environment notes (Windows host):** run `cargo` from PowerShell, not Git Bash (Git's `link` shadows MSVC `link.exe`). Commit with `git commit -s` and end the message with the `Co-Authored-By` trailer given by the harness. Never push or open a PR without the user's go-ahead (Task 10).

**Spec:** `docs/superpowers/specs/2026-10-30-zarpa-design.md` §5 (identity, pairing and trust), §12 (security), §4.1 (daemon owns all logic). Transport and encoding decisions: ADR-0004, ADR-0005.

---

## Decisions fixed by this plan

1. **Secret = 32-byte Ed25519 seed.** That is exactly what the `Transport` contract from the M1.1 spike takes (`bind(secret, trusted)`); the iroh endpoint ID is the same public key. `zarpa-core` does not depend on iroh.
2. **Secrets go through a `SecretStore` trait.** The OS keyring (Credential Manager / Keychain / Secret Service) is the preferred store per the spec; it is an optional Cargo feature (`os-keyring`) because headless CI and Linux servers have no keyring. `FileSecretStore` (owner-only file) is the documented fallback. Mobile platforms will supply their own store through UniFFI later (M5).
3. **A corrupt stored secret is an error, never silently regenerated.** Regenerating would orphan the device's identity on every paired peer.
4. **Trust list = one JSON file** (`{"version":1,"devices":[…]}`), written atomically (temp file + rename), loaded fully in memory. It is small, human-inspectable and needs no new native dependency. SQLite stays reserved for transfer history (M1.5+). Single writer: the daemon owns the file.
5. **Device ID text form = 64 lowercase hex characters.** `short()` (first 8 hex chars) is for display only and must never be used to authenticate.
6. **Peer-supplied names are hostile input:** control characters stripped, trimmed, at most 64 characters, empty falls back to `device-<short id>`.
7. **Mutations are all-or-nothing:** if writing the trust file fails, the in-memory state is rolled back so memory and disk never disagree.

## File structure (created or modified by this plan)

| Path | Responsibility |
|---|---|
| `core/Cargo.toml` (modify) | dependencies, `os-keyring` feature |
| `core/src/lib.rs` (modify) | module declarations and re-exports |
| `core/src/error.rs` | `Error`, `Result` |
| `core/src/fsutil.rs` | private `write_atomic` helper |
| `core/src/identity.rs` | `DeviceId`, `Identity` |
| `core/src/secret_store.rs` | `SecretStore`, `MemorySecretStore`, `FileSecretStore` |
| `core/src/keyring_store.rs` | `OsKeyringStore` (feature `os-keyring`) |
| `core/src/trust.rs` | `TrustedDevice`, `TrustStore` |
| `core/tests/persistence.rs` | restart scenario across identity and trust |
| `docs/adr/0006-local-state-storage.md` | ADR for decisions 2 and 4 |
| `docs/protocol/README.md` (modify) | device ID text form |

---

### Task 0: Branch and baseline

**Files:** none

- [ ] **Step 1: Create the branch from an up-to-date `main`**

```powershell
git switch main
git pull --ff-only
git switch -c feat/m1-2-identity-trust
```

- [ ] **Step 2: Confirm the baseline is green**

Run: `cargo test -p zarpa-core`
Expected: `1 passed` (`version_matches_cargo_manifest`).

---

### Task 1: Dependencies and error type

**Files:**
- Modify: `core/Cargo.toml`
- Modify: `core/src/lib.rs`
- Create: `core/src/error.rs`

- [ ] **Step 1: Add dependencies**

Append to `core/Cargo.toml`:

```toml

[dependencies]
ed25519-dalek = { version = "2", default-features = false, features = ["std", "zeroize", "rand_core"] }
rand_core = { version = "0.6", features = ["getrandom"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
zeroize = "1"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Write the error module**

Create `core/src/error.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! Error type shared by identity, secret storage and trust operations.

/// Errors returned by `zarpa-core` identity, secret-store and trust operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A device ID string is not 64 lowercase hexadecimal characters.
    #[error("invalid device id: {0}")]
    InvalidDeviceId(String),
    /// A stored secret does not have the expected 32 bytes (the found length is carried).
    #[error("stored secret is corrupt: expected 32 bytes, found {0}")]
    CorruptSecret(usize),
    /// A state file exists but cannot be understood.
    #[error("state file is corrupt: {0}")]
    Corrupt(String),
    /// A state file was written by a newer, incompatible version (the found version is carried).
    #[error("state file has unsupported version {0}")]
    UnsupportedVersion(u32),
    /// The operating-system secret store failed.
    #[error("secret store: {0}")]
    SecretStore(String),
    /// A filesystem operation failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 3: Declare the module**

In `core/src/lib.rs`, directly under the `//! Zarpa core library.` line, add:

```rust

pub mod error;

pub use error::{Error, Result};
```

- [ ] **Step 4: Verify it builds**

Run: `cargo check -p zarpa-core`
Expected: finishes without errors. If cargo reports that a dependency needs a newer `rustc` than `rust-version = "1.75"`, raise `rust-version` in the root `Cargo.toml` to the version cargo names and mention it in the commit body.

- [ ] **Step 5: Commit**

```powershell
git add Cargo.toml Cargo.lock core
git commit -s -m "feat(core): add error type and identity dependencies"
```

---

### Task 2: `DeviceId` (TDD)

**Files:**
- Create: `core/src/identity.rs`
- Modify: `core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `core/src/identity.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! Device identity: an Ed25519 key pair whose public key is the device ID.

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn sample() -> DeviceId {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        DeviceId::from_bytes(bytes)
    }

    #[test]
    fn display_is_64_lowercase_hex() {
        assert_eq!(sample().to_string(), HEX);
    }

    #[test]
    fn parse_roundtrips() {
        assert_eq!(HEX.parse::<DeviceId>().unwrap(), sample());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!("abcd".parse::<DeviceId>().is_err());
        assert!(format!("{HEX}00").parse::<DeviceId>().is_err());
    }

    #[test]
    fn parse_rejects_uppercase_and_non_hex() {
        assert!(HEX.to_uppercase().parse::<DeviceId>().is_err());
        assert!(format!("{}zz", &HEX[..62]).parse::<DeviceId>().is_err());
    }

    #[test]
    fn parse_rejects_non_ascii_without_panicking() {
        // 64 bytes long, but not hex.
        assert!("é".repeat(32).parse::<DeviceId>().is_err());
    }

    #[test]
    fn short_is_first_eight_hex_chars() {
        assert_eq!(sample().short(), "00010203");
    }

    #[test]
    fn debug_shows_only_the_short_form() {
        assert_eq!(format!("{:?}", sample()), "DeviceId(00010203)");
    }

    #[test]
    fn serde_uses_the_hex_string() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert_eq!(json, format!("\"{HEX}\""));
        assert_eq!(serde_json::from_str::<DeviceId>(&json).unwrap(), sample());
        assert!(serde_json::from_str::<DeviceId>("\"nope\"").is_err());
    }
}
```

In `core/src/lib.rs`, add `pub mod identity;` after `pub mod error;` and `pub use identity::DeviceId;` after the existing `pub use`.

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zarpa-core identity`
Expected: FAIL to compile (`cannot find type DeviceId`).

- [ ] **Step 3: Implement `DeviceId`**

Insert above the `#[cfg(test)]` line of `core/src/identity.rs`:

```rust
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The identity of a device: its Ed25519 public key.
///
/// The text form is 64 lowercase hexadecimal characters. [`DeviceId::short`] is a display
/// aid only and must never be used to authenticate a peer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Wraps raw public-key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw public-key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The first 8 hex characters, for showing in lists and logs.
    pub fn short(&self) -> String {
        encode_hex(&self.0[..4])
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short())
    }
}

impl FromStr for DeviceId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        decode_hex_32(s)
            .map(Self)
            .ok_or_else(|| Error::InvalidDeviceId("expected 64 lowercase hex characters".into()))
    }
}

impl From<DeviceId> for String {
    fn from(id: DeviceId) -> String {
        id.to_string()
    }
}

impl TryFrom<String> for DeviceId {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *slot = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zarpa-core identity`
Expected: `8 passed`.

- [ ] **Step 5: Lint and commit**

Run: `cargo fmt --all; cargo clippy -p zarpa-core --all-targets -- -D warnings`
Expected: no warnings.

```powershell
git add core
git commit -s -m "feat(core): add DeviceId with hex text form"
```

---

### Task 3: `Identity` key pair (TDD)

**Files:**
- Modify: `core/src/identity.rs`
- Modify: `core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Inside the existing `mod tests` of `core/src/identity.rs`, append:

```rust
    #[test]
    fn from_secret_matches_rfc_8032_test_vector_1() {
        // RFC 8032 section 7.1, TEST 1. The secret is parsed through DeviceId only to reuse
        // the hex decoder.
        let secret: DeviceId = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            .parse()
            .unwrap();
        let identity = Identity::from_secret(*secret.as_bytes());
        assert_eq!(
            identity.id().to_string(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(identity.secret(), secret.as_bytes());
    }

    #[test]
    fn generate_gives_distinct_identities() {
        assert_ne!(Identity::generate().id(), Identity::generate().id());
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let identity = Identity::from_secret([7u8; 32]);
        let text = format!("{identity:?}");
        assert!(text.contains(&identity.id().short()));
        assert!(!text.contains("0707"));
    }
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zarpa-core identity`
Expected: FAIL to compile (`cannot find type Identity`).

- [ ] **Step 3: Implement `Identity`**

In `core/src/identity.rs`, add to the `use` block: `use ed25519_dalek::SigningKey;`, `use rand_core::OsRng;` and `use zeroize::Zeroizing;`. Then insert above the `fn encode_hex` function:

```rust
/// This device's identity: the Ed25519 secret seed and the public key derived from it.
///
/// The secret is wiped from memory on drop and never appears in `Debug` output.
pub struct Identity {
    secret: Zeroizing<[u8; 32]>,
    id: DeviceId,
}

impl Identity {
    /// Generates a fresh identity from the operating system's random number generator.
    pub fn generate() -> Self {
        let key = SigningKey::generate(&mut OsRng);
        Self::from_secret(key.to_bytes())
    }

    /// Rebuilds an identity from its 32-byte secret seed.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let id = DeviceId(SigningKey::from_bytes(&secret).verifying_key().to_bytes());
        Self {
            secret: Zeroizing::new(secret),
            id,
        }
    }

    /// The device ID (public key).
    pub fn id(&self) -> DeviceId {
        self.id
    }

    /// The secret seed, for handing to a transport. Never log or persist it elsewhere.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
```

In `core/src/lib.rs` change the identity re-export to `pub use identity::{DeviceId, Identity};`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zarpa-core identity`
Expected: `11 passed`. If `SigningKey::generate` or `OsRng` do not resolve, check that `ed25519-dalek` has the `rand_core` feature and `rand_core` has `getrandom` (Task 1, Step 1).

- [ ] **Step 5: Lint and commit**

Run: `cargo fmt --all; cargo clippy -p zarpa-core --all-targets -- -D warnings`
Expected: no warnings.

```powershell
git add core
git commit -s -m "feat(core): add Ed25519 device identity"
```

---

### Task 4: Atomic write helper and secret stores (TDD)

**Files:**
- Create: `core/src/fsutil.rs`
- Create: `core/src/secret_store.rs`
- Modify: `core/src/lib.rs`

- [ ] **Step 1: Write the atomic-write helper**

Create `core/src/fsutil.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! Small filesystem helpers shared by the stores.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Writes `bytes` to `path` atomically: the data goes to `<path>.tmp`, is flushed to disk and
/// then renamed over `path`, so readers see either the old or the new content, never a mix.
///
/// Creates missing parent directories. With `private` set, the file is created readable and
/// writable by the owner only (Unix mode 0600); on Windows the user-profile directory ACL
/// already restricts access, so the flag has no further effect there.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;

    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}
```

- [ ] **Step 2: Write the failing tests for the stores**

Create `core/src/secret_store.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! Where the device's secret key is kept.

#[cfg(test)]
mod tests {
    use super::*;

    /// Behavior every store must have.
    fn contract(store: &dyn SecretStore) {
        assert!(store.load().unwrap().is_none());
        store.save(&[1, 2, 3]).unwrap();
        let got = store.load().unwrap().unwrap();
        assert_eq!(&got[..], &[1u8, 2, 3][..]);
        store.save(&[4]).unwrap();
        let got = store.load().unwrap().unwrap();
        assert_eq!(&got[..], &[4u8][..]);
    }

    #[test]
    fn memory_store_follows_the_contract() {
        contract(&MemorySecretStore::default());
    }

    #[test]
    fn file_store_follows_the_contract() {
        let dir = tempfile::tempdir().unwrap();
        contract(&FileSecretStore::new(dir.path().join("nested").join("device.key")));
    }

    #[test]
    fn file_store_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::new(dir.path().join("device.key"));
        store.save(&[9; 32]).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("device.key")]);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        FileSecretStore::new(path.clone()).save(&[9; 32]).unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
```

In `core/src/lib.rs` add `mod fsutil;` (private) and `pub mod secret_store;` after `pub mod identity;`, and `pub use secret_store::{FileSecretStore, MemorySecretStore, SecretStore};` after the other `pub use` lines.

- [ ] **Step 3: Run the tests to see them fail**

Run: `cargo test -p zarpa-core secret_store`
Expected: FAIL to compile (`cannot find trait SecretStore`).

- [ ] **Step 4: Implement the stores**

Insert above the `#[cfg(test)]` line of `core/src/secret_store.rs`:

```rust
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::error::Result;
use crate::fsutil;

/// Storage for the device's secret key material.
///
/// Implementations: [`MemorySecretStore`] (tests), [`FileSecretStore`] (owner-only file) and,
/// with the `os-keyring` feature, `OsKeyringStore` (the operating system's secure store).
pub trait SecretStore: Send + Sync {
    /// Returns the stored secret, or `None` if nothing has been saved yet.
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>>;

    /// Stores `secret`, replacing any previous value.
    fn save(&self, secret: &[u8]) -> Result<()>;
}

/// A store that keeps the secret in memory only. For tests.
#[derive(Default)]
pub struct MemorySecretStore {
    secret: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl SecretStore for MemorySecretStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let guard = self.secret.lock().unwrap_or_else(|e| e.into_inner());
        Ok(guard.as_ref().map(|s| Zeroizing::new(s.to_vec())))
    }

    fn save(&self, secret: &[u8]) -> Result<()> {
        let mut guard = self.secret.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(Zeroizing::new(secret.to_vec()));
        Ok(())
    }
}

/// A store that keeps the secret in a file readable only by its owner.
///
/// This is the fallback for systems without a usable OS keyring. The file is written
/// atomically with mode 0600 on Unix; on Windows it relies on the user-profile ACL.
pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    /// A store backed by the file at `path` (created on first save).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SecretStore for FileSecretStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, secret: &[u8]) -> Result<()> {
        fsutil::write_atomic(&self.path, secret, true)?;
        Ok(())
    }
}
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `cargo test -p zarpa-core secret_store`
Expected: `3 passed` on Windows (`4 passed` on Unix, which adds the permissions test).

- [ ] **Step 6: Lint and commit**

Run: `cargo fmt --all; cargo clippy -p zarpa-core --all-targets -- -D warnings`
Expected: no warnings (on Windows too: `private` is consumed by the `#[cfg(not(unix))] let _ = private;` line).

```powershell
git add core
git commit -s -m "feat(core): add secret store trait with memory and file stores"
```

---

### Task 5: `Identity::load_or_create` (TDD)

**Files:**
- Modify: `core/src/identity.rs`

- [ ] **Step 1: Write the failing tests**

Inside `mod tests` of `core/src/identity.rs`, add `use crate::secret_store::{MemorySecretStore, SecretStore};` below `use super::*;` and append:

```rust
    #[test]
    fn load_or_create_persists_the_first_identity() {
        let store = MemorySecretStore::default();
        let first = Identity::load_or_create(&store).unwrap();
        let second = Identity::load_or_create(&store).unwrap();
        assert_eq!(first.id(), second.id());
        assert_eq!(first.secret(), second.secret());
    }

    #[test]
    fn load_or_create_refuses_a_corrupt_secret_instead_of_replacing_it() {
        let store = MemorySecretStore::default();
        store.save(&[1, 2, 3]).unwrap();
        assert!(matches!(
            Identity::load_or_create(&store),
            Err(Error::CorruptSecret(3))
        ));
        // The corrupt value is still there: nothing was overwritten.
        assert_eq!(store.load().unwrap().unwrap().len(), 3);
    }
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zarpa-core load_or_create`
Expected: FAIL to compile (`no function named load_or_create`).

- [ ] **Step 3: Implement it**

In `core/src/identity.rs` add `use crate::secret_store::SecretStore;` to the `use` block and, inside `impl Identity`, after `from_secret`:

```rust
    /// Loads the identity kept in `store`, creating and saving a new one on first run.
    ///
    /// A stored value of the wrong length is reported as [`Error::CorruptSecret`] and left
    /// untouched: replacing it would silently change this device's ID on every paired peer.
    pub fn load_or_create(store: &dyn SecretStore) -> Result<Self> {
        match store.load()? {
            Some(bytes) => {
                let secret: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::CorruptSecret(bytes.len()))?;
                Ok(Self::from_secret(secret))
            }
            None => {
                let identity = Self::generate();
                store.save(identity.secret())?;
                Ok(identity)
            }
        }
    }
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zarpa-core identity`
Expected: `13 passed`.

- [ ] **Step 5: Lint and commit**

Run: `cargo fmt --all; cargo clippy -p zarpa-core --all-targets -- -D warnings`
Expected: no warnings.

```powershell
git add core
git commit -s -m "feat(core): load or create the device identity from a secret store"
```

---

### Task 6: `TrustStore` (TDD)

**Files:**
- Create: `core/src/trust.rs`
- Modify: `core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `core/src/trust.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! The list of devices this device trusts (paired devices), kept in a JSON file.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn id(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 32])
    }

    fn path_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("trusted.json")
    }

    #[test]
    fn a_missing_file_is_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(path_in(&dir)).unwrap();
        assert!(store.ids().is_empty());
        assert!(!store.is_trusted(&id(9)));
    }

    #[test]
    fn trust_adds_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::open(path_in(&dir)).unwrap();
        assert!(store.trust(id(1), "Laptop", 100).unwrap());
        assert!(store.is_trusted(&id(1)));

        let reopened = TrustStore::open(path_in(&dir)).unwrap();
        let device = reopened.get(&id(1)).unwrap();
        assert_eq!(device.name, "Laptop");
        assert_eq!(device.paired_at, 100);
    }

    #[test]
    fn trusting_again_updates_the_name_and_keeps_the_pairing_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::open(path_in(&dir)).unwrap();
        assert!(store.trust(id(1), "A", 100).unwrap());
        assert!(!store.trust(id(1), "B", 200).unwrap());
        let device = store.get(&id(1)).unwrap();
        assert_eq!(device.name, "B");
        assert_eq!(device.paired_at, 100);
    }

    #[test]
    fn rename_changes_only_known_devices() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::open(path_in(&dir)).unwrap();
        store.trust(id(1), "Old", 1).unwrap();
        assert!(store.rename(&id(1), "New").unwrap());
        assert!(!store.rename(&id(2), "Nobody").unwrap());
        assert_eq!(store.get(&id(1)).unwrap().name, "New");
        assert_eq!(TrustStore::open(path_in(&dir)).unwrap().get(&id(1)).unwrap().name, "New");
    }

    #[test]
    fn remove_forgets_the_device_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::open(path_in(&dir)).unwrap();
        store.trust(id(1), "Laptop", 1).unwrap();
        assert!(store.remove(&id(1)).unwrap());
        assert!(!store.remove(&id(1)).unwrap());
        assert!(!TrustStore::open(path_in(&dir)).unwrap().is_trusted(&id(1)));
    }

    #[test]
    fn ids_are_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::open(path_in(&dir)).unwrap();
        for n in [3, 1, 2] {
            store.trust(id(n), "d", 1).unwrap();
        }
        assert_eq!(store.ids(), vec![id(1), id(2), id(3)]);
    }

    #[test]
    fn names_are_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::open(path_in(&dir)).unwrap();
        store.trust(id(1), "  ev\u{7}il\nname  ", 1).unwrap();
        assert_eq!(store.get(&id(1)).unwrap().name, "evilname");
        store.trust(id(2), " \n ", 1).unwrap();
        assert_eq!(store.get(&id(2)).unwrap().name, "device-02020202");
        store.trust(id(3), &"x".repeat(100), 1).unwrap();
        assert_eq!(store.get(&id(3)).unwrap().name.chars().count(), 64);
    }

    #[test]
    fn open_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(path_in(&dir), "not json").unwrap();
        assert!(matches!(TrustStore::open(path_in(&dir)), Err(Error::Corrupt(_))));
    }

    #[test]
    fn open_rejects_a_newer_format_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(path_in(&dir), r#"{"version":2,"devices":[]}"#).unwrap();
        assert!(matches!(
            TrustStore::open(path_in(&dir)),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn open_rejects_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let one = format!(r#"{{"id":"{}","name":"a","paired_at":1}}"#, id(1));
        std::fs::write(path_in(&dir), format!(r#"{{"version":1,"devices":[{one},{one}]}}"#)).unwrap();
        assert!(matches!(TrustStore::open(path_in(&dir)), Err(Error::Corrupt(_))));
    }

    #[test]
    fn a_failed_save_rolls_back_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("trusted.json");
        let mut store = TrustStore::open(path).unwrap();
        // Make the parent directory impossible to create: a file now sits where it should be.
        std::fs::write(dir.path().join("sub"), "in the way").unwrap();
        assert!(store.trust(id(1), "Laptop", 1).is_err());
        assert!(!store.is_trusted(&id(1)));
    }
}
```

In `core/src/lib.rs` add `pub mod trust;` after `pub mod secret_store;` and `pub use trust::{TrustStore, TrustedDevice};` after the other `pub use` lines.

- [ ] **Step 2: Run the tests to see them fail**

Run: `cargo test -p zarpa-core trust`
Expected: FAIL to compile (`cannot find type TrustStore`).

- [ ] **Step 3: Implement the store**

Insert above the `#[cfg(test)]` line of `core/src/trust.rs`:

```rust
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fsutil;
use crate::identity::DeviceId;

const FORMAT_VERSION: u32 = 1;
const MAX_NAME_CHARS: usize = 64;

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// The device's public key.
    pub id: DeviceId,
    /// A human label chosen by the peer; display only, never used to authenticate.
    pub name: String,
    /// When the device was first trusted, in seconds since the Unix epoch.
    pub paired_at: u64,
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    devices: Vec<TrustedDevice>,
}

#[derive(Deserialize)]
struct Versioned {
    version: u32,
}

/// The persistent list of trusted devices.
///
/// The daemon is the only writer. Every change is written to disk atomically before it takes
/// effect in memory; if the write fails the change is undone and the error returned.
pub struct TrustStore {
    path: PathBuf,
    devices: BTreeMap<DeviceId, TrustedDevice>,
}

impl TrustStore {
    /// Opens the store at `path`. A missing file is an empty list; an unreadable, malformed
    /// or newer-version file is an error and is left untouched.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let devices = match fs::read(&path) {
            Ok(bytes) => parse(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, devices })
    }

    /// Whether `id` is a trusted device.
    pub fn is_trusted(&self, id: &DeviceId) -> bool {
        self.devices.contains_key(id)
    }

    /// The record for `id`, if trusted.
    pub fn get(&self, id: &DeviceId) -> Option<&TrustedDevice> {
        self.devices.get(id)
    }

    /// All trusted devices, sorted by ID.
    pub fn list(&self) -> impl Iterator<Item = &TrustedDevice> {
        self.devices.values()
    }

    /// The IDs of all trusted devices, sorted: the list a transport is given.
    pub fn ids(&self) -> Vec<DeviceId> {
        self.devices.keys().copied().collect()
    }

    /// Trusts `id`. Returns `true` if it was newly added; if it was already trusted only its
    /// name is updated and the original `paired_at` is kept. `paired_at` is seconds since the
    /// Unix epoch, supplied by the caller so the store stays deterministic.
    pub fn trust(&mut self, id: DeviceId, name: &str, paired_at: u64) -> Result<bool> {
        let name = sanitize_name(name, &id);
        let is_new = !self.is_trusted(&id);
        self.commit(|devices| match devices.get_mut(&id) {
            Some(existing) => existing.name = name,
            None => {
                devices.insert(
                    id,
                    TrustedDevice {
                        id,
                        name,
                        paired_at,
                    },
                );
            }
        })?;
        Ok(is_new)
    }

    /// Renames a trusted device. Returns `false` if `id` is not trusted.
    pub fn rename(&mut self, id: &DeviceId, name: &str) -> Result<bool> {
        if !self.is_trusted(id) {
            return Ok(false);
        }
        let name = sanitize_name(name, id);
        self.commit(|devices| {
            if let Some(existing) = devices.get_mut(id) {
                existing.name = name;
            }
        })?;
        Ok(true)
    }

    /// Stops trusting `id`. Returns `false` if it was not trusted.
    pub fn remove(&mut self, id: &DeviceId) -> Result<bool> {
        if !self.is_trusted(id) {
            return Ok(false);
        }
        self.commit(|devices| {
            devices.remove(id);
        })?;
        Ok(true)
    }

    /// Applies `change`, writes the result to disk and undoes the change if the write fails.
    fn commit<T>(
        &mut self,
        change: impl FnOnce(&mut BTreeMap<DeviceId, TrustedDevice>) -> T,
    ) -> Result<T> {
        let previous = self.devices.clone();
        let out = change(&mut self.devices);
        if let Err(e) = self.save() {
            self.devices = previous;
            return Err(e);
        }
        Ok(out)
    }

    fn save(&self) -> Result<()> {
        let file = FileFormat {
            version: FORMAT_VERSION,
            devices: self.devices.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| Error::Corrupt(e.to_string()))?;
        fsutil::write_atomic(&self.path, &bytes, true)?;
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<BTreeMap<DeviceId, TrustedDevice>> {
    // Check the version first: a newer file may not match this version's schema.
    let Versioned { version } =
        serde_json::from_slice(bytes).map_err(|e| Error::Corrupt(e.to_string()))?;
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let file: FileFormat =
        serde_json::from_slice(bytes).map_err(|e| Error::Corrupt(e.to_string()))?;
    let mut devices = BTreeMap::new();
    for device in file.devices {
        if devices.insert(device.id, device).is_some() {
            return Err(Error::Corrupt("duplicate device id".into()));
        }
    }
    Ok(devices)
}

/// Peer-supplied names are untrusted: strip control characters, trim, cap the length, and
/// fall back to a name derived from the ID when nothing is left.
fn sanitize_name(name: &str, id: &DeviceId) -> String {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();
    let cleaned: String = cleaned.trim().chars().take(MAX_NAME_CHARS).collect();
    if cleaned.is_empty() {
        format!("device-{}", id.short())
    } else {
        cleaned
    }
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test -p zarpa-core trust`
Expected: `10 passed`.

- [ ] **Step 5: Lint and commit**

Run: `cargo fmt --all; cargo clippy -p zarpa-core --all-targets -- -D warnings`
Expected: no warnings.

```powershell
git add core
git commit -s -m "feat(core): add persistent trust store"
```

---

### Task 7: Restart scenario (integration test)

**Files:**
- Create: `core/tests/persistence.rs`

- [ ] **Step 1: Write the test**

Create `core/tests/persistence.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! Identity and trust state must survive a restart of the daemon.

use zarpa_core::{FileSecretStore, Identity, TrustStore};

#[test]
fn identity_and_trust_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("device.key");
    let trust_path = dir.path().join("trusted.json");

    let first = Identity::load_or_create(&FileSecretStore::new(key_path.clone())).unwrap();
    let peer = Identity::generate().id();
    {
        let mut trust = TrustStore::open(trust_path.clone()).unwrap();
        trust.trust(peer, "Phone", 42).unwrap();
    }

    // "Restart": open everything again from disk.
    let second = Identity::load_or_create(&FileSecretStore::new(key_path)).unwrap();
    let trust = TrustStore::open(trust_path).unwrap();

    assert_eq!(first.id(), second.id());
    assert_eq!(trust.ids(), vec![peer]);
    assert!(!trust.is_trusted(&first.id()));
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p zarpa-core --test persistence`
Expected: `1 passed`. (No failing step first: this test composes already-tested units and exists to guard their contract.)

- [ ] **Step 3: Commit**

```powershell
git add core
git commit -s -m "test(core): cover identity and trust persistence across restarts"
```

---

### Task 8: OS keyring store (optional feature)

**Files:**
- Modify: `core/Cargo.toml`
- Modify: `core/src/lib.rs`
- Create: `core/src/keyring_store.rs`

The default build and CI do not enable this feature (headless runners have no keyring). It is verified manually on the Windows development machine in Step 5.

- [ ] **Step 1: Declare the feature and platform dependencies**

Append to `core/Cargo.toml`:

```toml

[features]
# The operating system's secure store (Credential Manager, Keychain, Secret Service).
os-keyring = ["dep:keyring"]

[target.'cfg(windows)'.dependencies]
keyring = { version = "3", optional = true, default-features = false, features = ["windows-native"] }

[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "3", optional = true, default-features = false, features = ["apple-native"] }

[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "3", optional = true, default-features = false, features = ["sync-secret-service"] }
```

If `keyring` 3.x names these features differently, use the names from its `Cargo.toml` (`cargo info keyring`) and keep one platform store per target.

- [ ] **Step 2: Declare the module**

In `core/src/lib.rs` add, after `pub mod identity;`:

```rust
#[cfg(feature = "os-keyring")]
pub mod keyring_store;
```

and, after the other `pub use` lines:

```rust
#[cfg(feature = "os-keyring")]
pub use keyring_store::OsKeyringStore;
```

- [ ] **Step 3: Write the store with its test**

Create `core/src/keyring_store.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! A [`SecretStore`] backed by the operating system's secure store.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret_store::SecretStore;

/// Keeps the secret in Windows Credential Manager, the macOS Keychain or the Linux Secret
/// Service. Preferred over [`FileSecretStore`](crate::FileSecretStore) when available.
pub struct OsKeyringStore {
    entry: keyring::Entry,
}

impl OsKeyringStore {
    /// A store for the credential identified by `service` and `account`.
    pub fn new(service: &str, account: &str) -> Result<Self> {
        keyring::Entry::new(service, account)
            .map(|entry| Self { entry })
            .map_err(|e| Error::SecretStore(e.to_string()))
    }
}

impl SecretStore for OsKeyringStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.entry.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::SecretStore(e.to_string())),
        }
    }

    fn save(&self, secret: &[u8]) -> Result<()> {
        self.entry
            .set_secret(secret)
            .map_err(|e| Error::SecretStore(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a real OS keyring, so it is skipped by default:
    /// `cargo test -p zarpa-core --features os-keyring -- --ignored`.
    #[test]
    #[ignore = "requires an operating-system keyring"]
    fn round_trips_through_the_os_keyring() {
        let account = format!("test-{}", std::process::id());
        let store = OsKeyringStore::new("zarpa-core-tests", &account).unwrap();
        assert!(store.load().unwrap().is_none());
        store.save(&[5u8; 32]).unwrap();
        let got = store.load().unwrap().unwrap();
        assert_eq!(&got[..], &[5u8; 32][..]);
        store.entry.delete_credential().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
```

- [ ] **Step 4: Check that both configurations build**

Run: `cargo clippy -p zarpa-core --all-targets -- -D warnings`
Expected: no warnings (feature off).

Run: `cargo clippy -p zarpa-core --all-targets --features os-keyring -- -D warnings`
Expected: no warnings (feature on). Fix any `keyring` API mismatches against the crate version cargo resolved.

- [ ] **Step 5: Run the real-keyring test on this machine**

Run: `cargo test -p zarpa-core --features os-keyring -- --ignored round_trips`
Expected: `1 passed`. The test deletes the credential it creates. Report the result honestly; if the keyring is unavailable, say so and leave the test `#[ignore]`d.

- [ ] **Step 6: Commit**

```powershell
git add Cargo.lock core
git commit -s -m "feat(core): add OS keyring secret store behind a feature"
```

---

### Task 9: Documentation

**Files:**
- Create: `docs/adr/0006-local-state-storage.md`
- Modify: `docs/protocol/README.md`

- [ ] **Step 1: Write the ADR**

Create `docs/adr/0006-local-state-storage.md`:

```markdown
# 6. Local state storage

- Status: accepted
- Date: 2026-10-30

## Context

The daemon must keep a device secret key and a list of trusted devices across restarts
(design spec section 5). The secret needs the strongest storage the platform offers; the
trust list is small and must be easy to inspect and back up.

## Decision

- The device secret (32-byte Ed25519 seed) goes through a `SecretStore` trait. The operating
  system's secure store is preferred (`OsKeyringStore`, Cargo feature `os-keyring`); an
  owner-only file (`FileSecretStore`, mode 0600 on Unix) is the fallback for systems without a
  keyring. Mobile platforms will provide their own store (M5).
- A stored secret of the wrong length is an error and is never replaced automatically.
- The trust list is a JSON file (`{"version":1,"devices":[...]}`) written atomically (temp file
  and rename), loaded fully in memory, with a single writer (the daemon).
- SQLite is reserved for transfer history.

## Consequences

- No new native dependency for the trust list; the file can be read, diffed and backed up.
- Losing the secret means a new device ID and re-pairing with every peer; the corrupt-secret
  rule exists to prevent doing that silently.
- The file fallback is weaker than a keyring against other processes running as the same user.
  The UI should say which store is in use (M3).
- A multi-writer or very large trust list would justify moving it into SQLite later; the
  `TrustStore` API hides the format.

## Alternatives considered

- **Everything in SQLite:** one storage engine, but adds a native dependency now and mixes
  secrets with ordinary data.
- **Keyring only:** unusable on headless Linux and CI, so there would be no way to run the
  daemon there.
```

- [ ] **Step 2: Specify the device ID text form in the protocol draft**

In `docs/protocol/README.md`, section "2. Identity", replace the line

`- A device identity is an Ed25519 key pair. The **device ID** is the public key.`

with

```markdown
- A device identity is an Ed25519 key pair. The **device ID** is the public key. In text form
  (API, CLI, files) it is written as 64 lowercase hexadecimal characters; the first 8 are used
  as a short display form only and MUST NOT be used to authenticate a peer.
```

- [ ] **Step 3: Commit**

```powershell
git add docs
git commit -s -m "docs: add ADR-0006 and specify the device ID text form"
```

---

### Task 10: Verify gates and open the PR (outward-facing — requires user confirmation)

**Files:** none

- [ ] **Step 1: Run every gate locally**

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all pass. If `cargo-deny` is installed, also run `cargo deny check`; otherwise CI runs it. New crates bring only licenses already allowed (Apache-2.0, MIT, BSD-3-Clause, ISC, Unicode-3.0); if `cargo deny` rejects one, report it instead of widening `deny.toml` silently.

- [ ] **Step 2: Ask the user before pushing**

Show the commit list (`git log --oneline main..`) and test totals. Push and open the PR only after the user agrees:

```powershell
git push -u origin feat/m1-2-identity-trust
gh pr create --repo SW3T0/zarpa --title "feat(core): device identity and trust store (M1.2)" --body "<body>"
```

Write the body from the list below. It states: what was added, the seven decisions above, test evidence, and that `os-keyring` is off by default and was checked manually on Windows. End it with the PR attribution line given by the harness.

---

## Self-review (spec coverage)

- **§5 identity:** Ed25519 key per device, device ID = public key, display name is only a label → Tasks 2–3, 6 (names sanitized, never used for auth).
- **§5 key stored in the OS secure store:** `SecretStore` + `OsKeyringStore` (Task 8), file fallback (Task 4). Mobile stores deferred to M5 (stated in decision 2).
- **§5 trust list / "trusted devices transfer without confirmation":** `TrustStore::is_trusted`/`ids` give M1.4–M1.6 the lookup and the transport's `trusted` list. Pairing itself (QR, verification code) is M1.4; unpaired-visible-device handling is M1.5/M1.6. Neither is in this plan.
- **§12 security:** hostile names (Task 6), atomic writes and rollback (Tasks 4, 6), secret zeroized and redacted from `Debug` (Task 3), no silent identity replacement (Task 5), owner-only file (Task 4).
- **AGENTS.md rules:** SPDX headers on every file, no `unwrap`/`expect` in library code (mutex poisoning handled with `unwrap_or_else`), all public items documented, `unsafe` never used, ADR and protocol doc updated in the same PR.
- **Placeholder scan:** none; every code step contains the code. The only judgment calls (MSRV bump, `keyring` feature names) name the exact check to make.
- **Type consistency:** `DeviceId::{from_bytes, as_bytes, short}`, `Identity::{generate, from_secret, load_or_create, id, secret}`, `SecretStore::{load, save}`, `FileSecretStore::new`, `TrustStore::{open, is_trusted, get, list, ids, trust, rename, remove}` and `TrustedDevice {id, name, paired_at}` are used with the same signatures in every task and in the integration test.
- **Not in this plan (later milestones):** discovery and interface selection (M1.3), pairing and verification code (M1.4), daemon, API and CLI (M1.5), end-to-end send over iroh and the `deny.toml` license additions (M1.6).
