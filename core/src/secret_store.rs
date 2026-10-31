// SPDX-License-Identifier: Apache-2.0
//! Where the device's secret key is kept.

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
        contract(&FileSecretStore::new(
            dir.path().join("nested").join("device.key"),
        ));
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
