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
