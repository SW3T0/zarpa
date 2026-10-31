// SPDX-License-Identifier: Apache-2.0
//! Zarpa core library.

pub mod error;
mod fsutil;
pub mod identity;
#[cfg(all(
    feature = "os-keyring",
    any(windows, target_os = "macos", target_os = "linux")
))]
pub mod keyring_store;
pub mod secret_store;
pub mod trust;

pub use error::{Error, Result};
pub use identity::{DeviceId, Identity};
#[cfg(all(
    feature = "os-keyring",
    any(windows, target_os = "macos", target_os = "linux")
))]
pub use keyring_store::OsKeyringStore;
pub use secret_store::{FileSecretStore, MemorySecretStore, SecretStore};
pub use trust::{TrustStore, TrustedDevice};

/// Returns the version of the `zarpa-core` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }
}
