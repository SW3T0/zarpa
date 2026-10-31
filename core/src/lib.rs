// SPDX-License-Identifier: Apache-2.0
//! Zarpa core library.

pub mod error;
pub mod identity;

pub use error::{Error, Result};
pub use identity::DeviceId;

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
