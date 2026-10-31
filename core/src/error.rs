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
    /// A state file was written in a version this build does not support (the found version is carried).
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
