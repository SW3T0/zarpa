// SPDX-License-Identifier: Apache-2.0
//! Device identity: an Ed25519 key pair whose public key is the device ID.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret_store::SecretStore;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::{MemorySecretStore, SecretStore};

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

    #[test]
    fn serde_uses_the_hex_string() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert_eq!(json, format!("\"{HEX}\""));
        assert_eq!(serde_json::from_str::<DeviceId>(&json).unwrap(), sample());
        assert!(serde_json::from_str::<DeviceId>("\"nope\"").is_err());
    }

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
}
