// SPDX-License-Identifier: Apache-2.0
//! Device identity: an Ed25519 key pair whose public key is the device ID.

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
