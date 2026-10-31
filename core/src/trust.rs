// SPDX-License-Identifier: Apache-2.0
//! The list of devices this device trusts (paired devices), kept in a JSON file.

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
        assert_eq!(
            TrustStore::open(path_in(&dir))
                .unwrap()
                .get(&id(1))
                .unwrap()
                .name,
            "New"
        );
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
        assert!(matches!(
            TrustStore::open(path_in(&dir)),
            Err(Error::Corrupt(_))
        ));
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
        std::fs::write(
            path_in(&dir),
            format!(r#"{{"version":1,"devices":[{one},{one}]}}"#),
        )
        .unwrap();
        assert!(matches!(
            TrustStore::open(path_in(&dir)),
            Err(Error::Corrupt(_))
        ));
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
