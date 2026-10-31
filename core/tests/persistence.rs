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
