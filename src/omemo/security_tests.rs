//! Security-critical tests for trust enforcement and BTBV policy.
//!
//! Phase 2 of the test suite rebuild.  Tests that cannot fail are not tests.
//! Every test here either asserts a negative (bad input is rejected) or
//! asserts an absent key (the device is not in encrypted_keys).

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use async_trait::async_trait;
    use base64::Engine;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    use crate::jid::BareJid;
    use crate::omemo::device_id::DeviceId;
    use crate::omemo::protocol::{DeviceIdentity, PreKeyBundle, SignedPreKeyBundle};
    use crate::omemo::storage::{DeviceListEntry, OmemoStorage, TrustLevel};
    use crate::omemo::{OmemoManager, OmemoPubSub, OMEMO_NAMESPACE};

    fn bjid(s: &str) -> BareJid { BareJid::parse(s).unwrap() }

    // ── Minimal DeviceIdentity builder ────────────────────────────────────────

    fn fake_identity(device_id: DeviceId, key_byte: u8) -> DeviceIdentity {
        DeviceIdentity {
            id: device_id,
            identity_key: vec![key_byte; 32],
            signed_pre_key: SignedPreKeyBundle {
                id: 1,
                public_key: vec![0xAA; 32],
                signature: vec![0xBB; 64],
            },
            pre_keys: vec![PreKeyBundle { id: 1, public_key: vec![0xCC; 32] }],
        }
    }

    // ── MockPubSub ────────────────────────────────────────────────────────────

    struct MockPubSub {
        responses: Mutex<HashMap<String, String>>,
    }
    impl MockPubSub {
        fn empty() -> Arc<dyn OmemoPubSub> {
            Arc::new(Self { responses: Mutex::new(HashMap::new()) })
        }
        fn with(m: HashMap<String, String>) -> Arc<dyn OmemoPubSub> {
            Arc::new(Self { responses: Mutex::new(m) })
        }
        async fn add_device_list(&self, jid: &str, ids: &[u32]) {
            let devs: String = ids.iter().map(|id| format!("<device id=\"{}\"/>", id)).collect();
            let xml = format!(
                "<items node=\"{ns}.devicelist\"><item>\
                    <list xmlns=\"{ns}\">{devs}</list>\
                </item></items>",
                ns = OMEMO_NAMESPACE, devs = devs
            );
            let mut r = self.responses.lock().await;
            for node in crate::omemo::devicelist_node_variants() {
                r.insert(format!("{}|{}", jid, node), xml.clone());
            }
        }
        async fn add_bundle(&self, jid: &str, did: u32, bundle: &crate::omemo::protocol::X3DHKeyBundle) {
            let b64 = base64::engine::general_purpose::STANDARD;
            let ik = b64.encode(&bundle.identity_key_pair.public_key);
            let spk = b64.encode(&bundle.signed_pre_key_pair.public_key);
            let sig = b64.encode(&bundle.signed_pre_key_signature);
            let pks: String = bundle.one_time_pre_key_pairs.iter().map(|(id, kp)| {
                format!("<preKeyPublic preKeyId=\"{}\">{}</preKeyPublic>", id, b64.encode(&kp.public_key))
            }).collect();
            let xml = format!(
                "<items node=\"{ns}.bundles:{did}\"><item id=\"current\">\
                    <bundle xmlns=\"{ns}\">\
                        <identityKey>{ik}</identityKey>\
                        <signedPreKeyPublic signedPreKeyId=\"{spkid}\">{spk}</signedPreKeyPublic>\
                        <signedPreKeySignature>{sig}</signedPreKeySignature>\
                        <prekeys>{pks}</prekeys>\
                    </bundle>\
                </item></items>",
                ns = OMEMO_NAMESPACE, did = did,
                ik = ik, spkid = bundle.signed_pre_key_id, spk = spk, sig = sig, pks = pks
            );
            for node in crate::omemo::bundle_node_variants(crate::omemo::device_id::DeviceId::from(did)) {
                let key = format!("{}|{}", jid, node);
                self.responses.lock().await.insert(key, xml.clone());
            }
        }
    }
    #[async_trait]
    impl OmemoPubSub for MockPubSub {
        async fn request_items(&self, jid: &str, node: &str) -> Result<String> {
            let key = format!("{}|{}", jid, node);
            Ok(self.responses.lock().await.get(&key).cloned()
                .unwrap_or_else(|| "<iq type='error'><error><item-not-found/></error></iq>".to_string()))
        }
        async fn publish_item(&self, _: Option<&str>, _: &str, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn publish_item_alternative(&self, _: Option<&str>, _: &str, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn publish_device_list(&self, _: &[DeviceId]) -> Result<()> { Ok(()) }
        async fn delete_bundle(&self, _: DeviceId) -> Result<()> { Ok(()) }
    }

    // ── Manager helper (mirrors encrypt_decrypt_test.rs) ─────────────────────

    async fn make_manager(jid: &str, did: u32, ps: Arc<dyn OmemoPubSub>) -> (OmemoManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let mgr = OmemoManager::new(storage, jid.to_string(), Some(did), ps)
            .await
            .expect("OmemoManager::new");
        (mgr, dir)
    }

    // ── §2.1 Trust enforcement at storage boundary ────────────────────────────

    /// `get_trust_level` must return `Err` for a corrupt DB row.
    /// Today's code returns `Err` here (the storage fix is already in), but
    /// `encrypt.rs` still swallows it with `unwrap_or(Undecided)`.
    #[test]
    fn malformed_trust_string_errors_not_defaults_to_undecided() {
        let dir = TempDir::new().unwrap();
        let mut storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let jid = bjid("bob@example.com");
        let dev = DeviceId::from(42u32);

        storage.set_trust_level(&jid, dev, TrustLevel::Trusted).unwrap();

        // Corrupt via direct SQLite — simulates a bad migration or external write.
        let db_path = dir.path().join("omemo.sqlite3");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE device_identities SET trust_level = 'trusetd' WHERE jid = ?1 AND device_id = ?2",
            rusqlite::params![jid.as_str(), dev],
        ).unwrap();
        drop(conn);

        let storage2 = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let result = storage2.get_trust_level(&jid, dev);
        assert!(
            result.is_err(),
            "corrupt trust string must return Err, not Undecided; got {:?}", result
        );
    }

    /// Same check for an empty string (another corruption variant).
    #[test]
    fn empty_trust_string_errors() {
        let dir = TempDir::new().unwrap();
        let mut storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let jid = bjid("carol@example.com");
        let dev = DeviceId::from(7u32);

        storage.set_trust_level(&jid, dev, TrustLevel::Trusted).unwrap();

        let db_path = dir.path().join("omemo.sqlite3");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE device_identities SET trust_level = '' WHERE jid = ?1 AND device_id = ?2",
            rusqlite::params![jid.as_str(), dev],
        ).unwrap();
        drop(conn);

        let storage2 = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        assert!(storage2.get_trust_level(&jid, dev).is_err());
    }

    /// An explicitly Untrusted device must not appear in encrypted_keys.
    #[tokio::test]
    async fn untrusted_device_excluded_from_encrypted_keys() -> Result<()> {
        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_did = 1001u32;
        let bob_did = 2001u32;

        let ps = Arc::new(MockPubSub { responses: Mutex::new(HashMap::new()) });

        let (mut alice, _adir) = make_manager(alice_jid, alice_did, ps.clone()).await;
        let (bob,   _bdir) = make_manager(bob_jid,   bob_did,  ps.clone()).await;

        let bob_bundle = bob.key_bundle.as_ref().unwrap();
        ps.add_device_list(bob_jid, &[bob_did]).await;
        ps.add_bundle(bob_jid, bob_did, bob_bundle).await;
        ps.add_device_list(alice_jid, &[alice_did]).await;

        // Mark bob's device Untrusted before encrypting.
        {
            let mut storage = alice.storage.lock().await;
            storage.set_trust_level(&bjid(bob_jid), DeviceId::from(bob_did), TrustLevel::Untrusted)?;
        }

        let result = alice.encrypt_message(bob_jid, "hello").await;
        match result {
            Ok(msg) => {
                assert!(
                    !msg.encrypted_keys.contains_key(&DeviceId::from(bob_did)),
                    "Untrusted device must be absent from encrypted_keys; \
                     got keys for: {:?}",
                    msg.encrypted_keys.keys().collect::<Vec<_>>()
                );
            }
            Err(_) => {
                // Acceptable: no eligible recipients → encryption error is correct.
            }
        }
        Ok(())
    }

    /// Corrupt trust DB row at the encrypt site must not allow the device.
    ///
    /// `encrypt.rs` currently uses `.unwrap_or(Undecided)` which silently
    /// grants access when reading trust fails.  This test fails until that
    /// line is changed to `.unwrap_or(Untrusted)`.
    #[tokio::test]
    async fn corrupt_trust_at_encrypt_site_fails_safe() -> Result<()> {
        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_did = 1002u32;
        let bob_did = 2002u32;

        let ps = Arc::new(MockPubSub { responses: Mutex::new(HashMap::new()) });
        let (mut alice, adir) = make_manager(alice_jid, alice_did, ps.clone()).await;
        let (bob, _bdir)  = make_manager(bob_jid, bob_did, ps.clone()).await;

        let bob_bundle = bob.key_bundle.as_ref().unwrap();
        ps.add_device_list(bob_jid, &[bob_did]).await;
        ps.add_bundle(bob_jid, bob_did, bob_bundle).await;
        ps.add_device_list(alice_jid, &[alice_did]).await;

        // First set a valid Trusted level so the row exists, then corrupt it.
        {
            let mut storage = alice.storage.lock().await;
            storage.set_trust_level(&bjid(bob_jid), DeviceId::from(bob_did), TrustLevel::Trusted)?;
        }
        let db_path = adir.path().join("omemo.sqlite3");
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE device_identities SET trust_level = 'trusetd' WHERE jid = ?1 AND device_id = ?2",
                rusqlite::params![bob_jid, bob_did],
            ).unwrap();
        }

        let result = alice.encrypt_message(bob_jid, "hello").await;
        if let Ok(msg) = result {
            assert!(
                !msg.encrypted_keys.contains_key(&DeviceId::from(bob_did)),
                "device with corrupt trust must be excluded (fail-closed), \
                 but found key for device {}",
                bob_did
            );
        }
        Ok(())
    }

    // ── §2.1 Trust storage properties ────────────────────────────────────────

    /// Trust level must survive storage restart.
    #[test]
    fn trust_survives_restart() {
        let dir = TempDir::new().unwrap();
        let mut storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let jid = bjid("dave@example.com");
        let dev = DeviceId::from(77u32);

        storage.set_trust_level(&jid, dev, TrustLevel::Verified).unwrap();

        let storage2 = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(storage2.get_trust_level(&jid, dev).unwrap(), TrustLevel::Verified);
    }

    /// Untrusted must not be treated as trusted.
    #[test]
    fn untrusted_is_not_trusted() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();
        let jid = bjid("eve@example.com");
        let dev = DeviceId::from(5u32);
        storage.set_trust_level(&jid, dev, TrustLevel::Untrusted).unwrap();
        assert!(!storage.is_device_trusted(&jid, dev).unwrap());
    }

    // ── §2.1 Identity key pinning ─────────────────────────────────────────────

    /// Identity key change must reset trust to Untrusted.
    #[test]
    fn identity_key_change_resets_trust() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();
        let jid = bjid("frank@example.com");
        let dev = DeviceId::from(55u32);

        let id1 = fake_identity(dev, 0x11);
        storage.save_device_identity(&jid, &id1).unwrap();
        storage.set_trust_level(&jid, dev, TrustLevel::Verified).unwrap();

        assert_eq!(storage.get_trust_level(&jid, dev).unwrap(), TrustLevel::Verified);

        // Different identity key for the same device (key change scenario).
        let id2 = fake_identity(dev, 0x22); // 0x22 ≠ 0x11
        let changed = storage.save_fetched_identity(&jid, &id2, "fp2").unwrap();

        assert!(changed, "must detect the key change");
        assert_eq!(
            storage.get_trust_level(&jid, dev).unwrap(),
            TrustLevel::Untrusted,
            "trust must be reset to Untrusted after key change"
        );
    }

    /// Same key on refetch must preserve existing trust level.
    #[test]
    fn identical_key_refetch_preserves_trust() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();
        let jid = bjid("grace@example.com");
        let dev = DeviceId::from(60u32);

        let id = fake_identity(dev, 0x33);
        storage.save_device_identity(&jid, &id).unwrap();
        storage.set_trust_level(&jid, dev, TrustLevel::Verified).unwrap();

        let changed = storage.save_fetched_identity(&jid, &id, "fp").unwrap();
        assert!(!changed, "same key must not be flagged as changed");
        assert_eq!(storage.get_trust_level(&jid, dev).unwrap(), TrustLevel::Verified);
    }

    // ── §2.2 BTBV policy ─────────────────────────────────────────────────────

    /// First device for a contact → Undecided (blind trust before verification).
    #[test]
    fn btbv_first_device_is_undecided() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();
        let jid = bjid("alice@example.com");
        let dev = DeviceId::from(10u32);

        let id = fake_identity(dev, 0x01);
        storage.save_device_identity(&jid, &id).unwrap();

        assert_eq!(storage.get_trust_level(&jid, dev).unwrap(), TrustLevel::Undecided);
        assert!(storage.is_device_trusted(&jid, dev).unwrap());
    }

    /// After one device is manually verified, a new device for the same
    /// contact must be Untrusted (BTBV: blind trust only before first verification).
    #[test]
    fn btbv_new_device_after_verification_is_untrusted() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();
        let jid = bjid("bob@example.com");
        let dev1 = DeviceId::from(20u32);
        let dev2 = DeviceId::from(21u32);

        // First device: verify it.
        let id1 = fake_identity(dev1, 0x01);
        storage.save_device_identity(&jid, &id1).unwrap();
        storage.set_trust_level(&jid, dev1, TrustLevel::Verified).unwrap();

        // Second device appears for the same contact.
        let id2 = fake_identity(dev2, 0x02);
        storage.save_device_identity(&jid, &id2).unwrap();

        assert_eq!(
            storage.get_trust_level(&jid, dev2).unwrap(),
            TrustLevel::Untrusted,
            "new device after verification must be Untrusted per BTBV"
        );
        assert!(!storage.is_device_trusted(&jid, dev2).unwrap());
    }

    /// `has_verified_device` must return false when no device is verified.
    #[test]
    fn no_verified_device_returns_false() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();
        let jid = bjid("charlie@example.com");
        let dev = DeviceId::from(30u32);

        let id = fake_identity(dev, 0xAA);
        storage.save_device_identity(&jid, &id).unwrap();
        // Only Undecided → no verified device.
        assert!(!storage.has_verified_device(&jid).unwrap());
    }

    // ── §5 Replay rejection ───────────────────────────────────────────────────

    /// Replaying msg1 to bob after msg2 was sent must:
    ///   (a) be rejected (returns Err),
    ///   (b) not mutate ratchet state — msg2 must still decrypt.
    #[tokio::test]
    async fn replayed_message_rejected_and_ratchet_state_unchanged() -> Result<()> {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let alice_did = DeviceId::from(9001u32);
        let bob_did   = DeviceId::from(9002u32);

        let ps = Arc::new(MockPubSub { responses: Mutex::new(HashMap::new()) });

        let (mut alice, _adir) = make_manager(alice_jid, alice_did.get(), ps.clone()).await;
        let (mut bob,   _bdir) = make_manager(bob_jid,   bob_did.get(),   ps.clone()).await;

        ps.add_device_list(alice_jid, &[alice_did.get()]).await;
        ps.add_device_list(bob_jid,   &[bob_did.get()]).await;
        ps.add_bundle(alice_jid, alice_did.get(), alice.key_bundle.as_ref().unwrap()).await;
        ps.add_bundle(bob_jid,   bob_did.get(),   bob.key_bundle.as_ref().unwrap()).await;

        // Alice sends msg1 → bob decrypts it.
        let msg1 = alice.encrypt_message(bob_jid, "one").await?;
        let dec1 = bob.decrypt_message(alice_jid, alice_did, &msg1).await?;
        assert_eq!(dec1, "one");

        // Alice sends msg2.
        let msg2 = alice.encrypt_message(bob_jid, "two").await?;

        // Replay of msg1 must be rejected.
        let replay = bob.decrypt_message(alice_jid, alice_did, &msg1).await;
        assert!(replay.is_err(), "replayed message must be rejected, got: {:?}", replay);

        // Ratchet state must be intact: msg2 must decrypt correctly.
        let dec2 = bob.decrypt_message(alice_jid, alice_did, &msg2).await
            .expect("msg2 must decrypt after replay rejection");
        assert_eq!(dec2, "two", "msg2 content must survive replay");

        Ok(())
    }
}
