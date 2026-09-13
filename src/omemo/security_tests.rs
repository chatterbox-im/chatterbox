//! Security-critical tests for trust enforcement and BTBV policy.
//!
//! Phase 2 of the test suite rebuild.  Tests that cannot fail are not tests.
//! Every test here either asserts a negative (bad input is rejected) or
//! asserts an absent key (the device is not in encrypted_keys).

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use crate::jid::BareJid;
    use crate::omemo::device_id::DeviceId;
    use crate::omemo::protocol::{DeviceIdentity, PreKeyBundle, SignedPreKeyBundle};
    use crate::omemo::storage::{OmemoStorage, TrustLevel};
    use crate::omemo::test_support::{RecordingPubSub, make_manager};

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

    // ── §2.1 Trust enforcement at storage boundary ────────────────────────────

    /// `get_trust_level` must return `Err` for a corrupt DB row.
    /// Today's code returns `Err` here (the storage fix is already in), but
    /// `encrypt.rs` still swallows it with `unwrap_or(Undecided)`.
    #[test]
    fn malformed_trust_string_errors_not_defaults_to_undecided() {
        let dir = TempDir::new().unwrap();
        let storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
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
        let storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
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


    /// A corrupt trust DB row must not grant encryption rights (fail-closed).
    /// carol_did_a stays trusted (default Undecided) so encryption succeeds;
    /// carol_did_b has its row corrupted and must be absent from encrypted_keys.
    #[tokio::test]
    async fn corrupt_trust_at_encrypt_site_fails_safe() -> Result<()> {
        let alice_jid  = "alice@example.com";
        let carol_jid  = "carol@example.com";
        let alice_did  = 1002u32;
        let carol_did_a = 3003u32; // default Undecided = trusted
        let carol_did_b = 3004u32; // trust row will be corrupted

        let ps = RecordingPubSub::new();
        let (mut alice, adir)  = make_manager(alice_jid, alice_did,   ps.clone()).await;
        let (carol_a, _cadir)  = make_manager(carol_jid, carol_did_a, ps.clone()).await;
        let (carol_b, _cbdir)  = make_manager(carol_jid, carol_did_b, ps.clone()).await;

        ps.add_device_list(carol_jid, &[carol_did_a, carol_did_b]).await;
        ps.add_bundle(carol_jid, carol_did_a, carol_a.key_bundle.as_ref().unwrap()).await;
        ps.add_bundle(carol_jid, carol_did_b, carol_b.key_bundle.as_ref().unwrap()).await;
        ps.add_device_list(alice_jid, &[alice_did]).await;

        // Give carol_did_b a valid Trusted row, then corrupt the string.
        {
            let storage = alice.storage.lock().await;
            storage.set_trust_level(&bjid(carol_jid), DeviceId::from(carol_did_b), TrustLevel::Trusted)?;
        }
        let db_path = adir.path().join("omemo.sqlite3");
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE device_identities SET trust_level = 'trusetd' WHERE jid = ?1 AND device_id = ?2",
                rusqlite::params![carol_jid, carol_did_b],
            ).unwrap();
        }

        let msg = alice.encrypt_message(carol_jid, "hello")
            .await
            .expect("carol_did_a is trusted — encryption must succeed");

        assert!(
            msg.encrypted_keys.contains_key(&DeviceId::from(carol_did_a)),
            "trusted device carol_did_a must be included in encrypted_keys"
        );
        assert!(
            !msg.encrypted_keys.contains_key(&DeviceId::from(carol_did_b)),
            "device with corrupt trust must be excluded (fail-closed)"
        );
        Ok(())
    }

    // ── §2.1 Trust storage properties ────────────────────────────────────────

    /// Trust level must survive storage restart.
    #[test]
    fn trust_survives_restart() {
        let dir = TempDir::new().unwrap();
        let storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let jid = bjid("dave@example.com");
        let dev = DeviceId::from(77u32);

        storage.set_trust_level(&jid, dev, TrustLevel::Verified).unwrap();

        let storage2 = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(storage2.get_trust_level(&jid, dev).unwrap(), TrustLevel::Verified);
    }


    // ── §2.1 Identity key pinning ─────────────────────────────────────────────



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

        let ps = RecordingPubSub::new();

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
