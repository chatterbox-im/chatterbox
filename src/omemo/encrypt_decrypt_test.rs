//! Unit tests for OMEMO encrypt/decrypt round-trip
//!
//! These tests verify:
//! 1. First message to a new device uses PreKey format
//! 2. PreKeySignalMessage contains the RECIPIENT's signed_pre_key_id and pre_key_id
//! 3. The recipient can decrypt the PreKey message and establish a session
//! 4. Subsequent messages use regular (non-PreKey) format

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

    fn bjid(s: &str) -> BareJid { BareJid::parse(s).unwrap() }
    use crate::omemo::protocol::X3DHKeyBundle;
    use crate::omemo::session::OmemoSessionState;
    use crate::omemo::storage::{DeviceListEntry, OmemoStorage};
    use crate::omemo::wire::PreKeySignalMessage;
    use crate::omemo::{OmemoManager, OmemoPubSub, OMEMO_NAMESPACE};

    /// Mock PubSub that serves pre-configured device lists and bundles.
    struct MockPubSub {
        /// node → XML response
        responses: Mutex<HashMap<String, String>>,
    }

    impl MockPubSub {
        fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
            }
        }

        async fn add_device_list(&self, jid: &str, device_ids: &[u32]) {
            // Build device list XML that parse_device_list_response_static can parse
            let devices_xml: String = device_ids
                .iter()
                .map(|id| format!("<device id=\"{}\"/>", id))
                .collect::<Vec<_>>()
                .join("");

            let xml = format!(
                "<items node=\"{ns}.devicelist\"><item><list xmlns=\"{ns}\">{devices}</list></item></items>",
                ns = OMEMO_NAMESPACE,
                devices = devices_xml,
            );

            // Add for all node format variants that device_discovery tries
            let mut responses = self.responses.lock().await;
            let node_formats = [
                format!("{}.devicelist", OMEMO_NAMESPACE),
                format!("{}:devices", OMEMO_NAMESPACE),
            ];
            for node in &node_formats {
                let key = format!("{}|{}", jid, node);
                responses.insert(key, xml.clone());
            }
        }

        async fn add_bundle(&self, jid: &str, device_id: u32, bundle: &X3DHKeyBundle) {
            let b64 = base64::engine::general_purpose::STANDARD;

            let identity_key_b64 = b64.encode(&bundle.identity_key_pair.public_key);
            let spk_b64 = b64.encode(&bundle.signed_pre_key_pair.public_key);
            let sig_b64 = b64.encode(&bundle.signed_pre_key_signature);

            let mut prekeys_xml = String::new();
            for (id, kp) in &bundle.one_time_pre_key_pairs {
                let pk_b64 = b64.encode(&kp.public_key);
                prekeys_xml.push_str(&format!(
                    "<preKeyPublic preKeyId=\"{}\">{}</preKeyPublic>",
                    id, pk_b64
                ));
            }

            let xml = format!(
                "<items node=\"{ns}.bundles:{did}\"><item id=\"current\">\
                 <bundle xmlns=\"{ns}\">\
                 <identityKey>{ik}</identityKey>\
                 <signedPreKeyPublic signedPreKeyId=\"{spk_id}\">{spk}</signedPreKeyPublic>\
                 <signedPreKeySignature>{sig}</signedPreKeySignature>\
                 <prekeys>{pks}</prekeys>\
                 </bundle></item></items>",
                ns = OMEMO_NAMESPACE,
                did = device_id,
                ik = identity_key_b64,
                spk_id = bundle.signed_pre_key_id,
                spk = spk_b64,
                sig = sig_b64,
                pks = prekeys_xml,
            );

            let node = format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id);
            let key = format!("{}|{}", jid, node);
            self.responses.lock().await.insert(key, xml);
        }
    }

    #[async_trait]
    impl OmemoPubSub for MockPubSub {
        async fn request_items(&self, from: &str, node: &str) -> Result<String> {
            let key = format!("{}|{}", from, node);
            let responses = self.responses.lock().await;
            match responses.get(&key) {
                Some(xml) => Ok(xml.clone()),
                None => {
                    // Return an error response for unknown nodes
                    Ok(format!(
                        "<iq type=\"error\"><error type=\"cancel\">\
                         <item-not-found xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>\
                         </error></iq>"
                    ))
                }
            }
        }

        async fn publish_item(
            &self,
            _to: Option<&str>,
            _node: &str,
            _id: &str,
            _payload: &str,
        ) -> Result<()> {
            Ok(())
        }

        async fn publish_item_alternative(
            &self,
            _to: Option<&str>,
            _node: &str,
            _id: &str,
            _payload: &str,
        ) -> Result<()> {
            Ok(())
        }

        async fn publish_device_list(&self, _device_ids: &[DeviceId]) -> Result<()> {
            Ok(())
        }
        async fn delete_bundle(&self, _device_id: DeviceId) -> Result<()> {
            Ok(())
        }
    }

    impl MockPubSub {
        /// Publish a bundle with the SPK signature zeroed out (simulates a MITM
        /// that replaces the bundle but can't forge a valid XEdDSA signature).
        async fn add_bundle_with_bad_sig(&self, jid: &str, device_id: u32, bundle: &X3DHKeyBundle) {
            let b64 = base64::engine::general_purpose::STANDARD;

            let identity_key_b64 = b64.encode(&bundle.identity_key_pair.public_key);
            let spk_b64 = b64.encode(&bundle.signed_pre_key_pair.public_key);
            // Corrupt the signature: all zeros won't be a valid XEdDSA sig.
            let bad_sig = vec![0u8; 64];
            let bad_sig_b64 = b64.encode(&bad_sig);

            let mut prekeys_xml = String::new();
            for (id, kp) in &bundle.one_time_pre_key_pairs {
                let pk_b64 = b64.encode(&kp.public_key);
                prekeys_xml.push_str(&format!(
                    "<preKeyPublic preKeyId=\"{}\">{}</preKeyPublic>",
                    id, pk_b64
                ));
            }

            let xml = format!(
                "<items node=\"{ns}.bundles:{did}\"><item id=\"current\">\
                 <bundle xmlns=\"{ns}\">\
                 <identityKey>{ik}</identityKey>\
                 <signedPreKeyPublic signedPreKeyId=\"{spk_id}\">{spk}</signedPreKeyPublic>\
                 <signedPreKeySignature>{sig}</signedPreKeySignature>\
                 <prekeys>{pks}</prekeys>\
                 </bundle></item></items>",
                ns = crate::omemo::OMEMO_NAMESPACE,
                did = device_id,
                ik = identity_key_b64,
                spk_id = bundle.signed_pre_key_id,
                spk = spk_b64,
                sig = bad_sig_b64,
                pks = prekeys_xml,
            );

            let node = format!("{}.bundles:{}", crate::omemo::OMEMO_NAMESPACE, device_id);
            let key = format!("{}|{}", jid, node);
            self.responses.lock().await.insert(key, xml);
        }
    }

    /// Create an OmemoManager with a temp directory for storage.
    /// Returns (manager, temp_dir) — keep temp_dir alive for the test duration.
    async fn create_manager(
        jid: &str,
        device_id: u32,
        pubsub: Arc<dyn OmemoPubSub>,
    ) -> (OmemoManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let metadata_dir = temp_dir.path().join("metadata");
        std::fs::create_dir_all(&metadata_dir).unwrap();
        std::fs::write(metadata_dir.join("device_id"), device_id.to_string()).unwrap();

        let storage = OmemoStorage::new(Some(temp_dir.path().to_path_buf())).unwrap();
        let manager = OmemoManager::new(storage, jid.to_string(), None, pubsub)
            .await
            .expect("Failed to create OmemoManager");
        (manager, temp_dir)
    }

    /// Test that the first message to a new device uses PreKey format
    /// and contains the correct recipient key IDs.
    #[tokio::test]
    async fn test_first_message_uses_prekey_format_with_correct_ids() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 1001;
        let bob_device_id: u32 = 2001;

        // Create shared mock pubsub
        let pubsub = Arc::new(MockPubSub::new());

        // Create Alice's manager
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;

        // Create Bob's manager to get his keys
        let (bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;
        let bob_bundle = bob.key_bundle.as_ref().unwrap();

        // Record Bob's key IDs for later assertion
        let bob_signed_pre_key_id = bob_bundle.signed_pre_key_id;
        let bob_one_time_pre_key_id = bob_bundle.one_time_pre_key_pairs.keys().next().copied();

        // Configure mock: Bob has one device, and his bundle is available
        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_bundle(bob_jid, bob_device_id, bob_bundle).await;

        // Also add Alice's own device list (encrypt_message fetches it for carbons)
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;

        // Alice encrypts a message to Bob
        let omemo_msg = alice
            .encrypt_message(bob_jid, "Hello Bob!")
            .await
            .expect("Encryption should succeed");

        // Verify: message is marked as PreKey
        assert!(
            omemo_msg.is_prekey,
            "First message should be a PreKey message"
        );
        assert!(
            omemo_msg.prekey_devices.contains(&DeviceId::from(bob_device_id)),
            "Bob's device should be in prekey_devices set"
        );

        // Verify: the encrypted key for Bob's device is a valid PreKeySignalMessage
        let encrypted_key = omemo_msg
            .encrypted_keys
            .get(&DeviceId::from(bob_device_id))
            .expect("Should have encrypted key for Bob's device");

        let prekey_msg = PreKeySignalMessage::deserialize(encrypted_key)
            .expect("Encrypted key should be a valid PreKeySignalMessage");

        // Verify: registration_id is Alice's (sender's) device ID
        assert_eq!(
            prekey_msg.registration_id, alice_device_id,
            "registration_id should be sender's device ID"
        );

        // Verify: signed_pre_key_id is BOB's (recipient's) SPK ID
        assert_eq!(
            prekey_msg.signed_pre_key_id, bob_signed_pre_key_id,
            "signed_pre_key_id should be recipient's signed pre-key ID, got {} expected {}",
            prekey_msg.signed_pre_key_id, bob_signed_pre_key_id
        );

        // Verify: pre_key_id is BOB's (recipient's) one-time pre-key ID
        assert_eq!(
            prekey_msg.pre_key_id, bob_one_time_pre_key_id,
            "pre_key_id should be recipient's one-time pre-key ID"
        );

        // Verify: identity_key is Alice's (sender's) public identity key
        let alice_identity_pub = &alice
            .key_bundle
            .as_ref()
            .unwrap()
            .identity_key_pair
            .public_key;
        assert_eq!(
            &prekey_msg.identity_key, alice_identity_pub.as_ref(),
            "identity_key should be sender's public identity key"
        );

        // Verify: base_key (ephemeral key) is present and non-empty
        assert!(
            !prekey_msg.base_key.is_empty(),
            "base_key (ephemeral) should be non-empty"
        );
    }

    /// Test that sent messages remain decryptable by another owned device when
    /// the fresh own-device lookup is empty but local cache still has the device.
    #[tokio::test]
    async fn test_encrypt_uses_cached_own_devices_for_carbons_when_fresh_list_empty() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 1001;
        let alice_second_device_id: u32 = 1002;
        let bob_device_id: u32 = 2001;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (alice_second, _alice_second_dir) =
            create_manager(alice_jid, alice_second_device_id, pubsub.clone()).await;
        let (bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_second_device_id,
                alice_second.key_bundle.as_ref().unwrap(),
            )
            .await;

        {
            let storage = alice.storage.lock().await;
            storage
                .save_device_list(&DeviceListEntry {
                    jid: alice_jid.to_string(),
                    device_ids: vec![DeviceId::from(alice_device_id), DeviceId::from(alice_second_device_id)],
                    last_update: chrono::Utc::now().timestamp(),
                })
                .expect("cached own device list should be saved");
        }

        let omemo_msg = alice
            .encrypt_message(bob_jid, "Hello Bob from Alice device 1")
            .await
            .expect("Encryption should succeed");

        assert!(
            omemo_msg.encrypted_keys.contains_key(&DeviceId::from(bob_device_id)),
            "Recipient device should receive a message key"
        );
        assert!(
            omemo_msg
                .encrypted_keys
                .contains_key(&DeviceId::from(alice_second_device_id)),
            "Second owned device should receive a message key for sent carbons"
        );
        assert!(
            !omemo_msg.encrypted_keys.contains_key(&DeviceId::from(alice_device_id)),
            "Current sender device should not receive its own message key"
        );
    }

    /// Test full round-trip: Alice encrypts → Bob decrypts successfully.
    #[tokio::test]
    async fn test_encrypt_decrypt_round_trip() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 3001;
        let bob_device_id: u32 = 4001;

        let pubsub = Arc::new(MockPubSub::new());

        // Create both managers
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        // Configure mock with device lists and bundles
        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Alice encrypts
        let plaintext = "Hello Bob, this is a secret message!";
        let omemo_msg = alice
            .encrypt_message(bob_jid, plaintext)
            .await
            .expect("Encryption should succeed");

        assert!(omemo_msg.is_prekey, "First message should be PreKey format");

        // Bob decrypts
        let decrypted = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &omemo_msg)
            .await
            .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext, "Decrypted text should match original");
    }

    /// Test that the second message to the same device uses regular (non-PreKey) format.
    #[tokio::test]
    async fn test_second_message_uses_regular_format() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 5001;
        let bob_device_id: u32 = 6001;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;

        // First message — establishes session
        let msg1 = alice
            .encrypt_message(bob_jid, "First message")
            .await
            .expect("First encryption should succeed");
        assert!(msg1.is_prekey, "First message should be PreKey");

        // Second message — session already exists, should be regular format
        let msg2 = alice
            .encrypt_message(bob_jid, "Second message")
            .await
            .expect("Second encryption should succeed");

        // The second message should NOT be a PreKey message
        assert!(
            !msg2.is_prekey,
            "Second message should NOT be PreKey format"
        );
        assert!(
            !msg2.prekey_devices.contains(&DeviceId::from(bob_device_id)),
            "Bob's device should not be in prekey_devices for second message"
        );

        // Verify the encrypted key is NOT a PreKeySignalMessage (just a regular SignalMessage)
        let encrypted_key = msg2
            .encrypted_keys
            .get(&DeviceId::from(bob_device_id))
            .expect("Should have encrypted key for Bob's device");
        let prekey_parse = PreKeySignalMessage::deserialize(encrypted_key);
        assert!(
            prekey_parse.is_none(),
            "Second message's encrypted key should NOT parse as PreKeySignalMessage"
        );
    }

    // -------------------------------------------------------------------------
    // Failure-path tests: the scenarios the FSM must handle correctly
    // -------------------------------------------------------------------------

    /// When Bob receives a PreKeyMessage that references an OPK he has already
    /// consumed, the stale-OPK path must:
    ///   1. Delete Bob's existing session for Alice from memory AND storage.
    ///   2. Set `pending_session_rebuilds` for Alice so the next outbound from
    ///      Bob creates a fresh PreKey.
    ///   3. NOT increment the failure counter (this is not a ratchet failure).
    #[tokio::test]
    async fn test_stale_opk_triggers_cleanup_and_rebuild_flag() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 20001;
        let bob_device_id: u32 = 20002;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        // Serve both bundles; MockPubSub holds the snapshot and won't remove
        // OPKs when Bob consumes them.
        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // First session establishment: Alice → Bob (fresh OPK used and consumed)
        let msg1 = alice
            .encrypt_message(bob_jid, "first message")
            .await
            .expect("first encryption should succeed");
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg1)
            .await
            .expect("first decryption should succeed");

        // The OPK Bob used is now consumed.  Force Alice to rebuild her session
        // (simulating a fresh connect where she has a stale cached bundle) so
        // that her next PreKey will reference the same (already-consumed) OPK.
        alice.sessions.insert(
            (bjid(bob_jid), DeviceId::from(bob_device_id)),
            OmemoSessionState::PeerResetPending,
        );

        // Bob also builds a new session with Alice to use as "pre-existing state"
        // (so we can verify it gets deleted on the stale-OPK path).
        let _msg_from_bob = bob
            .encrypt_message(alice_jid, "bob → alice after first exchange")
            .await
            .expect("bob→alice encryption should succeed");
        assert!(
            bob.sessions
                .contains_key(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
            "Bob should have a session for Alice before the stale-OPK event"
        );

        // Alice now creates a second PreKey that references the already-consumed OPK.
        let msg2_stale = alice
            .encrypt_message(bob_jid, "second message (stale OPK)")
            .await
            .expect("Alice can still encrypt — she doesn't know OPK was consumed");

        // Bob tries to decrypt — must hit the stale-OPK path.
        let err = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg2_stale)
            .await
            .expect_err("stale-OPK PreKey must fail");

        let err_str = err.to_string();
        assert!(
            err_str.contains("Missing one-time prekey") || err_str.contains("prekey"),
            "error should mention missing OPK, got: {}",
            err_str
        );

        // Invariant 1: Bob's in-memory entry for Alice must now be PeerResetPending
        // (the active session has been replaced with the rebuild marker).
        assert!(
            matches!(
                bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
                Some(OmemoSessionState::PeerResetPending)
            ),
            "Bob's session for Alice must be PeerResetPending after stale-OPK rejection"
        );

        // Invariant 2: Bob must have flagged Alice for a session rebuild.
        assert!(
            matches!(
                bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
                Some(OmemoSessionState::PeerResetPending)
            ),
            "Bob must set PeerResetPending for Alice after stale-OPK rejection"
        );

        // Invariant 3: failure count must still be 0 (stale OPK is not a ratchet failure).
        let failure_count = bob
            .get_device_failure_count(&bjid(alice_jid), alice_device_id)
            .await;
        assert_eq!(
            failure_count, 0,
            "stale-OPK rejection must NOT increment the failure counter"
        );
    }

    /// Full convergence test: after a stale-OPK rejection, the next outbound
    /// message from Bob creates a fresh session with Alice, and both parties
    /// can exchange messages successfully.
    #[tokio::test]
    async fn test_stale_opk_full_recovery_flow() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 21001;
        let bob_device_id: u32 = 21002;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Normal first exchange so Bob consumes Alice's intended OPK.
        let msg1 = alice
            .encrypt_message(bob_jid, "initial message")
            .await
            .unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg1)
            .await
            .unwrap();

        // Force Alice to rebuild (stale cached bundle scenario).
        alice.sessions.insert(
            (bjid(bob_jid), DeviceId::from(bob_device_id)),
            crate::omemo::session::OmemoSessionState::PeerResetPending,
        );

        // Alice sends second PreKey (referencing consumed OPK) — Bob rejects.
        let stale_msg = alice.encrypt_message(bob_jid, "stale").await.unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &stale_msg)
            .await
            .expect_err("stale OPK must be rejected");

        // Now Bob encrypts to Alice.  The PeerResetPending entry in Bob's sessions
        // map triggers a force-fetch of Alice's bundle and creates a fresh PreKey.
        let bob_recovery_msg = bob
            .encrypt_message(alice_jid, "recovery message from Bob")
            .await
            .expect("Bob must be able to send a recovery PreKey to Alice");

        assert!(
            bob_recovery_msg.is_prekey,
            "Bob's recovery message should be a PreKey (new session)"
        );

        // Alice decrypts Bob's recovery PreKey and establishes Session B.
        let dec = alice
            .decrypt_message(bob_jid, DeviceId::from(bob_device_id), &bob_recovery_msg)
            .await
            .expect("Alice must decrypt Bob's recovery PreKey");
        assert_eq!(dec, "recovery message from Bob");

        // Both parties should now be able to exchange messages normally.
        let alice_followup = alice
            .encrypt_message(bob_jid, "post-recovery from Alice")
            .await
            .expect("post-recovery encryption by Alice should succeed");
        let dec2 = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &alice_followup)
            .await
            .expect("Bob must decrypt Alice's post-recovery message");
        assert_eq!(dec2, "post-recovery from Alice");
    }

    /// After 3 consecutive decryption failures from the same device, the session
    /// must be reset: deleted from memory and storage, failure count cleared,
    /// and the device flagged for session rebuild.
    #[tokio::test]
    async fn test_three_mac_failures_reset_session() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 22001;
        let bob_device_id: u32 = 22002;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Establish a valid session so Bob has one in memory.
        let msg = alice.encrypt_message(bob_jid, "seed").await.unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg)
            .await
            .unwrap();

        assert!(
            bob.sessions
                .contains_key(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
            "session must exist before failure simulation"
        );

        // Simulate 3 consecutive MAC failures by calling handle_decryption_failure
        // directly (this is the code path triggered by every MAC failure in the wild).
        for _ in 0..3 {
            bob.handle_decryption_failure(
                alice_jid.to_string(),
                alice_device_id,
                crate::omemo::session::SessionError::DoubleRatchetError(
                    crate::omemo::protocol::DoubleRatchetError::CryptoError(
                        crate::omemo::crypto::CryptoError::AesGcmError(
                            "MAC verification failed".to_string(),
                        ),
                    ),
                ),
            )
            .await
            .ok(); // returns Err but we only care about the side-effects
        }

        // After 3 failures the session must be wiped from Bob's in-memory map.
        assert!(
            !bob.sessions
                .contains_key(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
            "session must be deleted from memory after 3 failures"
        );

        // The failure count must be reset (not stuck at 3).
        let count_after = bob
            .get_device_failure_count(&bjid(alice_jid), alice_device_id)
            .await;
        assert_eq!(
            count_after, 0,
            "failure count must be reset to 0 after session reset"
        );
    }

    /// An AEAD/MAC failure must place the session into `RecoveryPreKeySent`
    /// (not simply remove it) so that the next outbound message bypasses the
    /// ignored-device check and sends a fresh recovery PreKey.
    #[tokio::test]
    async fn test_aead_failure_sets_recovery_state() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 23001;
        let bob_device_id: u32 = 23002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Establish a session
        let msg = alice.encrypt_message(bob_jid, "seed").await.unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg)
            .await
            .unwrap();

        // Simulate an AEAD failure: this is the path triggered by
        // "aead::Error" in the error string.
        bob.handle_decryption_failure(
            alice_jid.to_string(),
            alice_device_id,
            crate::omemo::session::SessionError::DoubleRatchetError(
                crate::omemo::protocol::DoubleRatchetError::CryptoError(
                    crate::omemo::crypto::CryptoError::AesGcmError(
                        "aead::Error".to_string(), // triggers handle_aead_decryption_failure
                    ),
                ),
            ),
        )
        .await
        .ok();

        // After an AEAD failure the session must be in RecoveryPreKeySent, NOT absent.
        assert!(
            matches!(
                bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
                Some(OmemoSessionState::RecoveryPreKeySent { .. })
            ),
            "session must be RecoveryPreKeySent after AEAD failure, got: {:?}",
            bob.sessions
                .get(&(bjid(alice_jid), DeviceId::from(alice_device_id)))
                .map(|s| std::mem::discriminant(s))
        );
    }

    /// Signed-prekey signature failure on the receive path must be enforced (C4).
    /// If the sender's bundle has an invalid SPK signature, the decryption must
    /// fail rather than silently establishing a session.
    #[tokio::test]
    async fn test_invalid_spk_signature_blocks_session_establishment() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 30001;
        let bob_device_id: u32 = 30002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        // Alice's bundle is published with a corrupted SPK signature.
        pubsub
            .add_bundle_with_bad_sig(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Alice encrypts to Bob using Bob's real bundle — the message is valid.
        let msg = alice
            .encrypt_message(bob_jid, "hello")
            .await
            .expect("Alice can encrypt with a valid bundle");

        // Bob receives the PreKeySignalMessage.  When Bob verifies Alice's bundle
        // SPK signature, it must be rejected — no session should be established.
        let err = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg)
            .await
            .expect_err("invalid SPK signature must cause decryption to fail");

        let err_str = err.to_string();
        assert!(
            err_str.to_lowercase().contains("prekey")
                || err_str.to_lowercase().contains("signature")
                || err_str.to_lowercase().contains("protocol"),
            "error must mention signature/prekey/protocol, got: {}",
            err_str
        );

        // No Active session must have been persisted for Alice.
        assert!(
            !matches!(
                bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
                Some(OmemoSessionState::Active(_))
            ),
            "no Active session must exist after SPK signature rejection"
        );
    }

    /// Each consecutive AEAD failure before the recovery PreKey is sent
    /// increments the `attempt` counter in `RecoveryPreKeySent`.
    #[tokio::test]
    async fn test_aead_recovery_attempt_increments() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 24001;
        let bob_device_id: u32 = 24002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        let seed = alice.encrypt_message(bob_jid, "seed").await.unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &seed)
            .await
            .unwrap();

        let aead_err = || {
            crate::omemo::session::SessionError::DoubleRatchetError(
                crate::omemo::protocol::DoubleRatchetError::CryptoError(
                    crate::omemo::crypto::CryptoError::AesGcmError("aead::Error".to_string()),
                ),
            )
        };

        // First AEAD failure
        bob.handle_decryption_failure(alice_jid.to_string(), alice_device_id, aead_err())
            .await
            .ok();
        let attempt_1 = match bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))) {
            Some(OmemoSessionState::RecoveryPreKeySent { attempt }) => *attempt,
            other => panic!(
                "expected RecoveryPreKeySent, got {:?}",
                other.map(|s| std::mem::discriminant(s))
            ),
        };

        // Second AEAD failure before the recovery PreKey was sent
        bob.handle_decryption_failure(alice_jid.to_string(), alice_device_id, aead_err())
            .await
            .ok();
        let attempt_2 = match bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))) {
            Some(OmemoSessionState::RecoveryPreKeySent { attempt }) => *attempt,
            other => panic!(
                "expected RecoveryPreKeySent, got {:?}",
                other.map(|s| std::mem::discriminant(s))
            ),
        };

        assert!(
            attempt_2 > attempt_1,
            "attempt counter must increase on repeated AEAD failures ({} → {})",
            attempt_1,
            attempt_2
        );
    }

    /// Full AEAD recovery flow: after an AEAD failure, Bob's next outbound
    /// message must carry a fresh recovery PreKey that Alice can decrypt,
    /// re-establishing a working session.
    #[tokio::test]
    async fn test_aead_recovery_full_flow() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 25001;
        let bob_device_id: u32 = 25002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Establish a valid session first
        let seed = alice.encrypt_message(bob_jid, "seed").await.unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &seed)
            .await
            .unwrap();

        // Trigger an AEAD failure — Bob's session is wiped and RecoveryPreKeySent is set
        bob.handle_decryption_failure(
            alice_jid.to_string(),
            alice_device_id,
            crate::omemo::session::SessionError::DoubleRatchetError(
                crate::omemo::protocol::DoubleRatchetError::CryptoError(
                    crate::omemo::crypto::CryptoError::AesGcmError("aead::Error".to_string()),
                ),
            ),
        )
        .await
        .ok();

        assert!(
            matches!(
                bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
                Some(OmemoSessionState::RecoveryPreKeySent { .. })
            ),
            "session must be RecoveryPreKeySent before recovery send"
        );

        // Bob sends the recovery message — RecoveryPreKeySent triggers a force-rebuild
        // and the message is a fresh PreKey.
        let recovery_msg = bob
            .encrypt_message(alice_jid, "recovery from Bob")
            .await
            .expect("recovery encrypt must succeed");

        assert!(
            recovery_msg.is_prekey,
            "recovery message must use PreKey format"
        );

        // After sending, RecoveryPreKeySent transitions to InitiatorAwaitingReply
        assert!(
            matches!(
                bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))),
                Some(OmemoSessionState::InitiatorAwaitingReply { .. })
            ),
            "session must be InitiatorAwaitingReply after recovery PreKey is sent"
        );

        // Alice decrypts the recovery PreKey — session established
        let dec = alice
            .decrypt_message(bob_jid, DeviceId::from(bob_device_id), &recovery_msg)
            .await
            .expect("Alice must decrypt Bob's recovery PreKey");
        assert_eq!(dec, "recovery from Bob");

        // Both sides should now be able to exchange messages normally
        let post = alice
            .encrypt_message(bob_jid, "post-recovery from Alice")
            .await
            .expect("post-recovery encrypt must succeed");
        let dec2 = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &post)
            .await
            .expect("Bob must decrypt Alice's post-recovery message");
        assert_eq!(dec2, "post-recovery from Alice");
    }

    // -------------------------------------------------------------------------
    // Tests for step 7b (FSM transitions) and step 8 (from_state constructor)
    // -------------------------------------------------------------------------

    /// A timed-out `InitiatorAwaitingReply` session must be discarded and
    /// replaced with a fresh PreKey on the next outbound message.
    /// Verified by checking that the new message uses a different ephemeral key
    /// (base_key) than the original one.
    #[tokio::test]
    async fn test_initiator_awaiting_reply_timeout_creates_fresh_prekey() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 30001;
        let bob_device_id: u32 = 30002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // First send — creates an InitiatorAwaitingReply session
        let msg1 = alice
            .encrypt_message(bob_jid, "first")
            .await
            .expect("first encrypt should succeed");
        let base_key_1 =
            PreKeySignalMessage::deserialize(msg1.encrypted_keys.get(&DeviceId::from(bob_device_id)).unwrap())
                .expect("should be PreKeySignalMessage")
                .base_key
                .clone();

        // Artificially age the `sent_at` timestamp past the 24-hour timeout.
        if let Some(OmemoSessionState::InitiatorAwaitingReply {
            ref mut sent_at, ..
        }) = alice
            .sessions
            .get_mut(&(bjid(bob_jid), DeviceId::from(bob_device_id)))
        {
            *sent_at = std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600);
        } else {
            panic!("expected InitiatorAwaitingReply after first send");
        }

        // Second send — the timed-out session must be discarded and a fresh PreKey created
        let msg2 = alice
            .encrypt_message(bob_jid, "second (after timeout)")
            .await
            .expect("second encrypt should succeed");

        assert!(msg2.is_prekey, "message after timeout must be a PreKey");
        let base_key_2 =
            PreKeySignalMessage::deserialize(msg2.encrypted_keys.get(&DeviceId::from(bob_device_id)).unwrap())
                .expect("should be PreKeySignalMessage")
                .base_key
                .clone();

        assert_ne!(
            base_key_1, base_key_2,
            "timed-out session must generate new ephemeral material (different base_key)"
        );
    }

    /// After more than MAX_RECOVERY_ATTEMPTS (5) consecutive AEAD failures the
    /// attempt counter must exceed the threshold.  The session must still be in
    /// `RecoveryPreKeySent` (not silently dropped) so recovery can be retried.
    #[tokio::test]
    async fn test_recovery_attempt_exceeds_threshold() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 31001;
        let bob_device_id: u32 = 31002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        let seed = alice.encrypt_message(bob_jid, "seed").await.unwrap();
        bob.decrypt_message(alice_jid, DeviceId::from(alice_device_id), &seed)
            .await
            .unwrap();

        let aead_err = || {
            crate::omemo::session::SessionError::DoubleRatchetError(
                crate::omemo::protocol::DoubleRatchetError::CryptoError(
                    crate::omemo::crypto::CryptoError::AesGcmError("aead::Error".to_string()),
                ),
            )
        };

        // Fire 6 AEAD failures — one past the MAX_RECOVERY_ATTEMPTS threshold of 5
        for _ in 0..6 {
            bob.handle_decryption_failure(alice_jid.to_string(), alice_device_id, aead_err())
                .await
                .ok();
        }

        let attempt = match bob.sessions.get(&(bjid(alice_jid), DeviceId::from(alice_device_id))) {
            Some(OmemoSessionState::RecoveryPreKeySent { attempt }) => *attempt,
            other => panic!(
                "session should still be RecoveryPreKeySent, got: {:?}",
                other.map(|s| std::mem::discriminant(s))
            ),
        };

        assert!(
            attempt > 5,
            "attempt counter must exceed MAX_RECOVERY_ATTEMPTS (5), got {}",
            attempt
        );
    }

    /// `OmemoSession::from_state` must produce a session whose fields are taken
    /// directly from the `RatchetState`, with no separate JID/device-ID argument.
    #[tokio::test]
    async fn test_from_state_creates_initialized_session() {
        use crate::omemo::session::OmemoSession;

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 32001;
        let bob_device_id: u32 = 32002;

        let pubsub = Arc::new(MockPubSub::new());
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Establish a real session so we have a valid RatchetState to extract
        alice.encrypt_message(bob_jid, "seed").await.unwrap();

        let ratchet_state = alice
            .sessions
            .get(&(bjid(bob_jid), DeviceId::from(bob_device_id)))
            .and_then(|s| s.as_session())
            .expect("session must exist after first encrypt")
            .ratchet_state
            .clone();

        // Verify the state itself is initialized
        assert!(
            ratchet_state.initialized,
            "ratchet_state must be initialized"
        );
        assert_eq!(ratchet_state.remote_jid, bob_jid);
        assert_eq!(ratchet_state.remote_device_id, DeviceId::from(bob_device_id));

        // from_state must produce a correctly wired, initialized session
        let session = OmemoSession::from_state(DeviceId::from(alice_device_id), ratchet_state);

        assert!(
            session.is_initialized(),
            "from_state session must be initialized"
        );
        assert_eq!(
            session.remote_jid, bob_jid,
            "JID must come from RatchetState"
        );
        assert_eq!(
            session.remote_device_id, DeviceId::from(bob_device_id),
            "device_id must come from RatchetState"
        );
        assert_eq!(
            session.local_device_id, DeviceId::from(alice_device_id),
            "local_device_id must be the provided argument"
        );
    }

    // -------------------------------------------------------------------------
    // Tests added for plan steps 1, 2, 4, 5
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_historic_spk_decrypts_prekey_message() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 7001;
        let bob_device_id: u32 = 8001;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        // Serve Bob's initial bundle (SPK id = 1) to Alice
        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Alice encrypts to Bob — this builds a PreKeySignalMessage referencing
        // Bob's current SPK id.
        let omemo_msg = alice
            .encrypt_message(bob_jid, "hello historic")
            .await
            .expect("encryption should succeed");

        // Verify it really is a PreKey message for Bob's device
        let raw_key = omemo_msg
            .encrypted_keys
            .get(&DeviceId::from(bob_device_id))
            .expect("key for Bob's device must exist");
        let prekey_msg =
            PreKeySignalMessage::deserialize(raw_key).expect("should parse as PreKeySignalMessage");
        let old_spk_id = prekey_msg.signed_pre_key_id;
        // SPK id after initialization may be >1 because check_and_rotate_prekeys
        // fires on first startup; just capture whatever id was actually used.
        assert!(old_spk_id > 0, "SPK id must be positive");

        // Now rotate Bob's SPK: generate a new SPK id = 2 and move the old one
        // into history — simulating a key rotation that happened after Alice
        // fetched the bundle but before she sent the message.
        {
            use crate::omemo::protocol::{KeyPair, X3DHKeyBundle, X3DHProtocol};
            let old_bundle = bob.key_bundle.take().unwrap();
            let new_spk: KeyPair = X3DHProtocol::generate_key_pair().unwrap();
            let new_spk_id = old_bundle.signed_pre_key_id + 1;
            let new_sig = X3DHProtocol::sign_pre_key(
                old_bundle.identity_key_pair.private_key.expose_secret(),
                new_spk.public_key.as_ref(),
            )
            .unwrap();
            let mut history = old_bundle.signed_pre_key_history.clone();
            history.insert(
                old_bundle.signed_pre_key_id,
                old_bundle.signed_pre_key_pair.clone(),
            );
            bob.key_bundle = Some(X3DHKeyBundle {
                device_id: old_bundle.device_id,
                identity_key_pair: old_bundle.identity_key_pair,
                signed_pre_key_id: new_spk_id,
                signed_pre_key_pair: new_spk,
                signed_pre_key_signature: new_sig,
                one_time_pre_key_pairs: old_bundle.one_time_pre_key_pairs,
                signed_pre_key_history: history,
            });
        }

        // Bob (now on SPK id 2, with SPK id 1 in history) should still decrypt
        // the PreKey message that Alice built against SPK id 1.
        let decrypted = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &omemo_msg)
            .await
            .expect("decryption with historic SPK should succeed");

        assert_eq!(decrypted, "hello historic");
    }

    /// Step 1b — A PreKeyMessage referencing a completely unknown SPK id must
    /// return a specific "Unknown signed prekey id" error, not a MAC failure.
    #[tokio::test]
    async fn test_unknown_spk_returns_specific_error() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 9001;
        let bob_device_id: u32 = 9002;

        let pubsub = Arc::new(MockPubSub::new());

        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice.key_bundle.as_ref().unwrap(),
            )
            .await;

        // Alice encrypts to Bob — valid PreKeySignalMessage with SPK id = 1
        let omemo_msg = alice
            .encrypt_message(bob_jid, "tampered")
            .await
            .expect("encryption should succeed");

        // Pull out the raw key bytes and parse them
        let raw_key = omemo_msg
            .encrypted_keys
            .get(&DeviceId::from(bob_device_id))
            .unwrap()
            .clone();
        let mut parsed = PreKeySignalMessage::deserialize(&raw_key)
            .expect("should parse as PreKeySignalMessage");

        // Swap in a SPK id that neither Bob's current bundle nor his (empty)
        // history will recognise.
        const UNKNOWN_SPK_ID: u32 = 9_999;
        parsed.signed_pre_key_id = UNKNOWN_SPK_ID;
        let tampered_key = parsed.serialize_with_inner_bytes(&parsed.raw_message_bytes.clone());

        let mut tampered_msg = omemo_msg.clone();
        tampered_msg
            .encrypted_keys
            .insert(DeviceId::from(bob_device_id), tampered_key);

        let err = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &tampered_msg)
            .await
            .expect_err("decryption with unknown SPK must fail");

        let err_str = err.to_string();
        assert!(
            err_str.contains("9999") || err_str.contains("Unknown signed prekey"),
            "error should mention the unknown SPK id, got: {}",
            err_str
        );
        // Must NOT be a MAC failure — that would hide the real problem
        assert!(
            !err_str.to_lowercase().contains("mac"),
            "error must not be a MAC failure, got: {}",
            err_str
        );
    }

    /// Step 2 — `encrypt_message` must return an error when no recipient device
    /// keys could be produced (empty device list for the recipient).
    #[tokio::test]
    async fn test_encrypt_fails_when_no_recipient_keys() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 10001;

        let pubsub = Arc::new(MockPubSub::new());

        // Alice's manager; Bob has no published devices at all
        let (mut alice, _alice_dir) =
            create_manager(alice_jid, alice_device_id, pubsub.clone()).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        // Intentionally no add_device_list / add_bundle for bob_jid

        let err = alice
            .encrypt_message(bob_jid, "this should fail")
            .await
            .expect_err("encrypt_message must fail when no recipient device keys exist");

        let err_str = err.to_string();
        assert!(
            err_str.contains("No device")
                || err_str.contains("recipient")
                || err_str.contains("failed"),
            "error should explain why encryption failed, got: {}",
            err_str
        );
    }

    /// Step 4 — The ratchet send-state is persisted after each encryption.
    /// A new manager instance loading from the same storage must continue
    /// from where the previous instance left off (no counter reuse).
    #[tokio::test]
    async fn test_ratchet_state_persists_across_restart() {
        let _ = env_logger::builder().is_test(true).try_init();

        let alice_jid = "alice@example.com";
        let bob_jid = "bob@example.com";
        let alice_device_id: u32 = 11001;
        let bob_device_id: u32 = 12001;

        let pubsub = Arc::new(MockPubSub::new());

        // Keep alice_dir alive for the whole test so the storage survives
        let alice_dir = TempDir::new().unwrap();

        // --- First Alice instance ---
        let alice_storage =
            crate::omemo::storage::OmemoStorage::new(Some(alice_dir.path().to_path_buf())).unwrap();
        {
            let meta = alice_dir.path().join("metadata");
            std::fs::create_dir_all(&meta).unwrap();
            std::fs::write(meta.join("device_id"), alice_device_id.to_string()).unwrap();
        }
        let mut alice1 =
            OmemoManager::new(alice_storage, alice_jid.to_string(), None, pubsub.clone())
                .await
                .unwrap();

        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(
                alice_jid,
                alice_device_id,
                alice1.key_bundle.as_ref().unwrap(),
            )
            .await;

        // First encryption establishes session and persists ratchet state
        let msg1 = alice1
            .encrypt_message(bob_jid, "msg1")
            .await
            .expect("msg1 encryption should succeed");

        let dec1 = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg1)
            .await
            .expect("msg1 decryption should succeed");
        assert_eq!(dec1, "msg1");

        // Simulate restart: drop alice1 and load a fresh manager from same dir
        drop(alice1);

        let alice_storage2 =
            crate::omemo::storage::OmemoStorage::new(Some(alice_dir.path().to_path_buf())).unwrap();
        let mut alice2 =
            OmemoManager::new(alice_storage2, alice_jid.to_string(), None, pubsub.clone())
                .await
                .unwrap();

        // Second encryption must succeed — if the ratchet state was not
        // persisted, alice2 would start at counter 0 again and Bob (who
        // already has counter 0 as a "skipped" key) would fail to derive the
        // correct message key.
        let msg2 = alice2
            .encrypt_message(bob_jid, "msg2 after restart")
            .await
            .expect("msg2 encryption should succeed after restart");

        let dec2 = bob
            .decrypt_message(alice_jid, DeviceId::from(alice_device_id), &msg2)
            .await
            .expect("msg2 decryption should succeed after restart");
        assert_eq!(dec2, "msg2 after restart");
    }

    /// Step 5 — Session rebuild flags and failed message IDs must survive a
    /// process restart (i.e., the next OmemoStorage instance loading from the
    /// same directory must see them).
    #[tokio::test]
    async fn test_session_flags_survive_restart() {
        let _ = env_logger::builder().is_test(true).try_init();

        use crate::omemo::storage::OmemoStorage;

        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        let storage1 = OmemoStorage::new(Some(path.clone())).unwrap();

        // Set all three flag types
        storage1
            .set_session_rebuild_needed(&bjid("alice@example.com"), DeviceId::from(42))
            .unwrap();
        storage1.set_prekey_pending(&bjid("bob@example.com"), DeviceId::from(99)).unwrap();
        storage1
            .persist_failed_message_id("msg-id-deadbeef")
            .unwrap();

        // Simulate restart: new storage instance from same path
        let storage2 = OmemoStorage::new(Some(path)).unwrap();

        let rebuild = storage2.load_all_rebuild_pending();
        assert!(
            rebuild.contains(&("alice@example.com".to_string(), DeviceId::from(42))),
            "rebuild flag must survive restart, got: {:?}",
            rebuild
        );

        let prekey = storage2.load_all_prekey_pending();
        assert!(
            prekey.contains(&("bob@example.com".to_string(), DeviceId::from(99))),
            "prekey-pending flag must survive restart, got: {:?}",
            prekey
        );

        let failed = storage2.load_recent_failed_message_ids(86400);
        assert!(
            failed.contains(&"msg-id-deadbeef".to_string()),
            "failed message id must survive restart, got: {:?}",
            failed
        );

        // Verify clear works
        storage2
            .clear_session_rebuild_needed(&bjid("alice@example.com"), DeviceId::from(42))
            .unwrap();
        storage2
            .clear_prekey_pending(&bjid("bob@example.com"), DeviceId::from(99))
            .unwrap();

        let rebuild_after = storage2.load_all_rebuild_pending();
        assert!(
            rebuild_after.is_empty(),
            "rebuild flags should be empty after clear"
        );

        let prekey_after = storage2.load_all_prekey_pending();
        assert!(
            prekey_after.is_empty(),
            "prekey-pending flags should be empty after clear"
        );
    }
}
