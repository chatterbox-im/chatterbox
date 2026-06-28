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

    use crate::omemo::device_id::DeviceId;
    use crate::omemo::protocol::X3DHKeyBundle;
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
            omemo_msg.prekey_devices.contains(&bob_device_id),
            "Bob's device should be in prekey_devices set"
        );

        // Verify: the encrypted key for Bob's device is a valid PreKeySignalMessage
        let encrypted_key = omemo_msg
            .encrypted_keys
            .get(&bob_device_id)
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
            &prekey_msg.identity_key, alice_identity_pub,
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
                    device_ids: vec![alice_device_id, alice_second_device_id],
                    last_update: chrono::Utc::now().timestamp(),
                })
                .expect("cached own device list should be saved");
        }

        let omemo_msg = alice
            .encrypt_message(bob_jid, "Hello Bob from Alice device 1")
            .await
            .expect("Encryption should succeed");

        assert!(
            omemo_msg.encrypted_keys.contains_key(&bob_device_id),
            "Recipient device should receive a message key"
        );
        assert!(
            omemo_msg
                .encrypted_keys
                .contains_key(&alice_second_device_id),
            "Second owned device should receive a message key for sent carbons"
        );
        assert!(
            !omemo_msg.encrypted_keys.contains_key(&alice_device_id),
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
            .decrypt_message(alice_jid, alice_device_id, &omemo_msg)
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
            !msg2.prekey_devices.contains(&bob_device_id),
            "Bob's device should not be in prekey_devices for second message"
        );

        // Verify the encrypted key is NOT a PreKeySignalMessage (just a regular SignalMessage)
        let encrypted_key = msg2
            .encrypted_keys
            .get(&bob_device_id)
            .expect("Should have encrypted key for Bob's device");
        let prekey_parse = PreKeySignalMessage::deserialize(encrypted_key);
        assert!(
            prekey_parse.is_none(),
            "Second message's encrypted key should NOT parse as PreKeySignalMessage"
        );
    }

    // -------------------------------------------------------------------------
    // Tests added for plan steps 1, 2, 4, 5
    // -------------------------------------------------------------------------

    /// Step 1a — A PreKeyMessage built against a recently-rotated (but still
    /// historic) SPK should decrypt successfully on the recipient.
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
            .get(&bob_device_id)
            .expect("key for Bob's device must exist");
        let prekey_msg = PreKeySignalMessage::deserialize(raw_key)
            .expect("should parse as PreKeySignalMessage");
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
                &old_bundle.identity_key_pair.private_key,
                &new_spk.public_key,
            )
            .unwrap();
            let mut history = old_bundle.signed_pre_key_history.clone();
            history.insert(old_bundle.signed_pre_key_id, old_bundle.signed_pre_key_pair.clone());
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
            .decrypt_message(alice_jid, alice_device_id, &omemo_msg)
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
            .get(&bob_device_id)
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
        tampered_msg.encrypted_keys.insert(bob_device_id, tampered_key);

        let err = bob
            .decrypt_message(alice_jid, alice_device_id, &tampered_msg)
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
            err_str.contains("No device") || err_str.contains("recipient") || err_str.contains("failed"),
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
            crate::omemo::storage::OmemoStorage::new(Some(alice_dir.path().to_path_buf()))
                .unwrap();
        {
            let meta = alice_dir.path().join("metadata");
            std::fs::create_dir_all(&meta).unwrap();
            std::fs::write(meta.join("device_id"), alice_device_id.to_string()).unwrap();
        }
        let mut alice1 = OmemoManager::new(
            alice_storage,
            alice_jid.to_string(),
            None,
            pubsub.clone(),
        )
        .await
        .unwrap();

        let (mut bob, _bob_dir) = create_manager(bob_jid, bob_device_id, pubsub.clone()).await;

        pubsub.add_device_list(bob_jid, &[bob_device_id]).await;
        pubsub.add_device_list(alice_jid, &[alice_device_id]).await;
        pubsub
            .add_bundle(bob_jid, bob_device_id, bob.key_bundle.as_ref().unwrap())
            .await;
        pubsub
            .add_bundle(alice_jid, alice_device_id, alice1.key_bundle.as_ref().unwrap())
            .await;

        // First encryption establishes session and persists ratchet state
        let msg1 = alice1
            .encrypt_message(bob_jid, "msg1")
            .await
            .expect("msg1 encryption should succeed");

        let dec1 = bob
            .decrypt_message(alice_jid, alice_device_id, &msg1)
            .await
            .expect("msg1 decryption should succeed");
        assert_eq!(dec1, "msg1");

        // Simulate restart: drop alice1 and load a fresh manager from same dir
        drop(alice1);

        let alice_storage2 =
            crate::omemo::storage::OmemoStorage::new(Some(alice_dir.path().to_path_buf()))
                .unwrap();
        let mut alice2 = OmemoManager::new(
            alice_storage2,
            alice_jid.to_string(),
            None,
            pubsub.clone(),
        )
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
            .decrypt_message(alice_jid, alice_device_id, &msg2)
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
            .set_session_rebuild_needed("alice@example.com", 42)
            .unwrap();
        storage1
            .set_prekey_pending("bob@example.com", 99)
            .unwrap();
        storage1
            .persist_failed_message_id("msg-id-deadbeef")
            .unwrap();

        // Simulate restart: new storage instance from same path
        let storage2 = OmemoStorage::new(Some(path)).unwrap();

        let rebuild = storage2.load_all_rebuild_pending();
        assert!(
            rebuild.contains(&("alice@example.com".to_string(), 42)),
            "rebuild flag must survive restart, got: {:?}",
            rebuild
        );

        let prekey = storage2.load_all_prekey_pending();
        assert!(
            prekey.contains(&("bob@example.com".to_string(), 99)),
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
        storage2.clear_session_rebuild_needed("alice@example.com", 42).unwrap();
        storage2.clear_prekey_pending("bob@example.com", 99).unwrap();

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
