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
}
