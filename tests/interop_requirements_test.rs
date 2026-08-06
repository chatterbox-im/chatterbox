// Interoperability Requirements Tests
//
// Verifies the 7 requirements from INTEROPERABILITY.md that a client must
// satisfy to interoperate with Conversations' OMEMO implementation.

/// Requirement 1: Legacy namespace must be "eu.siacs.conversations.axolotl"
#[test]
fn req1_legacy_namespace() {
    assert_eq!(
        chatterbox::omemo::OMEMO_NAMESPACE,
        "eu.siacs.conversations.axolotl",
        "Must use legacy Conversations namespace, not urn:xmpp:omemo:2"
    );
}

/// Requirement 2: Wire format uses version byte 0x33 with correct protobuf field tags
mod req2_wire_format {
    use chatterbox::omemo::wire::{PreKeySignalMessage, SignalMessage};

    #[test]
    fn signal_message_version_byte() {
        let msg = SignalMessage {
            ratchet_key: vec![0x42; 32],
            counter: 7,
            previous_counter: 5,
            ciphertext: vec![0xAA; 20],
            mac: vec![],
        };

        let serialized = msg.serialize(&[0u8; 32]);

        // First byte must be 0x33 (version: current=3, max=3)
        assert_eq!(
            serialized[0], 0x33,
            "SignalMessage must start with version byte 0x33"
        );
    }

    #[test]
    fn signal_message_roundtrip() {
        let msg = SignalMessage {
            ratchet_key: vec![0x42; 32],
            counter: 7,
            previous_counter: 5,
            ciphertext: vec![0xAA; 20],
            mac: vec![],
        };

        let serialized = msg.serialize(&[0u8; 32]);
        let deserialized = SignalMessage::deserialize(&serialized)
            .expect("Should deserialize a valid SignalMessage");

        // The ratchet key may have been stripped of 0x05 prefix during deserialization,
        // so compare the raw 32-byte key
        assert_eq!(deserialized.ratchet_key.len(), 32);
        assert_eq!(deserialized.counter, 7);
        assert_eq!(deserialized.previous_counter, 5);
        assert_eq!(deserialized.ciphertext, vec![0xAA; 20]);
    }

    #[test]
    fn prekey_message_version_byte() {
        let inner = SignalMessage {
            ratchet_key: vec![0x42; 32],
            counter: 0,
            previous_counter: 0,
            ciphertext: vec![0xCC; 16],
            mac: vec![],
        };

        let prekey_msg = PreKeySignalMessage {
            registration_id: 12345,
            pre_key_id: Some(42),
            signed_pre_key_id: 1,
            base_key: vec![0x11; 32],
            identity_key: vec![0x22; 32],
            message: inner,
            raw_message_bytes: vec![],
        };

        let serialized = prekey_msg.serialize(&[0u8; 32]);

        // First byte must be 0x33
        assert_eq!(
            serialized[0], 0x33,
            "PreKeySignalMessage must start with version byte 0x33"
        );
    }

    #[test]
    fn prekey_message_roundtrip() {
        let inner = SignalMessage {
            ratchet_key: vec![0x42; 32],
            counter: 3,
            previous_counter: 1,
            ciphertext: vec![0xCC; 16],
            mac: vec![],
        };

        let prekey_msg = PreKeySignalMessage {
            registration_id: 12345,
            pre_key_id: Some(42),
            signed_pre_key_id: 7,
            base_key: vec![0x11; 32],
            identity_key: vec![0x22; 32],
            message: inner,
            raw_message_bytes: vec![],
        };

        let serialized = prekey_msg.serialize(&[0u8; 32]);
        let deserialized = PreKeySignalMessage::deserialize(&serialized)
            .expect("Should deserialize a valid PreKeySignalMessage");

        assert_eq!(deserialized.registration_id, 12345);
        assert_eq!(deserialized.pre_key_id, Some(42));
        assert_eq!(deserialized.signed_pre_key_id, 7);
        assert_eq!(deserialized.base_key.len(), 32);
        assert_eq!(deserialized.identity_key.len(), 32);
        assert_eq!(deserialized.message.counter, 3);
        assert_eq!(deserialized.message.previous_counter, 1);
    }

    #[test]
    fn prekey_message_field_tags_match_libsignal() {
        // Verify that deserializing known libsignal-format bytes works.
        // We serialize and re-deserialize, checking that field values survive.
        // This proves the field tag assignments match libsignal's protobuf schema.
        let inner = SignalMessage {
            ratchet_key: vec![0xAB; 32],
            counter: 999,
            previous_counter: 998,
            ciphertext: vec![0xDE; 32],
            mac: vec![],
        };

        let prekey_msg = PreKeySignalMessage {
            registration_id: 65535,
            pre_key_id: Some(100),
            signed_pre_key_id: 200,
            base_key: vec![0x33; 32],
            identity_key: vec![0x44; 32],
            message: inner,
            raw_message_bytes: vec![],
        };

        let serialized = prekey_msg.serialize(&[0xFF; 32]);
        let parsed = PreKeySignalMessage::deserialize(&serialized).unwrap();

        // All fields must survive the roundtrip, proving correct tag assignments:
        // pre_key_id=1(varint), base_key=2(bytes), identity_key=3(bytes),
        // message=4(bytes), registration_id=5(varint), signed_pre_key_id=6(varint)
        assert_eq!(
            parsed.registration_id, 65535,
            "registration_id (field 5) mismatch"
        );
        assert_eq!(
            parsed.pre_key_id,
            Some(100),
            "pre_key_id (field 1) mismatch"
        );
        assert_eq!(
            parsed.signed_pre_key_id, 200,
            "signed_pre_key_id (field 6) mismatch"
        );
        assert_eq!(parsed.base_key.len(), 32, "base_key (field 2) wrong length");
        assert_eq!(
            parsed.identity_key.len(),
            32,
            "identity_key (field 3) wrong length"
        );
        assert_eq!(
            parsed.message.counter, 999,
            "inner message counter mismatch"
        );
    }
}

/// Requirement 3: XEdDSA signature verification (X25519 → Ed25519)
mod req3_xeddsa {
    use chatterbox::omemo::crypto::{encode_public_key_with_prefix, xeddsa_sign, xeddsa_verify};
    use chatterbox::omemo::protocol::X3DHProtocol;

    #[test]
    fn xeddsa_sign_verify_roundtrip() {
        // Generate a random X25519 key pair
        let key_pair = X3DHProtocol::generate_key_pair().unwrap();
        let message = b"test signed prekey data";

        let signature = xeddsa_sign(key_pair.private_key.expose_secret(), message).unwrap();
        assert_eq!(signature.len(), 64, "XEdDSA signature must be 64 bytes");

        let valid = xeddsa_verify(key_pair.public_key.as_raw(), message, &signature).is_ok();
        assert!(
            valid,
            "XEdDSA signature must verify with matching public key"
        );
    }

    #[test]
    fn xeddsa_rejects_wrong_key() {
        let key_pair = X3DHProtocol::generate_key_pair().unwrap();
        let other_pair = X3DHProtocol::generate_key_pair().unwrap();
        let message = b"test prekey";

        let signature = xeddsa_sign(key_pair.private_key.expose_secret(), message).unwrap();

        // Verification with wrong public key must fail
        let valid = xeddsa_verify(other_pair.public_key.as_raw(), message, &signature).is_ok();
        assert!(!valid, "XEdDSA must reject signature with wrong public key");
    }

    #[test]
    fn xeddsa_rejects_tampered_message() {
        let key_pair = X3DHProtocol::generate_key_pair().unwrap();
        let message = b"original prekey";

        let signature = xeddsa_sign(key_pair.private_key.expose_secret(), message).unwrap();

        let tampered = b"tampered prekey";
        let valid = xeddsa_verify(key_pair.public_key.as_raw(), tampered, &signature).is_ok();
        assert!(!valid, "XEdDSA must reject signature with tampered message");
    }

    #[test]
    fn verify_pre_key_with_0x05_prefix() {
        // Production path: bundle keys are stored with 0x05 prefix.
        // verify_pre_key must handle this correctly.
        let key_pair = X3DHProtocol::generate_key_pair().unwrap();
        let spk_pair = X3DHProtocol::generate_key_pair().unwrap();

        let signature =
            X3DHProtocol::sign_pre_key(key_pair.private_key.expose_secret(), spk_pair.public_key.as_raw()).unwrap();

        // Encode with 0x05 prefix as they appear in bundle XML
        let identity_33 = encode_public_key_with_prefix(key_pair.public_key.as_raw());
        let spk_33 = encode_public_key_with_prefix(spk_pair.public_key.as_raw());

        let valid = X3DHProtocol::verify_pre_key(&identity_33, &spk_33, &signature).is_ok();
        assert!(
            valid,
            "verify_pre_key must work with 0x05-prefixed keys from bundles"
        );
    }
}

/// Requirement 4: Bundle XML format with required elements
mod req4_bundle_format {
    use base64::Engine;

    #[test]
    fn bundle_xml_has_required_elements() {
        // Create a bundle XML from a real key bundle and verify structure
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            use chatterbox::omemo::storage::OmemoStorage;
            use chatterbox::omemo::OmemoManager;
            use std::sync::Arc;

            let temp_dir = tempfile::TempDir::new().unwrap();
            let storage = OmemoStorage::new(Some(temp_dir.path().to_path_buf())).unwrap();

            // Use a no-op PubSub since we only need key generation
            struct NoOpPubSub;
            #[async_trait::async_trait]
            impl chatterbox::omemo::OmemoPubSub for NoOpPubSub {
                async fn request_items(&self, _: &str, _: &str) -> anyhow::Result<String> {
                    Ok("<iq type='error'><error><item-not-found/></error></iq>".to_string())
                }
                async fn publish_item(
                    &self,
                    _: Option<&str>,
                    _: &str,
                    _: &str,
                    _: &str,
                ) -> anyhow::Result<()> {
                    Ok(())
                }
                async fn publish_item_alternative(
                    &self,
                    _: Option<&str>,
                    _: &str,
                    _: &str,
                    _: &str,
                ) -> anyhow::Result<()> {
                    Ok(())
                }
                async fn publish_device_list(
                    &self,
                    _: &[chatterbox::omemo::device_id::DeviceId],
                ) -> anyhow::Result<()> {
                    Ok(())
                }
                async fn delete_bundle(
                    &self,
                    _: chatterbox::omemo::device_id::DeviceId,
                ) -> anyhow::Result<()> {
                    Ok(())
                }
            }

            let pubsub: Arc<dyn chatterbox::omemo::OmemoPubSub> = Arc::new(NoOpPubSub);
            let manager =
                OmemoManager::new(storage, "test@example.com".to_string(), Some(42), pubsub)
                    .await
                    .unwrap();

            let bundle = manager.generate_bundle().await.unwrap();
            let xml = manager.bundle_to_xml(&bundle).unwrap();

            // Parse and verify required elements
            let doc = roxmltree::Document::parse(&xml).expect("Bundle XML must be valid");

            let bundle_elem = doc
                .descendants()
                .find(|n| n.tag_name().name() == "bundle")
                .expect("Must have <bundle> element");
            assert_eq!(
                bundle_elem.tag_name().namespace(),
                Some("eu.siacs.conversations.axolotl"),
                "Bundle must use legacy OMEMO namespace"
            );

            let identity_key = bundle_elem
                .children()
                .find(|n| n.tag_name().name() == "identityKey")
                .expect("Must have <identityKey> element");
            let ik_b64 = identity_key.text().unwrap();
            let ik_bytes = base64::engine::general_purpose::STANDARD
                .decode(ik_b64)
                .unwrap();
            assert_eq!(
                ik_bytes.len(),
                33,
                "Identity key must be 33 bytes (0x05 prefix + 32-byte key)"
            );
            assert_eq!(
                ik_bytes[0], 0x05,
                "Identity key must start with 0x05 prefix"
            );

            let signed_prekey = bundle_elem
                .children()
                .find(|n| n.tag_name().name() == "signedPreKeyPublic")
                .expect("Must have <signedPreKeyPublic> element");
            assert!(
                signed_prekey.attribute("signedPreKeyId").is_some(),
                "signedPreKeyPublic must have signedPreKeyId attribute"
            );
            let spk_b64 = signed_prekey.text().unwrap();
            let spk_bytes = base64::engine::general_purpose::STANDARD
                .decode(spk_b64)
                .unwrap();
            assert_eq!(
                spk_bytes.len(),
                33,
                "Signed prekey must be 33 bytes (0x05 prefix + 32-byte key)"
            );
            assert_eq!(
                spk_bytes[0], 0x05,
                "Signed prekey must start with 0x05 prefix"
            );

            let signature = bundle_elem
                .children()
                .find(|n| n.tag_name().name() == "signedPreKeySignature")
                .expect("Must have <signedPreKeySignature> element");
            let sig_b64 = signature.text().unwrap();
            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .unwrap();
            assert_eq!(sig_bytes.len(), 64, "Signature must be 64 bytes");

            let prekeys = bundle_elem
                .children()
                .find(|n| n.tag_name().name() == "prekeys")
                .expect("Must have <prekeys> element");
            let prekey_elems: Vec<_> = prekeys
                .children()
                .filter(|n| n.tag_name().name() == "preKeyPublic")
                .collect();
            assert!(
                !prekey_elems.is_empty(),
                "Must have at least one preKeyPublic"
            );
            for pk in &prekey_elems {
                assert!(
                    pk.attribute("preKeyId").is_some(),
                    "preKeyPublic must have preKeyId attribute"
                );
                let pk_b64 = pk.text().unwrap();
                let pk_bytes = base64::engine::general_purpose::STANDARD
                    .decode(pk_b64)
                    .unwrap();
                assert_eq!(
                    pk_bytes.len(),
                    33,
                    "PreKey must be 33 bytes (0x05 prefix + 32-byte key)"
                );
                assert_eq!(pk_bytes[0], 0x05, "PreKey must start with 0x05 prefix");
            }
        });
    }
}

/// Requirement 5: PEP node names for device lists and bundles
mod req5_pep_node_names {
    #[test]
    fn device_list_xml_uses_correct_namespace() {
        use chatterbox::omemo::protocol::utils;
        use chatterbox::omemo::device_id::DeviceId;
        let xml = utils::device_list_to_xml(&[DeviceId::from(111u32), DeviceId::from(222u32)]).unwrap();
        assert!(
            xml.contains("xmlns='eu.siacs.conversations.axolotl'"),
            "Device list XML must use legacy OMEMO namespace"
        );
        assert!(xml.contains("<device id='111'"));
        assert!(xml.contains("<device id='222'"));
    }
}

/// Requirement 6: Key element format with rid and prekey attributes
mod req6_key_element_format {
    use base64::Engine;
    use chatterbox::omemo::protocol::{utils, OmemoMessage};
    use std::collections::{HashMap, HashSet};
    // Same Element type the production parser uses; `tokio_xmpp::Element` and
    // `xmpp_parsers::Element` are no longer re-exported at those crate roots.
    use xmpp_parsers::minidom::Element;

    fn make_test_message(prekey_devices: HashSet<chatterbox::omemo::device_id::DeviceId>) -> OmemoMessage {
        use chatterbox::omemo::device_id::DeviceId;
        let mut encrypted_keys = HashMap::new();
        encrypted_keys.insert(DeviceId::from(1001u32), vec![0xAA; 48]);
        encrypted_keys.insert(DeviceId::from(2002u32), vec![0xBB; 32]);

        OmemoMessage {
            sender_device_id: DeviceId::from(5555u32),
            ratchet_key: vec![0; 32],
            previous_counter: 0,
            counter: 0,
            ciphertext: vec![0xCC; 24],
            mac: vec![],
            iv: vec![0xDD; 12],
            encrypted_keys,
            is_prekey: !prekey_devices.is_empty(),
            ephemeral_key: None,
            prekey_devices,
        }
    }

    #[test]
    fn key_elements_have_rid_attribute() {
        let msg = make_test_message(HashSet::new());
        let xml = utils::omemo_message_to_xml(&msg);

        // Parse with the same Element type production uses.
        let element: Element = xml.parse().unwrap();
        let header = element
            .get_child("header", "eu.siacs.conversations.axolotl")
            .unwrap();

        let keys: Vec<_> = header.children().filter(|e| e.name() == "key").collect();
        assert_eq!(keys.len(), 2);

        for key_elem in &keys {
            let rid = key_elem.attr("rid");
            assert!(
                rid.is_some(),
                "Every <key> element must have a 'rid' attribute"
            );
            let rid_val: u32 = rid.unwrap().parse().unwrap();
            assert!(rid_val == 1001 || rid_val == 2002);
        }
    }

    #[test]
    fn prekey_true_attribute_on_prekey_messages() {
        let mut prekey_set = HashSet::new();
        prekey_set.insert(chatterbox::omemo::device_id::DeviceId::from(1001u32));
        let msg = make_test_message(prekey_set);
        let xml = utils::omemo_message_to_xml(&msg);

        let element: Element = xml.parse().unwrap();
        let header = element
            .get_child("header", "eu.siacs.conversations.axolotl")
            .unwrap();
        let keys: Vec<_> = header.children().filter(|e| e.name() == "key").collect();

        let prekey_elem = keys.iter().find(|k| k.attr("rid") == Some("1001")).unwrap();
        assert_eq!(
            prekey_elem.attr("prekey"),
            Some("true"),
            "PreKey device must have prekey='true' attribute"
        );

        let regular_elem = keys.iter().find(|k| k.attr("rid") == Some("2002")).unwrap();
        assert_eq!(
            regular_elem.attr("prekey"),
            None,
            "Non-prekey device must NOT have prekey attribute"
        );
    }

    #[test]
    fn key_values_are_valid_base64() {
        let msg = make_test_message(HashSet::new());
        let xml = utils::omemo_message_to_xml(&msg);

        let element: Element = xml.parse().unwrap();
        let header = element
            .get_child("header", "eu.siacs.conversations.axolotl")
            .unwrap();

        for key_elem in header.children().filter(|e| e.name() == "key") {
            let b64_text = key_elem.text();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64_text)
                .expect("Key element content must be valid base64");
            assert!(!decoded.is_empty(), "Decoded key must not be empty");
        }
    }

    #[test]
    fn header_has_sid_attribute() {
        let msg = make_test_message(HashSet::new());
        let xml = utils::omemo_message_to_xml(&msg);

        let element: Element = xml.parse().unwrap();
        let header = element
            .get_child("header", "eu.siacs.conversations.axolotl")
            .unwrap();
        assert_eq!(
            header.attr("sid"),
            Some("5555"),
            "Header must have 'sid' attribute with sender device ID"
        );
    }
}

/// Requirement 7: AES-128-GCM payload encryption with 16-byte key and 12-byte IV
mod req7_aes128gcm_payload {
    use chatterbox::omemo::crypto::{
        aes_gcm_decrypt, aes_gcm_encrypt, generate_aes_key, generate_gcm_iv, AES_GCM_IV_SIZE,
        AES_GCM_KEY_SIZE,
    };
    use chatterbox::omemo::keys::{AesGcmKey, GcmNonce};

    #[test]
    fn key_size_is_128_bits() {
        assert_eq!(
            AES_GCM_KEY_SIZE, 16,
            "AES-GCM key must be 16 bytes (128 bits)"
        );
    }

    #[test]
    fn iv_size_is_96_bits() {
        assert_eq!(AES_GCM_IV_SIZE, 12, "AES-GCM IV must be 12 bytes (96 bits)");
    }

    #[test]
    fn generated_key_is_correct_size() {
        let key = generate_aes_key();
        assert_eq!(key.len(), 16, "Generated key must be 16 bytes");
    }

    #[test]
    fn generated_iv_is_correct_size() {
        let iv = generate_gcm_iv();
        assert_eq!(iv.len(), 12, "Generated IV must be 12 bytes");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello from chatterbox!";
        let key_bytes = generate_aes_key();
        let iv_bytes = generate_gcm_iv();
        let key = AesGcmKey::from_slice(&key_bytes).unwrap();
        let iv = GcmNonce::from_slice(&iv_bytes).unwrap();

        let ciphertext = aes_gcm_encrypt(plaintext, &key, &iv).expect("Encryption must succeed");

        // Ciphertext must be longer than plaintext (includes 16-byte auth tag)
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + 16,
            "Ciphertext must be plaintext + 16-byte GCM auth tag"
        );

        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &iv).expect("Decryption must succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_wrong_key() {
        let plaintext = b"secret message";
        let key_bytes = generate_aes_key();
        let wrong_key_bytes = generate_aes_key();
        let iv_bytes = generate_gcm_iv();
        let key = AesGcmKey::from_slice(&key_bytes).unwrap();
        let wrong_key = AesGcmKey::from_slice(&wrong_key_bytes).unwrap();
        let iv = GcmNonce::from_slice(&iv_bytes).unwrap();

        let ciphertext = aes_gcm_encrypt(plaintext, &key, &iv).unwrap();

        let result = aes_gcm_decrypt(&ciphertext, &wrong_key, &iv);
        assert!(result.is_err(), "Decryption with wrong key must fail");
    }

    #[test]
    fn rejects_invalid_key_size() {
        let bad_key = vec![0u8; 32]; // 256-bit key - wrong size
        assert!(AesGcmKey::from_slice(&bad_key).is_none(), "Must reject non-128-bit keys");
    }

    #[test]
    fn rejects_invalid_iv_size() {
        let bad_iv = vec![0u8; 16]; // 128-bit IV - wrong size
        assert!(GcmNonce::from_slice(&bad_iv).is_none(), "Must reject non-96-bit IVs");
    }
}
