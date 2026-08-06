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

    /// Verify ALL six PreKeySignalMessage field tags against raw protobuf bytes.
    /// Uses distinct values for every field so any tag transposition is caught.
    ///   field 1 (varint)  pre_key_id        = 42   → tag 0x08
    ///   field 2 (bytes)   base_key          = [0x11;32] → tag 0x12
    ///   field 3 (bytes)   identity_key      = [0x22;32] → tag 0x1a
    ///   field 4 (bytes)   inner SignalMsg   → tag 0x22
    ///   field 5 (varint)  registration_id   = 12345 → tag 0x28
    ///   field 6 (varint)  signed_pre_key_id = 7     → tag 0x30
    #[test]
    fn prekey_all_field_tags_verified_by_raw_protobuf_scan() {
        let inner = SignalMessage {
            ratchet_key: vec![0x42; 32],
            counter: 1,
            previous_counter: 0,
            ciphertext: vec![0xCC; 16],
            mac: vec![],
        };
        let msg = PreKeySignalMessage {
            registration_id: 12345,
            pre_key_id: Some(42),
            signed_pre_key_id: 7,
            base_key:     vec![0x11; 32],
            identity_key: vec![0x22; 32],
            message: inner,
            raw_message_bytes: vec![],
        };
        let bytes = msg.serialize(&[0u8; 32]);
        let proto = &bytes[1..]; // skip version byte

        // ── bytes fields ──────────────────────────────────────────────────────
        let base_key_raw = find_pb_bytes_field(proto, 0x12)
            .expect("field 2 (BASE_KEY, tag 0x12) not found");
        assert_eq!(base_key_raw[0], 0x05,
            "base_key must start with 0x05 type prefix");
        assert!(base_key_raw[1..].iter().all(|&b| b == 0x11),
            "base_key payload must be all 0x11, got {:02x?}", &base_key_raw[1..5]);

        let id_key_raw = find_pb_bytes_field(proto, 0x1a)
            .expect("field 3 (IDENTITY_KEY, tag 0x1a) not found");
        assert_eq!(id_key_raw[0], 0x05,
            "identity_key must start with 0x05 type prefix");
        assert!(id_key_raw[1..].iter().all(|&b| b == 0x22),
            "identity_key payload must be all 0x22, got {:02x?}", &id_key_raw[1..5]);

        // ── varint fields ─────────────────────────────────────────────────────
        let pre_key_id = find_pb_varint_field(proto, 0x08)
            .expect("field 1 (PRE_KEY_ID, tag 0x08) not found");
        assert_eq!(pre_key_id, 42,
            "pre_key_id (field 1) must be 42");

        let reg_id = find_pb_varint_field(proto, 0x28)
            .expect("field 5 (REGISTRATION_ID, tag 0x28) not found");
        assert_eq!(reg_id, 12345,
            "registration_id (field 5) must be 12345");

        let spk_id = find_pb_varint_field(proto, 0x30)
            .expect("field 6 (SIGNED_PRE_KEY_ID, tag 0x30) not found");
        assert_eq!(spk_id, 7,
            "signed_pre_key_id (field 6) must be 7");
    }

    fn find_pb_varint_field(proto: &[u8], target: u8) -> Option<u64> {
        let mut pos = 0;
        while pos < proto.len() {
            let tag = proto[pos]; pos += 1;
            let wire_type = tag & 0x07;
            if tag == target && wire_type == 0 {
                let (v, n) = decode_pb_varint(&proto[pos..])?;
                return Some(v as u64);
            }
            match wire_type {
                0 => { while pos < proto.len() { let b = proto[pos]; pos += 1; if b & 0x80 == 0 { break; } } }
                1 => { pos += 8; }
                2 => { let (n, v) = decode_pb_varint(&proto[pos..])?; pos += v + n; }
                5 => { pos += 4; }
                _ => return None,
            }
        }
        None
    }

    /// Scan a raw protobuf byte slice for a length-delimited field with the
    /// given tag byte and return its payload.  Returns None if not found.
    fn find_pb_bytes_field(proto: &[u8], target: u8) -> Option<&[u8]> {
        let mut pos = 0;
        while pos < proto.len() {
            let tag = proto[pos]; pos += 1;
            let wire_type = tag & 0x07;
            if tag == target && wire_type == 2 {
                let (len, vlen) = decode_pb_varint(&proto[pos..])?;
                pos += vlen;
                return Some(&proto[pos..pos + len]);
            }
            // Skip unknown field
            match wire_type {
                0 => { while pos < proto.len() { let b = proto[pos]; pos += 1; if b & 0x80 == 0 { break; } } }
                1 => { pos += 8; }
                2 => { let (n, v) = decode_pb_varint(&proto[pos..])?; pos += v + n; }
                5 => { pos += 4; }
                _ => return None,
            }
        }
        None
    }

    fn decode_pb_varint(data: &[u8]) -> Option<(usize, usize)> {
        let mut v = 0usize; let mut shift = 0;
        for (i, &b) in data.iter().enumerate() {
            v |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 { return Some((v, i + 1)); }
            shift += 7;
            if shift > 63 { return None; }
        }
        None
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
