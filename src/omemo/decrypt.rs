// src/omemo/decrypt.rs
//! OMEMO message decryption

use hex;
use log::{debug, error, info, warn};
use std::time::Instant;

use crate::omemo::crypto;
use crate::omemo::protocol::{self, OmemoMessage};
use crate::omemo::session::{self, OmemoSession};
use crate::omemo::{OmemoError, OmemoManager};

impl OmemoManager {
    /// Decrypt a message from a sender
    pub async fn decrypt_message(
        &mut self,
        sender: &str,
        device_id: u32,
        message: &OmemoMessage,
    ) -> Result<String, OmemoError> {
        info!("Decrypting message from {}:{}", sender, device_id);

        let bare_jid = Self::normalize_jid_to_bare(sender);

        // First, check if we have an encrypted key for our device
        info!(
            "DECRYPT_DEBUG: Looking for encrypted key for our device {} in message from {}:{}",
            self.device_id, sender, device_id
        );

        let encrypted_key = match message.encrypted_keys.get(&self.device_id) {
            Some(key) => key.clone(),
            None => {
                error!(
                    "DECRYPT_DEBUG: No encrypted key found for our device {} in message from {}:{}",
                    self.device_id, sender, device_id
                );
                return Err(OmemoError::MissingDataError(format!(
                    "No encrypted key found for device {} (our device not in recipient list)",
                    self.device_id
                )));
            }
        };

        // Check if this is a PreKey message by trying to parse the encrypted key as PreKeySignalMessage
        if let Some(prekey_msg) =
            crate::omemo::wire::PreKeySignalMessage::deserialize(&encrypted_key)
        {
            info!(
                "Received PreKeySignalMessage from {}:{} (pre_key_id={:?}, spk_id={})",
                sender, device_id, prekey_msg.pre_key_id, prekey_msg.signed_pre_key_id
            );

            let ephemeral_key = prekey_msg.base_key.clone();

            let our_identity_key_pair = match &self.key_bundle {
                Some(bundle) => bundle.identity_key_pair.clone(),
                None => {
                    return Err(OmemoError::SessionError(
                        session::SessionError::InvalidStateError(
                            "Key bundle not initialized".to_string(),
                        ),
                    ))
                }
            };
            let our_signed_prekey_pair = match &self.key_bundle {
                Some(bundle) => bundle.signed_pre_key_pair.clone(),
                None => {
                    return Err(OmemoError::SessionError(
                        session::SessionError::InvalidStateError(
                            "Key bundle not initialized".to_string(),
                        ),
                    ))
                }
            };

            // Look up the one-time prekey pair if pre_key_id is provided
            let one_time_prekey_pair = if let Some(opk_id) = prekey_msg.pre_key_id {
                match &self.key_bundle {
                    Some(bundle) => bundle
                        .one_time_pre_key_pairs
                        .get(&opk_id)
                        .map(|kp| kp.clone()),
                    None => None,
                }
            } else {
                None
            };

            if prekey_msg.pre_key_id.is_some() && one_time_prekey_pair.is_none() {
                warn!("PreKeyMessage references OPK id {:?} but we don't have it — cannot establish session (sender needs our fresh bundle)", prekey_msg.pre_key_id);

                // Republish our bundle so the sender can fetch fresh OPKs
                if let Err(e) = self.publish_bundle_to_server().await {
                    warn!("Failed to republish bundle after missing OPK: {}", e);
                }

                // Mark the sender's session for rebuild so that the next time we
                // encrypt for them we force-fetch their current bundle and create a
                // fresh session.  Without this, our stored (potentially stale) session
                // for the sender would keep producing Signal messages that the sender
                // cannot decrypt because they never received our key-agreement reply.
                self.pending_session_rebuilds.insert((bare_jid.clone(), device_id));

                return Err(OmemoError::SessionError(
                    session::SessionError::InvalidStateError(format!(
                        "Missing one-time prekey {} — sender must re-establish session with fresh bundle",
                        prekey_msg.pre_key_id.unwrap()
                    ))
                ));
            }

            // Verify sender's identity key signature on their bundle
            let sender_identity = self.get_device_identity(&bare_jid, device_id).await?;
            match protocol::X3DHProtocol::verify_pre_key(
                &sender_identity.identity_key,
                &sender_identity.signed_pre_key.public_key,
                &sender_identity.signed_pre_key.signature,
            ) {
                Ok(true) => debug!(
                    "Sender's signed prekey verified for {}:{}",
                    bare_jid, device_id
                ),
                Ok(false) => warn!(
                    "Sender's signed prekey signature INVALID for {}:{}",
                    bare_jid, device_id
                ),
                Err(e) => warn!(
                    "Could not verify sender's signed prekey for {}:{}: {}",
                    bare_jid, device_id, e
                ),
            }

            // Create recipient session
            let session = OmemoSession::new_recipient(
                bare_jid.clone(),
                device_id,
                our_identity_key_pair,
                sender_identity.identity_key,
                our_signed_prekey_pair,
                one_time_prekey_pair,
                ephemeral_key,
                self.device_id,
            )?;

            // Store the session
            let key = (bare_jid.clone(), device_id);
            let ratchet_state = session.ratchet_state.clone();
            self.sessions.insert(key.clone(), session);
            self.store_session_state(&bare_jid, device_id, &ratchet_state)
                .await?;

            info!(
                "Created new recipient session for {}:{}",
                bare_jid, device_id
            );
        }

        // Track OPK to consume AFTER successful decryption (not before)
        let pending_opk_consumption = if let Some(prekey_msg) =
            crate::omemo::wire::PreKeySignalMessage::deserialize(&encrypted_key)
        {
            prekey_msg.pre_key_id
        } else {
            None
        };

        let key = (bare_jid.clone(), device_id);

        if self.pending_prekey_sends.contains_key(&key) {
            info!("Receiving message from {}:{} while waiting to send PreKey message - processing normally", bare_jid, device_id);
        }

        // Get the session for the sender device
        let sender_str = sender.to_string();

        let session = match tokio::time::timeout(
            std::time::Duration::from_secs(8),
            self.get_or_create_session(&sender_str, device_id),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(OmemoError::SessionError(
                    crate::omemo::session::SessionError::InvalidStateError(format!(
                        "Timeout while creating session for decryption with {}:{}",
                        sender_str, device_id
                    )),
                ));
            }
        };

        // Decrypt the message key
        let (decrypted_key_data, session_state_to_store) = {
            let decryption_result = session.decrypt_key(&encrypted_key);

            match decryption_result {
                Ok(data) => {
                    // Store ratchet state AFTER successful decrypt (it advances the ratchet)
                    let ratchet_state = session.ratchet_state.clone();
                    (data, Some(ratchet_state))
                }
                Err(session_error) => {
                    return self
                        .handle_decryption_failure(sender_str, device_id, session_error)
                        .await;
                }
            }
        };

        // Reset failure count after successful decryption
        {
            let storage_guard = self.storage.lock().await;
            if let Err(e) = storage_guard.reset_device_failure_count(&sender_str, device_id) {
                warn!(
                    "Failed to reset failure count for {}:{}: {}",
                    sender_str, device_id, e
                );
            }
        }

        debug!(
            "Decrypted key data ({} bytes): {}",
            decrypted_key_data.len(),
            hex::encode(&decrypted_key_data)
        );

        // Validate key data format
        if decrypted_key_data.len() != 32 {
            error!(
                "Invalid key data length: {} (expected 32 bytes for AES-GCM)",
                decrypted_key_data.len()
            );
            return Err(OmemoError::CryptoError(
                crypto::CryptoError::InvalidInputError(format!(
                    "Invalid key data length: {} (expected 32 bytes for AES-GCM)",
                    decrypted_key_data.len()
                )),
            ));
        }

        if message.iv.len() != 12 {
            error!(
                "Invalid IV length: {} (expected 12 bytes for AES-GCM)",
                message.iv.len()
            );
            return Err(OmemoError::CryptoError(crypto::CryptoError::InvalidIV(
                format!(
                    "Invalid IV length: {} (expected 12 bytes for AES-GCM)",
                    message.iv.len()
                ),
            )));
        }

        // Dino/Signal format: 16-byte AES key + 16-byte auth tag, 12-byte IV, AES-GCM
        debug!("Using Dino/Signal format (AES-GCM): 32-byte key+tag, 12-byte IV");
        let aes_key = &decrypted_key_data[0..16];
        let auth_tag = &decrypted_key_data[16..32];
        let iv = &message.iv;

        debug!("AES-GCM key (hex): {}", hex::encode(aes_key));
        debug!("Auth tag (hex): {}", hex::encode(auth_tag));
        debug!("IV (hex): {}", hex::encode(iv));
        debug!("Ciphertext (hex): {}", hex::encode(&message.ciphertext));

        // Combine ciphertext + auth_tag for AES-GCM decryption
        let mut gcm_ciphertext = message.ciphertext.clone();
        gcm_ciphertext.extend_from_slice(auth_tag);

        // Decrypt using AES-GCM
        let plaintext = crypto::aes_gcm_decrypt(&gcm_ciphertext, aes_key, iv)
            .map_err(|e| OmemoError::CryptoError(e))?;

        debug!("Successfully decrypted payload");

        // Store the updated session state
        if let Some(ratchet_state) = session_state_to_store {
            self.store_session_state(&sender_str, device_id, &ratchet_state)
                .await?;
        }

        let content = String::from_utf8(plaintext)
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to decode message: {}", e)))?;

        // Strip OMEMO padding (trailing space characters per XEP-0384 §13.4)
        let content = content.trim_end().to_string();

        // Consume the one-time prekey ONLY after successful decryption
        // This prevents stale/replayed PreKeyMessages from burning valid OPKs
        if let Some(opk_id) = pending_opk_consumption {
            if let Some(bundle) = self.key_bundle.as_mut() {
                if bundle.one_time_pre_key_pairs.remove(&opk_id).is_some() {
                    info!(
                        "Consumed one-time prekey {} after successful decryption from {}:{}",
                        opk_id, bare_jid, device_id
                    );

                    // Replenish OPKs if supply is low
                    let remaining = bundle.one_time_pre_key_pairs.len() as u32;
                    if remaining < self.prekey_rotation_config.min_one_time_prekeys {
                        let max_id = bundle
                            .one_time_pre_key_pairs
                            .keys()
                            .copied()
                            .max()
                            .unwrap_or(0);
                        let to_generate =
                            self.prekey_rotation_config.min_one_time_prekeys - remaining;
                        for i in 1..=to_generate {
                            if let Ok(key_pair) = protocol::X3DHProtocol::generate_key_pair() {
                                bundle.one_time_pre_key_pairs.insert(max_id + i, key_pair);
                            }
                        }
                        info!(
                            "Replenished {} one-time prekeys (now have {})",
                            to_generate,
                            bundle.one_time_pre_key_pairs.len()
                        );
                    }

                    // Persist updated bundle and republish
                    let bundle_clone = bundle.clone();
                    let storage_guard = self.storage.lock().await;
                    if let Err(e) = storage_guard.store_key_bundle(&bundle_clone) {
                        warn!("Failed to persist bundle after OPK consumption: {}", e);
                    }
                    drop(storage_guard);

                    if let Err(e) = self.publish_bundle_to_server().await {
                        warn!("Failed to republish bundle after OPK consumption: {}", e);
                    }
                }
            }
        }

        info!(
            "Message decrypted successfully from {}:{}",
            sender, device_id
        );

        Ok(content)
    }

    /// Decrypt a message key (public wrapper for external use)
    pub async fn decrypt_message_key(
        &mut self,
        from: String,
        sender_device_id: u32,
        encrypted_key: &[u8],
    ) -> Result<Vec<u8>, OmemoError> {
        debug!(
            "Decrypting message key from device {} (sender: {})",
            sender_device_id, from
        );

        let session = match tokio::time::timeout(
            std::time::Duration::from_secs(8),
            self.get_or_create_session(&from, sender_device_id),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(OmemoError::SessionError(
                    crate::omemo::session::SessionError::InvalidStateError(format!(
                        "Timeout while creating session for key decryption with {}:{}",
                        from, sender_device_id
                    )),
                ));
            }
        };

        match session.decrypt_key(encrypted_key) {
            Ok(key) => {
                debug!("Successfully decrypted message key");
                Ok(key)
            }
            Err(e) => {
                error!("Failed to decrypt message key: {}", e);
                Err(OmemoError::DecryptionError(format!(
                    "Failed to decrypt message key: {}",
                    e
                )))
            }
        }
    }

    /// Process an incoming OMEMO message from XML
    pub fn process_message_xml(&self, xml: &str) -> Result<OmemoMessage, OmemoError> {
        debug!("Processing OMEMO message XML");
        let message = protocol::utils::omemo_message_from_xml(xml).map_err(|e| {
            OmemoError::ProtocolError(format!("Failed to parse message XML: {}", e))
        })?;
        Ok(message)
    }

    /// Handle decryption failure with tracking and session management
    pub(crate) async fn handle_decryption_failure(
        &mut self,
        sender_jid: String,
        device_id: u32,
        session_error: crate::omemo::session::SessionError,
    ) -> Result<String, OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(&sender_jid);

        warn!(
            "Failed to decrypt message key from {}:{}: {}",
            sender_jid, device_id, session_error
        );

        // Check for AEAD errors specifically
        if let crate::omemo::session::SessionError::DoubleRatchetError(ref ratchet_error) =
            session_error
        {
            if let crate::omemo::protocol::DoubleRatchetError::CryptoError(ref crypto_error) =
                ratchet_error
            {
                if let crate::omemo::crypto::CryptoError::AesGcmError(ref aes_error) = crypto_error
                {
                    if aes_error.contains("aead::Error") {
                        warn!("AEAD decryption failure from {}:{} - triggering immediate session reset", sender_jid, device_id);

                        if let Err(reset_err) = self
                            .handle_aead_decryption_failure(&sender_jid, device_id)
                            .await
                        {
                            error!("Failed to handle AEAD decryption failure: {}", reset_err);
                        }

                        return Err(OmemoError::SessionError(session_error));
                    }
                }
            }
        }

        // Track the undecryptable message
        if let Err(e) = self
            .track_undecryptable_message(&sender_jid, device_id)
            .await
        {
            warn!("Failed to track undecryptable message: {}", e);
        }

        // Fallback logic for other types of errors
        let failure_count = self.get_device_failure_count(&bare_jid, device_id).await;
        if failure_count >= 3 {
            warn!(
                "Multiple consecutive failures ({}) from {}:{}, resetting session",
                failure_count, sender_jid, device_id
            );
            if let Err(reset_err) = self.reset_session(&bare_jid, device_id).await {
                error!("Failed to reset session: {}", reset_err);
            }
        }

        Err(OmemoError::SessionError(session_error))
    }

    /// Handle AEAD decryption failures by aggressively resetting sessions
    async fn handle_aead_decryption_failure(
        &mut self,
        sender_jid: &str,
        device_id: u32,
    ) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(sender_jid);
        warn!(
            "AEAD decryption failure detected for {}:{} - implementing aggressive session reset",
            bare_jid, device_id
        );

        // Immediately reset the session
        if let Err(e) = self.reset_session(&bare_jid, device_id).await {
            error!(
                "Failed to reset session during AEAD failure handling: {}",
                e
            );
        }

        // Mark this device as needing a fresh PreKey exchange
        let key = (bare_jid.clone(), device_id);
        self.pending_prekey_sends
            .insert(key.clone(), Instant::now());

        self.sessions.remove(&key);

        // Clear our own session with this contact to force mutual session reset
        let our_device_ids = match self.get_own_device_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!("Failed to get own device IDs during session reset: {}", e);
                vec![]
            }
        };

        for our_device_id in our_device_ids {
            let reverse_key = (bare_jid.clone(), our_device_id);
            if self.sessions.contains_key(&reverse_key) {
                warn!(
                    "Clearing our session with {}:{} to force mutual PreKey exchange",
                    bare_jid, our_device_id
                );
                self.sessions.remove(&reverse_key);
            }
        }

        // Force refresh device bundles
        if let Err(e) = self.force_refresh_device_list(&bare_jid).await {
            warn!("Failed to refresh device list during session reset: {}", e);
        }

        // Mark all devices of this contact for PreKey message sending
        let target_device_ids = match self.get_device_ids(&bare_jid).await {
            Ok(devices) => devices,
            Err(_) => vec![device_id],
        };

        for target_device_id in target_device_ids {
            let device_key = (bare_jid.clone(), target_device_id);
            self.pending_prekey_sends
                .insert(device_key.clone(), Instant::now());
            info!(
                "Marked device {}:{} for PreKey message sending after session reset",
                bare_jid, target_device_id
            );
        }

        warn!(
            "Mutual session reset initiated for {} - both parties will send PreKey messages",
            bare_jid
        );
        info!(
            "Session reset complete for {}:{} - waiting for new PreKey message",
            bare_jid, device_id
        );
        Ok(())
    }
}
