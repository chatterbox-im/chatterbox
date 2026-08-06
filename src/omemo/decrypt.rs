// src/omemo/decrypt.rs
//! OMEMO message decryption

use hex;
use log::{debug, error, info, warn};

use crate::jid::BareJid;
use crate::omemo::crypto;
use crate::omemo::keys::{AesGcmKey, GcmNonce};
use crate::omemo::protocol::{self, OmemoMessage};
use crate::omemo::session::{self, OmemoSession, OmemoSessionState};
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
        let incoming_prekey = crate::omemo::wire::PreKeySignalMessage::deserialize(&encrypted_key);

        // Does an initialised session for this device already exist?  Computed
        // up front so the borrow ends before we start mutating `self.sessions`.
        let existing_session_usable = self
            .sessions
            .get(&(bare_jid.clone(), device_id))
            .map(|s| s.is_initialized())
            .unwrap_or(false);

        // Decide whether this PreKey header should actually trigger a fresh
        // X3DH exchange.
        //
        // A libsignal initiator attaches the PreKey header to every message it
        // sends until it receives a message back *inside* that session (the
        // "unacknowledged prekey" state).  Conversations and Dino both do this.
        // Every one of those retransmits carries the same base key and the same
        // one-time-prekey id that we consumed on the first message.  Treating
        // each of them as a new session — and hard-failing when the OPK is gone
        // — is what breaks the conversation: we tear down a perfectly good
        // session, the peer builds another one, and neither side converges.
        //
        // Repeated PreKey headers must therefore be idempotent.
        let needs_x3dh = match incoming_prekey.as_ref() {
            None => false,
            // No usable session at all — this is a genuine session setup.
            Some(_) if !existing_session_usable => true,
            Some(pk) => {
                let established_by_this_base_key = self
                    .sessions
                    .get(&(bare_jid.clone(), device_id))
                    .and_then(|s| s.as_session())
                    .and_then(|s| s.ratchet_state.establishing_base_key.as_deref())
                    .map(|bk| bk == pk.base_key.as_slice())
                    .unwrap_or(false);

                // Do we still hold the OPK this header references?
                let opk_available = match pk.pre_key_id {
                    None => true,
                    Some(opk_id) => self
                        .key_bundle
                        .as_ref()
                        .map(|b| b.one_time_pre_key_pairs.contains_key(&opk_id))
                        .unwrap_or(false),
                };

                if established_by_this_base_key {
                    info!(
                        "PreKeyMessage from {}:{} repeats the base key that established the \
                         current session (pre_key_id={:?}) — reusing it instead of re-running X3DH",
                        bare_jid, device_id, pk.pre_key_id
                    );
                    false
                } else if !opk_available {
                    // Almost certainly a retransmit whose base key we can't
                    // match (e.g. a session persisted before establishing_base_key
                    // was recorded), or a replay.  Either way we have a working
                    // session — use it.  Never destroy session state because a
                    // consumed OPK was referenced; that turns any replayed
                    // stanza into a remote session-wipe.
                    warn!(
                        "PreKeyMessage from {}:{} references consumed OPK {:?} but an \
                         initialised session exists — decrypting in-session",
                        bare_jid, device_id, pk.pre_key_id
                    );
                    false
                } else {
                    // New base key and the referenced OPK is still available:
                    // the peer really is establishing a new session.
                    true
                }
            }
        };

        if let Some(prekey_msg) = incoming_prekey.filter(|_| needs_x3dh) {
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
                Some(bundle) => {
                    if bundle.signed_pre_key_id == prekey_msg.signed_pre_key_id {
                        // Current SPK — common path
                        bundle.signed_pre_key_pair.clone()
                    } else if let Some(historic) = bundle
                        .signed_pre_key_history
                        .get(&prekey_msg.signed_pre_key_id)
                    {
                        // Sender built this PreKey against a recently-rotated SPK that
                        // we still have in our history — use it.
                        info!(
                            "Using historic SPK id {} (current id={}) for PreKeyMessage from {}:{}",
                            prekey_msg.signed_pre_key_id,
                            bundle.signed_pre_key_id,
                            sender,
                            device_id
                        );
                        historic.clone()
                    } else {
                        // SPK id is unknown — we cannot reconstruct the X3DH shared
                        // secret.  Treat this like the stale-OPK path: delete any
                        // existing session and force a fresh exchange.
                        warn!(
                            "Unknown SPK id {} from {}:{} (current id={}, history ids={:?}) — \
                             session cannot be established; sender must fetch our fresh bundle",
                            prekey_msg.signed_pre_key_id,
                            sender,
                            device_id,
                            bundle.signed_pre_key_id,
                            bundle.signed_pre_key_history.keys().collect::<Vec<_>>()
                        );
                        // Only tear the session down when there is nothing to
                        // fall back on.  If an initialised session exists, an
                        // unresolvable SPK id means "this header is stale", not
                        // "our state is bad" — destroying it here would let a
                        // replayed stanza wipe a working session remotely.
                        if !existing_session_usable {
                            let spk_session_key = (bare_jid.clone(), device_id);
                            // Replace any existing session entry with PeerResetPending so
                            // the next outbound to this sender creates a fresh PreKey.
                            self.sessions
                                .insert(spk_session_key, OmemoSessionState::PeerResetPending);
                            // Persist the marker so it survives a restart.
                            {
                                let storage_guard = self.storage.lock().await;
                                let sk = format!("{}:{}", bare_jid, device_id);
                                if let Err(e) = storage_guard.delete_session(&sk) {
                                    warn!(
                                        "Failed to delete on-disk session after unknown SPK: {}",
                                        e
                                    );
                                }
                                if let Err(e) =
                                    storage_guard.set_session_rebuild_needed(&bare_jid, device_id)
                                {
                                    warn!(
                                        "Failed to persist rebuild flag for {}:{}: {}",
                                        bare_jid, device_id, e
                                    );
                                }
                            }
                        }
                        return Err(OmemoError::SessionError(
                            session::SessionError::InvalidStateError(format!(
                                "Unknown signed prekey id {} — sender must re-establish \
                                 session with our fresh bundle",
                                prekey_msg.signed_pre_key_id
                            )),
                        ));
                    }
                }
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

            // Reaching here with a missing OPK means `needs_x3dh` was true, i.e.
            // there is no initialised session to fall back on — a genuine
            // "cannot establish" case.  (The retransmit/replay cases were
            // filtered out above and never enter this block.)
            if prekey_msg.pre_key_id.is_some() && one_time_prekey_pair.is_none() {
                warn!("PreKeyMessage references OPK id {:?} but we don't have it and no session exists — cannot establish session (sender needs our fresh bundle)", prekey_msg.pre_key_id);

                // Replace any existing session entry for this sender with
                // PeerResetPending so that our next outbound message creates a
                // fresh PreKey session.  The old stale entry (if any) is gone.
                let stale_key = (bare_jid.clone(), device_id);
                self.sessions
                    .insert(stale_key, OmemoSessionState::PeerResetPending);
                {
                    let storage_guard = self.storage.lock().await;
                    let session_key_str = format!("{}:{}", bare_jid, device_id);
                    if let Err(e) = storage_guard.delete_session(&session_key_str) {
                        warn!(
                            "Failed to delete stale session for {} after missing OPK: {}",
                            session_key_str, e
                        );
                    }
                }

                // NOTE: deliberately no publish_bundle_to_server() here.  Peers
                // do not re-fetch our bundle because we republished it; they
                // fetch when they build a new session.  Republishing on every
                // stale PreKey is pure churn (and rotates OPKs out from under
                // in-flight messages).

                // Persist the rebuild marker so it survives a restart.
                {
                    let storage_guard = self.storage.lock().await;
                    if let Err(e) = storage_guard.set_session_rebuild_needed(&bare_jid, device_id) {
                        warn!(
                            "Failed to persist rebuild flag for {}:{}: {}",
                            bare_jid, device_id, e
                        );
                    }
                }

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
                Ok(false) => {
                    error!(
                        "Sender's signed prekey signature INVALID for {}:{} — rejecting session",
                        bare_jid, device_id
                    );
                    return Err(OmemoError::ProtocolError(format!(
                        "Signed prekey signature invalid for {}:{} — possible MITM",
                        bare_jid, device_id
                    )));
                }
                Err(e) => {
                    error!(
                        "Could not verify sender's signed prekey for {}:{}: {} — rejecting session",
                        bare_jid, device_id, e
                    );
                    return Err(OmemoError::ProtocolError(format!(
                        "Signed prekey signature verification error for {}:{}: {}",
                        bare_jid, device_id, e
                    )));
                }
            }

            // Create recipient session
            let session = OmemoSession::new_recipient(
                bare_jid.to_string(),
                device_id,
                our_identity_key_pair,
                sender_identity.identity_key,
                our_signed_prekey_pair,
                one_time_prekey_pair,
                ephemeral_key,
                self.device_id,
            )?;

            // Store the session wrapped in Active (we're the recipient; the
            // session is immediately usable in both directions).
            let key = (bare_jid.clone(), device_id);
            let ratchet_state = session.ratchet_state.clone();
            self.sessions
                .insert(key.clone(), OmemoSessionState::Active(session));
            self.store_session_state(&bare_jid, device_id, &ratchet_state)
                .await?;

            info!(
                "Created new recipient session for {}:{}",
                bare_jid, device_id
            );
        }

        // Track OPK to consume AFTER successful decryption (not before).
        // Only an actual X3DH exchange consumes a one-time prekey — retransmitted
        // PreKey headers must not touch the OPK pool.
        let pending_opk_consumption = if needs_x3dh {
            crate::omemo::wire::PreKeySignalMessage::deserialize(&encrypted_key)
                .and_then(|pk| pk.pre_key_id)
        } else {
            None
        };

        let key = (bare_jid.clone(), device_id);

        if matches!(
            self.sessions.get(&key),
            Some(OmemoSessionState::RecoveryPreKeySent { .. })
        ) {
            info!("Receiving message from {}:{} while recovery PreKey is pending — processing normally", bare_jid, device_id);
        }

        // Remember whether we were waiting for the peer's first reply — if so,
        // a successful decrypt means the session is now fully established.
        let was_awaiting_reply = matches!(
            self.sessions.get(&key),
            Some(OmemoSessionState::InitiatorAwaitingReply { .. })
        );

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
            if let Err(e) = storage_guard.reset_device_failure_count(&BareJid::from_raw_lossy(&sender_str), device_id) {
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

        let aes_gcm_key = AesGcmKey::from_slice(aes_key).ok_or_else(|| {
            OmemoError::CryptoError(crate::omemo::crypto::CryptoError::InvalidInputError(
                format!("invalid AES-GCM key length: {}", aes_key.len()),
            ))
        })?;
        let gcm_nonce = GcmNonce::from_slice(iv).ok_or_else(|| {
            OmemoError::CryptoError(crate::omemo::crypto::CryptoError::InvalidIV(
                format!("invalid GCM nonce length: {}", iv.len()),
            ))
        })?;

        // Decrypt using AES-GCM
        let plaintext = crypto::aes_gcm_decrypt(&gcm_ciphertext, &aes_gcm_key, &gcm_nonce)
            .map_err(|e| OmemoError::CryptoError(e))?;

        debug!("Successfully decrypted payload");

        // Store the updated session state
        if let Some(ratchet_state) = session_state_to_store {
            self.store_session_state(&BareJid::from_raw_lossy(&sender_str), device_id, &ratchet_state)
                .await?;
        }

        // Transition InitiatorAwaitingReply → Active on the first successful
        // incoming message: the peer has replied and the session is fully live.
        if was_awaiting_reply {
            if let Some(old_entry) = self.sessions.remove(&key) {
                if let OmemoSessionState::InitiatorAwaitingReply { session, .. } = old_entry {
                    info!(
                        "Session with {}:{} advanced from InitiatorAwaitingReply to Active",
                        bare_jid, device_id
                    );
                    self.sessions
                        .insert(key.clone(), OmemoSessionState::Active(session));
                }
            }
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
                        // Use max of remaining IDs AND the consumed ID so the
                        // new OPK never re-uses the just-consumed ID.  Without
                        // this, if the consumed OPK happened to have the
                        // highest ID (e.g. 20), max_id would be 19 and the
                        // replenished OPK would get ID 20 again — making the
                        // stale-OPK detection think the old message used a
                        // valid key when it does not.
                        let max_id = bundle
                            .one_time_pre_key_pairs
                            .keys()
                            .copied()
                            .max()
                            .unwrap_or(0)
                            .max(opk_id);
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

                    // Persist the updated bundle *together with* the session it
                    // established, in a single transaction.
                    //
                    // These were previously two independent writes. A crash in
                    // between left either a consumed OPK with no session (the
                    // peer's next message re-runs X3DH against a key we no
                    // longer hold → PeerResetPending) or a session whose OPK is
                    // still advertised (a replay re-derives a different session
                    // and every later decrypt fails its MAC →
                    // RecoveryPreKeySent). Both end at a "session broken"
                    // prompt, so the pair must commit atomically.
                    let bundle_clone = bundle.clone();
                    let session_state = self
                        .sessions
                        .get(&key)
                        .and_then(|s| s.as_session())
                        .map(|s| s.get_state().clone());

                    let storage_guard = self.storage.lock().await;
                    let persisted = match session_state {
                        Some(state) => storage_guard.commit_prekey_consumption(
                            &bare_jid,
                            device_id,
                            &state,
                            &bundle_clone,
                        ),
                        // No live session to pair it with (shouldn't happen on
                        // this path); fall back to writing the bundle alone.
                        None => storage_guard.store_key_bundle(&bundle_clone),
                    };
                    if let Err(e) = persisted {
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

        // "Counter too old" / "already processed" errors are Double Ratchet replay
        // detection working correctly — the message was already decrypted in a
        // previous session (e.g. a MAM re-delivery).  Do NOT count these as failures;
        // doing so would incorrectly trigger session resets for working sessions.
        let error_str = session_error.to_string();
        if error_str.contains("too old")
            || error_str.contains("already processed")
            || error_str.contains("no stored key")
        {
            return Err(OmemoError::SessionError(session_error));
        }


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

        // Save the existing recovery attempt count BEFORE reset_session removes the
        // sessions entry — otherwise prev_attempt would always read 0.
        let key = (bare_jid.clone(), device_id);
        let prev_attempt = self
            .sessions
            .get(&key)
            .and_then(|s| s.recovery_attempt())
            .unwrap_or(0);

        // Immediately reset the session
        if let Err(e) = self.reset_session(&bare_jid, device_id).await {
            error!(
                "Failed to reset session during AEAD failure handling: {}",
                e
            );
        }

        // Insert a RecoveryPreKeySent marker so the next outbound to this device
        // creates a fresh PreKey.  Increment the attempt counter each time so
        // callers can detect a persistent recovery loop.
        let new_attempt = prev_attempt.saturating_add(1);

        /// Maximum number of recovery PreKey cycles before surfacing a
        /// user-facing "session permanently broken" error.
        const MAX_RECOVERY_ATTEMPTS: u8 = 5;

        if new_attempt > MAX_RECOVERY_ATTEMPTS {
            warn!(
                "Session with {}:{} has failed to recover after {} consecutive attempts -- \
                 the session appears permanently broken and may require manual intervention.",
                bare_jid, device_id, new_attempt
            );
            // Keep the RecoveryPreKeySent state so the next send still tries a fresh
            // PreKey (better than giving up entirely), but return an error that the UI
            // can render as a clear, actionable "session broken" prompt.
        }

        self.sessions.insert(
            key.clone(),
            OmemoSessionState::RecoveryPreKeySent {
                attempt: new_attempt,
            },
        );
        // Persist so the recovery state survives a process restart.
        {
            let storage_guard = self.storage.lock().await;
            if let Err(e) = storage_guard.set_prekey_pending(&bare_jid, device_id) {
                warn!(
                    "Failed to persist prekey-pending flag for {}:{}: {}",
                    bare_jid, device_id, e
                );
            }
        }

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
            // Keep existing attempt counts: if the device is already in a recovery
            // cycle, don't reset its counter.
            let prev = self
                .sessions
                .get(&device_key)
                .and_then(|s| s.recovery_attempt())
                .unwrap_or(0);
            self.sessions.insert(
                device_key.clone(),
                OmemoSessionState::RecoveryPreKeySent {
                    attempt: prev.saturating_add(1),
                },
            );
            {
                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard.set_prekey_pending(&bare_jid, target_device_id) {
                    warn!(
                        "Failed to persist prekey-pending flag for {}:{}: {}",
                        bare_jid, target_device_id, e
                    );
                }
            }
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
