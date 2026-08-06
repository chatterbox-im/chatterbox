// src/omemo/encrypt.rs
//! OMEMO message encryption

use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tokio::time::{timeout, Duration};

use crate::jid::BareJid;
use crate::omemo::crypto;
use crate::omemo::device_id::DeviceId;
use crate::omemo::keys::{AesGcmKey, GcmNonce};
use crate::omemo::protocol::{self, DeviceIdentity, OmemoMessage};
use crate::omemo::session::{self, OmemoSession, OmemoSessionState};
use crate::omemo::{EncryptionVerificationError, OmemoError, OmemoManager, OMEMO_NAMESPACE};

impl OmemoManager {
    async fn cached_or_session_device_ids_for(&self, bare_jid: &BareJid) -> Vec<DeviceId> {
        let mut device_ids = Vec::new();

        {
            let storage_guard = self.storage.lock().await;
            if let Ok(entry) = storage_guard.load_device_list(bare_jid) {
                device_ids.extend(entry.device_ids);
            }
        }

        for (jid, device_id) in self.sessions.keys() {
            if jid == bare_jid && !device_ids.contains(device_id) {
                device_ids.push(*device_id);
            }
        }

        device_ids
    }

    /// Get or create a session with a remote device (with consistent initiator/recipient roles)
    pub async fn get_or_create_session(
        &mut self,
        remote_jid: &str,
        remote_device_id: DeviceId,
    ) -> Result<&mut OmemoSession, OmemoError> {
        // Normalize the JID to bare JID for consistent session lookup
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        let key = (bare_jid.clone(), remote_device_id);

        info!(
            "SESSION_DEBUG: get_or_create_session called for {}:{}",
            bare_jid, remote_device_id
        );

        // Check if this device has a PeerResetPending or RecoveryPreKeySent marker —
        // the peer's last PreKey referenced a key we no longer hold, or we are
        // proactively recovering from AEAD failures, so we must rebuild.
        let needs_rebuild = self
            .sessions
            .get(&key)
            .map(|s| s.needs_rebuild())
            .unwrap_or(false);

        // Also force a rebuild if InitiatorAwaitingReply has timed out: the peer
        // may never receive (or process) our PreKey, so we generate fresh key
        // material rather than continuing to send against the same ephemeral key.
        const INITIATOR_AWAIT_TIMEOUT: std::time::Duration =
            std::time::Duration::from_secs(24 * 3600); // 24 h
        let awaiting_timed_out = matches!(
            self.sessions.get(&key),
            Some(OmemoSessionState::InitiatorAwaitingReply { sent_at, .. })
                if sent_at.elapsed() > INITIATOR_AWAIT_TIMEOUT
        );
        if awaiting_timed_out {
            info!(
                "SESSION_DEBUG: InitiatorAwaitingReply timed out for {}:{}, re-keying",
                bare_jid, remote_device_id
            );
            self.sessions.remove(&key);
        }

        let needs_rebuild = needs_rebuild || awaiting_timed_out;
        if needs_rebuild && !awaiting_timed_out {
            info!(
                "SESSION_DEBUG: Forcing fresh session rebuild for {}:{} after previous reset",
                bare_jid, remote_device_id
            );
            // Clear the PeerResetPending or RecoveryPreKeySent marker.
            self.sessions.remove(&key);
            {
                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard.clear_session_rebuild_needed(&key.0, key.1) {
                    warn!("Failed to clear rebuild flag for {:?}: {}", key, e);
                }
                // Also clear prekey-pending (set by RecoveryPreKeySent path).
                if let Err(e) = storage_guard.clear_prekey_pending(&key.0, key.1) {
                    warn!("Failed to clear prekey-pending flag for {:?}: {}", key, e);
                }
            }
        }

        // Check if we already have a session (early return, no borrow held)
        let session_exists_and_initialized = self
            .sessions
            .get(&key)
            .map(|s| s.is_initialized())
            .unwrap_or(false);
        if session_exists_and_initialized && !needs_rebuild {
            info!(
                "SESSION_DEBUG: Reusing existing session for {}:{}",
                bare_jid, remote_device_id
            );
            return self
                .sessions
                .get_mut(&key)
                .and_then(|s| s.as_session_mut())
                .ok_or_else(|| {
                    OmemoError::SessionError(session::SessionError::InvalidStateError(
                        "Session not found after check".to_string(),
                    ))
                });
        }

        info!(
            "SESSION_DEBUG: Creating new session for {}:{} (exists: {}, needs_rebuild: {})",
            bare_jid, remote_device_id, session_exists_and_initialized, needs_rebuild
        );

        info!("SESSION_DEBUG: Creating initiator session with {}:{} (our device: {}, their device: {})", 
            bare_jid, remote_device_id, self.device_id, remote_device_id
        );

        // Gather all data and perform async calls BEFORE mutably borrowing self
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

        info!(
            "SESSION_DEBUG: Getting device identity for {}:{}",
            bare_jid, remote_device_id
        );
        // When creating any new initiator session (whether a rebuild or a first-time
        // session), always fetch the bundle fresh from the server.  The cached copy
        // may reference an OPK that the remote has already consumed in a previous
        // session; using a stale OPK causes an irrecoverable "missing one-time
        // prekey" failure on the receiver.
        let label = if needs_rebuild {
            "Session rebuild"
        } else {
            "New session"
        };
        info!(
            "SESSION_DEBUG: {} — force-fetching bundle from server for {}:{}",
            label, bare_jid, remote_device_id
        );
        let mut remote_identity = match self
            .fetch_device_identity_from_server(&bare_jid, remote_device_id)
            .await
        {
            Ok(identity) => identity,
            Err(e) => {
                warn!(
                    "Failed to fetch fresh bundle for {} of {}:{}: {} — falling back to cache",
                    label.to_lowercase(),
                    bare_jid,
                    remote_device_id,
                    e
                );
                self.get_device_identity(&bare_jid, remote_device_id)
                    .await?
            }
        };
        info!(
            "SESSION_DEBUG: Successfully retrieved device identity for {}:{}",
            bare_jid, remote_device_id
        );

        // Verify the signed prekey signature before using the bundle
        let verification = protocol::X3DHProtocol::verify_pre_key(
            &remote_identity.identity_key,
            &remote_identity.signed_pre_key.public_key,
            &remote_identity.signed_pre_key.signature,
        );

        let needs_refetch = matches!(&verification, Ok(false) | Err(_));
        if needs_refetch {
            // Cached bundle may be stale (device rotated keys). Re-fetch from server.
            warn!("Signed prekey verification failed for {}:{} with cached bundle, re-fetching from server", bare_jid, remote_device_id);
            match self
                .fetch_device_identity_from_server(&bare_jid, remote_device_id)
                .await
            {
                Ok(fresh_identity) => {
                    remote_identity = fresh_identity;
                    // Verify the fresh bundle
                    match protocol::X3DHProtocol::verify_pre_key(
                        &remote_identity.identity_key,
                        &remote_identity.signed_pre_key.public_key,
                        &remote_identity.signed_pre_key.signature,
                    ) {
                        Ok(true) => {
                            info!(
                                "Signed prekey signature verified for {}:{} after re-fetch",
                                bare_jid, remote_device_id
                            );
                        }
                        Ok(false) => {
                            error!("Signed prekey signature INVALID for {}:{} even after re-fetch — rejecting bundle to prevent potential MITM", bare_jid, remote_device_id);
                            return Err(OmemoError::ProtocolError(format!(
                                "Signed prekey signature verification failed for {}:{} — bundle rejected", bare_jid, remote_device_id
                            )));
                        }
                        Err(e) => {
                            error!("Signed prekey signature verification error for {}:{} after re-fetch: {} — rejecting bundle", bare_jid, remote_device_id, e);
                            return Err(OmemoError::ProtocolError(format!(
                                "Signed prekey signature verification error for {}:{}: {}",
                                bare_jid, remote_device_id, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to re-fetch bundle for {}:{}: {}",
                        bare_jid, remote_device_id, e
                    );
                    // Return the original verification error
                    match verification {
                        Ok(false) => {
                            return Err(OmemoError::ProtocolError(format!(
                                "Signed prekey signature verification failed for {}:{}",
                                bare_jid, remote_device_id
                            )))
                        }
                        Err(e) => {
                            return Err(OmemoError::ProtocolError(format!(
                                "Signed prekey signature verification error for {}:{}: {}",
                                bare_jid, remote_device_id, e
                            )))
                        }
                        _ => unreachable!(),
                    }
                }
            }
        } else {
            match verification {
                Ok(true) => {
                    debug!(
                        "Signed prekey signature verified for {}:{}",
                        bare_jid, remote_device_id
                    );
                }
                _ => unreachable!(),
            }
        }

        // In OMEMO, when we want to SEND to a device, we always act as X3DH initiator
        // (fetch their bundle and create a session). Recipient sessions are only created
        // when we RECEIVE a PreKeyMessage from them.
        // Generate a random ephemeral key pair for X3DH
        let ephemeral_key_pair = protocol::X3DHProtocol::generate_key_pair()
            .map_err(|e| OmemoError::CryptoError(crypto::CryptoError::KdfError(e.to_string())))?;

        // Store the ephemeral public key for this device to include in PreKey messages
        let device_key = (bare_jid.clone(), remote_device_id);
        self.prekey_ephemeral_keys.insert(
            device_key.clone(),
            (ephemeral_key_pair.public_key.clone(), Instant::now()),
        );

        // Store the remote device's PreKey IDs so the PreKeySignalMessage can reference them
        let remote_spk_id = remote_identity.signed_pre_key.id;
        let remote_opk_id = if remote_identity.pre_keys.is_empty() {
            None
        } else {
            Some(remote_identity.pre_keys[0].id)
        };
        self.remote_prekey_ids
            .insert(device_key, (remote_spk_id, remote_opk_id, Instant::now()));

        let session = OmemoSession::new_initiator_with_ephemeral(
            bare_jid.to_string(),
            remote_device_id,
            our_identity_key_pair,
            crypto::ensure_montgomery_form(&remote_identity.identity_key)
                .map_err(|e| OmemoError::CryptoError(e))?,
            remote_identity.signed_pre_key.public_key,
            if remote_identity.pre_keys.is_empty() {
                None
            } else {
                Some(remote_identity.pre_keys[0].public_key.clone())
            },
            ephemeral_key_pair.private_key.expose_secret().to_vec(),
            self.device_id,
        )?;

        let ratchet_state = session.ratchet_state.clone();

        // Evict oldest sessions if we exceed the cap to prevent unbounded memory growth
        const MAX_SESSIONS: usize = 500;
        if self.sessions.len() >= MAX_SESSIONS {
            // Remove a session that isn't the one we're about to use
            let evict_key = self.sessions.keys().find(|k| **k != key).cloned();
            if let Some(k) = evict_key {
                self.sessions.remove(&k);
            }
        }

        // Now, after all awaits, mutably borrow self and insert.
        // Wrap in InitiatorAwaitingReply — the session transitions to Active once
        // the peer replies with their first DH-ratchet message.
        self.sessions.insert(
            key.clone(),
            OmemoSessionState::InitiatorAwaitingReply {
                session,
                sent_at: std::time::Instant::now(),
            },
        );
        self.store_session_state(&bare_jid, remote_device_id, &ratchet_state)
            .await?;

        // If the user explicitly trusted this device, restore that trust now.
        // During a rebuild, save_fetched_identity may have reset trust to Untrusted
        // because the remote has a new identity key (e.g. fresh re-install).
        // The user has already decided to trust them, so we honour that.
        if self.pending_trust_restorations.remove(&key) {
            info!(
                "Restoring Trusted status for {}:{} after session rebuild",
                bare_jid, remote_device_id
            );
            let storage_guard = self.storage.lock().await;
            let _ = storage_guard.set_trust_level(
                &bare_jid,
                remote_device_id,
                crate::omemo::storage::TrustLevel::Trusted,
            );
        }

        return self
            .sessions
            .get_mut(&key)
            .and_then(|s| s.as_session_mut())
            .ok_or_else(|| {
                OmemoError::SessionError(session::SessionError::InvalidStateError(
                    "Session not found after check".to_string(),
                ))
            });
    }

    /// Get a device identity from storage or fetch it
    pub(crate) async fn get_device_identity(
        &self,
        remote_jid: &BareJid,
        device_id: DeviceId,
    ) -> Result<DeviceIdentity, OmemoError> {
        debug!("Getting device identity for {}:{}", remote_jid, device_id);

        // First try to get from storage
        let mut storage_guard = self.storage.lock().await;
        if let Ok(identity) = storage_guard.load_device_identity(remote_jid, device_id) {
            debug!(
                "Found device identity in storage for {}:{}",
                remote_jid, device_id
            );
            return Ok(identity);
        }
        drop(storage_guard);

        // If not in storage, fetch from server
        self.fetch_device_identity_from_server(remote_jid, device_id)
            .await
    }

    /// Fetch a device identity directly from the server, bypassing and replacing the cache
    async fn fetch_device_identity_from_server(
        &self,
        remote_jid: &BareJid,
        device_id: DeviceId,
    ) -> Result<DeviceIdentity, OmemoError> {
        info!(
            "Fetching device bundle from server for {}:{}",
            remote_jid, device_id
        );

        let bundle_node = format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id);

        // Make the request
        let response = match self.pubsub.request_items(remote_jid.as_str(), &bundle_node).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!(
                    "Failed to fetch device bundle for {}:{}: {}",
                    remote_jid, device_id, e
                );
                return Err(OmemoError::MissingDataError(format!(
                    "Failed to fetch device bundle: {}",
                    e
                )));
            }
        };

        // Parse the response to extract the device bundle
        let identity = self.parse_device_bundle_response(&response, device_id)?;

        // Store the identity with identity-key pinning. If the device's identity
        // key changed since we last saw it, trust is reset to Untrusted and the
        // user is prompted to re-verify (possible MITM); otherwise prior trust is
        // preserved. Compute the fingerprint before taking the storage lock.
        let new_fingerprint = self.generate_standard_fingerprint(&identity.identity_key);
        let mut storage_guard = self.storage.lock().await;
        let key_changed = storage_guard
            .save_fetched_identity(remote_jid, &identity, &new_fingerprint)
            .map_err(|e| {
                OmemoError::StorageError(format!("Failed to store device identity: {}", e))
            })?;
        drop(storage_guard);

        if key_changed {
            warn!(
                "OMEMO identity key for {}:{} changed — marked Untrusted, awaiting re-verification",
                remote_jid, device_id
            );
        }

        Ok(identity)
    }

    /// Encrypt a message for a recipient
    pub async fn encrypt_message(
        &mut self,
        recipient: &str,
        plaintext: &str,
    ) -> Result<OmemoMessage, OmemoError> {
        // Normalize once at the boundary; every downstream use sees a consistent bare JID.
        let recipient = &Self::normalize_jid_to_bare(recipient);
        debug!("encrypt_message called for recipient '{}'", recipient);
        info!("Encrypting message for {}", recipient);

        // Evict stale pending entries to prevent unbounded growth
        self.evict_stale_entries();

        // Get the device list for the recipient with timeout protection.
        // Use the cached list when available — the cache is populated on connect and
        // updated via PEP device-list subscriptions. Only hit the server when the
        // cache is empty (first message to this contact this session).
        let device_discovery_timeout = Duration::from_secs(15);
        let cached_recipient_device_ids = self.cached_or_session_device_ids_for(recipient).await;
        let force_refresh_recipient = cached_recipient_device_ids.is_empty();
        if force_refresh_recipient {
            info!("No cached device list for {}, fetching from server", recipient);
        } else {
            info!("Using cached device list for {}: {:?}", recipient, cached_recipient_device_ids);
        }
        let recipient_device_ids = match timeout(
            device_discovery_timeout,
            self.get_device_ids_with_force_refresh(recipient.as_str(), force_refresh_recipient),
        )
        .await
        {
            Ok(Ok(devices)) if !devices.is_empty() => {
                info!("Device list for {} resolved: {:?}", recipient, devices);
                devices
            }
            Ok(Ok(empty)) => {
                if !cached_recipient_device_ids.is_empty() {
                    warn!(
                        "Device list for {} was empty; falling back to cached/session devices {:?}",
                        recipient, cached_recipient_device_ids
                    );
                    cached_recipient_device_ids.clone()
                } else {
                    empty
                }
            }
            Ok(Err(e)) => {
                if !cached_recipient_device_ids.is_empty() {
                    warn!(
                        "Device list fetch failed for {}: {}; falling back to cached/session devices {:?}",
                        recipient, e, cached_recipient_device_ids
                    );
                    cached_recipient_device_ids.clone()
                } else {
                    error!(
                        "Device list fetch failed for {}: {} with no cache fallback",
                        recipient, e
                    );
                    return Err(e);
                }
            }
            Err(_) => {
                if !cached_recipient_device_ids.is_empty() {
                    warn!(
                        "Timeout fetching device list for {}; falling back to cached/session devices {:?}",
                        recipient, cached_recipient_device_ids
                    );
                    cached_recipient_device_ids.clone()
                } else {
                    error!(
                        "Timeout fetching device list for {} with no cache fallback",
                        recipient
                    );
                    return Err(OmemoError::TimeoutError(
                        "Device list fetch timeout".to_string(),
                    ));
                }
            }
        };

        info!(
            "ENCRYPT_DEBUG: Recipient device discovery for {}: {:?}",
            recipient, recipient_device_ids
        );

        let final_recipient_device_ids = if recipient_device_ids.is_empty() {
            error!(
                "ENCRYPT_DEBUG: No devices found for recipient {}, trying fallback",
                recipient
            );

            // FALLBACK: Try to use known sessions as a source of device IDs
            warn!("ENCRYPT_DEBUG: Falling back to known sessions for device discovery");
            let fallback_devices: Vec<DeviceId> = self
                .sessions
                .keys()
                .filter(|(jid, _device_id)| jid == recipient)
                .map(|(_jid, device_id)| *device_id)
                .collect();

            if !fallback_devices.is_empty() {
                warn!(
                    "ENCRYPT_DEBUG: Found {} devices from known sessions: {:?}",
                    fallback_devices.len(),
                    fallback_devices
                );
                fallback_devices
            } else {
                error!("ENCRYPT_DEBUG: No devices found even in fallback, cannot encrypt");
                return Err(OmemoError::NoDeviceError(recipient.to_string()));
            }
        } else {
            recipient_device_ids
        };

        // Get our own device IDs (important for message carbons) with timeout.
        // Keep a local snapshot first: some servers transiently return an empty
        // own-device list, and sending without own-device keys makes sent carbons
        // unreadable on the user's other clients.
        let user_bare_jid = Self::normalize_jid_to_bare(&self.local_jid);
        let cached_own_device_ids = self.cached_or_session_device_ids_for(&user_bare_jid).await;
        let merge_cached_own_device_ids = |mut devices: Vec<DeviceId>| {
            for device_id in &cached_own_device_ids {
                if !devices.contains(device_id) {
                    devices.push(*device_id);
                }
            }
            devices
        };
        let force_refresh_own = cached_own_device_ids.is_empty();
        if force_refresh_own {
            info!("No cached own device list for {}, fetching from server", user_bare_jid);
        } else {
            info!("Using cached own device list for {}: {:?}", user_bare_jid, cached_own_device_ids);
        }
        let own_device_ids = match timeout(
            device_discovery_timeout,
            self.get_device_ids_with_force_refresh(user_bare_jid.as_str(), force_refresh_own),
        )
        .await
        {
            Ok(Ok(devices)) if !devices.is_empty() => merge_cached_own_device_ids(devices),
            Ok(Ok(_)) if !cached_own_device_ids.is_empty() => {
                warn!(
                    "Own device list for {} was empty; using cached/session devices {:?}",
                    user_bare_jid, cached_own_device_ids
                );
                cached_own_device_ids.clone()
            }
            Ok(Ok(devices)) => devices,
            Ok(Err(e)) => {
                if cached_own_device_ids.is_empty() {
                    warn!("Failed to get own device list: {} - continuing with recipient devices only", e);
                    Vec::new()
                } else {
                    warn!(
                        "Failed to get own device list: {}; using cached/session devices {:?}",
                        e, cached_own_device_ids
                    );
                    cached_own_device_ids.clone()
                }
            }
            Err(_) => {
                if cached_own_device_ids.is_empty() {
                    warn!("Timeout fetching own device list - continuing with recipient devices only");
                    Vec::new()
                } else {
                    warn!(
                        "Timeout fetching own device list; using cached/session devices {:?}",
                        cached_own_device_ids
                    );
                    cached_own_device_ids.clone()
                }
            }
        };

        info!(
            "ENCRYPT_DEBUG: Own device discovery for {}: {:?}",
            user_bare_jid, own_device_ids
        );
        info!("ENCRYPT_DEBUG: Our current device ID: {}", self.device_id);

        info!(
            "Found {} devices for recipient {}: {:?}",
            final_recipient_device_ids.len(),
            recipient,
            final_recipient_device_ids
        );
        info!(
            "Found {} own devices: {:?}",
            own_device_ids.len(),
            own_device_ids
        );

        // Generate a 16-byte AES key and 12-byte IV
        let aes_key_bytes = crypto::generate_aes_key(); // 16 bytes
        let iv_bytes = crypto::generate_gcm_iv(); // 12 bytes
        debug!("Generated 16-byte AES-GCM key and 12-byte IV (Dino-compatible format)");

        let aes_key = AesGcmKey::from_slice(&aes_key_bytes).expect("generate_aes_key produces 16 bytes");
        let gcm_iv = GcmNonce::from_slice(&iv_bytes).expect("generate_gcm_iv produces 12 bytes");

        // Encrypt the plaintext with AES-GCM
        let gcm_result = crypto::aes_gcm_encrypt(plaintext.as_bytes(), &aes_key, &gcm_iv)
            .map_err(OmemoError::CryptoError)?;

        if gcm_result.len() < 16 {
            return Err(OmemoError::CryptoError(
                crypto::CryptoError::InvalidInputError("AES-GCM result too short".to_string()),
            ));
        }

        let ciphertext_len = gcm_result.len() - 16;
        let ciphertext = gcm_result[0..ciphertext_len].to_vec();
        let auth_tag = gcm_result[ciphertext_len..].to_vec();

        debug!(
            "Encrypted payload with AES-GCM: ciphertext {} bytes, auth tag {} bytes",
            ciphertext.len(),
            auth_tag.len()
        );

        // For Dino compatibility, the message key is aes_key_bytes + auth_tag (32 bytes total)
        let mut message_key = aes_key_bytes.clone();
        message_key.extend_from_slice(&auth_tag);
        debug!(
            "Created message key: {} bytes (16-byte AES key + 16-byte auth tag)",
            message_key.len()
        );

        // Now encrypt the random key for each recipient device and our own devices
        let mut encrypted_keys = HashMap::new();
        let mut all_devices = Vec::new();

        // Add recipient devices (filter out explicitly untrusted devices per BTBV)
        let storage_guard = self.storage.lock().await;
        for device_id in final_recipient_device_ids {
            let trust_level = storage_guard
                .get_trust_level(recipient, device_id)
                .unwrap_or(crate::omemo::storage::TrustLevel::Undecided);
            if trust_level == crate::omemo::storage::TrustLevel::Untrusted {
                warn!(
                    "ENCRYPT_DEBUG: Skipping untrusted device {}:{}",
                    recipient, device_id
                );
                continue;
            }
            if !all_devices.contains(&((*recipient).clone(), device_id)) {
                all_devices.push(((*recipient).clone(), device_id));
                info!(
                    "ENCRYPT_DEBUG: Added recipient device {}:{}",
                    recipient, device_id
                );
            } else {
                warn!(
                    "ENCRYPT_DEBUG: Duplicate recipient device {}:{} found",
                    recipient, device_id
                );
            }
        }
        drop(storage_guard);

        // Add our own devices (for message carbons), but exclude our current device
        // and any own device explicitly marked Untrusted (e.g. a revoked/compromised device).
        let storage_guard = self.storage.lock().await;
        for device_id in own_device_ids {
            if device_id == self.device_id {
                debug!(
                    "ENCRYPT_DEBUG: Skipping our current device {} for message encryption",
                    device_id
                );
                continue;
            }

            let trust_level = storage_guard
                .get_trust_level(&user_bare_jid, device_id)
                .unwrap_or(crate::omemo::storage::TrustLevel::Undecided);
            if trust_level == crate::omemo::storage::TrustLevel::Untrusted {
                warn!(
                    "ENCRYPT_DEBUG: Skipping untrusted own device {}:{}",
                    user_bare_jid, device_id
                );
                continue;
            }

            if !all_devices.contains(&(user_bare_jid.clone(), device_id)) {
                all_devices.push((user_bare_jid.clone(), device_id));
                info!(
                    "ENCRYPT_DEBUG: Added own device {}:{}",
                    user_bare_jid, device_id
                );
            } else {
                warn!(
                    "ENCRYPT_DEBUG: Duplicate own device {}:{} found",
                    user_bare_jid, device_id
                );
            }
        }
        drop(storage_guard);

        info!(
            "ENCRYPT_DEBUG: Final merged device list for encryption: {:?}",
            all_devices
        );
        info!(
            "ENCRYPT_DEBUG: Total devices to encrypt for: {}",
            all_devices.len()
        );
        for (jid, device_id) in &all_devices {
            info!("ENCRYPT_DEBUG: Target device: {}:{}", jid, device_id);
        }

        info!(
            "Encrypting message key for {} total devices",
            all_devices.len()
        );

        let device_list_copy = all_devices.clone();

        // Encrypt the message key for all devices
        let overall_timeout = Duration::from_secs(15);
        let mut prekey_device_set: HashSet<DeviceId> = HashSet::new();
        let session_creation_future = async {
            for (jid, device_id) in all_devices {
                info!("ENCRYPT_DEBUG: Processing device {}:{}", jid, device_id);
                let device_key = (jid.clone(), device_id);

                // True when we need to force a PreKey exchange for recovery.
                // RecoveryPreKeySent: AEAD recovery path.
                // PeerResetPending: peer sent a PreKey referencing a consumed OPK — we
                //   must start a fresh X3DH session next time we send to them.
                // Both states guarantee get_or_create_session will build a new initiator
                // session, but we also set this flag so that use_prekey_format is true
                // even if has_ephemeral is not set (defensive belt-and-suspenders).
                let needs_prekey = matches!(
                    self.sessions.get(&device_key),
                    Some(OmemoSessionState::RecoveryPreKeySent { .. })
                        | Some(OmemoSessionState::PeerResetPending)
                );
                info!(
                    "ENCRYPT_DEBUG: Device {}:{} needs_prekey: {}",
                    jid, device_id, needs_prekey
                );

                // Skip ignored devices UNLESS they need a PreKey message
                if !needs_prekey {
                    if let Ok(true) = self.is_device_ignored(&jid, device_id.get()).await {
                        warn!(
                            "ENCRYPT_DEBUG: Skipping ignored device {}:{} (no PreKey needed)",
                            jid, device_id
                        );
                        continue;
                    }
                }

                let device_timeout = Duration::from_secs(8);
                info!(
                    "ENCRYPT_DEBUG: Getting or creating session for {}:{}",
                    jid, device_id
                );
                let session_result =
                    timeout(device_timeout, self.get_or_create_session(jid.as_str(), device_id)).await;

                // Check if session creation succeeded. We can't hold the session
                // reference while accessing other self fields, so just check success here.
                let session_ok = match &session_result {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => {
                        error!(
                            "ENCRYPT_DEBUG: Failed to get or create session with {}:{}: {}",
                            jid, device_id, e
                        );
                        false
                    }
                    Err(_) => {
                        error!(
                            "ENCRYPT_DEBUG: Timeout getting session with {}:{}, skipping device",
                            jid, device_id
                        );
                        false
                    }
                };

                if !session_ok {
                    continue;
                }
                // Drop the borrow from session_result
                drop(session_result);

                // Now we can safely access other self fields
                let has_ephemeral = self.prekey_ephemeral_keys.contains_key(&device_key);
                let use_prekey_format = needs_prekey || has_ephemeral;

                let prekey_params = if use_prekey_format {
                    let identity_key = self
                        .key_bundle
                        .as_ref()
                        .unwrap()
                        .identity_key_pair
                        .public_key
                        .clone();
                    let base_key = self
                        .prekey_ephemeral_keys
                        .get(&device_key)
                        .map(|(k, _)| k.clone());
                    let registration_id = self.device_id;
                    // Get the REMOTE device's PreKey IDs (stored during session creation)
                    let (remote_spk_id, remote_opk_id) = self.remote_prekey_ids
                        .get(&device_key)
                        .map(|(spk, opk, _)| (*spk, *opk))
                        .unwrap_or_else(|| {
                            warn!("ENCRYPT_DEBUG: No stored remote prekey IDs for {}:{}, using defaults", jid, device_id);
                            (0, None)
                        });
                    Some((
                        identity_key,
                        base_key,
                        registration_id,
                        remote_spk_id,
                        remote_opk_id,
                    ))
                } else {
                    None
                };

                // Re-acquire the session (it's in self.sessions now)
                let session_key = (jid.clone(), device_id);

                // Perform encryption and capture a ratchet-state snapshot in the
                // same borrow, then release the borrow before the async
                // store_session_state call (which needs &mut self).
                let (encrypt_result, ratchet_snapshot) = {
                    let session = self
                        .sessions
                        .get_mut(&session_key)
                        .and_then(|s| s.as_session_mut())
                        .unwrap();

                    let result = if let Some((
                        identity_key,
                        base_key_opt,
                        registration_id,
                        remote_spk_id,
                        remote_opk_id,
                    )) = prekey_params
                    {
                        let base_key = base_key_opt.unwrap_or_else(|| {
                            session.ratchet_state.ratchet_key_pair.public_key.clone()
                        });

                        session.encrypt_key_prekey(
                            &message_key,
                            crate::omemo::keys::RegistrationId(registration_id.get()),
                            remote_opk_id.map(crate::omemo::keys::OneTimePreKeyId),
                            crate::omemo::keys::SignedPreKeyId(remote_spk_id),
                            &base_key,
                            &identity_key,
                        )
                    } else {
                        session.encrypt_key(&message_key)
                    };

                    let snapshot = session.ratchet_state.clone();
                    (result, snapshot)
                };

                match encrypt_result {
                    Ok(encrypted_key) => {
                        // Persist the advanced ratchet state so that the send
                        // counter survives a process restart.  Without this the
                        // stored counter is stale and the peer sees counter reuse,
                        // which produces a MAC failure on their side.
                        if let Err(e) = self
                            .store_session_state(&jid, device_id, &ratchet_snapshot)
                            .await
                        {
                            warn!(
                                "Failed to persist ratchet state after encrypt for {}:{}: {}",
                                jid, device_id, e
                            );
                        }
                        encrypted_keys.insert(device_id, encrypted_key);
                        if use_prekey_format {
                            prekey_device_set.insert(device_id);
                        }
                        info!("ENCRYPT_DEBUG: Successfully encrypted message key for {}:{} (prekey={})", jid, device_id, use_prekey_format);

                        if needs_prekey {
                            // The RecoveryPreKeySent state was already replaced by
                            // InitiatorAwaitingReply when get_or_create_session created
                            // the new session.  Clear the persistent prekey-pending flag
                            // so the recovery marker does not resurface on the next restart.
                            {
                                let storage_guard = self.storage.lock().await;
                                if let Err(e) =
                                    storage_guard.clear_prekey_pending(&device_key.0, device_key.1)
                                {
                                    warn!(
                                        "Failed to clear prekey-pending flag for {}:{}: {}",
                                        device_key.0, device_key.1, e
                                    );
                                }
                            }
                            info!(
                                "ENCRYPT_DEBUG: Sent recovery PreKey to {}:{}",
                                jid, device_id
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            "ENCRYPT_DEBUG: Failed to encrypt message key for {}:{}: {}",
                            jid, device_id, e
                        );
                    }
                }
            }
        };

        if let Err(_) = timeout(overall_timeout, session_creation_future).await {
            warn!("Overall timeout while creating sessions for message encryption");
        }

        // Require at least one key for a recipient device.  Sending a message
        // with only own-device (carbon) keys — or with no keys at all — means
        // the actual recipient can never decrypt it.
        let has_recipient_key = device_list_copy
            .iter()
            .filter(|(jid, _)| jid == recipient)
            .any(|(_, did)| encrypted_keys.contains_key(did));
        if !has_recipient_key {
            return Err(OmemoError::ProtocolError(if encrypted_keys.is_empty() {
                "All per-device key encryptions failed — message cannot be delivered".to_string()
            } else {
                format!(
                    "No recipient-device key encrypted for {} \
                     (only {} own-device carbon key(s) produced)",
                    recipient,
                    encrypted_keys.len()
                )
            }));
        }

        info!(
            "ENCRYPT_DEBUG: Message encrypted successfully for {} devices",
            encrypted_keys.len()
        );
        info!(
            "ENCRYPT_DEBUG: Final encrypted_keys map contains device IDs: {:?}",
            encrypted_keys.keys().collect::<Vec<_>>()
        );

        let has_prekey_devices = !prekey_device_set.is_empty();

        let ephemeral_key = if has_prekey_devices {
            device_list_copy.iter().find_map(|(jid, device_id)| {
                let device_key = (jid.clone(), *device_id);
                self.prekey_ephemeral_keys
                    .get(&device_key)
                    .map(|(k, _)| k.clone())
            })
        } else {
            None
        };

        // Create the complete OMEMO message
        let message = OmemoMessage {
            sender_device_id: self.device_id,
            ratchet_key: self
                .key_bundle
                .as_ref()
                .unwrap()
                .signed_pre_key_pair
                .public_key
                .clone(),
            previous_counter: 0,
            counter: 0,
            ciphertext,
            mac: vec![],
            iv: iv_bytes.to_vec(),
            encrypted_keys,
            is_prekey: has_prekey_devices,
            ephemeral_key: ephemeral_key.clone(),
            prekey_devices: prekey_device_set,
        };

        // Clear the ephemeral keys and remote prekey IDs for devices that got PreKey messages
        if has_prekey_devices {
            for (jid, device_id) in &device_list_copy {
                let device_key = (jid.clone(), *device_id);
                self.prekey_ephemeral_keys.remove(&device_key);
                self.remote_prekey_ids.remove(&device_key);
            }
        }

        Ok(message)
    }

    /// Convert an OMEMO message to XML for sending
    pub fn message_to_xml(&self, message: &OmemoMessage) -> String {
        debug!("Converting OMEMO message to XML");
        protocol::utils::omemo_message_to_xml(message)
    }

    /// Verify that a message is encrypted and isn't leaking plaintext
    pub fn verify_message_encryption(
        &self,
        xml: &str,
        plaintext: &str,
    ) -> Result<(), EncryptionVerificationError> {
        debug!("Verifying message encryption");
        if xml.contains(plaintext) {
            error!("Plaintext detected in encrypted message");
            return Err(EncryptionVerificationError::PlaintextDetected);
        }
        Ok(())
    }
}
