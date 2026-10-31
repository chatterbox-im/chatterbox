// src/xmpp/omemo_handler.rs
//! OMEMO encryption handling at the XMPP layer:
//! initialization, message decryption dispatch, trust management, key verification

use anyhow::{anyhow, Result};
use base64::Engine;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::Duration;

use super::transport;
use super::{custom_ns, XMPPClient, NS_JABBER_CLIENT};
use crate::models::{DeliveryStatus, Message};
use crate::jid::BareJid;
use crate::omemo::device_id::DeviceId;

impl XMPPClient {
    /// Initialize the client
    pub async fn initialize_client(&mut self) -> Result<()> {
        let stanza_tx = self
            .stanza_tx
            .as_ref()
            .ok_or_else(|| anyhow!("Client not initialized"))?
            .clone();

        // Publish late state NOW so the event loop has the OMEMO manager available
        // during the rest of initialization (device list fetch, etc.)
        crate::xmpp::publish_late_state(self);

        let pubsub_bridge: Arc<dyn crate::omemo::OmemoPubSub> =
            Arc::new(crate::xmpp::omemo_integration::XmppPubSubBridge::new(
                stanza_tx,
                self.iq_registry.clone(),
            ));

        // Create the OMEMO manager
        let storage = match &self.omemo_dir {
            Some(dir) => crate::omemo::storage::OmemoStorage::new(Some(dir.clone()))?,
            None => crate::omemo::storage::OmemoStorage::new_default()?,
        };
        let omemo_manager =
            match crate::omemo::OmemoManager::new(storage, self.jid.clone(), None, pubsub_bridge)
                .await
            {
                Ok(manager) => manager,
                Err(e) => {
                    error!("Failed to initialize OMEMO manager: {}", e);
                    return Err(anyhow!("Failed to initialize OMEMO manager: {}", e));
                }
            };

        // Initialize OMEMO for this client
        info!("Initializing OMEMO for {}", self.jid);

        // Generate and publish device list if needed
        if std::env::var("CHATTERBOX_RESET_OMEMO_DEVICES")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            if let Err(e) = omemo_manager.reset_device_list().await {
                warn!("Failed to reset device list: {}", e);
            }
        }
        if let Err(e) = omemo_manager.ensure_device_list_published().await {
            error!("Failed to publish device list: {}", e);
            return Err(anyhow!("Failed to publish device list: {}", e));
        }

        // Generate and publish device bundle if needed
        if let Err(e) = omemo_manager.ensure_bundle_published().await {
            error!("Failed to publish device bundle: {}", e);
            return Err(anyhow!("Failed to publish device bundle: {}", e));
        }

        // Store the OMEMO manager in the client
        self.omemo_manager = Some(Arc::new(TokioMutex::new(omemo_manager)));
        info!("OMEMO initialized successfully");

        // Re-publish late state with the OMEMO manager now available
        // so the event loop can decrypt incoming messages
        crate::xmpp::publish_late_state(self);

        info!("Refreshing OMEMO device lists and key bundles for known contacts");
        tokio::spawn({
            let client = self.clone();
            async move {
                // Give the server time to process our publications
                tokio::time::sleep(Duration::from_secs(2)).await;

                if let Ok(Some(contacts)) = client.get_roster().await {
                    for contact_jid in contacts {
                        if let Err(e) = client.refresh_omemo_keys_for_contact(&contact_jid).await {
                            warn!("Failed to refresh OMEMO keys for {}: {}", contact_jid, e);
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                } else {
                    warn!("Failed to get contact list for OMEMO key refresh");
                }
            }
        });

        Ok(())
    }

    /// Handle an encrypted message using OMEMO
    pub async fn handle_message_encrypted(
        &mut self,
        element: &xmpp_parsers::minidom::Element,
    ) -> Result<()> {
        // Extract important attributes
        let from = element.attr("from").unwrap_or("unknown@server.example");
        let wire_id = element.attr("id").unwrap_or("unknown");
        // Prefer origin-id for storage/UI dedup; wire id for receipts and session dedup.
        let msg_id = super::canonical_msg_id(element)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Look for OMEMO encrypted element - check empty namespace first (most common)
        let encrypted = element
            .get_child("encrypted", "")
            .or_else(|| element.get_child("encrypted", custom_ns::OMEMO))
            .or_else(|| element.get_child("encrypted", custom_ns::OMEMO_V1));

        if let Some(encrypted) = encrypted {
            // Get header - children inherit namespace from parent encrypted element
            let header = encrypted
                .get_child("header", "")
                .or_else(|| encrypted.get_child("header", custom_ns::OMEMO));

            if let Some(header) = header {
                // Extract sender device ID
                let sender_device_id = match header.attr("sid") {
                    Some(sid) => match sid.parse::<u32>() {
                        Ok(id) => id,
                        Err(e) => {
                            error!("Invalid sender device ID: {}", e);
                            return Err(anyhow!("Invalid sender device ID: {}", e));
                        }
                    },
                    None => {
                        error!("Missing sender device ID in OMEMO header");
                        return Err(anyhow!("Missing sender device ID in OMEMO header"));
                    }
                };

                // Get our OMEMO manager
                let omemo_manager = match &self.omemo_manager {
                    Some(manager) => manager.clone(),
                    None => {
                        error!("OMEMO manager not initialized");
                        return Err(anyhow!("OMEMO manager not initialized"));
                    }
                };

                // Skip decryption if this is our own sent message (e.g. MAM replay)
                // Per XEP-0384, the sender does not encrypt for its own device
                {
                    let manager_guard = omemo_manager.lock().await;
                    let own_device_id = manager_guard.get_device_id();
                    if DeviceId::from(sender_device_id) == own_device_id {
                        debug!(
                            "Skipping decryption of our own sent message (device {})",
                            sender_device_id
                        );
                        // Update status on the local echo; bail if `to` is absent to avoid BareJid::parse("") panic.
                        if let Some(to_raw) = element.attr("to") {
                            let recipient_jid = to_raw.split('/').next().unwrap_or(to_raw).to_string();
                            let mut upd = Message::outgoing_encrypted(msg_id.clone(), recipient_jid, "");
                            upd.delivery_status = DeliveryStatus::Delivered;
                            let _ = self.msg_tx.send(crate::models::AppEvent::Chat(upd)).await;
                        }
                        return Ok(());
                    }
                }

                // Process encrypted message using the OMEMO manager

                // Get IV - children inherit namespace from parent encrypted element
                let iv = match header
                    .get_child("iv", "")
                    .or_else(|| header.get_child("iv", custom_ns::OMEMO))
                {
                    Some(iv_elem) => match iv_elem.text() {
                        text => {
                            let iv_base64 = text;
                            match base64::engine::general_purpose::STANDARD.decode(iv_base64) {
                                Ok(iv_bytes) => iv_bytes,
                                Err(e) => {
                                    error!("Failed to decode IV: {}", e);
                                    return Err(anyhow!("Failed to decode IV: {}", e));
                                }
                            }
                        }
                    },
                    None => {
                        error!("Missing IV in OMEMO header");
                        return Err(anyhow!("Missing IV in OMEMO header"));
                    }
                };

                // Collect encrypted keys for each device
                let mut encrypted_keys: std::collections::HashMap<DeviceId, Vec<u8>> = std::collections::HashMap::new();
                let mut is_prekey_message = false;
                for key_elem in header.children().filter(|e| e.name() == "key") {
                    if let (Some(rid_str), text) = (key_elem.attr("rid"), key_elem.text()) {
                        let key_base64 = text;
                        // Check if this key element has prekey="true" attribute (Conversations format)
                        if key_elem.attr("prekey") == Some("true")
                            || key_elem.attr("prekey") == Some("1")
                        {
                            is_prekey_message = true;
                        }
                        match rid_str.parse::<u32>() {
                            Ok(recipient_id) => {
                                match base64::engine::general_purpose::STANDARD.decode(key_base64) {
                                    Ok(key_bytes) => {
                                        encrypted_keys.insert(DeviceId::from(recipient_id), key_bytes);
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to decode key for device {}: {}",
                                            rid_str, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Invalid recipient ID: {}", e);
                            }
                        }
                    }
                }

                // Get payload - children inherit namespace from parent encrypted element
                // Note: key-transport-only messages (no payload) are valid OMEMO messages
                // used for silent session establishment. We process them but don't show them.
                let payload = match encrypted
                    .get_child("payload", "")
                    .or_else(|| encrypted.get_child("payload", custom_ns::OMEMO))
                {
                    Some(payload_elem) => match payload_elem.text() {
                        text => {
                            let payload_base64 = text;
                            match base64::engine::general_purpose::STANDARD.decode(payload_base64) {
                                Ok(payload_bytes) => Some(payload_bytes),
                                Err(e) => {
                                    error!("Failed to decode payload: {}", e);
                                    return Err(anyhow!("Failed to decode payload: {}", e));
                                }
                            }
                        }
                    },
                    None => {
                        debug!(
                            "Key-transport OMEMO message (no payload) from {}:{}",
                            from, sender_device_id
                        );
                        None
                    }
                };

                // For key-transport messages (no payload), just process the key exchange
                if payload.is_none() {
                    let mut omemo_manager_guard = omemo_manager.lock().await;
                    debug!(
                        "Processing key-transport message from {}:{}",
                        from, sender_device_id
                    );
                    // Process the PreKey message to establish/advance the session
                    if let Some(our_key) = encrypted_keys.get(&omemo_manager_guard.get_device_id())
                    {
                        match omemo_manager_guard
                            .decrypt_message_key(from.to_string(), DeviceId::from(sender_device_id), our_key)
                            .await
                        {
                            Ok(_) => debug!(
                                "Key-transport message processed successfully from {}:{}",
                                from, sender_device_id
                            ),
                            Err(e) => warn!(
                                "Failed to process key-transport message from {}:{}: {}",
                                from, sender_device_id, e
                            ),
                        }
                    }
                    return Ok(());
                }

                // Create the OMEMO message
                let omemo_message = crate::omemo::protocol::OmemoMessage {
                    sender_device_id: DeviceId::from(sender_device_id),
                    ratchet_key: vec![],
                    previous_counter: 0,
                    counter: 0,
                    ciphertext: payload.unwrap(),
                    mac: vec![],
                    iv,
                    encrypted_keys,
                    is_prekey: is_prekey_message,
                    ephemeral_key: None,
                    prekey_devices: std::collections::HashSet::new(),
                };

                // Decrypt the message
                let mut omemo_manager_guard = omemo_manager.lock().await;
                warn!(
                    "DECRYPT_DEBUG: Starting decryption for message from {}:{}",
                    from, sender_device_id
                );
                match omemo_manager_guard
                    .decrypt_message(from, DeviceId::from(sender_device_id), &omemo_message)
                    .await
                {
                    Ok(plaintext) => {
                        // NB: never log decrypted plaintext content — doing so would
                        // persist private message bodies to the log file on disk.
                        info!(
                            "Successfully decrypted message from {}:{} ({} bytes)",
                            from,
                            sender_device_id,
                            plaintext.len()
                        );

                        // Record this message ID so that a duplicate delivery (e.g. a
                        // message-carbon copy of a direct stanza) skips re-decryption
                        // and avoids double-advancing the ratchet.
                        omemo_manager_guard.mark_message_decrypted(wire_id);

                        // Strip resource from sender JID to get bare JID
                        let sender_bare_jid = from.split('/').next().unwrap_or(from).to_string();

                        // Create a message for the UI
                        let message = Message::incoming_encrypted(
                            msg_id,
                            sender_bare_jid.clone(),
                            plaintext.clone(),
                        );

                        // Send to UI (capture identifiers first; send() moves `message`)
                        let logged_id = message.id.clone();
                        if let Err(e) = self.msg_tx.send(crate::models::AppEvent::Chat(message)).await {
                            error!("FAILED to send decrypted message to UI: {}", e);
                        } else {
                            debug!(
                                "Sent decrypted OMEMO message {} from {} to UI channel",
                                logged_id, sender_bare_jid
                            );
                        }

                        // Send a receipt if requested
                        if element.has_child("request", custom_ns::RECEIPTS) {
                            if let Some(stanza_tx) = &self.stanza_tx {
                                let receipt = xmpp_parsers::minidom::Element::builder(
                                    "message",
                                    NS_JABBER_CLIENT,
                                )
                                .attr("to".try_into().unwrap(), from)
                                .attr("id".try_into().unwrap(), &uuid::Uuid::new_v4().to_string())
                                .append(
                                    xmpp_parsers::minidom::Element::builder(
                                        "received",
                                        custom_ns::RECEIPTS,
                                    )
                                    .attr("id".try_into().unwrap(), wire_id)
                                    .build(),
                                )
                                .build();

                                if let Err(e) = transport::send_stanza(stanza_tx, receipt) {
                                    error!("Failed to send receipt: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to decrypt message from {} (device {}): {}",
                            from, sender_device_id, e
                        );
                        error!("Message ID: {}, Decryption failure details: {:?}", wire_id, e);

                        // Mark this message ID as failed so the carbon copy of the
                        // same message is not also counted as a separate failure
                        // (which would prematurely reset the OMEMO session).
                        omemo_manager_guard.mark_message_failed(wire_id);

                        debug!("OMEMO message structure - Sender device: {}, IV length: {}, Payload length: {}, Number of keys: {}", 
                            omemo_message.sender_device_id,
                            omemo_message.iv.len(),
                            omemo_message.ciphertext.len(),
                            omemo_message.encrypted_keys.len());

                        let message = Message::incoming_encrypted(
                            msg_id,
                            from.to_string(),
                            format!("[Encrypted message could not be decrypted: {}. You may need to refresh the OMEMO keys or verify device identity.]", e),
                        );

                        if let Err(e) = self.msg_tx.send(crate::models::AppEvent::Chat(message)).await {
                            error!("Failed to send error message to UI: {}", e);
                        }
                    }
                }

                return Ok(());
            }
        }

        error!("Could not find required OMEMO elements in encrypted message");
        Err(anyhow!(
            "Could not find required OMEMO elements in encrypted message"
        ))
    }

    /// Process a key verification response from the user.
    /// `trusted = true` → accept; `trusted = false` → reject.
    pub async fn handle_key_verification_response(
        &self,
        contact: &str,
        level: crate::omemo::storage::TrustLevel,
    ) -> Result<()> {
        info!("Processing key verification response for {}: level={:?}", contact, level);

        let label = match level {
            crate::omemo::storage::TrustLevel::Trusted  => "accepted and marked as trusted",
            crate::omemo::storage::TrustLevel::Verified => "verified",
            _                                           => "rejected",
        };
        let system_message = Message::system(contact, format!("OMEMO key for {} has been {}", contact, label));
        if let Err(e) = self.msg_tx.send(crate::models::AppEvent::Chat(system_message)).await {
            error!("Failed to send key response message to UI: {}", e);
        }

        if let Err(e) = self.process_omemo_verification_response(contact, level).await {
            error!("Failed to process key verification in OMEMO: {}", e);
            return Err(anyhow!("Failed to process key verification: {}", e));
        }

        self.check_omemo_keys_for_contact(contact).await
    }

    /// Check OMEMO keys for a contact and request verification if needed.
    pub async fn check_omemo_keys_for_contact(&self, contact: &str) -> Result<()> {
        let omemo_manager = match &self.omemo_manager {
            Some(m) => m,
            None => {
                warn!("No OMEMO manager available for key verification");
                return Ok(());
            }
        };
        let mut guard = omemo_manager.lock().await;
        prompt_first_untrusted_key(&mut *guard, contact, &self.msg_tx).await
    }

    /// Request verification for an OMEMO key
    pub async fn process_key_verification_response(
        &self,
        sender: &str,
        key_fingerprint: &str,
        device_id: Option<u32>,
    ) -> Result<()> {
        let event = crate::models::AppEvent::KeyVerifyRequest {
            sender: sender.to_string(),
            fingerprint: key_fingerprint.to_string(),
            device_id,
        };
        if let Err(e) = self.msg_tx.send(event).await {
            error!("Failed to send key verification request to UI: {}", e);
            return Err(anyhow!("Failed to send key verification request to UI: {}", e));
        }
        Ok(())
    }

    /// Check if OMEMO encryption is enabled
    pub async fn is_omemo_enabled(&self) -> bool {
        self.omemo_manager.is_some()
    }

    /// Get device IDs for a user
    pub async fn get_device_ids_for_user(&self, jid: &str) -> Result<Vec<DeviceId>> {
        if let Some(omemo_manager) = &self.omemo_manager {
            // Normalize to bare JID
            let bare_jid = if jid.contains('/') {
                jid.split('/').next().unwrap_or(jid)
            } else {
                jid
            };

            // Try to acquire the lock without blocking; if contended, read from storage directly
            match omemo_manager.try_lock() {
                Ok(manager) => match manager.get_device_ids_for_test(bare_jid).await {
                    Ok(devices) => Ok(devices),
                    Err(e) => Err(anyhow!("Failed to get device IDs: {}", e)),
                },
                Err(_) => {
                    info!(
                        "OMEMO manager lock contended, reading device list from cache for {}",
                        bare_jid
                    );
                    let storage = {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            omemo_manager.lock(),
                        )
                        .await
                        {
                            Ok(manager) => manager.get_storage(),
                            Err(_) => {
                                return Err(anyhow!(
                                    "OMEMO manager busy, could not read device list"
                                ));
                            }
                        }
                    };
                    let storage_guard = storage.lock().await;
                    match storage_guard.load_device_list(&BareJid::parse(bare_jid).expect("expected valid JID")) {
                        Ok(entry) if !entry.device_ids.is_empty() => Ok(entry.device_ids),
                        Ok(_) => Ok(vec![]),
                        Err(e) => Err(anyhow!("No cached device list for {}: {}", bare_jid, e)),
                    }
                }
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Fetch a user's device list from the server, bypassing cached IDs.
    pub async fn force_refresh_device_list_for_user(&self, jid: &str) -> Result<Vec<DeviceId>> {
        let omemo_manager = self
            .omemo_manager
            .as_ref()
            .ok_or_else(|| anyhow!("OMEMO manager not initialized"))?;
        let bare_jid = BareJid::parse(jid)?;
        let manager = omemo_manager.lock().await;
        manager
            .force_refresh_device_list(&bare_jid)
            .await
            .map_err(|e| anyhow!("Failed to refresh device list: {}", e))
    }

    async fn refresh_omemo_keys_for_contact(&self, jid: &str) -> Result<()> {
        let bare_jid = BareJid::parse(jid)?;
        let omemo_manager = self
            .omemo_manager
            .as_ref()
            .ok_or_else(|| anyhow!("OMEMO manager not initialized"))?;
        let mut manager = omemo_manager.lock().await;
        let device_ids = manager.force_refresh_device_list(&bare_jid).await?;

        for device_id in device_ids {
            match manager
                .fetch_device_identity_from_server(&bare_jid, device_id)
                .await
            {
                Ok((_, key_changed)) => {
                    if key_changed {
                        manager
                            .pending_trust_restorations
                            .remove(&(bare_jid.clone(), device_id));
                        manager.reset_session(&bare_jid, device_id.get()).await?;
                    }
                    info!("Refreshed OMEMO key bundle for {}:{}", bare_jid, device_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to refresh OMEMO key bundle for {}:{}: {}",
                        bare_jid, device_id, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Get fingerprint for a device
    pub async fn get_device_fingerprint(&self, jid: &str, device_id: DeviceId) -> Result<String> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.get_device_fingerprint(jid, device_id).await {
                Ok(fingerprint) => Ok(fingerprint),
                Err(e) => Err(anyhow!("Failed to get device fingerprint: {}", e)),
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Get a fingerprint and queue undecided keys for interactive verification.
    pub async fn get_device_fingerprint_for_verification(
        &self,
        jid: &str,
        device_id: DeviceId,
    ) -> Result<String> {
        let omemo_manager = self
            .omemo_manager
            .as_ref()
            .ok_or_else(|| anyhow!("OMEMO manager not initialized"))?;
        let manager = omemo_manager.lock().await;
        let jid = BareJid::parse(jid)?;
        let level = manager
            .get_device_trust_level(jid.as_str(), device_id)
            .await?;
        if level == crate::omemo::storage::TrustLevel::Undecided {
            queue_undecided_key(&manager, &jid, device_id).await
        } else {
            Ok(manager
                .get_device_fingerprint(jid.as_str(), device_id)
                .await?)
        }
    }

    /// Toggle the trust status for all of a contact's OMEMO devices
    pub async fn toggle_omemo_trust(&self, contact: &str) -> Result<bool> {
        if self.omemo_manager.is_none() {
            warn!("No OMEMO manager available for key trust toggle");
            return Err(anyhow!("No OMEMO manager available"));
        }

        let omemo_manager = self.omemo_manager.as_ref().unwrap();

        let device_ids = {
            let manager_guard = omemo_manager.lock().await;
            manager_guard.get_device_ids_for_test(contact).await?
        };

        if device_ids.is_empty() {
            return Err(anyhow!("No OMEMO devices found"));
        }

        info!("Found {} OMEMO devices for {}", device_ids.len(), contact);

        let mut all_trusted = true;
        let mut _any_trusted = false;
        let mut statuses = Vec::new();

        for device_id in &device_ids {
            let trusted = {
                let manager_guard = omemo_manager.lock().await;
                manager_guard
                    .is_device_identity_trusted(contact, *device_id)
                    .await?
            };

            statuses.push((*device_id, trusted));
            if trusted {
                _any_trusted = true;
            } else {
                all_trusted = false;
            }
        }

        let set_trusted = !all_trusted;

        for (device_id, current_trusted) in statuses {
            if current_trusted != set_trusted {
                let mut manager_guard = omemo_manager.lock().await;

                if set_trusted {
                    if let Err(e) = manager_guard
                        .trust_device_identity(contact, device_id)
                        .await
                    {
                        error!("Failed to trust device: {}", e);
                        return Err(anyhow!("Failed to trust device: {}", e));
                    }
                } else {
                    if let Err(e) = manager_guard
                        .untrust_device_identity(contact, device_id)
                        .await
                    {
                        error!("Failed to untrust device: {}", e);
                        return Err(anyhow!("Failed to untrust device: {}", e));
                    }
                }
            }
        }

        let status_desc = if set_trusted { "trusted" } else { "untrusted" };
        info!(
            "Successfully toggled {} devices for {} to {}",
            device_ids.len(),
            contact,
            status_desc
        );

        Ok(set_trusted)
    }

    /// Get access to the OMEMO manager (primarily for testing)
    pub fn get_omemo_manager(&self) -> Option<Arc<TokioMutex<crate::omemo::OmemoManager>>> {
        self.omemo_manager.clone()
    }

    /// Get the stored trust level for a specific device.
    pub async fn get_device_trust_level(
        &self,
        jid: &str,
        device_id: crate::omemo::device_id::DeviceId,
    ) -> Result<crate::omemo::TrustLevel> {
        let manager = self
            .omemo_manager
            .as_ref()
            .ok_or_else(|| anyhow!("No OMEMO manager available"))?;
        let guard = manager.lock().await;
        guard
            .get_device_trust_level(jid, device_id)
            .await
            .map_err(|e| anyhow!("{}", e))
    }

    /// Set trust for a single device (trusted = true → Trusted, false → Untrusted).
    pub async fn set_single_device_trust(
        &self,
        jid: &str,
        device_id: crate::omemo::device_id::DeviceId,
        level: crate::omemo::storage::TrustLevel,
    ) -> Result<()> {
        let manager = self
            .omemo_manager
            .as_ref()
            .ok_or_else(|| anyhow!("No OMEMO manager available"))?;
        let mut guard = manager.lock().await;
        if level.is_trusted() {
            guard
                .trust_device_identity(jid, device_id)
                .await
                .map_err(|e| anyhow!("{}", e))
        } else {
            guard
                .untrust_device_identity(jid, device_id)
                .await
                .map_err(|e| anyhow!("{}", e))
        }
    }
}

async fn queue_undecided_key(
    manager: &crate::omemo::OmemoManager,
    jid: &BareJid,
    device_id: DeviceId,
) -> Result<String> {
    let fingerprint = manager
        .get_device_fingerprint(jid.as_str(), device_id)
        .await?;
    if device_id == manager.get_device_id() && *jid == BareJid::parse(&manager.local_jid)? {
        return Ok(fingerprint);
    }
    let storage = manager.get_storage();
    storage
        .lock()
        .await
        .store_pending_device_verification(jid, device_id, &fingerprint)?;
    Ok(fingerprint)
}

/// Queue undecided keys for `contact` and show the first pending verification.
/// Single source of truth used by both the XMPP handler and the coordinator.
pub(crate) async fn prompt_first_untrusted_key(
    omemo_manager: &mut crate::omemo::OmemoManager,
    contact: &str,
    msg_tx: &tokio::sync::mpsc::Sender<crate::models::AppEvent>,
) -> Result<()> {
    if contact.starts_with('[') && contact.ends_with(']') {
        return Ok(());
    }

    let jid = BareJid::parse(contact)?;
    let storage = omemo_manager.get_storage();

    let device_ids = match tokio::time::timeout(
        Duration::from_secs(10),
        omemo_manager.get_device_ids_for_test(contact),
    )
    .await
    {
        Ok(Ok(ids)) => ids,
        Ok(Err(e)) => {
            warn!("Failed to get device IDs for {}: {}", contact, e);
            return Ok(());
        }
        Err(_) => {
            warn!("Timeout getting device IDs for {}", contact);
            return Ok(());
        }
    };

    info!("Found {} OMEMO devices for {}", device_ids.len(), contact);

    for device_id in device_ids {
        let level = match tokio::time::timeout(
            Duration::from_secs(8),
            omemo_manager.get_device_trust_level(contact, device_id),
        )
        .await
        {
            Ok(Ok(level)) => level,
            Ok(Err(e)) => {
                warn!("Failed to check trust for {}:{}: {}", contact, device_id, e);
                continue;
            }
            Err(_) => {
                warn!(
                    "Timeout checking trust for {}:{}, skipping",
                    contact, device_id
                );
                continue;
            }
        };

        if level != crate::omemo::storage::TrustLevel::Undecided {
            continue;
        }

        match tokio::time::timeout(
            Duration::from_secs(8),
            queue_undecided_key(omemo_manager, &jid, device_id),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                warn!(
                    "Failed to queue key verification for {}:{}: {}",
                    contact, device_id, e
                );
            }
            Err(_) => {
                warn!(
                    "Timeout queuing key verification for {}:{}, skipping",
                    contact, device_id
                );
            }
        }
    }

    let pending = storage.lock().await.get_pending_device_verification(&jid)?;
    if let Some((device_id, fingerprint)) = pending {
        info!(
            "Requesting verification for {}:{} with fingerprint {}",
            jid, device_id, fingerprint
        );
        let event = crate::models::AppEvent::KeyVerifyRequest {
            sender: jid.to_string(),
            fingerprint,
            device_id: Some(device_id.get()),
        };
        if let Err(e) = msg_tx.send(event).await {
            error!("Failed to send key verification request to UI: {}", e);
            return Err(anyhow!(
                "Failed to send key verification request to UI: {}",
                e
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AppEvent;
    use crate::omemo::storage::{DeviceListEntry, OmemoStorage, TrustLevel};
    use crate::omemo::test_support::RecordingPubSub;
    use crate::omemo::OmemoManager;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    async fn client_with_omemo(
        jid: &str,
        device_id: u32,
        pubsub: Arc<RecordingPubSub>,
    ) -> (XMPPClient, mpsc::Receiver<AppEvent>, TempDir) {
        let dir = TempDir::new().unwrap();
        let mut storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        storage.store_device_id(DeviceId::from(device_id)).unwrap();
        let manager = OmemoManager::new(storage, jid.to_string(), None, pubsub)
            .await
            .unwrap();
        let (mut client, rx) = XMPPClient::new();
        client.jid = jid.to_string();
        client.omemo_manager = Some(Arc::new(TokioMutex::new(manager)));
        (client, rx, dir)
    }

    async fn publish_peer_bundle(pubsub: &RecordingPubSub, peer: &XMPPClient) -> String {
        let manager = peer.get_omemo_manager().unwrap();
        let manager = manager.lock().await;
        let bundle = manager.key_bundle.as_ref().unwrap();
        pubsub
            .add_bundle(&peer.jid, manager.device_id.get(), bundle)
            .await;
        manager.generate_standard_fingerprint(bundle.identity_key_pair.public_key.as_ref())
    }

    fn assert_key_request(
        rx: &mut mpsc::Receiver<AppEvent>,
        jid: &str,
        device_id: u32,
        fingerprint: &str,
    ) {
        match rx.try_recv().expect("expected a key verification popup") {
            AppEvent::KeyVerifyRequest {
                sender,
                device_id: requested_device_id,
                fingerprint: requested_fingerprint,
            } => {
                assert_eq!(sender, jid);
                assert_eq!(requested_device_id, Some(device_id));
                assert_eq!(requested_fingerprint, fingerprint);
            }
            event => panic!("expected key verification, got {:?}", event),
        }
    }

    #[tokio::test]
    async fn startup_key_refresh_updates_bundles_and_discovers_new_devices() {
        let pubsub = RecordingPubSub::new();
        let (client, _rx, _dir) = client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let (peer, _peer_rx, _peer_dir) =
            client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
        let (other_peer, _other_rx, _other_dir) =
            client_with_omemo("bob@example.com", 3, pubsub.clone()).await;
        let jid = BareJid::parse("bob@example.com").unwrap();
        let device_id = DeviceId::from(2u32);
        let fingerprint = publish_peer_bundle(&pubsub, &peer).await;
        let other_fingerprint = publish_peer_bundle(&pubsub, &other_peer).await;
        pubsub.add_device_list(jid.as_str(), &[2]).await;
        client.get_device_ids_for_user(jid.as_str()).await.unwrap();

        let manager = client.get_omemo_manager().unwrap();
        let storage = {
            let mut manager = manager.lock().await;
            manager
                .get_or_create_session(jid.as_str(), device_id)
                .await
                .unwrap();
            manager.get_storage()
        };
        storage
            .lock()
            .await
            .set_trust_level(&jid, device_id, TrustLevel::Verified)
            .unwrap();

        let signed_prekey_id = {
            let peer_manager = peer.get_omemo_manager().unwrap();
            let mut peer_manager = peer_manager.lock().await;
            peer_manager.prekey_rotation_config.max_signed_prekey_age = 0;
            peer_manager.prekey_rotation_config.last_rotation = 0;
            peer_manager.check_and_rotate_prekeys().await.unwrap();
            peer_manager.key_bundle.as_ref().unwrap().signed_pre_key_id
        };
        publish_peer_bundle(&pubsub, &peer).await;
        pubsub.add_device_list(jid.as_str(), &[2, 3]).await;

        client
            .refresh_omemo_keys_for_contact(jid.as_str())
            .await
            .unwrap();

        let manager = manager.lock().await;
        assert!(manager.sessions.contains_key(&(jid.clone(), device_id)));
        let mut storage = storage.lock().await;
        assert_eq!(
            storage.load_device_list(&jid).unwrap().device_ids,
            vec![device_id, DeviceId::from(3u32)]
        );
        let identity = storage.load_device_identity(&jid, device_id).unwrap();
        assert_eq!(identity.signed_pre_key.id, signed_prekey_id);
        assert_eq!(
            manager.generate_standard_fingerprint(&identity.identity_key),
            fingerprint
        );
        assert_eq!(
            storage.get_trust_level(&jid, device_id).unwrap(),
            TrustLevel::Verified
        );
        let other_identity = storage
            .load_device_identity(&jid, DeviceId::from(3u32))
            .unwrap();
        assert_eq!(
            manager.generate_standard_fingerprint(&other_identity.identity_key),
            other_fingerprint
        );
    }

    #[tokio::test]
    async fn startup_key_refresh_resets_sessions_for_changed_identities() {
        let pubsub = RecordingPubSub::new();
        let (client, _rx, _dir) = client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let (peer, _peer_rx, _peer_dir) =
            client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
        let jid = BareJid::parse("bob@example.com").unwrap();
        let device_id = DeviceId::from(2u32);
        let old_fingerprint = publish_peer_bundle(&pubsub, &peer).await;
        pubsub.add_device_list(jid.as_str(), &[2]).await;
        let manager = client.get_omemo_manager().unwrap();
        let storage = {
            let mut manager = manager.lock().await;
            manager
                .get_or_create_session(jid.as_str(), device_id)
                .await
                .unwrap();
            manager
                .pending_trust_restorations
                .insert((jid.clone(), device_id));
            manager.get_storage()
        };
        storage
            .lock()
            .await
            .set_trust_level(&jid, device_id, TrustLevel::Verified)
            .unwrap();

        let (replacement_peer, _replacement_rx, _replacement_dir) =
            client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
        let fingerprint = publish_peer_bundle(&pubsub, &replacement_peer).await;
        assert_ne!(old_fingerprint, fingerprint);

        client
            .refresh_omemo_keys_for_contact(jid.as_str())
            .await
            .unwrap();

        let manager = manager.lock().await;
        assert!(!manager.sessions.contains_key(&(jid.clone(), device_id)));
        assert!(!manager
            .pending_trust_restorations
            .contains(&(jid.clone(), device_id)));
        let storage = storage.lock().await;
        assert!(!storage
            .load_all_sessions()
            .unwrap()
            .contains_key(&format!("{}:{}", jid, device_id)));
        assert_eq!(
            storage.get_trust_level(&jid, device_id).unwrap(),
            TrustLevel::Untrusted
        );
        assert_eq!(
            storage.get_pending_device_verification(&jid).unwrap(),
            Some((device_id, fingerprint))
        );
    }

    #[tokio::test]
    async fn startup_key_refresh_keeps_cached_keys_and_continues_after_bundle_failure() {
        let pubsub = RecordingPubSub::new();
        let (client, _rx, _dir) = client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let (peer, _peer_rx, _peer_dir) =
            client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
        let jid = BareJid::parse("bob@example.com").unwrap();
        let device_id = DeviceId::from(2u32);
        let fingerprint = publish_peer_bundle(&pubsub, &peer).await;
        client
            .get_device_fingerprint(jid.as_str(), device_id)
            .await
            .unwrap();
        for node in crate::omemo::bundle_node_variants(device_id) {
            pubsub
                .responses
                .lock()
                .await
                .remove(&format!("{}|{}", jid, node));
        }
        let (other_peer, _other_rx, _other_dir) =
            client_with_omemo("bob@example.com", 3, pubsub.clone()).await;
        let other_fingerprint = publish_peer_bundle(&pubsub, &other_peer).await;
        pubsub.add_device_list(jid.as_str(), &[2, 3]).await;

        client
            .refresh_omemo_keys_for_contact(jid.as_str())
            .await
            .unwrap();

        let manager = client.get_omemo_manager().unwrap();
        let manager = manager.lock().await;
        let storage = manager.get_storage();
        let mut storage = storage.lock().await;
        let identity = storage.load_device_identity(&jid, device_id).unwrap();
        assert_eq!(
            manager.generate_standard_fingerprint(&identity.identity_key),
            fingerprint
        );
        let other_identity = storage
            .load_device_identity(&jid, DeviceId::from(3u32))
            .unwrap();
        assert_eq!(
            manager.generate_standard_fingerprint(&other_identity.identity_key),
            other_fingerprint
        );
    }

    #[tokio::test]
    async fn forced_device_refresh_bypasses_cache_and_allows_fingerprint_lookup() {
        let pubsub = RecordingPubSub::new();
        let (client, _rx, _dir) = client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let (peer, _peer_rx, _peer_dir) =
            client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
        let device_id = DeviceId::from(2u32);
        let expected_fingerprint = publish_peer_bundle(&pubsub, &peer).await;
        pubsub
            .add_device_list("bob@example.com", &[device_id.get()])
            .await;

        let manager = client.get_omemo_manager().unwrap();
        let storage = manager.lock().await.get_storage();
        storage
            .lock()
            .await
            .save_device_list(&DeviceListEntry {
                jid: "bob@example.com".to_string(),
                device_ids: vec![DeviceId::from(0u32)],
                last_update: 0,
            })
            .unwrap();

        let device_ids = tokio::time::timeout(Duration::from_secs(2), async {
            match client
                .force_refresh_device_list_for_user("Bob@Example.com/desktop")
                .await
            {
                Ok(ids) => {
                    let fingerprint = client
                        .get_device_fingerprint("bob@example.com", device_id)
                        .await
                        .unwrap();
                    assert_eq!(fingerprint, expected_fingerprint);
                    ids
                }
                Err(e) => panic!("device refresh failed: {}", e),
            }
        })
        .await
        .expect("fingerprint lookup must not deadlock after a device refresh");

        assert_eq!(device_ids, vec![device_id]);
        assert_eq!(
            storage
                .lock()
                .await
                .load_device_list(&BareJid::parse("bob@example.com").unwrap())
                .unwrap()
                .device_ids,
            device_ids
        );
    }

    #[tokio::test]
    async fn forced_device_refresh_clears_stale_cached_devices() {
        let pubsub = RecordingPubSub::new();
        let (client, _rx, _dir) = client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let jid = BareJid::parse("bob@example.com").unwrap();
        let manager = client.get_omemo_manager().unwrap();
        let storage = manager.lock().await.get_storage();
        storage
            .lock()
            .await
            .save_device_list(&DeviceListEntry {
                jid: jid.to_string(),
                device_ids: vec![DeviceId::from(42u32)],
                last_update: 0,
            })
            .unwrap();
        pubsub.add_device_list(jid.as_str(), &[]).await;

        let device_ids = client
            .force_refresh_device_list_for_user(jid.as_str())
            .await
            .unwrap();

        assert!(device_ids.is_empty());
        assert!(storage
            .lock()
            .await
            .load_device_list(&jid)
            .unwrap()
            .device_ids
            .is_empty());
    }

    #[tokio::test]
    async fn refreshed_keys_prompt_once_and_preserve_decisions() {
        for decision in [TrustLevel::Trusted, TrustLevel::Untrusted] {
            let pubsub = RecordingPubSub::new();
            let (client, mut rx, _dir) =
                client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
            let (peer, _peer_rx, _peer_dir) =
                client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
            let fingerprint = publish_peer_bundle(&pubsub, &peer).await;
            let jid = BareJid::parse("bob@example.com").unwrap();
            let manager = client.get_omemo_manager().unwrap();
            let storage = manager.lock().await.get_storage();
            storage
                .lock()
                .await
                .set_trust_level(&jid, DeviceId::from(3u32), TrustLevel::Verified)
                .unwrap();
            storage
                .lock()
                .await
                .set_trust_level(&jid, DeviceId::from(4u32), TrustLevel::Untrusted)
                .unwrap();
            pubsub.add_device_list(jid.as_str(), &[3, 4]).await;
            client
                .check_omemo_keys_for_contact(jid.as_str())
                .await
                .unwrap();
            assert!(rx.try_recv().is_err());

            pubsub.add_device_list(jid.as_str(), &[2, 3, 4]).await;
            client
                .force_refresh_device_list_for_user(jid.as_str())
                .await
                .unwrap();
            assert_eq!(
                client
                    .get_device_fingerprint_for_verification(jid.as_str(), DeviceId::from(2u32))
                    .await
                    .unwrap(),
                fingerprint
            );
            client
                .check_omemo_keys_for_contact(jid.as_str())
                .await
                .unwrap();

            assert_key_request(&mut rx, jid.as_str(), 2, &fingerprint);
            assert!(rx.try_recv().is_err());
            client
                .handle_key_verification_response(jid.as_str(), decision)
                .await
                .unwrap();
            assert!(matches!(rx.try_recv().unwrap(), AppEvent::Chat(_)));
            assert!(rx.try_recv().is_err());

            client
                .force_refresh_device_list_for_user(jid.as_str())
                .await
                .unwrap();
            client
                .get_device_fingerprint_for_verification(jid.as_str(), DeviceId::from(2u32))
                .await
                .unwrap();
            client
                .check_omemo_keys_for_contact(jid.as_str())
                .await
                .unwrap();
            assert!(rx.try_recv().is_err());
            let storage = storage.lock().await;
            assert_eq!(
                storage.get_trust_level(&jid, DeviceId::from(2u32)).unwrap(),
                decision
            );
            assert_eq!(
                storage.get_trust_level(&jid, DeviceId::from(3u32)).unwrap(),
                TrustLevel::Verified
            );
            assert_eq!(
                storage.get_trust_level(&jid, DeviceId::from(4u32)).unwrap(),
                TrustLevel::Untrusted
            );
        }
    }

    #[tokio::test]
    async fn key_verifications_advance_through_pending_devices() {
        let pubsub = RecordingPubSub::new();
        let (client, mut rx, _dir) =
            client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let (peer, _peer_rx, _peer_dir) =
            client_with_omemo("bob@example.com", 2, pubsub.clone()).await;
        let (other_peer, _other_rx, _other_dir) =
            client_with_omemo("bob@example.com", 3, pubsub.clone()).await;
        let fingerprint = publish_peer_bundle(&pubsub, &peer).await;
        let other_fingerprint = publish_peer_bundle(&pubsub, &other_peer).await;
        pubsub.add_device_list("bob@example.com", &[3, 2]).await;

        for id in [3u32, 2] {
            client
                .get_device_fingerprint_for_verification("bob@example.com", DeviceId::from(id))
                .await
                .unwrap();
        }
        client
            .check_omemo_keys_for_contact("bob@example.com")
            .await
            .unwrap();
        assert_key_request(&mut rx, "bob@example.com", 2, &fingerprint);
        assert!(rx.try_recv().is_err());

        client
            .handle_key_verification_response("bob@example.com", TrustLevel::Trusted)
            .await
            .unwrap();
        assert!(matches!(rx.try_recv().unwrap(), AppEvent::Chat(_)));
        assert_key_request(&mut rx, "bob@example.com", 3, &other_fingerprint);
        assert!(rx.try_recv().is_err());

        client
            .handle_key_verification_response("bob@example.com", TrustLevel::Untrusted)
            .await
            .unwrap();
        assert!(matches!(rx.try_recv().unwrap(), AppEvent::Chat(_)));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn saved_key_change_requests_are_shown_even_when_untrusted() {
        let pubsub = RecordingPubSub::new();
        let (client, mut rx, _dir) =
            client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let jid = BareJid::parse("bob@example.com").unwrap();
        let manager = client.get_omemo_manager().unwrap();
        let storage = manager.lock().await.get_storage();
        storage
            .lock()
            .await
            .set_trust_level(&jid, DeviceId::from(2u32), TrustLevel::Untrusted)
            .unwrap();
        storage
            .lock()
            .await
            .store_pending_device_verification(&jid, DeviceId::from(2u32), "changed fingerprint")
            .unwrap();
        pubsub.add_device_list(jid.as_str(), &[2]).await;

        client
            .check_omemo_keys_for_contact(jid.as_str())
            .await
            .unwrap();

        assert_key_request(&mut rx, jid.as_str(), 2, "changed fingerprint");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn other_own_devices_require_verification_but_this_device_does_not() {
        let pubsub = RecordingPubSub::new();
        let (client, mut rx, _dir) =
            client_with_omemo("alice@example.com", 1, pubsub.clone()).await;
        let (peer, _peer_rx, _peer_dir) =
            client_with_omemo("alice@example.com", 2, pubsub.clone()).await;
        publish_peer_bundle(&pubsub, &client).await;
        let fingerprint = publish_peer_bundle(&pubsub, &peer).await;
        pubsub.add_device_list("alice@example.com", &[1, 2]).await;

        for id in [1u32, 2] {
            client
                .get_device_fingerprint_for_verification("alice@example.com", DeviceId::from(id))
                .await
                .unwrap();
        }
        client
            .check_omemo_keys_for_contact("alice@example.com")
            .await
            .unwrap();

        assert_key_request(&mut rx, "alice@example.com", 2, &fingerprint);
        assert!(rx.try_recv().is_err());
        client
            .handle_key_verification_response("alice@example.com", TrustLevel::Trusted)
            .await
            .unwrap();
        assert!(matches!(rx.try_recv().unwrap(), AppEvent::Chat(_)));
        assert!(rx.try_recv().is_err());
    }
}
