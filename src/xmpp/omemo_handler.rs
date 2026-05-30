// src/xmpp/omemo_handler.rs
//! OMEMO encryption handling at the XMPP layer:
//! initialization, message decryption dispatch, trust management, key verification

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use base64::Engine;

use crate::models::{Message, DeliveryStatus};
use crate::omemo::device_id::DeviceId;
use super::{XMPPClient, custom_ns, NS_JABBER_CLIENT};

impl XMPPClient {
    /// Initialize the client
    pub async fn initialize_client(&mut self) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("Client not initialized"));
        }
        
        // Set the current client for OMEMO operations (still needed for pubsub internals)
        if let Some(client_ref) = &self.client {
            crate::xmpp::omemo_integration::set_current_client_arc(client_ref.clone());
        }
        
        // Create the PubSub bridge with the XMPP client
        let pubsub_bridge: Arc<dyn crate::omemo::OmemoPubSub> = Arc::new(
            crate::xmpp::omemo_integration::XmppPubSubBridge::new(
                self.client.as_ref().unwrap().clone()
            )
        );
        
        // Create the OMEMO manager
        let omemo_manager = match crate::omemo::OmemoManager::new(
            crate::omemo::storage::OmemoStorage::new_default()?,
            self.jid.clone(),
            None,
            pubsub_bridge,
        ).await {
            Ok(manager) => manager,
            Err(e) => {
                error!("Failed to initialize OMEMO manager: {}", e);
                return Err(anyhow!("Failed to initialize OMEMO manager: {}", e));
            }
        };
        
        // Initialize OMEMO for this client
        info!("Initializing OMEMO for {}", self.jid);
        
        // Generate and publish device list if needed
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
        
        // Force refresh device lists after initialization to ensure fresh data
        info!("Forcing device list refresh for known contacts to avoid stale data");
        tokio::spawn({
            let client = self.clone();
            async move {
                // Give the server time to process our publications
                tokio::time::sleep(Duration::from_secs(2)).await;
                
                // Get our contact list and refresh their device lists
                if let Ok(Some(contacts)) = client.get_roster().await {
                    for contact_jid in contacts {
                        if let Some(omemo_manager) = &client.omemo_manager {
                            let manager_guard = omemo_manager.lock().await;
                            if let Err(e) = manager_guard.get_device_ids_for_test(&contact_jid).await {
                                warn!("Failed to refresh device list for {}: {}", contact_jid, e);
                            } else {
                                info!("Successfully refreshed device list for {}", contact_jid);
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                } else {
                    warn!("Failed to get contact list for device list refresh");
                }
            }
        });
        
        Ok(())
    }

    /// Handle an encrypted message using OMEMO
    pub async fn handle_message_encrypted(&mut self, element: &xmpp_parsers::Element) -> Result<()> {
        // Extract important attributes
        let from = element.attr("from").unwrap_or("unknown@server.example");
        let id = element.attr("id").unwrap_or("unknown");
        
        // Look for OMEMO encrypted element - check empty namespace first (most common)
        let encrypted = element.get_child("encrypted", "")
            .or_else(|| element.get_child("encrypted", custom_ns::OMEMO))
            .or_else(|| element.get_child("encrypted", custom_ns::OMEMO_V1));
            
        if let Some(encrypted) = encrypted {
                // Get header - children inherit namespace from parent encrypted element  
                let header = encrypted.get_child("header", "")
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
                
                // Process encrypted message using the OMEMO manager
                
                // Get IV - children inherit namespace from parent encrypted element
                let iv = match header.get_child("iv", "")
                    .or_else(|| header.get_child("iv", custom_ns::OMEMO)) {
                    Some(iv_elem) => {
                        match iv_elem.text() {
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
                        }
                    },
                    None => {
                        error!("Missing IV in OMEMO header");
                        return Err(anyhow!("Missing IV in OMEMO header"));
                    }
                };
                
                // Collect encrypted keys for each device
                let mut encrypted_keys = std::collections::HashMap::new();
                let mut is_prekey_message = false;
                for key_elem in header.children().filter(|e| e.name() == "key") {
                    if let (Some(rid_str), text) = (key_elem.attr("rid"), key_elem.text()) {
                        let key_base64 = text;
                        // Check if this key element has prekey="true" attribute (Conversations format)
                        if key_elem.attr("prekey") == Some("true") || key_elem.attr("prekey") == Some("1") {
                            is_prekey_message = true;
                        }
                        match rid_str.parse::<u32>() {
                            Ok(recipient_id) => {
                                match base64::engine::general_purpose::STANDARD.decode(key_base64) {
                                    Ok(key_bytes) => {
                                        encrypted_keys.insert(recipient_id, key_bytes);
                                    },
                                    Err(e) => {
                                        error!("Failed to decode key for device {}: {}", rid_str, e);
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Invalid recipient ID: {}", e);
                            }
                        }
                    }
                }
                
                // Get payload - children inherit namespace from parent encrypted element
                let payload = match encrypted.get_child("payload", "")
                    .or_else(|| encrypted.get_child("payload", custom_ns::OMEMO)) {
                    Some(payload_elem) => {
                        match payload_elem.text() {
                            text => {
                                let payload_base64 = text;
                                match base64::engine::general_purpose::STANDARD.decode(payload_base64) {
                                    Ok(payload_bytes) => payload_bytes,
                                    Err(e) => {
                                        error!("Failed to decode payload: {}", e);
                                        return Err(anyhow!("Failed to decode payload: {}", e));
                                    }
                                }
                            }
                        }
                    },
                    None => {
                        error!("Missing payload in OMEMO message");
                        return Err(anyhow!("Missing payload in OMEMO message"));
                    }
                };
                
                // Create the OMEMO message
                let omemo_message = crate::omemo::protocol::OmemoMessage {
                    sender_device_id,
                    ratchet_key: vec![],
                    previous_counter: 0,
                    counter: 0,
                    ciphertext: payload,
                    mac: vec![],
                    iv,
                    encrypted_keys,
                    is_prekey: is_prekey_message,
                    ephemeral_key: None,
                    prekey_devices: std::collections::HashSet::new(),
                };
                
                // Decrypt the message
                let mut omemo_manager_guard = omemo_manager.lock().await;
                warn!("DECRYPT_DEBUG: Starting decryption for message from {}:{}", from, sender_device_id);
                match omemo_manager_guard.decrypt_message(from, sender_device_id, &omemo_message).await {
                    Ok(plaintext) => {
                        warn!("DECRYPT_SUCCESS: Successfully decrypted message from {}:{}", from, sender_device_id);
                        warn!("DECRYPT_SUCCESS: Plaintext length: {} bytes", plaintext.len());
                        warn!("DECRYPT_SUCCESS: Plaintext content: '{}'", plaintext);
                        
                        // Strip resource from sender JID to get bare JID
                        let sender_bare_jid = from.split('/').next().unwrap_or(from).to_string();
                        
                        // Create a message for the UI
                        let message = Message {
                            id: id.to_string(),
                            sender_id: sender_bare_jid.clone(),
                            recipient_id: self.jid.clone(),
                            content: plaintext.clone(),
                            timestamp: chrono::Utc::now().timestamp() as u64,
                            delivery_status: DeliveryStatus::Delivered,
                        };
                        
                        warn!("UI_DELIVERY_DEBUG: Sending decrypted message to UI channel");
                        warn!("UI_DELIVERY_DEBUG: Message details - ID: {}, Sender: {}, Content: '{}'", 
                            message.id, message.sender_id, message.content);
                        
                        // Send to UI
                        if let Err(e) = self.msg_tx.send(message).await {
                            error!("FAILED to send decrypted message to UI: {}", e);
                        } else {
                            warn!("SUCCESS: Sent decrypted OMEMO message to UI channel");
                        }
                        
                        // Send a receipt if requested
                        if element.has_child("request", custom_ns::RECEIPTS) {
                            if let Some(client) = &self.client {
                                let receipt = xmpp_parsers::Element::builder("message", NS_JABBER_CLIENT)
                                    .attr("to", from)
                                    .attr("id", &uuid::Uuid::new_v4().to_string())
                                    .append(
                                        xmpp_parsers::Element::builder("received", custom_ns::RECEIPTS)
                                            .attr("id", id)
                                            .build()
                                    )
                                    .build();
                                
                                let mut client_guard = client.lock().await;
                                if let Err(e) = client_guard.send_stanza(receipt).await {
                                    error!("Failed to send receipt: {}", e);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        error!("Failed to decrypt message from {} (device {}): {}", from, sender_device_id, e);
                        error!("Message ID: {}, Decryption failure details: {:?}", id, e);
                        
                        debug!("OMEMO message structure - Sender device: {}, IV length: {}, Payload length: {}, Number of keys: {}", 
                            omemo_message.sender_device_id,
                            omemo_message.iv.len(),
                            omemo_message.ciphertext.len(),
                            omemo_message.encrypted_keys.len());
                        
                        let message = Message {
                            id: id.to_string(),
                            sender_id: from.to_string(),
                            recipient_id: self.jid.clone(),
                            content: format!("[Encrypted message could not be decrypted: {}. You may need to refresh the OMEMO keys or verify device identity.]", e),
                            timestamp: chrono::Utc::now().timestamp() as u64,
                            delivery_status: DeliveryStatus::Delivered,
                        };
                        
                        if let Err(e) = self.msg_tx.send(message).await {
                            error!("Failed to send error message to UI: {}", e);
                        }
                    }
                }
                
                return Ok(());
            }
        }
        
        error!("Could not find required OMEMO elements in encrypted message");
        Err(anyhow!("Could not find required OMEMO elements in encrypted message"))
    }

    /// Process an OMEMO encrypted message and attempt to decrypt it
    pub async fn process_encrypted_message(stanza: &xmpp_parsers::Element) -> Result<Option<(String, String)>> {
        // First check if this is an OMEMO encrypted message
        if !stanza.name().eq("message") {
            return Ok(None);
        }

        let encrypted = match stanza.get_child("encrypted", custom_ns::OMEMO)
            .or_else(|| stanza.get_child("encrypted", custom_ns::OMEMO_V1))
            .or_else(|| stanza.get_child("encrypted", "")) {
            Some(elem) => elem,
            None => return Ok(None),
        };

        // Extract sender JID
        let from = match stanza.attr("from") {
            Some(from_str) => from_str.to_string(),
            None => return Err(anyhow!("No sender JID in encrypted message")),
        };

        info!("Processing OMEMO encrypted message from {}", from);

        // Extract the header and encrypted data
        let header = match encrypted.get_child("header", "") {
            Some(h) => h,
            None => return Err(anyhow!("Missing header in OMEMO message")),
        };

        // Get the sender device ID
        let sid = match header.attr("sid") {
            Some(sid_str) => match sid_str.parse::<u32>() {
                Ok(sid) => sid,
                Err(_) => return Err(anyhow!("Invalid device ID in OMEMO message")),
            },
            None => return Err(anyhow!("Missing device ID in OMEMO message")),
        };

        // Extract the key information
        let key_element = match header.get_child("key", "") {
            Some(k) => k,
            None => return Err(anyhow!("Missing key element in OMEMO message")),
        };

        // Check if this key is intended for us by checking the "rid" attribute
        let _recipient_device_id = match key_element.attr("rid") {
            Some(rid_str) => match rid_str.parse::<u32>() {
                Ok(rid) => rid,
                Err(_) => {
                    warn!("Invalid recipient device ID '{}' in key element", rid_str);
                    return Err(anyhow!("Invalid recipient device ID in OMEMO message"));
                }
            },
            None => 0
        };

        // Get the encrypted key data
        let key_text = key_element.text();
        if key_text.is_empty() {
            return Err(anyhow!("Empty key data in OMEMO message"));
        }
        
        let encrypted_key = match base64::engine::general_purpose::STANDARD.decode(key_text.trim()) {
            Ok(decoded) => decoded,
            Err(e) => {
                error!("Failed to decode key data: {}", e);
                return Err(anyhow!("Failed to decode key data: {}", e));
            }
        };

        // Get the IV (initialization vector)
        let iv_data = match header.get_child("iv", "") {
            Some(iv_elem) => {
                let iv_text = iv_elem.text();
                if iv_text.is_empty() {
                    return Err(anyhow!("Empty IV in OMEMO message"));
                }
                
                match base64::engine::general_purpose::STANDARD.decode(iv_text.trim()) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode IV: {}", e);
                        return Err(anyhow!("Failed to decode IV: {}", e));
                    }
                }
            },
            None => return Err(anyhow!("Missing IV in OMEMO message")),
        };

        // Extract the payload (actual encrypted content)
        let payload_data = match encrypted.get_child("payload", "") {
            Some(p) => {
                let payload_text = p.text();
                if payload_text.is_empty() {
                    return Err(anyhow!("Empty payload in OMEMO message"));
                }
                
                match base64::engine::general_purpose::STANDARD.decode(payload_text.trim()) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode payload: {}", e);
                        return Err(anyhow!("Failed to decode payload: {}", e));
                    }
                }
            },
            None => return Err(anyhow!("Missing payload in OMEMO message")),
        };

        // Get the associated data for authenticated encryption
        let auth_data = match encrypted.get_child("auth", "") {
            Some(a) => {
                let auth_text = a.text();
                if !auth_text.is_empty() {
                    match base64::engine::general_purpose::STANDARD.decode(auth_text.trim()) {
                        Ok(decoded) => decoded,
                        Err(e) => {
                            warn!("Failed to decode auth tag, proceeding without it: {}", e);
                            vec![]
                        }
                    }
                } else {
                    vec![]
                }
            },
            None => vec![],
        };

        // Retrieve session and decrypt
        let sender_bare_jid = from.split('/').next().unwrap_or(&from).to_string();
        
        let device_id = 1;
        
        let storage = match crate::omemo::storage::OmemoStorage::new_default() {
            Ok(storage) => storage,
            Err(e) => return Err(anyhow!("Failed to create OMEMO storage: {}", e)),
        };
        
        // Create a PubSub bridge for this temporary manager
        let pubsub_bridge: Arc<dyn crate::omemo::OmemoPubSub> = match crate::xmpp::omemo_integration::get_current_client() {
            Some(client_arc) => Arc::new(crate::xmpp::omemo_integration::XmppPubSubBridge::new(client_arc)),
            None => return Err(anyhow!("No XMPP client available for OMEMO decryption")),
        };
        
        let _omemo_manager = match crate::omemo::OmemoManager::new(
            storage,
            "me".to_string(),
            Some(device_id),
            pubsub_bridge,
        ).await {
            Ok(manager) => manager,
            Err(e) => return Err(anyhow!("Failed to create OMEMO manager: {}", e)),
        };

        info!("Retrieving session state for {}, device {}", sender_bare_jid, sid);
        
        // Get the session key from storage
        let session_key = match Self::get_session_key(&sender_bare_jid, sid) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to retrieve session key: {}", e);
                return Err(anyhow!("Failed to retrieve session key: {}", e));
            }
        };

        // Decrypt the message key
        info!("Decrypting message key");
        let message_key = match crate::omemo::crypto::decrypt(&encrypted_key, &session_key, &iv_data, &auth_data) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to decrypt message key: {}", e);
                return Err(anyhow!("Failed to decrypt message key: {}. Please make sure you have exchanged OMEMO keys with this contact.", e));
            }
        };

        // Now decrypt the actual message payload with the message key
        info!("Decrypting message payload");
        let decrypted_payload = match crate::omemo::crypto::decrypt(&payload_data, &message_key, &iv_data, &auth_data) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                error!("Failed to decrypt message payload: {}", e);
                return Err(anyhow!("Failed to decrypt message payload: {}", e));
            }
        };

        // Convert the decrypted bytes to a UTF-8 string
        let decrypted_message = match String::from_utf8(decrypted_payload) {
            Ok(text) => text,
            Err(e) => {
                error!("Decrypted data is not valid UTF-8: {}", e);
                return Err(anyhow!("Decrypted data is not valid UTF-8: {}", e));
            }
        };

        info!("Successfully decrypted OMEMO message from {}", from);
        Ok(Some((from, decrypted_message)))
    }

    // Helper function to get a session key for a sender
    fn get_session_key(sender_jid: &str, device_id: u32) -> Result<Vec<u8>> {
        match crate::omemo::storage::OmemoStorage::new_default() {
            Ok(storage) => {
                match storage.get_session_ratchet_state(sender_jid, device_id) {
                    Ok(state) => {
                        Ok(state.unwrap().root_key.clone())
                    },
                    Err(e) => {
                        error!("No valid session found for {} (device {}): {}", sender_jid, device_id, e);
                        Err(anyhow!("No valid session found: {}. You may need to refresh your OMEMO keys.", e))
                    }
                }
            },
            Err(e) => {
                error!("Failed to create OMEMO storage: {}", e);
                Err(anyhow!("Failed to create OMEMO storage: {}", e))
            }
        }
    }

    /// Process a key verification response from the user
    pub async fn handle_key_verification_response(&self, contact: &str, response: &str) -> Result<()> {
        info!("Processing key verification response for {}: {}", contact, response);
        
        match response {
            "__KEY_ACCEPTED__" => {
                info!("OMEMO key for {} has been accepted by user", contact);
                
                let system_message = Message {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender_id: "system".to_string(),
                    recipient_id: "me".to_string(),
                    content: format!("OMEMO key for {} has been accepted and marked as trusted", contact),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    delivery_status: DeliveryStatus::Unknown,
                };
                
                if let Err(e) = self.msg_tx.send(system_message).await {
                    error!("Failed to send key acceptance message to UI: {}", e);
                }
                
                if let Err(e) = self.process_omemo_verification_response(contact, response).await {
                    error!("Failed to process key verification in OMEMO: {}", e);
                    return Err(anyhow!("Failed to process key verification: {}", e));
                }
            },
            "__KEY_REJECTED__" => {
                info!("OMEMO key for {} has been rejected by user", contact);
                
                let system_message = Message {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender_id: "system".to_string(),
                    recipient_id: "me".to_string(),
                    content: format!("OMEMO key for {} has been rejected", contact),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    delivery_status: DeliveryStatus::Unknown,
                };
                
                if let Err(e) = self.msg_tx.send(system_message).await {
                    error!("Failed to send key rejection message to UI: {}", e);
                }
                
                if let Err(e) = self.process_omemo_verification_response(contact, response).await {
                    error!("Failed to process key rejection in OMEMO: {}", e);
                    return Err(anyhow!("Failed to process key rejection: {}", e));
                }
            },
            _ => {
                warn!("Unknown key verification response: {}", response);
                return Err(anyhow!("Unknown key verification response: {}", response));
            }
        }
        
        Ok(())
    }

    /// Check OMEMO keys for a contact and request verification if needed
    pub async fn check_omemo_keys_for_contact(&self, contact: &str) -> Result<()> {
        // Skip checks for special contacts
        if contact.starts_with('[') && contact.ends_with(']') {
            return Ok(());
        }

        if self.omemo_manager.is_none() {
            warn!("No OMEMO manager available for key verification");
            return Ok(());
        }
        
        let omemo_manager = self.omemo_manager.as_ref().unwrap();
        
        // First, get the device IDs for this contact with timeout protection
        let device_ids = {
            let manager_guard = omemo_manager.lock().await;
            match tokio::time::timeout(
                std::time::Duration::from_secs(10), 
                manager_guard.get_device_ids_for_test(contact)
            ).await {
                Ok(Ok(device_ids)) => device_ids,
                Ok(Err(e)) => {
                    warn!("Failed to get device IDs for {}: {}", contact, e);
                    return Ok(());
                },
                Err(_) => {
                    warn!("Timeout while getting device IDs for {}, skipping OMEMO verification", contact);
                    return Ok(());
                }
            }
        };
        
        if device_ids.is_empty() {
            return Ok(());
        }
        
        info!("Found {} OMEMO devices for {}", device_ids.len(), contact);
        
        let storage = crate::omemo::storage::OmemoStorage::new_default()?;
        let pending_verification = storage.get_pending_device_verification(contact);
        
        if let Ok(Some(_)) = pending_verification {
            return Ok(());
        }
        
        // Check each device to see if it's trusted
        for device_id in device_ids {
            let trusted = {
                let manager_guard = omemo_manager.lock().await;
                match tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    manager_guard.is_device_identity_trusted(contact, device_id)
                ).await {
                    Ok(Ok(trusted)) => trusted,
                    Ok(Err(e)) => {
                        warn!("Failed to check trust for {}:{}: {}", contact, device_id, e);
                        false
                    },
                    Err(_) => {
                        warn!("Timeout checking trust for {}:{}, assuming not trusted", contact, device_id);
                        false
                    }
                }
            };
            
            if !trusted {
                let fingerprint = {
                    let manager_guard = omemo_manager.lock().await;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(8),
                        manager_guard.get_device_fingerprint(contact, device_id)
                    ).await {
                        Ok(Ok(fingerprint)) => fingerprint,
                        Ok(Err(e)) => {
                            warn!("Failed to get fingerprint for {}:{}: {}", contact, device_id, e);
                            continue;
                        },
                        Err(_) => {
                            warn!("Timeout getting fingerprint for {}:{}, skipping device", contact, device_id);
                            continue;
                        }
                    }
                };
                
                // Double-check if this fingerprint is already trusted in the database
                let fingerprint_trusted = storage.is_device_trusted(contact, device_id)?;
                if fingerprint_trusted {
                    let manager_guard = omemo_manager.lock().await;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        manager_guard.trust_device_identity(contact, device_id)
                    ).await {
                        Ok(Ok(_)) => {},
                        Ok(Err(e)) => {
                            warn!("Failed to update device trust state in manager: {}", e);
                        },
                        Err(_) => {
                            warn!("Timeout updating trust state for {}:{}", contact, device_id);
                        }
                    }
                    continue;
                }
                
                if let Err(e) = storage.store_pending_device_verification(contact, device_id, &fingerprint) {
                    warn!("Failed to store pending verification: {}", e);
                }
                
                info!("Requesting verification for untrusted device {}:{} with fingerprint {}", 
                     contact, device_id, fingerprint);
                
                if let Err(e) = self.detect_unrecognized_omemo_key(contact, &fingerprint, Some(device_id)).await {
                    error!("Failed to request key verification: {}", e);
                    return Err(anyhow!("Failed to request key verification: {}", e));
                }
                
                // Only request verification for one device at a time
                break;
            }
        }
        
        Ok(())
    }

    /// Request verification for an OMEMO key
    pub async fn process_key_verification_response(&self, sender: &str, key_fingerprint: &str, device_id: Option<u32>) -> Result<()> {
        let special_message = Message {
            id: uuid::Uuid::new_v4().to_string(),
            sender_id: "system".to_string(),
            recipient_id: "me".to_string(),
            content: format!("__OMEMO_KEY_VERIFY__:{}:{}:{}", 
                            sender, 
                            key_fingerprint, 
                            device_id.map(|id| id.to_string()).unwrap_or_default()),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
        };
        
        if let Err(e) = self.msg_tx.send(special_message).await {
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
                Ok(manager) => {
                    match manager.get_device_ids_for_test(bare_jid).await {
                        Ok(devices) => Ok(devices),
                        Err(e) => Err(anyhow!("Failed to get device IDs: {}", e))
                    }
                },
                Err(_) => {
                    info!("OMEMO manager lock contended, reading device list from cache for {}", bare_jid);
                    let storage = {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            omemo_manager.lock()
                        ).await {
                            Ok(manager) => manager.get_storage(),
                            Err(_) => {
                                return Err(anyhow!("OMEMO manager busy, could not read device list"));
                            }
                        }
                    };
                    let storage_guard = storage.lock().await;
                    match storage_guard.load_device_list(bare_jid) {
                        Ok(entry) if !entry.device_ids.is_empty() => Ok(entry.device_ids),
                        Ok(_) => Ok(vec![]),
                        Err(e) => Err(anyhow!("No cached device list for {}: {}", bare_jid, e))
                    }
                }
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Get fingerprint for a device
    pub async fn get_device_fingerprint(&self, jid: &str, device_id: DeviceId) -> Result<String> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.get_device_fingerprint(jid, device_id).await {
                Ok(fingerprint) => Ok(fingerprint),
                Err(e) => Err(anyhow!("Failed to get device fingerprint: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
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
                manager_guard.is_device_identity_trusted(contact, *device_id).await?
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
                let manager_guard = omemo_manager.lock().await;
                
                if set_trusted {
                    if let Err(e) = manager_guard.trust_device_identity(contact, device_id).await {
                        error!("Failed to trust device: {}", e);
                        return Err(anyhow!("Failed to trust device: {}", e));
                    }
                } else {
                    if let Err(e) = manager_guard.untrust_device_identity(contact, device_id).await {
                        error!("Failed to untrust device: {}", e);
                        return Err(anyhow!("Failed to untrust device: {}", e));
                    }
                }
            }
        }
        
        let status_desc = if set_trusted { "trusted" } else { "untrusted" };
        info!("Successfully toggled {} devices for {} to {}", device_ids.len(), contact, status_desc);
        
        Ok(set_trusted)
    }

    /// Get access to the OMEMO manager (primarily for testing)
    pub fn get_omemo_manager(&self) -> Option<Arc<TokioMutex<crate::omemo::OmemoManager>>> {
        self.omemo_manager.clone()
    }
}
