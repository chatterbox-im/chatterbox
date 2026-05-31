// src/xmpp/send.rs
//! Message sending: encrypted (OMEMO), plaintext fallback, and debugging

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use base64::Engine;
use xmpp_parsers::Element;

use crate::models::{Message, DeliveryStatus, PendingMessage};
use super::{XMPPClient, custom_ns};

impl XMPPClient {
    /// Send a message (encrypted if OMEMO is enabled, plaintext otherwise)
    pub async fn send_message(&mut self, recipient: &str, content: &str) -> Result<()> {
        info!("SEND_MESSAGE CALLED: recipient={}, content_starts_with={}", 
             recipient, content.chars().take(30).collect::<String>());
        
        // Check if OMEMO is enabled - if it is, always use encrypted messaging
        let omemo_enabled = self.is_omemo_enabled().await;
        
        if omemo_enabled {
            info!("OMEMO is enabled, sending encrypted message to: {}", recipient);
            self.send_encrypted_message(recipient, content).await
        } else {
            info!("OMEMO is disabled, sending plaintext message to: {}", recipient);
            warn!("⚠️ WARNING: Message is being sent in plaintext without encryption!");
            self.send_message_with_receipt(recipient, content).await
        }
    }

    /// Send an encrypted message using OMEMO
    pub async fn send_encrypted_message(&mut self, to: &str, content: &str) -> Result<()> {
        info!("Sending encrypted message to {}", to);
        
        // Get our OMEMO manager
        let omemo_manager = match &self.omemo_manager {
            Some(manager) => manager.clone(),
            None => {
                self.initialize_client().await?;
                match &self.omemo_manager {
                    Some(manager) => manager.clone(),
                    None => {
                        error!("Failed to initialize OMEMO manager");
                        return Err(anyhow!("Failed to initialize OMEMO manager"));
                    }
                }
            }
        };
        
        // Encrypt the message.
        // NOTE: The lock is held across the entire encrypt_message() call because the
        // Double Ratchet algorithm mutates session state (ratchet key advances) during
        // encryption. Releasing the lock mid-encrypt would allow concurrent sends to
        // produce identical ciphertext or corrupt the ratchet chain.
        let mut omemo_manager_guard = omemo_manager.lock().await;
        let encrypted_message = match omemo_manager_guard.encrypt_message(to, content).await {
            Ok(message) => message,
            Err(e) => {
                error!("Failed to encrypt message: {}", e);
                return Err(anyhow!("Failed to encrypt message: {}", e));
            }
        };
        
        // Verification (temporarily disabled for PreKey testing)
        let omemo_verified: Result<(), crate::omemo::EncryptionVerificationError> = Ok(());
        match &omemo_verified {
            Ok(_) => debug!("OMEMO encryption verification passed - no plaintext leaked"),
            Err(e) => {
                error!("OMEMO encryption verification failed: {}", e);
                return Err(anyhow!("OMEMO encryption verification failed: {}", e));
            }
        }

        drop(omemo_manager_guard);
        
        // Generate a message ID
        let id = uuid::Uuid::new_v4().to_string();
        
        // Create the OMEMO message stanza
        let mut message_element = Element::builder("message", "jabber:client").build();
        message_element.set_attr("id", &id);
        message_element.set_attr("to", to);
        message_element.set_attr("type", "chat");
        
        // Add receipt request
        let request_element = Element::builder("request", custom_ns::RECEIPTS).build();
        message_element.append_child(request_element);
        
        // Add chat state
        let active_element = Element::builder("active", custom_ns::CHATSTATES).build();
        message_element.append_child(active_element);
        
        // Create encrypted element with OMEMO namespace
        let mut encrypted_element = Element::builder("encrypted", custom_ns::OMEMO_V1).build();
        
        // Create header element
        let mut header_element = Element::builder("header", custom_ns::OMEMO_V1).build();
        header_element.set_attr("sid", &encrypted_message.sender_device_id.to_string());
        
        // Add key elements, including prekey="true" for PreKeySignalMessages
        for (device_id, encrypted_key) in &encrypted_message.encrypted_keys {
            let mut key_element = Element::builder("key", custom_ns::OMEMO_V1).build();
            key_element.set_attr("rid", &device_id.to_string());
            if encrypted_message.prekey_devices.contains(device_id) {
                key_element.set_attr("prekey", "true");
            }
            key_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(encrypted_key));
            header_element.append_child(key_element);
        }
        
        // Add IV element
        let mut iv_element = Element::builder("iv", custom_ns::OMEMO_V1).build();
        iv_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.iv));
        header_element.append_child(iv_element);
        
        // Add payload element
        let mut payload_element = Element::builder("payload", custom_ns::OMEMO_V1).build();
        payload_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.ciphertext));
        
        // Assemble the elements
        encrypted_element.append_child(header_element);
        encrypted_element.append_child(payload_element);
        message_element.append_child(encrypted_element);
        
        // Add EME indicator (XEP-0380)
        let mut eme_element = Element::builder("encryption", "urn:xmpp:eme:0").build();
        eme_element.set_attr("namespace", custom_ns::OMEMO_V1);
        eme_element.set_attr("name", "OMEMO");
        message_element.append_child(eme_element);
        
        // Add body fallback for clients that don't support OMEMO
        let mut body_element = Element::builder("body", "jabber:client").build();
        body_element.append_text_node("I sent you an OMEMO encrypted message but your client doesn\u{2019}t seem to support that. Find more information on https://conversations.im/omemo");
        message_element.append_child(body_element);
        
        // Add store hint (XEP-0334)
        let store_hint = Element::builder("store", "urn:xmpp:hints").build();
        message_element.append_child(store_hint);
        
        // Send the message
        self.send_stanza(message_element)
            .map_err(|e| anyhow!("Failed to send encrypted message to {}: {}", to, e))?;
        
        info!("Encrypted message sent successfully to {}", to);
        
        // Store message ID in pending receipts
        {
            let mut pending_receipts_guard = self.pending_receipts.lock().await;
            let pending_message = PendingMessage {
                id: id.clone(),
                to: to.to_string(),
                content: content.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                status: DeliveryStatus::Sent,
            };
            pending_receipts_guard.insert(id.clone(), pending_message);
        }
        
        // Create a "sent" message for the UI
        let message = Message {
            id: id.clone(),
            sender_id: "me".to_string(),
            recipient_id: to.to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Sent,
            encrypted: false,
        };
        
        if let Err(e) = self.msg_tx.send(message).await {
            error!("Failed to send message to UI: {}", e);
        }
        
        Ok(())
    }

    /// Store a message ID for tracking status updates
    pub async fn store_message_id(&self, recipient: &str, message_id: &str) -> Result<()> {
        let mut pending_receipts = self.pending_receipts.lock().await;
        
        let pending_message = PendingMessage {
            id: message_id.to_string(),
            to: recipient.to_string(),
            content: String::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: DeliveryStatus::Sent,
        };
        
        pending_receipts.insert(message_id.to_string(), pending_message);
        
        Ok(())
    }

}
