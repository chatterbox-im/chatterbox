// src/xmpp/send.rs
//! Message sending: encrypted (OMEMO), plaintext fallback, and debugging

use anyhow::{anyhow, Result};
use base64::Engine;
use log::{debug, error, info, warn};
use xmpp_parsers::minidom::Element;

use super::{custom_ns, XMPPClient};
use crate::models::{DeliveryStatus, Message, PendingMessage};

impl XMPPClient {
    /// Send a message (encrypted if OMEMO is enabled, plaintext otherwise).
    /// `msg_id` is caller-supplied so the wire ID matches what was stored/returned.
    pub async fn send_message(&mut self, recipient: &str, content: &str) -> Result<()> {
        self.send_message_with_id(recipient, content, &uuid::Uuid::new_v4().to_string()).await
    }

    /// Like `send_message` but uses a specific message ID.
    pub async fn send_message_with_id(&mut self, recipient: &str, content: &str, msg_id: &str) -> Result<()> {
        eprintln!("SEND_DEBUG: send_message_with_id entered recipient={} msg_id={}", recipient, msg_id);
        info!(
            "SEND_MESSAGE CALLED: recipient={}, content_starts_with={}",
            recipient,
            content.chars().take(30).collect::<String>()
        );

        // Normalize JIDs for self-message detection (strip resource, lowercase)
        let recipient_bare = recipient.split('/').next().unwrap_or(recipient).to_lowercase();
        let self_bare = self.jid.split('/').next().unwrap_or(&self.jid).to_lowercase();
        let is_self_message = recipient_bare == self_bare;

        if is_self_message {
            info!("Self-message detected, sending plaintext to: {}", recipient);
            return self.send_message_with_receipt(recipient, content).await;
        }

        let omemo_enabled = self.is_omemo_enabled().await;

        if omemo_enabled {
            info!("OMEMO is enabled, sending encrypted message to: {}", recipient);
            self.send_encrypted_message_with_id(recipient, content, msg_id).await
        } else {
            info!("OMEMO is disabled, sending plaintext message to: {}", recipient);
            warn!("⚠️ WARNING: Message is being sent in plaintext without encryption!");
            self.send_message_with_receipt(recipient, content).await
        }
    }

    /// Send an encrypted message using OMEMO
    pub async fn send_encrypted_message(&mut self, to: &str, content: &str) -> Result<()> {
        self.send_encrypted_message_with_id(to, content, &uuid::Uuid::new_v4().to_string()).await
    }

    /// Send an encrypted message using a specific message ID (used by the FFI layer).
    pub async fn send_encrypted_message_with_id(&mut self, to: &str, content: &str, msg_id: &str) -> Result<()> {
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

        // Verify that the serialised OMEMO payload does not contain the plaintext.
        // This is a defence-in-depth check; a real encryption bug would be caught
        // here before the stanza reaches the network.
        let omemo_xml = omemo_manager_guard.message_to_xml(&encrypted_message);
        match omemo_manager_guard.verify_message_encryption(&omemo_xml, content) {
            Ok(_) => debug!("OMEMO encryption verification passed"),
            Err(e) => {
                error!(
                    "OMEMO encryption verification FAILED — aborting send: {}",
                    e
                );
                return Err(anyhow!("OMEMO encryption verification failed: {}", e));
            }
        }

        drop(omemo_manager_guard);

        // Use the caller-supplied message ID so the wire ID matches storage.
        let id = msg_id.to_string();

        // Create the OMEMO message stanza
        let mut message_element = Element::builder("message", "jabber:client").build();
        message_element.set_attr(
            xmpp_parsers::minidom::rxml::Namespace::NONE,
            "id".try_into().unwrap(),
            &id,
        );
        message_element.set_attr(
            xmpp_parsers::minidom::rxml::Namespace::NONE,
            "to".try_into().unwrap(),
            to,
        );
        message_element.set_attr(
            xmpp_parsers::minidom::rxml::Namespace::NONE,
            "type".try_into().unwrap(),
            "chat",
        );

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
        header_element.set_attr(
            xmpp_parsers::minidom::rxml::Namespace::NONE,
            "sid".try_into().unwrap(),
            &encrypted_message.sender_device_id.to_string(),
        );

        // Add key elements, including prekey="true" for PreKeySignalMessages
        for (device_id, encrypted_key) in &encrypted_message.encrypted_keys {
            let mut key_element = Element::builder("key", custom_ns::OMEMO_V1).build();
            key_element.set_attr(
                xmpp_parsers::minidom::rxml::Namespace::NONE,
                "rid".try_into().unwrap(),
                &device_id.to_string(),
            );
            if encrypted_message.prekey_devices.contains(device_id) {
                key_element.set_attr(
                    xmpp_parsers::minidom::rxml::Namespace::NONE,
                    "prekey".try_into().unwrap(),
                    "true",
                );
            }
            key_element
                .append_text_node(&base64::engine::general_purpose::STANDARD.encode(encrypted_key));
            header_element.append_child(key_element);
        }

        // Add IV element
        let mut iv_element = Element::builder("iv", custom_ns::OMEMO_V1).build();
        iv_element.append_text_node(
            &base64::engine::general_purpose::STANDARD.encode(&encrypted_message.iv),
        );
        header_element.append_child(iv_element);

        // Add payload element
        let mut payload_element = Element::builder("payload", custom_ns::OMEMO_V1).build();
        payload_element.append_text_node(
            &base64::engine::general_purpose::STANDARD.encode(&encrypted_message.ciphertext),
        );

        // Assemble the elements
        encrypted_element.append_child(header_element);
        encrypted_element.append_child(payload_element);
        message_element.append_child(encrypted_element);

        // Add EME indicator (XEP-0380)
        let mut eme_element = Element::builder("encryption", "urn:xmpp:eme:0").build();
        eme_element.set_attr(
            xmpp_parsers::minidom::rxml::Namespace::NONE,
            "namespace".try_into().unwrap(),
            custom_ns::OMEMO_V1,
        );
        eme_element.set_attr(
            xmpp_parsers::minidom::rxml::Namespace::NONE,
            "name".try_into().unwrap(),
            "OMEMO",
        );
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
        let message = Message::outgoing_encrypted(id.clone(), to, content);

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
