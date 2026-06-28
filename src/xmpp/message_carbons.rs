// XEP-0280: Message Carbons Implementation
// https://xmpp.org/extensions/xep-0280.html

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};

use super::custom_ns;
use crate::models::{DeliveryStatus, Message};
use base64::Engine;
use xmpp_parsers::Element;

/// Implementation of XEP-0280 Message Carbons
impl super::XMPPClient {
    /// Enable Message Carbons feature
    pub async fn enable_carbons_protocol(&self) -> Result<bool> {
        let enable = Element::builder("enable", custom_ns::CARBONS).build();

        match self.send_iq_and_await("set", enable, 10).await {
            Ok(_) => {
                info!("Message carbons successfully enabled");
                self.set_carbons_enabled(true);
                Ok(true)
            }
            Err(e) => {
                error!("Failed to enable message carbons: {}", e);
                Err(anyhow!(
                    "Server rejected message carbons enable request: {}",
                    e
                ))
            }
        }
    }

    /// Disable Message Carbons feature
    pub async fn disable_carbons(&self) -> Result<bool> {
        let disable = Element::builder("disable", custom_ns::CARBONS).build();

        match self.send_iq_and_await("set", disable, 10).await {
            Ok(_) => {
                info!("Message carbons successfully disabled");
                self.set_carbons_enabled(false);
                Ok(true)
            }
            Err(e) => {
                // Soft failure — assume success on timeout
                warn!(
                    "Failed to disable message carbons ({}), assuming success",
                    e
                );
                self.set_carbons_enabled(false);
                Ok(true)
            }
        }
    }

    /// Build a UI message from carbon metadata and send it to the UI channel.
    async fn send_carbon_to_ui(
        &self,
        from: &str,
        to: &str,
        is_sent: bool,
        msg_id: Option<&str>,
        content: impl Into<String>,
        encrypted: bool,
    ) -> Result<()> {
        let msg_id = msg_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let (sender_id, recipient_id) = if is_sent {
            ("me".to_string(), to.to_string())
        } else {
            (from.to_string(), "me".to_string())
        };

        let ui_message = match (sender_id.as_str(), encrypted) {
            ("me", false) => Message::outgoing_plaintext(msg_id, recipient_id, content),
            ("me", true) => Message::outgoing_encrypted(msg_id, recipient_id, content),
            (_, false) => Message::incoming_plaintext(msg_id, sender_id, content),
            (_, true) => Message::incoming_encrypted(msg_id, sender_id, content),
        };

        debug!(
            "Sending carbon message to UI ({} bytes)",
            ui_message.content.len()
        );
        if let Err(e) = self.msg_tx.send(ui_message).await {
            error!("Failed to send carbon message to UI: {}", e);
        }
        Ok(())
    }

    /// Process a received carbon message
    pub async fn process_carbon(&self, stanza: &xmpp_parsers::Element) -> Result<()> {
        // Process carbon copy of a message (sent or received from another client)
        debug!("Processing message carbon");

        // Check if it's a sent or received carbon
        let is_sent = stanza.has_child("sent", custom_ns::CARBONS);
        let is_received = stanza.has_child("received", custom_ns::CARBONS);

        if !is_sent && !is_received {
            return Err(anyhow!("Not a valid carbon message"));
        }

        let carbon_type = if is_sent { "sent" } else { "received" };
        debug!("Carbon type: {}", carbon_type);

        let carbon_element = stanza
            .get_child(carbon_type, custom_ns::CARBONS)
            .ok_or_else(|| anyhow!("Missing {} element in carbon", carbon_type))?;

        // Extract the forwarded message
        let forwarded = carbon_element
            .get_child("forwarded", custom_ns::FORWARD)
            .ok_or_else(|| anyhow!("Missing forwarded element in carbon"))?;

        let message = forwarded
            .get_child("message", "jabber:client")
            .ok_or_else(|| anyhow!("Missing message element in forwarded carbon"))?;

        // Log message attributes without using debug formatting
        debug!(
            "Carbon message from: {}, to: {}",
            message.attr("from").unwrap_or("unknown"),
            message.attr("to").unwrap_or("unknown")
        );

        for child in message.children() {
            debug!("Carbon message child: {}", child.name());
        }

        // Check if this is an OMEMO encrypted message
        if message.has_child("encrypted", custom_ns::OMEMO) {
            debug!("Carbon contains an OMEMO encrypted message");
            return self.process_carbon_omemo(message, is_sent).await;
        }

        // Extract message details
        let from = message
            .attr("from")
            .ok_or_else(|| anyhow!("No from attribute in carbon message"))?;
        let to = message
            .attr("to")
            .ok_or_else(|| anyhow!("No to attribute in carbon message"))?;

        // Get the body element - look for it with namespace "" or "jabber:client"
        let body_text = match message.get_child("body", "") {
            Some(body_elem) => {
                debug!("Found body element with empty namespace");
                body_elem.text()
            }
            None => match message.get_child("body", "jabber:client") {
                Some(body_elem) => {
                    debug!("Found body element with jabber:client namespace");
                    body_elem.text()
                }
                None => {
                    // Empty body is allowed, but first check if this is a receipt or chat state
                    if message.has_child("received", custom_ns::RECEIPTS) {
                        if let Some(receipt) = message.get_child("received", custom_ns::RECEIPTS) {
                            if let Some(receipt_id) = receipt.attr("id") {
                                debug!(
                                    "Carbon contains delivery receipt for message ID: {}",
                                    receipt_id
                                );
                                // Process the receipt if needed
                                return Ok(());
                            }
                        }
                    }

                    // Check for chat states
                    for state in &["active", "composing", "paused", "inactive", "gone"] {
                        if message.has_child(state, custom_ns::CHATSTATES) {
                            debug!("Carbon contains chat state notification: {}", state);
                            // We could process chat states here, but for now we'll just log
                            return Ok(());
                        }
                    }

                    // Search through all children for a body element regardless of namespace
                    for child in message.children() {
                        if child.name() == "body" {
                            debug!("Found body element with custom namespace: {}", child.ns());
                            if child.text().is_empty() {
                                debug!("Body element is empty, skipping carbon processing");
                                return Ok(());
                            }
                            let body = child.text();
                            debug!(
                                "Carbon message {}-> {} ({}): {}",
                                if is_sent { "sent " } else { "received " },
                                to,
                                from,
                                body
                            );
                            return self
                                .send_carbon_to_ui(
                                    from,
                                    to,
                                    is_sent,
                                    message.attr("id"),
                                    body,
                                    false,
                                )
                                .await;
                        }
                    }

                    // If we get here, it's some other kind of message we don't specifically handle
                    debug!("Carbon contains empty-body message of unknown type");
                    return Ok(());
                }
            },
        };

        // Only reaches here if we found a body in one of the first two checks
        debug!(
            "Carbon message {}-> {} ({}): {}",
            if is_sent { "sent " } else { "received " },
            to,
            from,
            body_text
        );

        self.send_carbon_to_ui(from, to, is_sent, message.attr("id"), body_text, false)
            .await
    }

    /// Process an OMEMO encrypted carbon message
    async fn process_carbon_omemo(
        &self,
        message: &xmpp_parsers::Element,
        is_sent: bool,
    ) -> Result<()> {
        debug!("Processing OMEMO encrypted carbon message");

        // Extract message details
        let from = message
            .attr("from")
            .ok_or_else(|| anyhow!("No from attribute in carbon message"))?;
        let to = message
            .attr("to")
            .ok_or_else(|| anyhow!("No to attribute in carbon message"))?;

        debug!("Carbon OMEMO message from: {},: to:: {}", from, to);

        // Get the OMEMO manager
        let omemo_manager = match self.omemo_manager.clone() {
            Some(m) => m,
            None => {
                warn!("OMEMO manager not initialized for processing carbon");
                return Err(anyhow!("OMEMO manager not initialized"));
            }
        };

        // Extract the encrypted element
        let encrypted = message
            .get_child("encrypted", custom_ns::OMEMO)
            .ok_or_else(|| anyhow!("Missing encrypted element in OMEMO carbon message"))?;

        // Get the header element which contains keys and other metadata
        let header = match encrypted.get_child("header", custom_ns::OMEMO) {
            Some(h) => h,
            None => {
                warn!("Missing header in OMEMO carbon message");
                return Err(anyhow!("Missing header in OMEMO carbon message"));
            }
        };

        // Extract the sender device ID
        let sender_device_id = match header.attr("sid") {
            Some(sid) => match sid.parse::<u32>() {
                Ok(id) => id,
                Err(e) => {
                    error!("Invalid sender device ID in carbon: {}", e);
                    return Err(anyhow!("Invalid sender device ID: {}", e));
                }
            },
            None => {
                error!("Missing sender device ID in carbon OMEMO header");
                return Err(anyhow!("Missing sender device ID in header"));
            }
        };

        // Get our device ID
        let own_device_id = {
            let manager = omemo_manager.lock().await;
            manager.get_device_id()
        };

        debug!(
            "OMEMO carbon message from device ID: {}, our device ID: {}",
            sender_device_id, own_device_id
        );

        // Extract encrypted keys
        let mut encrypted_keys = std::collections::HashMap::new();

        for key_elem in header.children().filter(|n| n.name() == "key") {
            if let Some(rid_str) = key_elem.attr("rid") {
                match rid_str.parse::<u32>() {
                    Ok(recipient_id) => {
                        let key_base64 = key_elem.text();
                        match base64::engine::general_purpose::STANDARD.decode(key_base64) {
                            Ok(key_bytes) => {
                                debug!("Found encrypted key for device ID: {}", recipient_id);
                                encrypted_keys.insert(recipient_id, key_bytes);
                            }
                            Err(e) => {
                                debug!("Failed to decode key for device {}: {}", rid_str, e);
                                // Continue with other keys
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Invalid recipient ID: {}", e);
                        // Continue with other keys
                    }
                }
            }
        }

        // If the sender device is our own device, this is a sent carbon echo — skip decryption
        if sender_device_id == own_device_id {
            debug!(
                "Skipping decryption of our own sent carbon (device {})",
                sender_device_id
            );
            let msg_id = message
                .attr("id")
                .map(|s| s.to_string())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let recipient_jid = to.split('/').next().unwrap_or(to).to_string();
            let mut ui_message =
                Message::outgoing_encrypted(msg_id, recipient_jid, "[Sent encrypted message]");
            ui_message.delivery_status = DeliveryStatus::Delivered;
            if let Err(e) = self.msg_tx.send(ui_message).await {
                error!("Failed to send own-carbon placeholder to UI: {}", e);
            }
            return Ok(());
        }

        if !encrypted_keys.contains_key(&own_device_id) {
            debug!(
                "No key found for our device ID {} in carbon message",
                own_device_id
            );
            return self
                .send_carbon_to_ui(
                    from,
                    to,
                    is_sent,
                    message.attr("id"),
                    "[Message from another device - not encrypted for this device]",
                    true,
                )
                .await;
        }

        // Get IV (initialization vector)
        let iv = match header
            .get_child("iv", custom_ns::OMEMO)
            .or_else(|| header.get_child("iv", ""))
        {
            Some(iv_elem) => {
                let iv_base64 = iv_elem.text();
                match base64::engine::general_purpose::STANDARD.decode(iv_base64) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode IV in carbon: {}", e);
                        return Err(anyhow!("Failed to decode IV: {}", e));
                    }
                }
            }
            None => {
                error!("Missing IV in carbon OMEMO header");
                return Err(anyhow!("Missing IV in header"));
            }
        };

        // Get the payload (encrypted message content)
        // Key-transport messages (no payload) are valid but contain no visible content
        let payload = match encrypted
            .get_child("payload", custom_ns::OMEMO)
            .or_else(|| encrypted.get_child("payload", ""))
        {
            Some(payload_elem) => {
                let payload_base64 = payload_elem.text();
                match base64::engine::general_purpose::STANDARD.decode(payload_base64) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode payload in carbon: {}", e);
                        return Err(anyhow!("Failed to decode payload: {}", e));
                    }
                }
            }
            None => {
                debug!("Key-transport OMEMO carbon message (no payload) - skipping");
                return Ok(());
            }
        };

        // Determine the bare JID of the sender
        let sender_jid = if is_sent {
            // For sent carbons, we are the sender
            self.jid.split('/').next().unwrap_or(&self.jid).to_string()
        } else {
            // For received carbons, the other party is the sender
            from.split('/').next().unwrap_or(from).to_string()
        };

        debug!("Decrypting carbon from sender JID: {}", sender_jid);

        // Deduplication: if the same OMEMO message was already successfully decrypted
        // by the direct-delivery handler (which runs concurrently), skip re-decryption
        // here. Advancing the Double Ratchet twice for the same message would corrupt
        // the session state and cause subsequent MAC verification failures.
        let msg_id = message.attr("id").unwrap_or("unknown");
        {
            let manager = omemo_manager.lock().await;
            if manager.was_message_decrypted(msg_id) {
                debug!(
                    "Skipping carbon decryption for already-decrypted message {} from {}:{}",
                    msg_id, sender_jid, sender_device_id
                );
                return self
                    .send_carbon_to_ui(from, to, is_sent, message.attr("id"), "", true)
                    .await;
            }
        }

        // Now we need to decrypt the message using the OMEMO manager
        let decrypted_content = {
            let mut manager = omemo_manager.lock().await;

            debug!(
                "Decrypting OMEMO carbon message from {}:{}",
                sender_jid, sender_device_id
            );

            // Get the encrypted key for our device
            let _encrypted_key = encrypted_keys.get(&own_device_id).unwrap().clone();

            // Create an OMEMO message structure with the parts we extracted
            let omemo_message = crate::omemo::protocol::OmemoMessage {
                sender_device_id,
                ratchet_key: vec![], // This will be handled by the session
                previous_counter: 0, // This will be handled by the session
                counter: 0,          // This will be handled by the session
                ciphertext: payload,
                mac: vec![], // The MAC will be verified by the session
                iv,
                encrypted_keys,
                is_prekey: false,    // Will be determined by session state
                ephemeral_key: None, // Will be extracted from XML if present
                prekey_devices: std::collections::HashSet::new(),
            };

            // Try to decrypt the message
            match manager
                .decrypt_message(&sender_jid, sender_device_id, &omemo_message)
                .await
            {
                Ok(content) => {
                    // Record the ID so a future duplicate (direct delivery racing
                    // ahead of this carbon) does not re-decrypt the same message.
                    manager.mark_message_decrypted(msg_id);
                    content
                }
                Err(e) => {
                    error!("Failed to decrypt OMEMO carbon message: {}", e);
                    return Err(anyhow!("Failed to decrypt OMEMO carbon message: {}", e));
                }
            }
        };

        debug!("Successfully decrypted OMEMO carbon message");

        self.send_carbon_to_ui(
            from,
            to,
            is_sent,
            message.attr("id"),
            decrypted_content,
            true,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::custom_ns;
    use xmpp_parsers::Element;

    fn make_carbon_received(from: &str, body: &str) -> Element {
        let inner_msg = Element::builder("message", "jabber:client")
            .attr("from", from)
            .attr("to", "me@server.example")
            .attr("id", "orig-id-1")
            .append(
                Element::builder("body", "jabber:client")
                    .append(body)
                    .build(),
            )
            .build();

        let forwarded = Element::builder("forwarded", custom_ns::FORWARD)
            .append(inner_msg)
            .build();

        let received = Element::builder("received", custom_ns::CARBONS)
            .append(forwarded)
            .build();

        Element::builder("message", "jabber:client")
            .attr("from", "me@server.example")
            .attr("to", "me@server.example/resource")
            .append(received)
            .build()
    }

    fn make_carbon_sent(to: &str, body: &str) -> Element {
        let inner_msg = Element::builder("message", "jabber:client")
            .attr("from", "me@server.example/other-device")
            .attr("to", to)
            .attr("id", "orig-id-2")
            .append(
                Element::builder("body", "jabber:client")
                    .append(body)
                    .build(),
            )
            .build();

        let forwarded = Element::builder("forwarded", custom_ns::FORWARD)
            .append(inner_msg)
            .build();

        let sent = Element::builder("sent", custom_ns::CARBONS)
            .append(forwarded)
            .build();

        Element::builder("message", "jabber:client")
            .attr("from", "me@server.example")
            .attr("to", "me@server.example/resource")
            .append(sent)
            .build()
    }

    #[test]
    fn test_detect_received_carbon() {
        let stanza = make_carbon_received("alice@example.com/phone", "Hello!");
        assert!(stanza.has_child("received", custom_ns::CARBONS));
        assert!(!stanza.has_child("sent", custom_ns::CARBONS));
    }

    #[test]
    fn test_detect_sent_carbon() {
        let stanza = make_carbon_sent("bob@example.com", "Hey!");
        assert!(stanza.has_child("sent", custom_ns::CARBONS));
        assert!(!stanza.has_child("received", custom_ns::CARBONS));
    }

    #[test]
    fn test_extract_forwarded_message_from_received_carbon() {
        let stanza = make_carbon_received("alice@example.com/phone", "Test message");
        let received = stanza.get_child("received", custom_ns::CARBONS).unwrap();
        let forwarded = received.get_child("forwarded", custom_ns::FORWARD).unwrap();
        let message = forwarded.get_child("message", "jabber:client").unwrap();

        assert_eq!(message.attr("from").unwrap(), "alice@example.com/phone");
        let body = message.get_child("body", "jabber:client").unwrap();
        assert_eq!(body.text(), "Test message");
    }

    #[test]
    fn test_extract_forwarded_message_from_sent_carbon() {
        let stanza = make_carbon_sent("bob@example.com", "Outgoing");
        let sent = stanza.get_child("sent", custom_ns::CARBONS).unwrap();
        let forwarded = sent.get_child("forwarded", custom_ns::FORWARD).unwrap();
        let message = forwarded.get_child("message", "jabber:client").unwrap();

        assert_eq!(message.attr("to").unwrap(), "bob@example.com");
        let body = message.get_child("body", "jabber:client").unwrap();
        assert_eq!(body.text(), "Outgoing");
    }

    #[test]
    fn test_non_carbon_message_not_detected() {
        let stanza = Element::builder("message", "jabber:client")
            .attr("from", "bob@example.com")
            .append(
                Element::builder("body", "jabber:client")
                    .append("plain msg")
                    .build(),
            )
            .build();
        assert!(!stanza.has_child("sent", custom_ns::CARBONS));
        assert!(!stanza.has_child("received", custom_ns::CARBONS));
    }
}
