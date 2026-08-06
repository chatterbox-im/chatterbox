// XEP-0313: Message Archive Management Implementation
// https://xmpp.org/extensions/xep-0313.html

use anyhow::{anyhow, Result};
use base64::Engine;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use super::custom_ns;
use crate::models::{DeliveryStatus, Message};
use crate::omemo::device_id::DeviceId;
use crate::omemo::crypto;

#[derive(Debug, Clone)]
pub struct MAMQueryOptions {
    pub with: Option<String>,
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
    pub after: Option<String>, // RSM pagination token for continuing a query
}

// Result structure with information about pagination
#[derive(Debug, Clone)]
pub struct MAMQueryResult {
    pub messages: Vec<Message>,
    pub complete: bool,
    pub rsm_first: Option<String>, // First item in the result set
    pub rsm_last: Option<String>,  // Last item in the result set
    pub rsm_count: Option<usize>,  // Total count of items available
}

impl MAMQueryOptions {
    pub fn new() -> Self {
        MAMQueryOptions {
            with: None,
            start: None,
            end: None,
            limit: Some(50), // Default limit
            after: None,
        }
    }

    pub fn with_jid(mut self, jid: &str) -> Self {
        self.with = Some(jid.to_string());
        self
    }

    pub fn with_start(mut self, start: chrono::DateTime<chrono::Utc>) -> Self {
        self.start = Some(start);
        self
    }

    pub fn with_end(mut self, end: chrono::DateTime<chrono::Utc>) -> Self {
        self.end = Some(end);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_after(mut self, after: &str) -> Self {
        self.after = Some(after.to_string());
        self
    }
}

/// Implementation of XEP-0313 Message Archive Management
impl super::XMPPClient {
    /// Retrieve message history using XEP-0313 Message Archive Management (MAM)
    ///
    /// This method fetches historical messages from the server archive with pagination support.
    /// It returns a MAMQueryResult with the messages and pagination information.
    ///
    /// # Arguments
    ///
    /// * `options` - Query options including with whom to fetch messages, time ranges, and limits
    ///
    /// # Returns
    ///
    /// A Result containing a MAMQueryResult with messages and pagination info
    pub async fn get_message_history_with_pagination(
        &self,
        options: MAMQueryOptions,
    ) -> Result<MAMQueryResult> {
        info!("Fetching message history with options: {:?}", options);

        // Check OMEMO initialization state before proceeding
        let omemo_initialized = Self::is_omemo_fully_initialized(&self.omemo_manager).await;
        if !omemo_initialized {
            info!("OMEMO not fully initialized yet when fetching message history - encrypted messages may not be decrypted");
        }

        // Generate a unique ID for this MAM query
        let query_id = Uuid::new_v4().to_string();

        // Register for both MAM messages and the final IQ BEFORE sending
        let (mut msg_rx, mut iq_rx) = {
            let mut registry = self.iq_registry.lock().await;
            registry.register_mam(query_id.clone())
        };

        // Build query element
        let mut query = xmpp_parsers::minidom::Element::builder("query", custom_ns::MAM)
            .attr("queryid".try_into().unwrap(), &query_id);

        // Create the data form
        let mut x_data = xmpp_parsers::minidom::Element::builder("x", "jabber:x:data")
            .attr("type".try_into().unwrap(), "submit");

        // Add form type field
        let mut form_type_field = xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
            .attr("var".try_into().unwrap(), "FORM_TYPE")
            .attr("type".try_into().unwrap(), "hidden")
            .build();

        let mut value_element =
            xmpp_parsers::minidom::Element::builder("value", "jabber:x:data").build();
        value_element.append_text_node("urn:xmpp:mam:2");
        form_type_field.append_child(value_element);

        x_data = x_data.append(form_type_field);

        // Add "with" filter if specified
        if let Some(with_jid) = &options.with {
            let mut with_field = xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                .attr("var".try_into().unwrap(), "with")
                .build();

            let mut with_value =
                xmpp_parsers::minidom::Element::builder("value", "jabber:x:data").build();
            with_value.append_text_node(with_jid);
            with_field.append_child(with_value);

            x_data = x_data.append(with_field);
        }

        // Add start time filter if specified
        if let Some(start_time) = options.start {
            let start_str = start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            let mut start_field = xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                .attr("var".try_into().unwrap(), "start")
                .build();

            let mut start_value =
                xmpp_parsers::minidom::Element::builder("value", "jabber:x:data").build();
            start_value.append_text_node(&start_str);
            start_field.append_child(start_value);

            x_data = x_data.append(start_field);
        }

        // Add end time filter if specified
        if let Some(end_time) = options.end {
            let end_str = end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            let mut end_field = xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                .attr("var".try_into().unwrap(), "end")
                .build();

            let mut end_value =
                xmpp_parsers::minidom::Element::builder("value", "jabber:x:data").build();
            end_value.append_text_node(&end_str);
            end_field.append_child(end_value);

            x_data = x_data.append(end_field);
        }

        // Add Result Set Management (RSM) for pagination
        let mut set =
            xmpp_parsers::minidom::Element::builder("set", "http://jabber.org/protocol/rsm")
                .build();

        if let Some(limit) = options.limit {
            let mut max_element =
                xmpp_parsers::minidom::Element::builder("max", "http://jabber.org/protocol/rsm")
                    .build();
            max_element.append_text_node(&limit.to_string());
            set.append_child(max_element);
        }

        if let Some(after) = &options.after {
            let mut after_element =
                xmpp_parsers::minidom::Element::builder("after", "http://jabber.org/protocol/rsm")
                    .build();
            after_element.append_text_node(after);
            set.append_child(after_element);
        }

        query = query.append(set);

        let query_element = query.append(x_data.build()).build();

        // Create the IQ stanza
        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &query_id)
            .append(query_element)
            .build();

        info!("Sending MAM query with ID: {}", query_id);

        // Send the MAM query
        self.send_stanza(iq)
            .map_err(|e| anyhow!("Failed to send MAM query: {}", e))?;

        // Collect messages until the final IQ arrives or timeout
        let mut archived_messages = Vec::new();
        let mut result_complete = false;
        let mut rsm_first = None;
        let mut rsm_last = None;
        let mut rsm_count = None;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            tokio::select! {
                // Receive a MAM message from the collector
                msg = msg_rx.recv() => {
                    match msg {
                        Some(stanza) => {
                            self.process_mam_message_stanza(&stanza, &query_id, &mut archived_messages).await;
                        },
                        None => {
                            // Channel closed (registry evicted or dropped)
                            break;
                        }
                    }
                },
                // Receive the final IQ result
                iq_result = &mut iq_rx => {
                    match iq_result {
                        Ok(stanza) => {
                            if stanza.attr("type") == Some("result") {
                                info!("Received MAM query result - archiving complete");
                                result_complete = true;

                                if let Some(fin) = stanza.get_child("fin", custom_ns::MAM) {
                                    if let Some(complete) = fin.attr("complete") {
                                        result_complete = complete == "true";
                                    }

                                    if let Some(set) = fin.get_child("set", "http://jabber.org/protocol/rsm") {
                                        if let Some(first) = set.get_child("first", "http://jabber.org/protocol/rsm") {
                                            rsm_first = Some(first.text());
                                        }
                                        if let Some(last) = set.get_child("last", "http://jabber.org/protocol/rsm") {
                                            rsm_last = Some(last.text());
                                        }
                                        if let Some(count) = set.get_child("count", "http://jabber.org/protocol/rsm") {
                                            if let Ok(count_val) = count.text().parse::<usize>() {
                                                rsm_count = Some(count_val);
                                            }
                                        }
                                    }
                                }
                            } else if stanza.attr("type") == Some("error") {
                                if let Some(error) = stanza.get_child("error", "") {
                                    let error_type = error.attr("type").unwrap_or("unknown");
                                    let mut error_msg = format!("MAM query failed with error type: {}", error_type);
                                    if let Some(text) = error.get_child("text", "urn:ietf:params:xml:ns:xmpp-stanzas") {
                                        error_msg = format!("{} - {}", error_msg, text.text());
                                    }
                                    error!("{}", error_msg);
                                    return Err(anyhow!(error_msg));
                                }
                            }
                        },
                        Err(_) => {
                            warn!("IQ response channel closed for MAM query");
                        }
                    }
                    break;
                },
                // Timeout
                _ = tokio::time::sleep_until(deadline) => {
                    warn!("MAM query timed out before completion - returning partial results");
                    break;
                }
            }
        }

        // Drain any remaining messages that arrived before the IQ
        while let Ok(stanza) = msg_rx.try_recv() {
            self.process_mam_message_stanza(&stanza, &query_id, &mut archived_messages)
                .await;
        }

        info!("Retrieved {} archived messages", archived_messages.len());

        // Sort messages by timestamp from oldest to newest
        archived_messages.sort_by(|a: &Message, b: &Message| a.timestamp.cmp(&b.timestamp));

        Ok(MAMQueryResult {
            messages: archived_messages,
            complete: result_complete,
            rsm_first,
            rsm_last,
            rsm_count,
        })
    }

    /// Process a single MAM message stanza received from the collector channel.
    async fn process_mam_message_stanza(
        &self,
        stanza: &xmpp_parsers::minidom::Element,
        query_id: &str,
        archived_messages: &mut Vec<Message>,
    ) {
        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
            if result.attr("queryid") != Some(query_id) {
                return;
            }

            if let Some(forwarded) = result.get_child("forwarded", "urn:xmpp:forward:0") {
                if let Some(message_stanza) = forwarded.get_child("message", "jabber:client") {
                    if let Some(delay) = forwarded.get_child("delay", "urn:xmpp:delay") {
                        let from = message_stanza.attr("from").map(|s| s.to_string());
                        // Some archived messages (especially self-messages sent to
                        // our own bare JID) omit the `to` attribute.  Fall back to
                        // our own bare JID so that OMEMO processing is not silently
                        // skipped for such messages.
                        let our_bare_jid =
                            self.jid.split('/').next().unwrap_or(&self.jid).to_string();
                        let to = message_stanza
                            .attr("to")
                            .map(|s| s.to_string())
                            .or_else(|| Some(our_bare_jid));

                        let timestamp_str = delay.attr("stamp").unwrap_or("");
                        let timestamp = if !timestamp_str.is_empty() {
                            match chrono::DateTime::parse_from_rfc3339(timestamp_str) {
                                Ok(dt) => dt.timestamp_millis().into(),
                                Err(_) => chrono::Utc::now().timestamp_millis().into(),
                            }
                        } else {
                            chrono::Utc::now().timestamp_millis().into()
                        };

                        let message_id = message_stanza
                            .attr("id")
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| Uuid::new_v4().to_string());

                        if let (Some(from), Some(to)) = (from.clone(), to.clone()) {
                            let (sender_id, recipient_id) = if from.contains(&self.jid) {
                                ("me".to_string(), to)
                            } else {
                                (from.clone(), "me".to_string())
                            };

                            // Check for OMEMO encrypted message
                            let has_omemo_v1 =
                                message_stanza.has_child("encrypted", custom_ns::OMEMO);
                            let has_omemo_axolotl =
                                message_stanza.has_child("encrypted", custom_ns::OMEMO_V1);
                            if has_omemo_v1 || has_omemo_axolotl {
                                debug!(
                                    "Found OMEMO encrypted message in archive from {}",
                                    sender_id
                                );

                                if let Some(ref mgr) = self.omemo_manager {
                                    match Self::decrypt_archived_omemo_message(
                                        &message_stanza,
                                        &from,
                                        mgr,
                                    )
                                    .await
                                    {
                                        Ok(Some(decrypted_content)) => {
                                            archived_messages.push(Message {
                                                id: message_id,
                                                sender_id,
                                                recipient_id,
                                                content: decrypted_content,
                                                timestamp,
                                                delivery_status: DeliveryStatus::Delivered,
                                                encrypted: true,
                                            });
                                            return;
                                        }
                                        Ok(None) => {}
                                        Err(e) => {
                                            warn!("Failed to decrypt archived message: {}", e);
                                            archived_messages.push(Message {
                                                id: message_id,
                                                sender_id,
                                                recipient_id,
                                                content: format!(
                                                    "[Encrypted message - couldn't decrypt: {}]",
                                                    e
                                                ),
                                                timestamp,
                                                delivery_status: DeliveryStatus::Delivered,
                                                encrypted: true,
                                            });
                                            return;
                                        }
                                    }
                                } else {
                                    archived_messages.push(Message {
                                        id: message_id,
                                        sender_id,
                                        recipient_id,
                                        content: "[Encrypted message - OMEMO not initialized]"
                                            .to_string(),
                                        timestamp,
                                        delivery_status: DeliveryStatus::Delivered,
                                        encrypted: true,
                                    });
                                    return;
                                }
                            }

                            // Fall back to regular body content
                            if let Some(body) = message_stanza
                                .get_child("body", "jabber:client")
                                .map(|b| b.text())
                            {
                                if !body.is_empty() {
                                    archived_messages.push(Message {
                                        id: message_id,
                                        sender_id,
                                        recipient_id,
                                        content: body,
                                        timestamp,
                                        delivery_status: DeliveryStatus::Delivered,
                                        encrypted: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Simplified wrapper around get_message_history_with_pagination
    /// that just returns the messages for backward compatibility
    pub async fn get_message_history(&self, options: MAMQueryOptions) -> Result<Vec<Message>> {
        match self.get_message_history_with_pagination(options).await {
            Ok(result) => Ok(result.messages),
            Err(e) => Err(e),
        }
    }

    /// Check if message history exists for a contact
    /// This is a lightweight check that returns quickly
    ///
    /// # Arguments
    ///
    /// * `jid` - The JID of the contact to check history for
    /// * `limit` - Maximum number of results to check for (smaller = faster)
    ///
    /// # Returns
    ///
    /// A Result containing a boolean: true if history exists, false otherwise
    pub async fn has_message_history(&self, jid: &str, limit: usize) -> Result<bool> {
        // Generate a unique ID for this MAM query
        let query_id = Uuid::new_v4().to_string();

        // Register for both MAM messages and the final IQ
        let (mut msg_rx, iq_rx) = {
            let mut registry = self.iq_registry.lock().await;
            registry.register_mam(query_id.clone())
        };

        // Build query element with minimal parameters for a quick check
        let mut query = xmpp_parsers::minidom::Element::builder("query", custom_ns::MAM)
            .attr("queryid".try_into().unwrap(), &query_id);

        let mut x_data = xmpp_parsers::minidom::Element::builder("x", "jabber:x:data")
            .attr("type".try_into().unwrap(), "submit");

        let mut form_type_field = xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
            .attr("var".try_into().unwrap(), "FORM_TYPE")
            .attr("type".try_into().unwrap(), "hidden")
            .build();

        let mut value_element =
            xmpp_parsers::minidom::Element::builder("value", "jabber:x:data").build();
        value_element.append_text_node("urn:xmpp:mam:2");
        form_type_field.append_child(value_element);

        x_data = x_data.append(form_type_field);

        // Add "with" filter
        let mut with_field = xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
            .attr("var".try_into().unwrap(), "with")
            .build();

        let mut with_value =
            xmpp_parsers::minidom::Element::builder("value", "jabber:x:data").build();
        with_value.append_text_node(jid);
        with_field.append_child(with_value);

        x_data = x_data.append(with_field);

        // Small limit
        let mut set =
            xmpp_parsers::minidom::Element::builder("set", "http://jabber.org/protocol/rsm")
                .build();
        let mut max_element =
            xmpp_parsers::minidom::Element::builder("max", "http://jabber.org/protocol/rsm")
                .build();
        max_element.append_text_node(&limit.to_string());
        set.append_child(max_element);

        query = query.append(set);

        let query_element = query.append(x_data.build()).build();

        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &query_id)
            .append(query_element)
            .build();

        // Send the query
        self.send_stanza(iq)
            .map_err(|e| anyhow!("Failed to send MAM history check query: {}", e))?;

        // Wait for either a message (means history exists) or the final IQ
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        tokio::select! {
            msg = msg_rx.recv() => {
                // Got a MAM message — history exists
                Ok(msg.is_some())
            },
            iq_result = iq_rx => {
                // Got the final IQ without any messages first — no history
                // (or there was an error)
                match iq_result {
                    Ok(stanza) => {
                        if stanza.attr("type") == Some("error") {
                            if let Some(error) = stanza.get_child("error", "") {
                                let error_type = error.attr("type").unwrap_or("unknown");
                                error!("MAM history check query returned error: {}", error_type);
                            }
                        }
                        Ok(false)
                    },
                    Err(_) => Ok(false),
                }
            },
            _ = tokio::time::sleep_until(deadline) => {
                Ok(false)
            }
        }
    }

    // Helper method for decrypting archived OMEMO messages
    async fn decrypt_archived_omemo_message(
        message_stanza: &xmpp_parsers::minidom::Element,
        sender_jid: &str,
        omemo_manager: &Arc<TokioMutex<crate::omemo::OmemoManager>>,
    ) -> Result<Option<String>> {
        //debug!("Attempting to decrypt archived OMEMO message from {}", sender_jid);

        // Extract the OMEMO encrypted element (try both namespaces)
        let encrypted = match message_stanza
            .get_child("encrypted", custom_ns::OMEMO)
            .or_else(|| message_stanza.get_child("encrypted", custom_ns::OMEMO_V1))
        {
            Some(e) => e,
            None => return Ok(None), // No encrypted element found
        };

        // Get the header element which contains keys and other metadata (try both namespaces)
        let header = match encrypted
            .get_child("header", custom_ns::OMEMO)
            .or_else(|| encrypted.get_child("header", custom_ns::OMEMO_V1))
        {
            Some(h) => h,
            None => {
                warn!("Missing header in OMEMO encrypted message");
                return Err(anyhow!("Missing header in OMEMO encrypted message"));
            }
        };

        // Extract the sender device ID
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

        // Use the provided OMEMO manager instance directly
        let omemo_manager = omemo_manager.clone();

        // Get IV (initialization vector) - try with OMEMO namespace first, then with no namespace
        let iv = match header
            .get_child("iv", custom_ns::OMEMO)
            .or_else(|| header.get_child("iv", custom_ns::OMEMO_V1))
            .or_else(|| header.get_child("iv", ""))
        {
            Some(iv_elem) => {
                let iv_base64 = iv_elem.text();
                match base64::engine::general_purpose::STANDARD.decode(iv_base64) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode IV: {}", e);
                        return Err(anyhow!("Failed to decode IV: {}", e));
                    }
                }
            }
            None => {
                error!("Missing IV in OMEMO header");
                return Err(anyhow!("Missing IV in OMEMO header"));
            }
        };

        // Extract our device ID from the key elements to find our key
        // First get our own device ID from the OMEMO manager
        let own_device_id = {
            let manager = omemo_manager.lock().await;
            manager.get_device_id()
        };

        // If the sender is our own device, this is an archive echo of a message
        // WE sent.  The ratchet for the self-session has already advanced; trying
        // to re-decrypt it will always fail and corrupt the session state.
        // Skip decryption — we already have the plaintext from when we sent it.
        if DeviceId::from(sender_device_id) == own_device_id {
            debug!(
                "Skipping MAM decryption of own-device message (device {})",
                sender_device_id
            );
            return Ok(None);
        }

        // Look for a key element intended for our device
        let mut key_data = None;

        // Try to find a key element for our device
        // The xmpp_parsers::minidom::Element doesn't have a get_children method, so we need to manually
        // iterate through all children and filter for key elements
        let mut found_key = false;
        for child in header.children() {
            if child.name() == "key"
                && (child.ns() == custom_ns::OMEMO
                    || child.ns() == custom_ns::OMEMO_V1
                    || child.ns() == "")
            {
                if let Some(rid) = child.attr("rid") {
                    match rid.parse::<u32>() {
                        Ok(device_id) if DeviceId::from(device_id) == own_device_id => {
                            // This key is for our device
                            let key_base64 = child.text();
                            match base64::engine::general_purpose::STANDARD.decode(key_base64) {
                                Ok(decoded) => {
                                    key_data = Some(decoded);
                                    // Check if this is a prekey message and log it
                                    if child.attr("prekey").is_some() {
                                        //debug!("Received a prekey message from device {}", sender_device_id);
                                    }
                                    found_key = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("Failed to decode key data: {}", e);
                                    continue;
                                }
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }

        if !found_key {
            //debug!("No key found for our device (ID: {}) in OMEMO message", own_device_id);
        }

        // If we didn't find a key for our device, we can't decrypt the message
        let key = match key_data {
            Some(k) => k,
            None => {
                warn!("No key found for our device in archived message");
                return Err(anyhow!("No key found for our device in archived message"));
            }
        };

        // Get the payload (encrypted message content) - try both OMEMO namespaces
        // Key-transport messages (no payload) are valid but contain no visible content
        let payload = match encrypted
            .get_child("payload", custom_ns::OMEMO)
            .or_else(|| encrypted.get_child("payload", custom_ns::OMEMO_V1))
            .or_else(|| encrypted.get_child("payload", ""))
        {
            Some(payload_elem) => {
                let payload_base64 = payload_elem.text();
                match base64::engine::general_purpose::STANDARD.decode(payload_base64) {
                    Ok(decoded) => Some(decoded),
                    Err(e) => {
                        error!("Failed to decode payload: {}", e);
                        return Err(anyhow!("Failed to decode payload: {}", e));
                    }
                }
            }
            None => {
                debug!("Key-transport OMEMO message in MAM (no payload) - skipping");
                return Ok(None);
            }
        };

        // Now we need to decrypt the message using the OMEMO manager
        // Extract bare JID from sender's full JID
        let bare_sender_jid = match sender_jid.split('/').next() {
            Some(jid) => jid,
            None => sender_jid,
        };

        // Create a clone of the manager for the locked section
        let manager_clone = omemo_manager.clone();

        // Process the message for decryption
        let decrypted_content = {
            let mut manager = manager_clone.lock().await;

            //debug!("Decrypting OMEMO message from {} (device {})", bare_sender_jid, sender_device_id);

            // Try to decrypt the message
            match manager
                .decrypt_message(
                    bare_sender_jid,
                    DeviceId::from(sender_device_id),
                    &crate::omemo::protocol::OmemoMessage {
                        sender_device_id: DeviceId::from(sender_device_id),
                        ratchet_key: vec![], // This will be handled by the session
                        previous_counter: 0, // This will be handled by the session
                        counter: 0,          // This will be handled by the session
                        ciphertext: payload.unwrap(),
                        mac: crypto::sha256_hash(&key)[..16].to_vec(),
                        iv,
                        encrypted_keys: {
                            let mut keys = std::collections::HashMap::new();
                            keys.insert(own_device_id, key);
                            keys
                        },
                        is_prekey: false,    // Will be determined by session state
                        ephemeral_key: None, // Will be extracted from XML if present
                        prekey_devices: std::collections::HashSet::new(),
                    },
                )
                .await
            {
                Ok(content) => content,
                Err(e) => {
                    // Ratchet replay errors ("counter too old", "MAC verification failed")
                    // are expected when MAM re-delivers already-processed messages.
                    // Log at WARN — these are not bugs, just normal MAM catch-up noise.
                    // Also reset the failure counter so replays never accumulate into a
                    // session reset that would destroy a working live-message session.
                    warn!("Failed to decrypt OMEMO message (likely a MAM replay): {}", e);
                    // Reuse the guard we already hold — acquiring the same lock again
                    // from the same task would deadlock on Tokio's async Mutex.
                    let _ = manager.reset_failure_count(sender_jid, sender_device_id).await;
                    return Err(anyhow!("Failed to decrypt OMEMO message: {}", e));
                }
            }
        };

        //debug!("Successfully decrypted archived OMEMO message");
        Ok(Some(decrypted_content))
    }

    // Use the implementation from mod.rs instead of duplicating it here

    // Helper method to check if OMEMO is fully initialized
    pub async fn is_omemo_fully_initialized(
        omemo_manager: &Option<Arc<TokioMutex<crate::omemo::OmemoManager>>>,
    ) -> bool {
        if let Some(omemo_manager) = omemo_manager {
            let manager = omemo_manager.lock().await;
            // Consider OMEMO fully initialized if we have a device ID and bundle published
            if manager.get_device_id().get() > 0 {
                // Additional check to make sure the bundle is published
                if let Ok(true) = manager.is_bundle_published().await {
                    return true;
                }
            }
        }
        false
    }

    /// Continuously load message history in the background until all history is retrieved
    ///
    /// This function is called after the initial message history load detects partial results.
    /// It will continue fetching history in the background and sending messages to the UI.
    ///
    /// # Arguments
    ///
    /// * `jid` - The JID of the contact whose history we're loading
    /// * `initial_result` - The initial query result with pagination info
    /// * `message_tx` - A channel to send retrieved messages to the UI
    /// * `max_pages` - Maximum number of pages to retrieve (to avoid infinite loops)
    pub async fn load_complete_message_history_in_background(
        &self,
        jid: &str,
        initial_result: MAMQueryResult,
        message_tx: tokio::sync::mpsc::Sender<crate::models::Message>,
        max_pages: usize,
    ) -> Result<()> {
        info!("Starting background history load for {}", jid);

        // Create a clone of the initial query result
        let mut current_result = initial_result;
        let mut page_count = 1;

        // Create a system message to inform the user that background loading has started
        if !current_result.complete && current_result.rsm_last.is_some() {
            // Don't send this notification if we retrieved everything in the first query
            if let Some(count) = current_result.rsm_count {
                let notification = crate::models::Message {
                    id: Uuid::new_v4().to_string(),
                    sender_id: "[System]".to_string(),
                    recipient_id: jid.to_string(),
                    content: format!(
                        "Loading message history ({}/{} messages)...",
                        current_result.messages.len(),
                        count
                    ),
                    timestamp: chrono::Utc::now().timestamp_millis().into(),
                    delivery_status: DeliveryStatus::Delivered,
                    encrypted: false,
                };

                // Send this notification to the UI
                if let Err(e) = message_tx.send(notification).await {
                    error!("Failed to send history loading notification: {}", e);
                }
            }
        }

        // Continue fetching until we have all history or reach the max pages limit
        while !current_result.complete && page_count < max_pages {
            // Do we have the "last" token to continue from?
            if let Some(last_id) = &current_result.rsm_last {
                // Wait a short time to avoid flooding the server
                tokio::time::sleep(Duration::from_millis(300)).await;

                // Create new options with the pagination token
                let next_options = MAMQueryOptions::new()
                    .with_jid(jid)
                    .with_after(last_id)
                    .with_limit(50);

                // Fetch the next page
                match self.get_message_history_with_pagination(next_options).await {
                    Ok(result) => {
                        let messages_count = result.messages.len();
                        if messages_count == 0 {
                            // No more messages, exit the loop
                            //debug!("No more messages to retrieve for {}", jid);
                            break;
                        }

                        info!(
                            "Retrieved page {} with {} additional messages for {}",
                            page_count + 1,
                            messages_count,
                            jid
                        );

                        // Update progress notification
                        if let Some(count) = result.rsm_count {
                            let loaded_so_far = current_result.messages.len() + messages_count;
                            let notification = crate::models::Message {
                                id: Uuid::new_v4().to_string(),
                                sender_id: "[System]".to_string(),
                                recipient_id: jid.to_string(),
                                content: format!(
                                    "Loading message history ({}/{} messages)...",
                                    loaded_so_far, count
                                ),
                                timestamp: chrono::Utc::now().timestamp_millis().into(),
                                delivery_status: DeliveryStatus::Delivered,
                                encrypted: false,
                            };

                            // Send this notification to the UI
                            if let Err(e) = message_tx.send(notification).await {
                                error!("Failed to send history loading notification: {}", e);
                            }
                        }

                        // Send messages to the UI
                        for message in &result.messages {
                            if let Err(e) = message_tx.send(message.clone()).await {
                                error!("Failed to send historical message to UI: {}", e);
                                break;
                            }
                        }

                        // Update the current result for the next iteration
                        current_result = result;
                        page_count += 1;
                    }
                    Err(e) => {
                        error!(
                            "Error retrieving additional message history for {}: {}",
                            jid, e
                        );

                        // Notify the user about the error
                        let error_notification = crate::models::Message {
                            id: Uuid::new_v4().to_string(),
                            sender_id: "[System]".to_string(),
                            recipient_id: jid.to_string(),
                            content: format!("Failed to retrieve full message history: {}", e),
                            timestamp: chrono::Utc::now().timestamp_millis().into(),
                            delivery_status: DeliveryStatus::Delivered,
                            encrypted: false,
                        };

                        if let Err(send_e) = message_tx.send(error_notification).await {
                            error!("Failed to send error notification: {}", send_e);
                        }

                        break;
                    }
                }
            } else {
                // No pagination token, exit the loop
                //debug!("No pagination token available to continue loading history for {}", jid);
                break;
            }
        }

        // Final notification when all history is loaded
        let completion_notification = crate::models::Message {
            id: Uuid::new_v4().to_string(),
            sender_id: "[System]".to_string(),
            recipient_id: jid.to_string(),
            content: if current_result.complete || page_count >= max_pages {
                if let Some(count) = current_result.rsm_count {
                    format!("Message history complete ({} messages)", count)
                } else {
                    format!("Message history complete ({} pages retrieved)", page_count)
                }
            } else {
                "Partial message history loaded (not all messages could be retrieved)".to_string()
            },
            timestamp: chrono::Utc::now().timestamp_millis().into(),
            delivery_status: DeliveryStatus::Delivered,
            encrypted: false,
        };

        if let Err(e) = message_tx.send(completion_notification).await {
            error!("Failed to send history completion notification: {}", e);
        }

        info!(
            "Completed background history load for {} ({} pages retrieved)",
            jid, page_count
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mam_query_options_defaults() {
        let opts = MAMQueryOptions::new();
        assert_eq!(opts.limit, Some(50));
        assert!(opts.with.is_none());
        assert!(opts.start.is_none());
        assert!(opts.end.is_none());
        assert!(opts.after.is_none());
    }

    #[test]
    fn test_mam_query_options_builder() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let opts = MAMQueryOptions::new()
            .with_jid("alice@example.com")
            .with_start(start)
            .with_end(end)
            .with_limit(25)
            .with_after("page-token-123");

        assert_eq!(opts.with.as_deref(), Some("alice@example.com"));
        assert_eq!(opts.start, Some(start));
        assert_eq!(opts.end, Some(end));
        assert_eq!(opts.limit, Some(25));
        assert_eq!(opts.after.as_deref(), Some("page-token-123"));
    }

    #[test]
    fn test_mam_query_result_empty() {
        let result = MAMQueryResult {
            messages: vec![],
            complete: true,
            rsm_first: None,
            rsm_last: None,
            rsm_count: Some(0),
        };
        assert!(result.messages.is_empty());
        assert!(result.complete);
    }
}
