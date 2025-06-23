// XEP-0313: Message Archive Management Implementation
// https://xmpp.org/extensions/xep-0313.html

use anyhow::{anyhow, Result};
use log::{error, info, warn};
use std::time::Duration;
use uuid::Uuid;
use futures_util::StreamExt;
use base64::Engine;

use crate::models::{Message, DeliveryStatus};
use crate::omemo::crypto;
use super::custom_ns;

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
    pub async fn get_message_history_with_pagination(&self, options: MAMQueryOptions) -> Result<MAMQueryResult> {
        info!("Fetching message history with options: {:?}", options);
        
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        // Check OMEMO initialization state before proceeding
        let omemo_initialized = Self::is_omemo_fully_initialized().await;
        if !omemo_initialized {
            info!("OMEMO not fully initialized yet when fetching message history - encrypted messages may not be decrypted");
        }
        
        let client = self.client.as_ref().unwrap();
        
        // Generate a unique ID for this MAM query
        let query_id = Uuid::new_v4().to_string();
        
        // Build query element
        let mut query = xmpp_parsers::Element::builder("query", custom_ns::MAM)
            .attr("queryid", &query_id);
        
        // Create the data form
        let mut x_data = xmpp_parsers::Element::builder("x", "jabber:x:data")
            .attr("type", "submit");

        // Add form type field - this needs proper namespace
        let mut form_type_field = xmpp_parsers::Element::builder("field", "jabber:x:data")
            .attr("var", "FORM_TYPE")
            .attr("type", "hidden")
            .build();

        let mut value_element = xmpp_parsers::Element::builder("value", "jabber:x:data").build();
        value_element.append_text_node("urn:xmpp:mam:2");
        form_type_field.append_child(value_element);
        
        x_data = x_data.append(form_type_field);

        // Add "with" filter if specified
        if let Some(with_jid) = &options.with {
            //debug!("Adding 'with' filter for JID: {}", with_jid);
            
            let mut with_field = xmpp_parsers::Element::builder("field", "jabber:x:data")
                .attr("var", "with")
                .build();
                
            let mut with_value = xmpp_parsers::Element::builder("value", "jabber:x:data").build();
            with_value.append_text_node(with_jid);
            with_field.append_child(with_value);
                
            x_data = x_data.append(with_field);
        }
        
        // Add start time filter if specified
        if let Some(start_time) = options.start {
            let start_str = start_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            //debug!("Adding 'start' filter: {}", start_str);
            
            let mut start_field = xmpp_parsers::Element::builder("field", "jabber:x:data")
                .attr("var", "start")
                .build();
            
            let mut start_value = xmpp_parsers::Element::builder("value", "jabber:x:data").build();
            start_value.append_text_node(&start_str);
            start_field.append_child(start_value);
            
            x_data = x_data.append(start_field);
        }
        
        // Add end time filter if specified
        if let Some(end_time) = options.end {
            let end_str = end_time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            //debug!("Adding 'end' filter: {}", end_str);
            
            let mut end_field = xmpp_parsers::Element::builder("field", "jabber:x:data")
                .attr("var", "end")
                .build();
            
            let mut end_value = xmpp_parsers::Element::builder("value", "jabber:x:data").build();
            end_value.append_text_node(&end_str);
            end_field.append_child(end_value);
            
            x_data = x_data.append(end_field);
        }
        
        // Add Result Set Management (RSM) for pagination
        let mut set = xmpp_parsers::Element::builder("set", "http://jabber.org/protocol/rsm").build();
        
        // Add limit if specified
        if let Some(limit) = options.limit {
            //debug!("Adding 'max' limit: {}", limit);
            let mut max_element = xmpp_parsers::Element::builder("max", "http://jabber.org/protocol/rsm").build();
            max_element.append_text_node(&limit.to_string());
            set.append_child(max_element);
        }
        
        // Add 'after' token if specified for pagination
        if let Some(after) = &options.after {
            //debug!("Adding 'after' token for pagination: {}", after);
            let mut after_element = xmpp_parsers::Element::builder("after", "http://jabber.org/protocol/rsm").build();
            after_element.append_text_node(after);
            set.append_child(after_element);
        }
        
        query = query.append(set);
        
        // Finalize the query
        let query_element = query
            .append(x_data.build())
            .build();
        
        // Create the IQ stanza
        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &query_id)
            .append(query_element)
            .build();
        
        info!("Sending MAM query with ID: {}", query_id);
        
        // Collect messages from the archive
        let mut archived_messages = Vec::new();
        let mut result_complete = false;
        let mut rsm_first = None;
        let mut rsm_last = None;
        let mut rsm_count = None;
        
        // Send the MAM query with a short-lived lock
        let send_result = {
            // Acquire lock only for the duration of sending the stanza
            let lock_timeout = Duration::from_secs(5);
            let mut client_guard = match tokio::time::timeout(lock_timeout, client.lock()).await {
                Ok(guard) => guard,
                Err(_) => return Err(anyhow!("Timed out acquiring client lock for message history request")),
            };
            
            // Send the query within a timeout
            tokio::time::timeout(
                Duration::from_secs(5),
                async { client_guard.send_stanza(iq).await }
            ).await
        };
        
        // Check if send was successful
        match send_result {
            Ok(Ok(_)) => {
                //debug!("MAM query sent successfully, waiting for responses");
            },
            Ok(Err(e)) => {
                error!("Failed to send MAM query: {}", e);
                return Err(anyhow!("Failed to send MAM query: {}", e));
            },
            Err(_) => {
                error!("Timed out sending MAM query");
                return Err(anyhow!("Timed out sending MAM query"));
            }
        }
        
        // Process responses until we get the IQ result or timeout
        let response_timeout = Duration::from_secs(30); // Timeout for archive queries
        let start_time = tokio::time::Instant::now();
        
        while !result_complete && tokio::time::Instant::now() - start_time < response_timeout {
            // Acquire lock only for short durations to check for events
            let event = {
                let lock_result = tokio::time::timeout(
                    Duration::from_secs(1),
                    client.lock()
                ).await;
                
                match lock_result {
                    Ok(mut client_guard) => {
                        match tokio::time::timeout(
                            Duration::from_millis(500),
                            client_guard.next()
                        ).await {
                            Ok(event) => event,
                            Err(_) => {
                                // Timeout on this check, release the lock and wait briefly
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        }
                    },
                    Err(_) => {
                        // Failed to acquire lock, wait briefly and retry
                        //debug!("Failed to acquire lock for MAM response check, retrying");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                }
            };
            
            // Process the event if we got one
            match event {
                Some(tokio_xmpp::Event::Stanza(stanza)) => {
                    // IQ result indicates the end of the archive query
                    if stanza.name() == "iq" && 
                       stanza.attr("id") == Some(&query_id) {
                        if stanza.attr("type") == Some("result") {
                            info!("Received MAM query result - archiving complete");
                            result_complete = true;
                            
                            // Extract RSM set info from the result
                            if let Some(fin) = stanza.get_child("fin", custom_ns::MAM) {
                                // Check if there are more results available
                                if let Some(complete) = fin.attr("complete") {
                                    result_complete = complete == "true";
                                }
                                
                                // Extract RSM information
                                if let Some(set) = fin.get_child("set", "http://jabber.org/protocol/rsm") {
                                    // Get first item
                                    if let Some(first) = set.get_child("first", "http://jabber.org/protocol/rsm") {
                                        rsm_first = Some(first.text());
                                    }
                                    
                                    // Get last item
                                    if let Some(last) = set.get_child("last", "http://jabber.org/protocol/rsm") {
                                        rsm_last = Some(last.text());
                                    }
                                    
                                    // Get count
                                    if let Some(count) = set.get_child("count", "http://jabber.org/protocol/rsm") {
                                        if let Ok(count_val) = count.text().parse::<usize>() {
                                            rsm_count = Some(count_val);
                                        }
                                    }
                                }
                            }
                            
                            continue;
                        } else if stanza.attr("type") == Some("error") {
                            // Check for error information
                            if let Some(error) = stanza.get_child("error", "") {
                                let error_type = error.attr("type").unwrap_or("unknown");
                                let mut error_msg = format!("MAM query failed with error type: {}", error_type);
                                
                                // Try to get error text
                                if let Some(text) = error.get_child("text", "urn:ietf:params:xml:ns:xmpp-stanzas") {
                                    error_msg = format!("{} - {}", error_msg, text.text());
                                }
                                
                                error!("{}", error_msg);
                                return Err(anyhow!(error_msg));
                            }
                            result_complete = true; // Even with an error, consider the query complete
                        }
                        continue;
                    }
                    
                    // Process MAM message results
                    if stanza.name() == "message" {
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if result.attr("queryid") == Some(&query_id) {
                                // Store the result ID for pagination
                                let _result_id = result.attr("id").map(|s| s.to_string());
                                
                                if let Some(forwarded) = result.get_child("forwarded", "urn:xmpp:forward:0") {
                                    // Extract the original message and delay info
                                    if let Some(message_stanza) = forwarded.get_child("message", "jabber:client") {
                                        if let Some(delay) = forwarded.get_child("delay", "urn:xmpp:delay") {
                                            // Process and extract the message content as before
                                            let from = message_stanza.attr("from").map(|s| s.to_string());
                                            let to = message_stanza.attr("to").map(|s| s.to_string());
                                            
                                            // Process timestamp from delay element
                                            let timestamp_str = delay.attr("stamp").unwrap_or("");
                                            let timestamp = if !timestamp_str.is_empty() {
                                                match chrono::DateTime::parse_from_rfc3339(timestamp_str) {
                                                    Ok(dt) => dt.timestamp() as u64,
                                                    Err(_) => chrono::Utc::now().timestamp() as u64
                                                }
                                            } else {
                                                chrono::Utc::now().timestamp() as u64
                                            };
                                            
                                            let message_id = message_stanza.attr("id")
                                                .map(|s| s.to_string())
                                                .unwrap_or_else(|| Uuid::new_v4().to_string());
                                            
                                            // Only create a message if we have the required fields
                                            if let (Some(from), Some(to)) = (from.clone(), to.clone()) {
                                                // Determine message direction (from me or to me)
                                                let (sender_id, recipient_id) = if from.contains(&self.jid) {
                                                    ("me".to_string(), to)
                                                } else {
                                                    (from.clone(), "me".to_string())
                                                };
                                                
                                                // Check if this is an OMEMO encrypted message (try both namespaces)
                                                let has_omemo_v1 = message_stanza.has_child("encrypted", custom_ns::OMEMO);
                                                let has_omemo_axolotl = message_stanza.has_child("encrypted", custom_ns::OMEMO_V1);
                                                if has_omemo_v1 || has_omemo_axolotl {
                                                    info!("Found OMEMO encrypted message in archive from {} (v1={}, axolotl={})", sender_id, has_omemo_v1, has_omemo_axolotl);
                                                    
                                                    // Try to decrypt the message if we have an OMEMO manager
                                                    if let Some(_omemo_manager) = &self.omemo_manager {
                                                        // This is similar to how we process live encrypted messages
                                                        match Self::decrypt_archived_omemo_message(&message_stanza, &from).await {
                                                            Ok(Some(decrypted_content)) => {
                                                                // Successfully decrypted
                                                                let message = Message {
                                                                    id: message_id,
                                                                    sender_id,
                                                                    recipient_id,
                                                                    content: decrypted_content,
                                                                    timestamp,
                                                                    delivery_status: DeliveryStatus::Delivered,
                                                                };
                                                                archived_messages.push(message);
                                                                continue;
                                                            },
                                                            Ok(None) => {
                                                                //debug!("No encrypted content found in message from archive");
                                                            },
                                                            Err(e) => {
                                                                warn!("Failed to decrypt archived message: {}", e);
                                                                
                                                                // Add a message with a note that decryption failed
                                                                let message = Message {
                                                                    id: message_id,
                                                                    sender_id,
                                                                    recipient_id,
                                                                    content: format!("[Encrypted message - couldn't decrypt: {}]", e),
                                                                    timestamp,
                                                                    delivery_status: DeliveryStatus::Delivered,
                                                                };
                                                                archived_messages.push(message);
                                                                continue;
                                                            }
                                                        }
                                                    } else {
                                                        //debug!("OMEMO manager not available for decrypting archived message");
                                                        
                                                        // Add an informative message that OMEMO isn't initialized
                                                        let message = Message {
                                                            id: message_id,
                                                            sender_id,
                                                            recipient_id,
                                                            content: "[Encrypted message - OMEMO not initialized]".to_string(),
                                                            timestamp,
                                                            delivery_status: DeliveryStatus::Delivered,
                                                        };
                                                        archived_messages.push(message);
                                                        continue;
                                                    }
                                                }
                                                
                                                // Fall back to regular body content for non-OMEMO or failed decryption
                                                if let Some(body) = message_stanza.get_child("body", "jabber:client").map(|b| b.text()) {
                                                    if !body.is_empty() {
                                                        let message = Message {
                                                            id: message_id,
                                                            sender_id,
                                                            recipient_id,
                                                            content: body,
                                                            timestamp,
                                                            delivery_status: DeliveryStatus::Delivered,
                                                        };
                                                        
                                                        archived_messages.push(message);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                Some(tokio_xmpp::Event::Disconnected(err)) => {
                    return Err(anyhow!("Disconnected while retrieving message history: {:?}", err));
                },
                Some(_) => {}, // Ignore other events
                None => {
                    error!("Stream ended while waiting for MAM response");
                    break;
                }
            }
            
            // Sleep a little between checks to avoid tight loop
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        if !result_complete {
            warn!("MAM query timed out before completion - returning partial results");
        }
        
        info!("Retrieved {} archived messages", archived_messages.len());
        
        // Sort messages by timestamp from oldest to newest
        archived_messages.sort_by(|a: &Message, b: &Message| a.timestamp.cmp(&b.timestamp));
        
        // Create the result structure with pagination info
        let result = MAMQueryResult {
            messages: archived_messages,
            complete: result_complete,
            rsm_first,
            rsm_last,
            rsm_count,
        };
        
        Ok(result)
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
        //debug!("Checking if message history exists for {}", jid);
        
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        
        // Generate a unique ID for this MAM query
        let query_id = Uuid::new_v4().to_string();
        
        // Build query element with minimal parameters for a quick check
        let mut query = xmpp_parsers::Element::builder("query", custom_ns::MAM)
            .attr("queryid", &query_id);
        
        // Create the data form
        let mut x_data = xmpp_parsers::Element::builder("x", "jabber:x:data")
            .attr("type", "submit");

        // Add form type field - properly namespaced
        let mut form_type_field = xmpp_parsers::Element::builder("field", "jabber:x:data")
            .attr("var", "FORM_TYPE")
            .attr("type", "hidden")
            .build();

        let mut value_element = xmpp_parsers::Element::builder("value", "jabber:x:data").build();
        value_element.append_text_node("urn:xmpp:mam:2");
        form_type_field.append_child(value_element);
        
        x_data = x_data.append(form_type_field);
        
        // Add "with" filter - properly namespaced
        let mut with_field = xmpp_parsers::Element::builder("field", "jabber:x:data")
            .attr("var", "with")
            .build();
            
        let mut with_value = xmpp_parsers::Element::builder("value", "jabber:x:data").build();
        with_value.append_text_node(jid);
        with_field.append_child(with_value);
            
        x_data = x_data.append(with_field);
        
        // Add a very small limit for the check (XEP-0059 Result Set Management)
        let mut set = xmpp_parsers::Element::builder("set", "http://jabber.org/protocol/rsm").build();
        let mut max_element = xmpp_parsers::Element::builder("max", "http://jabber.org/protocol/rsm").build();
        max_element.append_text_node(&limit.to_string());
        set.append_child(max_element);
        
        query = query.append(set);
        
        // Create the full query element
        let query_element = query
            .append(x_data.build())
            .build();
        
        // Create the IQ stanza
        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &query_id)
            .append(query_element)
            .build();
        
        //debug!("Sending lightweight MAM check query with ID: {}", query_id);
        
        // Use a short-lived lock to send the query
        let send_result = {
            let lock_timeout = Duration::from_secs(2);
            match tokio::time::timeout(lock_timeout, client.lock()).await {
                Ok(mut client_guard) => {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        client_guard.send_stanza(iq)
                    ).await
                },
                Err(_) => return Err(anyhow!("Timed out acquiring client lock for history check")),
            }
        };
        
        // Check if send was successful
        match send_result {
            Ok(Ok(_)) => {
                //debug!("MAM history check query sent successfully, waiting for responses");
            },
            Ok(Err(e)) => {
                error!("Failed to send MAM history check query: {}", e);
                return Err(anyhow!("Failed to send MAM history check query: {}", e));
            },
            Err(_) => {
                error!("Timed out sending MAM history check query");
                return Err(anyhow!("Timed out sending MAM history check query"));
            }
        }
        
        // Process responses with a short timeout
        let response_timeout = Duration::from_secs(5); // Short timeout for quick check
        let start_time = tokio::time::Instant::now();
        let mut has_messages = false;
        let mut query_complete = false;
        
        while !query_complete && tokio::time::Instant::now() - start_time < response_timeout {
            // Acquire lock only for short durations to check for events
            let event = {
                let lock_result = tokio::time::timeout(
                    Duration::from_millis(500),
                    client.lock()
                ).await;
                
                match lock_result {
                    Ok(mut client_guard) => {
                        match tokio::time::timeout(
                            Duration::from_millis(500),
                            client_guard.next()
                        ).await {
                            Ok(event) => event,
                            Err(_) => {
                                // Timeout just for this check, we'll retry
                                None
                            }
                        }
                    },
                    Err(_) => {
                        // Failed to acquire lock, wait briefly and retry
                        //debug!("Failed to acquire lock for MAM response check, retrying");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            };
            
            // Process the event if we got one
            match event {
                Some(tokio_xmpp::Event::Stanza(stanza)) => {
                    // IQ result indicates the end of the archive query
                    if stanza.name() == "iq" && stanza.attr("id") == Some(&query_id) {
                        if stanza.attr("type") == Some("result") {
                            query_complete = true;
                        } else if stanza.attr("type") == Some("error") {
                            // Check for error information
                            if let Some(error) = stanza.get_child("error", "") {
                                let error_type = error.attr("type").unwrap_or("unknown");
                                error!("MAM history check query returned error: {}", error_type);
                                
                                // Try to get error text
                                if let Some(text) = error.get_child("text", "urn:ietf:params:xml:ns:xmpp-stanzas") {
                                    error!("Error details: {}", text.text());
                                }
                            } else {
                                error!("MAM history check query returned unknown error");
                            }
                            query_complete = true;
                        }
                        continue;
                    }
                    
                    // If we receive any MAM message, we have history
                    if stanza.name() == "message" {
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if result.attr("queryid") == Some(&query_id) {
                                //debug!("Found message history for {}", jid);
                                has_messages = true;
                                // We can exit early since we just need to know if any history exists
                                break;
                            }
                        }
                    }
                },
                Some(tokio_xmpp::Event::Disconnected(err)) => {
                    return Err(anyhow!("Disconnected while checking for message history: {:?}", err));
                },
                Some(_) => {}, // Ignore other events
                None => {
                    //debug!("No events while checking for message history");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
            
            // Small sleep to avoid tight loop
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        
        if !query_complete {
            //debug!("History check query timed out, but we have sufficient results");
        }
        
        Ok(has_messages)
    }

    // Helper method for decrypting archived OMEMO messages
    async fn decrypt_archived_omemo_message(
        message_stanza: &xmpp_parsers::Element,
        sender_jid: &str,
    ) -> Result<Option<String>> {
        //debug!("Attempting to decrypt archived OMEMO message from {}", sender_jid);
        
        // Extract the OMEMO encrypted element (try both namespaces)
        let encrypted = match message_stanza.get_child("encrypted", custom_ns::OMEMO)
            .or_else(|| message_stanza.get_child("encrypted", custom_ns::OMEMO_V1)) {
            Some(e) => e,
            None => return Ok(None),  // No encrypted element found
        };
        
        // Get the header element which contains keys and other metadata (try both namespaces)
        let header = match encrypted.get_child("header", custom_ns::OMEMO)
            .or_else(|| encrypted.get_child("header", custom_ns::OMEMO_V1)) {
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
        
        // Retrieve our OMEMO manager instance
        let omemo_manager = match super::XMPPClient::get_global_omemo_manager().await {
            Some(m) => m,
            None => {
                warn!("OMEMO manager not initialized");
                return Err(anyhow!("OMEMO manager not initialized"));
            }
        };
        
        // Get IV (initialization vector) - try with OMEMO namespace first, then with no namespace
        let iv = match header.get_child("iv", custom_ns::OMEMO)
            .or_else(|| header.get_child("iv", custom_ns::OMEMO_V1))
            .or_else(|| header.get_child("iv", "")) {
            Some(iv_elem) => {
                let iv_base64 = iv_elem.text();
                match base64::engine::general_purpose::STANDARD.decode(iv_base64) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode IV: {}", e);
                        return Err(anyhow!("Failed to decode IV: {}", e));
                    }
                }
            },
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
        
        // Look for a key element intended for our device
        let mut key_data = None;
        
        // Try to find a key element for our device
        // The xmpp_parsers::Element doesn't have a get_children method, so we need to manually
        // iterate through all children and filter for key elements
        let mut found_key = false;
        for child in header.children() {
            if child.name() == "key" && (child.ns() == custom_ns::OMEMO || child.ns() == custom_ns::OMEMO_V1 || child.ns() == "") {
                if let Some(rid) = child.attr("rid") {
                    match rid.parse::<u32>() {
                        Ok(device_id) if device_id == own_device_id => {
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
                                },
                                Err(e) => {
                                    warn!("Failed to decode key data: {}", e);
                                    continue;
                                }
                            }
                        },
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
        let payload = match encrypted.get_child("payload", custom_ns::OMEMO)
            .or_else(|| encrypted.get_child("payload", custom_ns::OMEMO_V1))
            .or_else(|| encrypted.get_child("payload", "")) {
            Some(payload_elem) => {
                let payload_base64 = payload_elem.text();
                match base64::engine::general_purpose::STANDARD.decode(payload_base64) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode payload: {}", e);
                        return Err(anyhow!("Failed to decode payload: {}", e));
                    }
                }
            },
            None => {
                error!("Missing payload in OMEMO message");
                return Err(anyhow!("Missing payload in OMEMO message"));
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
            match manager.decrypt_message(
                bare_sender_jid,
                sender_device_id,
                &crate::omemo::protocol::OmemoMessage {
                    sender_device_id,
                    ratchet_key: vec![], // This will be handled by the session
                    previous_counter: 0,  // This will be handled by the session
                    counter: 0,           // This will be handled by the session
                    ciphertext: payload,
                    mac: crypto::sha256_hash(&key)[..16].to_vec(),
                    iv,
                    encrypted_keys: {
                        let mut keys = std::collections::HashMap::new();
                        keys.insert(own_device_id, key);
                        keys
                    },
                }
            ).await {
                Ok(content) => content,
                Err(e) => {
                    error!("Failed to decrypt OMEMO message: {}", e);
                    return Err(anyhow!("Failed to decrypt OMEMO message: {}", e));
                }
            }
        };
        
        //debug!("Successfully decrypted archived OMEMO message");
        Ok(Some(decrypted_content))
    }

    // Use the implementation from mod.rs instead of duplicating it here

    // Helper method to check if OMEMO is fully initialized
    pub async fn is_omemo_fully_initialized() -> bool {
        if let Some(omemo_manager) = super::XMPPClient::get_global_omemo_manager().await {
            let manager = omemo_manager.lock().await;
            // Consider OMEMO fully initialized if we have a device ID and bundle published
            if manager.get_device_id() > 0 {
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
                    content: format!("Loading message history ({}/{} messages)...", 
                        current_result.messages.len(), count),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    delivery_status: DeliveryStatus::Delivered,
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
                        
                        info!("Retrieved page {} with {} additional messages for {}", 
                             page_count + 1, messages_count, jid);
                        
                        // Update progress notification
                        if let Some(count) = result.rsm_count {
                            let loaded_so_far = current_result.messages.len() + messages_count;
                            let notification = crate::models::Message {
                                id: Uuid::new_v4().to_string(),
                                sender_id: "[System]".to_string(),
                                recipient_id: jid.to_string(),
                                content: format!("Loading message history ({}/{} messages)...", 
                                    loaded_so_far, count),
                                timestamp: chrono::Utc::now().timestamp() as u64,
                                delivery_status: DeliveryStatus::Delivered,
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
                    },
                    Err(e) => {
                        error!("Error retrieving additional message history for {}: {}", jid, e);
                        
                        // Notify the user about the error
                        let error_notification = crate::models::Message {
                            id: Uuid::new_v4().to_string(),
                            sender_id: "[System]".to_string(),
                            recipient_id: jid.to_string(),
                            content: format!("Failed to retrieve full message history: {}", e),
                            timestamp: chrono::Utc::now().timestamp() as u64,
                            delivery_status: DeliveryStatus::Delivered,
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
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
        };
        
        if let Err(e) = message_tx.send(completion_notification).await {
            error!("Failed to send history completion notification: {}", e);
        }
        
        info!("Completed background history load for {} ({} pages retrieved)", jid, page_count);
        Ok(())
    }
}
