// XEP-0184: Message Delivery Receipts Implementation
// https://xmpp.org/extensions/xep-0184.html

use anyhow::{Result, anyhow};
use log::{debug, error, info};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::Duration;
use uuid::Uuid;

use tokio_xmpp::AsyncClient as XMPPAsyncClient;
use xmpp_parsers::message::Message as XMPPMessage;
use xmpp_parsers::Element;

use crate::models::{Message, DeliveryStatus};
use super::custom_ns;
use super::PendingMessage;

/// Handle receipt notification in an incoming message
pub async fn handle_receipt(
    stanza: &Element,
    pending_receipts: &Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
    msg_tx: &tokio::sync::mpsc::Sender<Message>
) -> Result<()> {
    // Check if this is a receipt (XEP-0184)
    if let Some(received) = stanza.get_child("received", custom_ns::RECEIPTS) {
        let from = stanza.attr("from").map(|s| s.to_string());
        
        // Extract the message ID that this receipt is for
        if let Some(receipt_id) = received.attr("id") {
            debug!("Received delivery receipt from {:?} for message ID: {}", from, receipt_id);
            
            // Process the receipt
            let pending_clone = pending_receipts.clone();
            let msg_tx_clone = msg_tx.clone();
            let receipt_id = receipt_id.to_string();
            
            // Process receipt in a separate task
            tokio::spawn(async move {
                super::XMPPClient::process_receipt(
                    msg_tx_clone,
                    pending_clone,
                    from,
                    &receipt_id,
                ).await;
            });
            
            return Ok(());
        }
    }
    
    // Not a receipt or missing ID
    Ok(())
}

/// Send a receipt for a received message
pub async fn send_receipt(
    client: &mut XMPPAsyncClient,
    from: &str,
    id: &str
) -> Result<()> {
    debug!("Sending receipt for message {} to {}", id, from);
    
    // Create receipt stanza
    let receipt = Element::builder("message", "jabber:client")
        .attr("to", from)
        .attr("id", &Uuid::new_v4().to_string())
        .append(
            Element::builder("received", custom_ns::RECEIPTS)
                .attr("id", id)
                .build()
        )
        .build();
    
    // Send the receipt
    match client.send_stanza(receipt).await {
        Ok(_) => {
            debug!("Successfully sent receipt for message {}", id);
            Ok(())
        },
        Err(e) => {
            error!("Failed to send receipt: {}", e);
            Err(anyhow!("Failed to send receipt: {}", e))
        }
    }
}

/// Implementation of XEP-0184 Message Delivery Receipts
impl super::XMPPClient {
    /// Create an XMPP message with receipt request
    pub fn create_message(&self, recipient_jid: impl Into<String>, msg_id: String, content: &str) -> XMPPMessage {
        // First, check if we need to verify OMEMO keys for this recipient
        let recipient_str = recipient_jid.into();
        
        // Extract the bare JID (remove resource part) for OMEMO checks
        let bare_jid = match recipient_str.parse::<xmpp_parsers::Jid>() {
            Ok(jid) => match jid {
                xmpp_parsers::Jid::Full(full) => {
                    let node = full.node.as_ref().map(|n| n.as_ref()).unwrap_or("");
                    let domain = full.domain.to_string();
                    format!("{}@{}", node, domain)
                },
                xmpp_parsers::Jid::Bare(bare) => bare.to_string(),
            },
            Err(e) => {
                error!("Failed to parse JID '{}': {}", recipient_str, e);
                "unknown@example.com".to_string()
            }
        };
        
        // Schedule an OMEMO key check in the background
        let client_clone = self.clone();
        let recipient_bare = bare_jid.clone();
        tokio::spawn(async move {
            debug!("Checking OMEMO keys before sending message to {}", recipient_bare);
            if let Err(e) = client_clone.check_omemo_keys_for_contact(&recipient_bare).await {
                error!("Failed to check OMEMO keys for {}: {}", recipient_bare, e);
            }
        });
        
        // Continue with regular message creation
        let mut message = XMPPMessage::new(None);
        message.id = Some(msg_id);
        
        // Parse the string into a Jid
        let jid = match recipient_str.parse::<xmpp_parsers::Jid>() {
            Ok(jid) => jid,
            Err(e) => {
                error!("Failed to parse JID '{}': {}", recipient_str, e);
                // Return a placeholder JID
                "unknown@example.com".parse().unwrap()
            }
        };
        
        message.to = Some(jid);
        message.type_ = xmpp_parsers::message::MessageType::Chat;
        message.bodies.insert(String::new(), xmpp_parsers::message::Body(content.to_string()));
        
        // Add XEP-0184 receipt request
        let receipt_request = Element::builder("request", custom_ns::RECEIPTS).build();
        message.payloads.push(receipt_request);
        
        // Add a hint for the server to store the message in the archive (XEP-0313)
        // This ensures the message will be available in history later
        let store_hint = Element::builder("store", custom_ns::HINTS).build();
        message.payloads.push(store_hint);
        
        message
    }

    /// Send a message to a recipient with delivery receipt support
    pub async fn send_message_with_receipt(&self, recipient: &str, content: &str) -> Result<()> {
        if self.client.is_none() {
            error!("XMPP client not initialized when trying to send message");
            return Err(anyhow::anyhow!("XMPP client not initialized"));
        }

        let client = self.client.as_ref().unwrap();
        let recipient_jid: xmpp_parsers::BareJid = match recipient.parse() {
            Ok(jid) => jid,
            Err(e) => {
                error!("Invalid recipient JID '{}': {}", recipient, e);
                return Err(anyhow::anyhow!("Invalid recipient JID: {}", e));
            }
        };
        
        let msg_id = Uuid::new_v4().to_string();
        info!("Preparing to send message to {} with ID: {}", recipient, msg_id);
        
        // Create message
        let message = self.create_message(recipient_jid.clone(), msg_id.clone(), content);
        
        // Add to pending receipts before sending
        {
            let mut pending_receipts = self.pending_receipts.lock().await;
            pending_receipts.insert(msg_id.clone(), PendingMessage {
                id: msg_id.clone(),
                to: recipient.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                status: DeliveryStatus::Sending,
                content: content.to_string(),
            });
        }
        
        // Create and immediately send UI message to show pending message
        let ui_message = Message {
            id: msg_id.clone(),
            sender_id: "me".to_string(),
            recipient_id: recipient.to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Sending,
        };
        
        // Send to UI first
        if let Err(e) = self.msg_tx.send(ui_message).await {
            error!("Failed to send message to UI: {}", e);
        }
        
        // Constants for retry logic - reduced to minimize race conditions
        const MAX_RETRIES: usize = 2;
        const TOTAL_TIMEOUT_SECS: u64 = 3;
        
        let total_timeout = tokio::time::Instant::now() + Duration::from_secs(TOTAL_TIMEOUT_SECS);
        
        // Quick check if client is accessible
        if !self.is_client_accessible() {
            error!("Client is not accessible - cannot send message");
            self.update_message_status(&msg_id, DeliveryStatus::Failed).await;
            return Err(anyhow::anyhow!("XMPP client is not accessible"));
        }
        
        for attempt in 1..=MAX_RETRIES {
            // Check if we've exceeded total timeout
            if tokio::time::Instant::now() > total_timeout {
                error!("Exceeded total timeout trying to send message");
                self.update_message_status(&msg_id, DeliveryStatus::Failed).await;
                return Err(anyhow::anyhow!("Timed out sending message"));
            }
            
            debug!("Sending message attempt {}/{}", attempt, MAX_RETRIES);
            
            // Try to send the message
            let result = match self.send_message_attempt(client.clone(), message.clone()).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Error during send attempt {}: {}", attempt, e);
                    continue;
                }
            };
            
            match result {
                Ok(_) => {
                    info!("Message sent successfully on attempt {}", attempt);
                    self.update_message_status(&msg_id, DeliveryStatus::Sent).await;
                    return Ok(());
                },
                Err(e) => {
                    error!("Failed to send message on attempt {}: {}", attempt, e);
                    
                    // Check if we should retry
                    if attempt < MAX_RETRIES {
                        if !self.prepare_for_retry(attempt).await {
                            error!("Cannot retry - client in bad state");
                            break;
                        }
                    }
                }
            }
        }
        
        // If we get here, all attempts failed
        error!("Failed to send message after {} attempts", MAX_RETRIES);
        self.update_message_status(&msg_id, DeliveryStatus::Failed).await;
        
        Err(anyhow::anyhow!("Failed to send message after {} attempts", MAX_RETRIES))
    }

    /// Send a single message attempt with timeout - simplified version to avoid race conditions
    async fn send_message_attempt(
        &self, 
        client: Arc<TokioMutex<XMPPAsyncClient>>,
        message: XMPPMessage
    ) -> Result<Result<(), anyhow::Error>> {
        // Use a shorter timeout for sending to fail faster
        const SEND_TIMEOUT_SECS: u64 = 2;
        
        // Convert the message to a stanza before acquiring the lock
        let stanza = message.into();
        
        // Send directly without spawning a task to avoid race conditions
        let send_future = async {
            let mut client_guard = client.lock().await;
            match client_guard.send_stanza(stanza).await {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("Failed to send stanza: {}", e))
            }
        };
        
        // Wait for the send operation to complete with timeout
        match tokio::time::timeout(
            Duration::from_secs(SEND_TIMEOUT_SECS),
            send_future
        ).await {
            Ok(result) => Ok(result),
            Err(_) => Err(anyhow::anyhow!("Timed out sending message")),
        }
    }

    /// Prepare for retry by validating connection and adding backoff
    async fn prepare_for_retry(&self, attempt: usize) -> bool {
        // Calculate backoff with jitter to prevent thundering herd
        let backoff_base = 500 * 2u64.pow(attempt as u32); 
        let jitter = rand::random::<u64>() % 500;
        let backoff = Duration::from_millis(backoff_base + jitter);
        
        info!("Retrying message send in {:?}...", backoff);
        
        // Before waiting, check if client is still accessible
        let pre_backoff_accessible = self.is_client_accessible();
        if !pre_backoff_accessible {
            error!("Client not accessible before backoff");
            return false;
        }
        
        // Wait for backoff period
        tokio::time::sleep(backoff).await;
        
        // Check if client is still accessible after backoff
        let client_accessible = self.is_client_accessible();
        if !client_accessible {
            error!("Client not accessible after backoff");
            return false;
        }
        
        true
    }

    /// Send an XEP-0184 receipt acknowledgment
    pub async fn send_receipt(client: Arc<TokioMutex<XMPPAsyncClient>>, to: Option<String>, msg_id: String) {
        if to.is_none() {
            error!("Cannot send receipt: no recipient specified");
            return;
        }
        
        // Create receipt message
        let mut receipt = XMPPMessage::new(None);
        
        // Convert String to Jid for the to field
        let jid_to = to.map(|to_str| {
            match to_str.parse::<xmpp_parsers::Jid>() {
                Ok(jid) => jid,
                Err(e) => {
                    error!("Failed to parse JID for receipt: {}", e);
                    // Return a placeholder JID in case of parsing error
                    "unknown@example.com".parse().unwrap()
                }
            }
        });
        
        receipt.to = jid_to;
        receipt.id = Some(Uuid::new_v4().to_string());
        
        // Add received element with id attribute
        let received = Element::builder("received", custom_ns::RECEIPTS)
            .attr("id", &msg_id)
            .build();
        receipt.payloads.push(received);
        
        // Send receipt
        debug!("Sending message receipt for ID: {}", msg_id);
        match tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(receipt.into()).await
            }
        ).await {
            Ok(Ok(_)) => debug!("Sent message receipt successfully"),
            Ok(Err(e)) => error!("Failed to send message receipt: {}", e),
            Err(_) => error!("Timed out sending message receipt"),
        }
    }

    /// Process a received delivery receipt
    pub async fn process_receipt(
        msg_tx: tokio::sync::mpsc::Sender<Message>,
        pending_receipts: Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
        _from: Option<String>,
        receipt_id: &str,
    ) {
        debug!("Processing receipt for message ID: {}", receipt_id);
        
        // First try direct match on message ID
        let mut found = false;
        {
            let pending_receipts_lock = pending_receipts.lock().await;
            if pending_receipts_lock.contains_key(receipt_id) {
                found = true;
            }
        }
        
        if found {
            // Update message status directly
            Self::update_tracked_message_status(
                pending_receipts,
                receipt_id,
                DeliveryStatus::Delivered,
                msg_tx,
            ).await;
            return;
        }
        
        // If not found by direct ID, we don't have enough context here
        // to do additional lookup, so just log the event
        debug!("Could not find message for receipt ID: {}", receipt_id);
    }


    /// Static helper to update message status from background handler
    pub async fn update_tracked_message_status(
        pending_receipts: Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
        msg_id: &str,
        new_status: DeliveryStatus,
        msg_tx: tokio::sync::mpsc::Sender<Message>,
    ) {
        // Update the status in our tracking map
        let pending_message;
        
        {
            let mut pending_receipts_lock = pending_receipts.lock().await;
            if let Some(pending) = pending_receipts_lock.get_mut(msg_id) {
                info!("Updating message {} status from {:?} to {:?}", msg_id, pending.status, new_status);
                pending.status = new_status.clone();
                pending_message = Some(pending.clone());
            } else {
                debug!("Tried to update status for unknown message ID: {}", msg_id);
                return;
            }
        }
        
        // If we found and updated the message, send an update to the UI
        if let Some(pending) = pending_message {
            // Create a new message with the updated status for the UI
            let ui_message = Message {
                id: pending.id.clone(),
                sender_id: "me".to_string(),
                recipient_id: pending.to.clone(),
                content: pending.content.clone(),
                timestamp: pending.timestamp,
                delivery_status: new_status,
            };
            
            // Send to UI
            match msg_tx.send(ui_message).await {
                Ok(_) => debug!("Sent message status update to UI from background handler"),
                Err(e) => error!("Failed to send message status update to UI from background handler: {}", e),
            }
        }
    }
}