// XEP-0184: Message Delivery Receipts Implementation
// https://xmpp.org/extensions/xep-0184.html

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use xmpp_parsers::message::Message as XMPPMessage;
use xmpp_parsers::minidom::Element;

use super::custom_ns;
use super::transport::{self, StanzaTx};
use super::PendingMessage;
use crate::models::{DeliveryStatus, Message};

/// Handle receipt notification in an incoming message
pub async fn handle_receipt(
    stanza: &Element,
    pending_receipts: &Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
    msg_tx: &tokio::sync::mpsc::Sender<Message>,
) -> Result<()> {
    // Check if this is a receipt (XEP-0184)
    if let Some(received) = stanza.get_child("received", custom_ns::RECEIPTS) {
        let from = stanza.attr("from").map(|s| s.to_string());

        // Extract the message ID that this receipt is for
        if let Some(receipt_id) = received.attr("id") {
            debug!(
                "Received delivery receipt from {:?} for message ID: {}",
                from, receipt_id
            );

            // Process the receipt
            let pending_clone = pending_receipts.clone();
            let msg_tx_clone = msg_tx.clone();
            let receipt_id = receipt_id.to_string();

            // Process receipt in a separate task
            tokio::spawn(async move {
                super::XMPPClient::process_receipt(msg_tx_clone, pending_clone, from, &receipt_id)
                    .await;
            });

            return Ok(());
        }
    }

    // Not a receipt or missing ID
    Ok(())
}

/// Send a receipt for a received message
pub fn send_receipt(stanza_tx: &StanzaTx, from: &str, id: &str) -> Result<()> {
    debug!("Sending receipt for message {} to {}", id, from);

    // Create receipt stanza
    let receipt = Element::builder("message", "jabber:client")
        .attr("to".try_into().unwrap(), from)
        .attr("id".try_into().unwrap(), &Uuid::new_v4().to_string())
        .append(
            Element::builder("received", custom_ns::RECEIPTS)
                .attr("id".try_into().unwrap(), id)
                .build(),
        )
        .build();

    transport::send_stanza(stanza_tx, receipt).map_err(|e| anyhow!("Failed to send receipt: {}", e))
}

/// Implementation of XEP-0184 Message Delivery Receipts
impl super::XMPPClient {
    /// Create an XMPP message with receipt request
    pub fn create_message(
        &self,
        recipient_jid: impl Into<String>,
        msg_id: String,
        content: &str,
    ) -> XMPPMessage {
        // First, check if we need to verify OMEMO keys for this recipient
        let recipient_str: String = recipient_jid.into();

        // Extract the bare JID (remove resource part) for OMEMO checks
        let bare_jid = recipient_str
            .parse::<xmpp_parsers::jid::Jid>()
            .map(|j| j.to_bare().to_string())
            .unwrap_or_else(|_| recipient_str.clone());

        // Schedule an OMEMO key check in the background
        let client_clone = self.clone();
        let recipient_bare = bare_jid.clone();
        tokio::spawn(async move {
            debug!(
                "Checking OMEMO keys before sending message to {}",
                recipient_bare
            );
            if let Err(e) = client_clone
                .check_omemo_keys_for_contact(&recipient_bare)
                .await
            {
                error!("Failed to check OMEMO keys for {}: {}", recipient_bare, e);
            }
        });

        // Continue with regular message creation
        let mut message = XMPPMessage::new(None);
        message.id = Some(xmpp_parsers::message::Id(msg_id));

        // Parse the string into a Jid
        let jid = match recipient_str.parse::<xmpp_parsers::jid::Jid>() {
            Ok(jid) => jid,
            Err(e) => {
                error!("Failed to parse JID '{}': {}", recipient_str, e);
                // Return a placeholder JID
                "unknown@example.com".parse().unwrap()
            }
        };

        message.to = Some(jid);
        message.type_ = xmpp_parsers::message::MessageType::Chat;
        message.bodies.insert(
            xmpp_parsers::message::Lang(String::new()),
            content.to_string(),
        );

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
        let stanza_tx = self.stanza_tx.as_ref().ok_or_else(|| {
            error!("XMPP client not initialized when trying to send message");
            anyhow::anyhow!("XMPP client not initialized")
        })?;
        let recipient_jid: xmpp_parsers::jid::BareJid = match recipient.parse() {
            Ok(jid) => jid,
            Err(e) => {
                error!("Invalid recipient JID '{}': {}", recipient, e);
                return Err(anyhow::anyhow!("Invalid recipient JID: {}", e));
            }
        };

        let msg_id = Uuid::new_v4().to_string();
        info!(
            "Preparing to send message to {} with ID: {}",
            recipient, msg_id
        );

        // Create message
        let message = self.create_message(recipient_jid.to_string(), msg_id.clone(), content);

        // Add to pending receipts before sending
        {
            let mut pending_receipts = self.pending_receipts.lock().await;
            pending_receipts.insert(
                msg_id.clone(),
                PendingMessage {
                    id: msg_id.clone(),
                    to: recipient.to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis().into(),
                    status: DeliveryStatus::Sending,
                    content: content.to_string(),
                },
            );
        }

        // Create and immediately send UI message to show pending message
        let mut ui_message =
            Message::outgoing_plaintext(msg_id.clone(), recipient.to_string(), content.to_string());
        ui_message.delivery_status = DeliveryStatus::Sending;

        // Send to UI first
        if let Err(e) = self.msg_tx.send(ui_message).await {
            error!("Failed to send message to UI: {}", e);
        }

        // Send via transport channel
        match transport::send_stanza(stanza_tx, message.into()) {
            Ok(_) => {
                info!("Message sent successfully to {}", recipient);
                self.update_message_status(&msg_id, DeliveryStatus::Sent)
                    .await;
                Ok(())
            }
            Err(e) => {
                error!("Failed to send message: {}", e);
                self.update_message_status(&msg_id, DeliveryStatus::Failed)
                    .await;
                Err(anyhow::anyhow!("Failed to send message: {}", e))
            }
        }
    }

    /// Send an XEP-0184 receipt acknowledgment
    pub fn send_receipt_via(stanza_tx: &StanzaTx, to: Option<String>, msg_id: String) {
        if to.is_none() {
            error!("Cannot send receipt: no recipient specified");
            return;
        }

        // Create receipt message
        let mut receipt = XMPPMessage::new(None);

        // Convert String to Jid for the to field
        let jid_to = to.map(|to_str| match to_str.parse::<xmpp_parsers::jid::Jid>() {
            Ok(jid) => jid,
            Err(e) => {
                error!("Failed to parse JID for receipt: {}", e);
                "unknown@example.com".parse().unwrap()
            }
        });

        receipt.to = jid_to;
        receipt.id = Some(xmpp_parsers::message::Id(Uuid::new_v4().to_string()));

        // Add received element with id attribute
        let received = Element::builder("received", custom_ns::RECEIPTS)
            .attr("id".try_into().unwrap(), &msg_id)
            .build();
        receipt.payloads.push(received);

        // Send receipt
        debug!("Sending message receipt for ID: {}", msg_id);
        match transport::send_stanza(stanza_tx, receipt.into()) {
            Ok(_) => debug!("Sent message receipt successfully"),
            Err(e) => error!("Failed to send message receipt: {}", e),
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
            )
            .await;
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
                info!(
                    "Updating message {} status from {:?} to {:?}",
                    msg_id, pending.status, new_status
                );
                pending.status = new_status.clone();
                pending_message = Some(pending.clone());
            } else {
                debug!("Tried to update status for unknown message ID: {}", msg_id);
                return;
            }

            // Remove from tracking once delivered (no longer pending)
            if new_status == DeliveryStatus::Delivered || new_status == DeliveryStatus::Read {
                pending_receipts_lock.remove(msg_id);
            }

            // Evict stale entries older than 1 hour to prevent unbounded growth
            let now = crate::units::Millis::now();
            if pending_receipts_lock.len() > 100 {
                pending_receipts_lock.retain(|_, v| now.get().saturating_sub(v.timestamp.get()) < 3_600_000);
            }
        }

        // If we found and updated the message, send an update to the UI
        if let Some(pending) = pending_message {
            // Create a new message with the updated status for the UI
            let ui_message = Message::delivery_update(
                pending.id.clone(),
                pending.to.clone(),
                pending.content.clone(),
                new_status,
                false,
            );

            // Send to UI
            match msg_tx.send(ui_message).await {
                Ok(_) => debug!("Sent message status update to UI from background handler"),
                Err(e) => error!(
                    "Failed to send message status update to UI from background handler: {}",
                    e
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DeliveryStatus;
    use std::collections::HashMap;

    fn make_receipt_stanza(from: &str, receipt_id: &str) -> Element {
        Element::builder("message", "jabber:client")
            .attr("from".try_into().unwrap(), from)
            .attr("to".try_into().unwrap(), "me@server.example")
            .append(
                Element::builder("received", custom_ns::RECEIPTS)
                    .attr("id".try_into().unwrap(), receipt_id)
                    .build(),
            )
            .build()
    }

    fn make_message_with_receipt_request(from: &str, id: &str) -> Element {
        Element::builder("message", "jabber:client")
            .attr("from".try_into().unwrap(), from)
            .attr("to".try_into().unwrap(), "me@server.example")
            .attr("id".try_into().unwrap(), id)
            .append(
                Element::builder("body", "jabber:client")
                    .append("Hello")
                    .build(),
            )
            .append(Element::builder("request", custom_ns::RECEIPTS).build())
            .build()
    }

    #[tokio::test]
    async fn test_handle_receipt_updates_pending() {
        let pending = Arc::new(TokioMutex::new(HashMap::new()));
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(10);

        // Insert a pending receipt
        {
            let mut p = pending.lock().await;
            p.insert(
                "msg-42".to_string(),
                PendingMessage {
                    id: "msg-42".to_string(),
                    to: "alice@example.com".to_string(),
                    content: "Hello".to_string(),
                    timestamp: crate::units::Millis(1700000000),
                    status: DeliveryStatus::Sending,
                },
            );
        }

        let stanza = make_receipt_stanza("alice@example.com/phone", "msg-42");
        let result = handle_receipt(&stanza, &pending, &msg_tx).await;
        assert!(result.is_ok());

        // Give the spawned task time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // The pending receipt should be removed
        let p = pending.lock().await;
        assert!(!p.contains_key("msg-42"));
    }

    #[tokio::test]
    async fn test_handle_receipt_no_id_is_noop() {
        let pending = Arc::new(TokioMutex::new(HashMap::new()));
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(10);

        // Receipt with no id attribute
        let stanza = Element::builder("message", "jabber:client")
            .attr("from".try_into().unwrap(), "alice@example.com")
            .append(Element::builder("received", custom_ns::RECEIPTS).build())
            .build();

        let result = handle_receipt(&stanza, &pending, &msg_tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_non_receipt_stanza_is_noop() {
        let pending = Arc::new(TokioMutex::new(HashMap::new()));
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(10);

        let stanza = Element::builder("message", "jabber:client")
            .attr("from".try_into().unwrap(), "bob@example.com")
            .append(
                Element::builder("body", "jabber:client")
                    .append("hi")
                    .build(),
            )
            .build();

        let result = handle_receipt(&stanza, &pending, &msg_tx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_receipt_request_element_present() {
        let stanza = make_message_with_receipt_request("alice@example.com", "msg-99");
        assert!(stanza.get_child("request", custom_ns::RECEIPTS).is_some());
        assert_eq!(stanza.attr("id").unwrap(), "msg-99");
    }
}
