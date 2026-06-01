// XEP-0085: Chat State Notifications Implementation
// https://xmpp.org/extensions/xep-0085.html

use anyhow::{anyhow, Result};
use log::{debug, error};
use uuid::Uuid;

use xmpp_parsers::message::{Message as XMPPMessage, MessageType};
use xmpp_parsers::Element;

use super::custom_ns;
use super::transport::{self};

// Definition of TypingStatus enum (copied from ui.rs to avoid import issues)
#[derive(Clone, Debug, PartialEq)]
pub enum TypingStatus {
    Active,    // User is actively participating in the chat
    Composing, // User is composing a message
    Paused,    // User started composing but paused
    Inactive,  // User has not been active recently
    Gone,      // User has effectively ended their participation
}

/// Handle chat state notifications in incoming messages.
/// `typing_tx` is the channel sender for forwarding typing status to the UI.
pub fn handle_chat_state(
    stanza: &Element,
    typing_tx: Option<&tokio::sync::mpsc::Sender<(String, TypingStatus)>>,
) -> Result<()> {
    // Check the stanza for chat state elements
    let chat_states = ["active", "composing", "paused", "inactive", "gone"];

    // Get the from attribute
    let from = stanza.attr("from").map(|s| s.to_string());

    // Check for each possible chat state
    for state in chat_states.iter() {
        if stanza.has_child(state, custom_ns::CHATSTATES) {
            debug!("Received {} chat state from {:?}", state, from);

            // Since we can't use the async process_chat_state method directly in this synchronous function,
            // we'll manually convert the chat state to a typing status
            let typing_status = match *state {
                "active" => Some(TypingStatus::Active),
                "composing" => Some(TypingStatus::Composing),
                "paused" => Some(TypingStatus::Paused),
                "inactive" => Some(TypingStatus::Inactive),
                "gone" => Some(TypingStatus::Gone),
                _ => None,
            };

            if let (Some(jid), Some(status)) = (from.clone(), typing_status) {
                // Try to send the typing notification to the UI
                if let Some(tx) = typing_tx {
                    match tx.try_send((jid, status)) {
                        Ok(_) => debug!("Sent typing status to UI"),
                        Err(e) => debug!("Failed to send typing status to UI: {}", e),
                    }
                }
            }

            return Ok(());
        }
    }

    // No chat state found
    Ok(())
}

/// Implementation of XEP-0085 Chat State Notifications
impl super::XMPPClient {
    /// Send a chat state notification (XEP-0085)
    pub fn send_chat_state(&self, recipient: &str, state: &TypingStatus) -> Result<()> {
        let stanza_tx = self.stanza_tx.as_ref().ok_or_else(|| {
            error!("XMPP client not initialized when trying to send chat state");
            anyhow!("XMPP client not initialized")
        })?;

        // Parse recipient
        let recipient_jid: xmpp_parsers::Jid = recipient
            .parse()
            .map_err(|e| anyhow!("Invalid recipient JID '{}': {}", recipient, e))?;

        // Create chat state message
        let mut message = XMPPMessage::new(None);
        message.id = Some(Uuid::new_v4().to_string());
        message.to = Some(recipient_jid);
        message.type_ = MessageType::Chat;

        // Add appropriate chat state element based on the state
        let state_name = match state {
            TypingStatus::Active => "active",
            TypingStatus::Composing => "composing",
            TypingStatus::Paused => "paused",
            TypingStatus::Inactive => "inactive",
            TypingStatus::Gone => "gone",
        };

        // Add the chat state element to the message
        let state_element =
            xmpp_parsers::Element::builder(state_name, custom_ns::CHATSTATES).build();
        message.payloads.push(state_element);

        // Send via transport channel
        transport::send_stanza(stanza_tx, message.into())
            .map_err(|e| anyhow!("Failed to send chat state: {}", e))?;

        debug!("Sent {} chat state to {}", state_name, recipient);
        Ok(())
    }

    /// Process a received chat state notification from a contact
    pub async fn process_chat_state(
        from_jid: Option<String>,
        chat_state: &str,
    ) -> Option<(String, TypingStatus)> {
        // Extract the bare JID from the full JID
        let bare_jid = match from_jid {
            Some(jid) => jid,
            None => return None,
        };

        // Convert chat state string to TypingStatus enum
        let typing_status = match chat_state {
            "active" => TypingStatus::Active,
            "composing" => TypingStatus::Composing,
            "paused" => TypingStatus::Paused,
            "inactive" => TypingStatus::Inactive,
            "gone" => TypingStatus::Gone,
            _ => return None,
        };

        Some((bare_jid, typing_status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmpp_parsers::Element;

    fn make_message_with_state(from: &str, state: &str) -> Element {
        Element::builder("message", "jabber:client")
            .attr("from", from)
            .attr("to", "me@server.example")
            .attr("type", "chat")
            .append(Element::builder(state, super::custom_ns::CHATSTATES).build())
            .build()
    }

    #[test]
    fn test_handle_composing_state() {
        let stanza = make_message_with_state("alice@example.com/phone", "composing");
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let result = handle_chat_state(&stanza, Some(&tx));
        assert!(result.is_ok());
        let (jid, status) = rx.try_recv().unwrap();
        assert_eq!(jid, "alice@example.com/phone");
        assert_eq!(status, TypingStatus::Composing);
    }

    #[test]
    fn test_handle_active_state() {
        let stanza = make_message_with_state("bob@example.com/laptop", "active");
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let result = handle_chat_state(&stanza, Some(&tx));
        assert!(result.is_ok());
        let (_, status) = rx.try_recv().unwrap();
        assert_eq!(status, TypingStatus::Active);
    }

    #[test]
    fn test_handle_paused_state() {
        let stanza = make_message_with_state("bob@example.com", "paused");
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        handle_chat_state(&stanza, Some(&tx)).unwrap();
        let (_, status) = rx.try_recv().unwrap();
        assert_eq!(status, TypingStatus::Paused);
    }

    #[test]
    fn test_handle_gone_state() {
        let stanza = make_message_with_state("bob@example.com", "gone");
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        handle_chat_state(&stanza, Some(&tx)).unwrap();
        let (_, status) = rx.try_recv().unwrap();
        assert_eq!(status, TypingStatus::Gone);
    }

    #[test]
    fn test_no_chat_state_in_message() {
        let stanza = Element::builder("message", "jabber:client")
            .attr("from", "alice@example.com")
            .append(
                Element::builder("body", "jabber:client")
                    .append("hello")
                    .build(),
            )
            .build();
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        handle_chat_state(&stanza, Some(&tx)).unwrap();
        assert!(rx.try_recv().is_err()); // nothing sent
    }

    #[test]
    fn test_handle_chat_state_without_sender() {
        // No typing_tx provided — should not panic
        let stanza = make_message_with_state("alice@example.com", "composing");
        let result = handle_chat_state(&stanza, None);
        assert!(result.is_ok());
    }
}
