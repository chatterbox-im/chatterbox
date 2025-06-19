// XEP-0085: Chat State Notifications Implementation
// https://xmpp.org/extensions/xep-0085.html

use anyhow::{anyhow, Result};
use log::{debug, error};
use tokio::time::Duration;
use uuid::Uuid;

use xmpp_parsers::message::{Message as XMPPMessage, MessageType};
use xmpp_parsers::Element;

use super::custom_ns;

// Definition of TypingStatus enum (copied from ui.rs to avoid import issues)
#[derive(Clone, Debug, PartialEq)]
pub enum TypingStatus {
    Active,    // User is actively participating in the chat
    Composing, // User is composing a message
    Paused,    // User started composing but paused
    Inactive,  // User has not been active recently
    Gone       // User has effectively ended their participation
}

/// Handle chat state notifications in incoming messages
pub fn handle_chat_state(stanza: &Element) -> Result<()> {
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
                if let Ok(typing_tx_guard) = super::TYPING_TX.lock() {
                    if let Some(typing_tx) = typing_tx_guard.as_ref() {
                        // Don't block on sending - use try_send to avoid deadlocks
                        match typing_tx.try_send((jid, status)) {
                            Ok(_) => debug!("Sent typing status to UI"),
                            Err(e) => debug!("Failed to send typing status to UI: {}", e),
                        }
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
    pub async fn send_chat_state(&self, recipient: &str, state: &TypingStatus) -> Result<()> {
        if self.client.is_none() {
            error!("XMPP client not initialized when trying to send chat state");
            return Err(anyhow!("XMPP client not initialized"));
        }

        // Create a clone of what we need for the background task
        let client_clone = self.client.as_ref().unwrap().clone();
        let recipient = recipient.to_string();
        let state = state.clone();
        
        // Use "fire and forget" approach - spawn a background task that won't block the UI
        tokio::spawn(async move {
            // Parse recipient 
            let recipient_jid = match recipient.parse() {
                Ok(jid) => jid,
                Err(e) => {
                    error!("Invalid recipient JID '{}': {}", recipient, e);
                    return;
                }
            };
            
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
            let state_element = xmpp_parsers::Element::builder(state_name, custom_ns::CHATSTATES).build();
            message.payloads.push(state_element);
            
            // Send the message
            match tokio::time::timeout(
                Duration::from_millis(500), // Very short timeout to avoid blocking
                async {
                    if let Ok(mut client_guard) = client_clone.try_lock() {
                        match client_guard.send_stanza(message.into()).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(anyhow!("Failed to send stanza: {}", e))
                        }
                    } else {
                        // Skip sending if we can't get lock immediately
                        debug!("Skipping chat state notification - client busy");
                        Ok(()) // Return success anyway to avoid blocking UI
                    }
                }
            ).await {
                Ok(Ok(_)) => {
                    debug!("Sent {} chat state to {}", state_name, recipient);
                },
                Ok(Err(e)) => {
                    debug!("Failed to send chat state: {}", e);
                },
                Err(_) => {
                    debug!("Timed out sending chat state");
                }
            }
        });
        
        // Return success immediately to avoid blocking the UI
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