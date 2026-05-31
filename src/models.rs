use chrono::Utc;
use uuid::Uuid;

pub struct Contact {
    pub id: String,
    pub name: String,
    pub status: ContactStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContactStatus {
    Online,
    Offline,
    Away,
}

/// Typed presence event that preserves the raw XMPP signal.
/// The UI layer decides how to render this — invalid mappings (e.g. subscription → Online)
/// become impossible because `Subscription` variants have no `ContactStatus` interpretation.
#[derive(Debug, Clone)]
pub enum PresenceEvent {
    Available {
        jid: String,
        show: Option<ShowStatus>,
        idle_since: Option<chrono::DateTime<chrono::Utc>>,
    },
    Unavailable {
        jid: String,
    },
    Subscription {
        jid: String,
        kind: SubscriptionKind,
    },
    Error {
        jid: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ShowStatus {
    Chat,
    Away,
    Xa,
    Dnd,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionKind {
    Subscribe,
    Subscribed,
    Unsubscribe,
    Unsubscribed,
}

impl PresenceEvent {
    /// Convert to a display status for the UI, if applicable.
    /// Returns `None` for events that should not update the contact list (subscriptions, errors).
    pub fn to_contact_status(&self) -> Option<(String, ContactStatus)> {
        match self {
            Self::Available { jid, show, idle_since } => {
                let is_idle = idle_since.map_or(false, |t| {
                    chrono::Utc::now() - t > chrono::Duration::minutes(5)
                });
                let status = if is_idle {
                    ContactStatus::Away
                } else {
                    match show {
                        Some(ShowStatus::Away | ShowStatus::Xa | ShowStatus::Dnd) => ContactStatus::Away,
                        _ => ContactStatus::Online,
                    }
                };
                Some((jid.clone(), status))
            }
            Self::Unavailable { jid } => Some((jid.clone(), ContactStatus::Offline)),
            Self::Subscription { .. } | Self::Error { .. } => None,
        }
    }

    /// Get the JID associated with this event
    pub fn jid(&self) -> &str {
        match self {
            Self::Available { jid, .. }
            | Self::Unavailable { jid }
            | Self::Subscription { jid, .. }
            | Self::Error { jid, .. } => jid,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub content: String,
    pub timestamp: u64,
    pub delivery_status: DeliveryStatus,
    pub encrypted: bool,
}

impl Message {
    /// Outgoing encrypted message (OMEMO). Use this for all sent OMEMO messages.
    pub fn outgoing_encrypted(id: impl Into<String>, recipient: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sender_id: "me".to_string(),
            recipient_id: recipient.into(),
            content: content.into(),
            timestamp: Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Sent,
            encrypted: true,
        }
    }

    /// Outgoing plaintext message. Use this for unencrypted sends.
    pub fn outgoing_plaintext(id: impl Into<String>, recipient: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sender_id: "me".to_string(),
            recipient_id: recipient.into(),
            content: content.into(),
            timestamp: Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Sent,
            encrypted: false,
        }
    }

    /// Incoming encrypted message (OMEMO). Use for received OMEMO messages.
    pub fn incoming_encrypted(id: impl Into<String>, sender: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sender_id: sender.into(),
            recipient_id: "me".to_string(),
            content: content.into(),
            timestamp: Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
            encrypted: true,
        }
    }

    /// Incoming plaintext message. Use for received unencrypted messages.
    pub fn incoming_plaintext(id: impl Into<String>, sender: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sender_id: sender.into(),
            recipient_id: "me".to_string(),
            content: content.into(),
            timestamp: Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
            encrypted: false,
        }
    }

    /// System/notification message. Never encrypted.
    pub fn system(recipient: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            sender_id: "system".to_string(),
            recipient_id: recipient.into(),
            content: content.into(),
            timestamp: Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
            encrypted: false,
        }
    }

    /// Delivery status update message (echoed back to UI to update status display).
    pub fn delivery_update(id: impl Into<String>, recipient: impl Into<String>, content: impl Into<String>, status: DeliveryStatus, encrypted: bool) -> Self {
        Self {
            id: id.into(),
            sender_id: "me".to_string(),
            recipient_id: recipient.into(),
            content: content.into(),
            timestamp: Utc::now().timestamp() as u64,
            delivery_status: status,
            encrypted,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub id: String,
    pub to: String,
    pub content: String,
    pub timestamp: u64,
    pub status: DeliveryStatus,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DeliveryStatus {
    Unknown = 0,   // Default/uncertain status
    Sending = 1,   // Message is being sent
    Sent = 2,      // Successfully sent to server
    Stored = 3,    // Stored on server (offline message)
    Delivered = 4, // Delivered to recipient's device 
    Read = 5,      // Read by recipient
    Failed = 6,    // Failed to send
}