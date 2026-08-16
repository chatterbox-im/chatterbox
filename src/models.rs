use chrono::Utc;
use uuid::Uuid;

use crate::jid::BareJid;

/// Whether a message was sent, received, or is a system notification.
/// Replaces the `sender_id == "me"` / `"system"` sentinel pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Outgoing { to: BareJid },
    Incoming { from: BareJid },
    System   { about: BareJid },
}

impl Direction {
    /// The conversation (contact) this message belongs to. Total function — no sentinels.
    pub fn conversation(&self) -> &BareJid {
        match self {
            Self::Outgoing { to }    => to,
            Self::Incoming { from }  => from,
            Self::System   { about } => about,
        }
    }

    /// Reconstruct a Direction from the SQL storage representation.
    /// `contact_jid` is the conversation column; `sender_id`/`recipient_id` are the raw columns.
    pub fn from_sql(sender_id: &str, _recipient_id: &str, contact_jid: &str) -> Self {
        let contact = BareJid::parse(contact_jid).expect("expected valid JID");
        match sender_id {
            "me"     => Direction::Outgoing { to: contact },
            "system" => Direction::System   { about: contact },
            _        => Direction::Incoming { from: BareJid::parse(sender_id).expect("expected valid JID") },
        }
    }
}

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
            Self::Available {
                jid,
                show,
                idle_since,
            } => {
                let is_idle = idle_since.map_or(false, |t| {
                    chrono::Utc::now() - t > chrono::Duration::minutes(5)
                });
                let status = if is_idle {
                    ContactStatus::Away
                } else {
                    match show {
                        Some(ShowStatus::Away | ShowStatus::Xa | ShowStatus::Dnd) => {
                            ContactStatus::Away
                        }
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
    pub timestamp: crate::units::Millis,
    pub delivery_status: DeliveryStatus,
    pub encrypted: bool,
    /// Typed direction; derived from `sender_id`/`recipient_id` at construction.
    pub direction: Direction,
}

impl Message {
    /// Convenience: the JID of the conversation this message belongs to.
    pub fn contact_jid(&self) -> &BareJid {
        self.direction.conversation()
    }

    /// Outgoing encrypted message (OMEMO). Use this for all sent OMEMO messages.
    pub fn outgoing_encrypted(
        id: impl Into<String>,
        recipient: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        let recipient = recipient.into();
        let direction = Direction::Outgoing { to: BareJid::parse(&recipient).expect("expected valid JID") };
        Self {
            id: id.into(),
            sender_id: "me".to_string(),
            recipient_id: recipient,
            content: content.into(),
            timestamp: Utc::now().timestamp_millis().into(),
            delivery_status: DeliveryStatus::Sent,
            encrypted: true,
            direction,
        }
    }

    /// Outgoing plaintext message. Use this for unencrypted sends.
    pub fn outgoing_plaintext(
        id: impl Into<String>,
        recipient: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        let recipient = recipient.into();
        let direction = Direction::Outgoing { to: BareJid::parse(&recipient).expect("expected valid JID") };
        Self {
            id: id.into(),
            sender_id: "me".to_string(),
            recipient_id: recipient,
            content: content.into(),
            timestamp: Utc::now().timestamp_millis().into(),
            delivery_status: DeliveryStatus::Sent,
            encrypted: false,
            direction,
        }
    }

    /// Incoming encrypted message (OMEMO). Use for received OMEMO messages.
    pub fn incoming_encrypted(
        id: impl Into<String>,
        sender: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        let sender = sender.into();
        let direction = Direction::Incoming { from: BareJid::parse(&sender).expect("expected valid JID") };
        Self {
            id: id.into(),
            sender_id: sender,
            recipient_id: "me".to_string(),
            content: content.into(),
            timestamp: Utc::now().timestamp_millis().into(),
            delivery_status: DeliveryStatus::Delivered,
            encrypted: true,
            direction,
        }
    }

    /// Incoming plaintext message. Use for received unencrypted messages.
    pub fn incoming_plaintext(
        id: impl Into<String>,
        sender: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        let sender = sender.into();
        let direction = Direction::Incoming { from: BareJid::parse(&sender).expect("expected valid JID") };
        Self {
            id: id.into(),
            sender_id: sender,
            recipient_id: "me".to_string(),
            content: content.into(),
            timestamp: Utc::now().timestamp_millis().into(),
            delivery_status: DeliveryStatus::Delivered,
            encrypted: false,
            direction,
        }
    }

    /// System/notification message. Never encrypted.
    pub fn system(recipient: impl Into<String>, content: impl Into<String>) -> Self {
        let recipient = recipient.into();
        let about = BareJid::try_from(recipient.clone())
            .unwrap_or_else(|_| BareJid::try_from("system@localhost").unwrap());
        let direction = Direction::System { about };
        Self {
            id: Uuid::new_v4().to_string(),
            sender_id: "system".to_string(),
            recipient_id: recipient,
            content: content.into(),
            timestamp: Utc::now().timestamp_millis().into(),
            delivery_status: DeliveryStatus::Delivered,
            encrypted: false,
            direction,
        }
    }

    /// Delivery status update message (echoed back to UI to update status display).
    pub fn delivery_update(
        id: impl Into<String>,
        recipient: impl Into<String>,
        content: impl Into<String>,
        status: DeliveryStatus,
        encrypted: bool,
    ) -> Self {
        let recipient = recipient.into();
        let direction = Direction::Outgoing { to: BareJid::parse(&recipient).expect("expected valid JID") };
        Self {
            id: id.into(),
            sender_id: "me".to_string(),
            recipient_id: recipient,
            content: content.into(),
            timestamp: Utc::now().timestamp_millis().into(),
            delivery_status: status,
            encrypted,
            direction,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub id: String,
    pub to: String,
    pub content: String,
    pub timestamp: crate::units::Millis,
    pub status: DeliveryStatus,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DeliveryStatus {
    Unknown = 0,
    Sending = 1,
    Sent = 2,
    Stored = 3,
    Delivered = 4,
    Read = 5,
    Failed = 6,
}

/// Events sent from the XMPP layer to the UI event loop.
/// Replaces the `Message`-as-RPC pattern: `Chat` carries real messages,
/// transient UI status uses `Toast`, and key-verification prompts travel as a
/// typed variant instead of a sentinel string.
#[derive(Debug, Clone)]
pub enum AppEvent {
    Chat(Message),
    Toast(String),
    KeyVerifyRequest {
        sender: String,
        fingerprint: String,
        device_id: Option<u32>,
    },
}
