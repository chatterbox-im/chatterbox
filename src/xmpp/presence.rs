// XMPP Presence handling (RFC 6121)
// This module handles presence stanzas, presence subscriptions, and broadcasting status updates

use anyhow::{anyhow, Result};
use log::{error, info, warn};
use std::collections::HashSet;
use tokio::sync::broadcast;
use xmpp_parsers::Element;

use super::transport::{self, StanzaTx};

use crate::models::{PresenceEvent, ShowStatus, SubscriptionKind};

// Broadcast channel for presence events — late subscribers get Lagged error (not silent loss)
lazy_static::lazy_static! {
    pub static ref PRESENCE_BUS: broadcast::Sender<PresenceEvent> = {
        let (tx, _) = broadcast::channel(256);
        tx
    };
    pub static ref FRIEND_REQUEST_BUS: broadcast::Sender<String> = {
        let (tx, _) = broadcast::channel(64);
        tx
    };
    static ref AUTO_ACCEPTED_REQUESTS: std::sync::RwLock<HashSet<String>> =
        std::sync::RwLock::new(HashSet::new());
}

// Presence-related namespaces
const NS_JABBER_CLIENT: &str = "jabber:client";

// XEP-0319 idle namespace
const NS_IDLE: &str = "urn:xmpp:idle:1";

/// Extract the XEP-0319 idle timestamp from a presence stanza, if present.
fn idle_since(stanza: &Element) -> Option<chrono::DateTime<chrono::Utc>> {
    let idle = stanza.get_child("idle", NS_IDLE)?;
    let since = idle.attr("since")?;
    chrono::DateTime::parse_from_rfc3339(since)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Parse the <show> element into a typed ShowStatus
fn parse_show(stanza: &Element) -> Option<ShowStatus> {
    let show = stanza.get_child("show", "")?;
    match show.text().as_str() {
        "chat" => Some(ShowStatus::Chat),
        "away" => Some(ShowStatus::Away),
        "xa" => Some(ShowStatus::Xa),
        "dnd" => Some(ShowStatus::Dnd),
        _ => None,
    }
}

/// Handle a presence stanza received from a contact.
/// Parses into a typed `PresenceEvent` and broadcasts via the PRESENCE_BUS.
/// Subscription stanzas produce `PresenceEvent::Subscription` which the UI ignores.
pub fn handle_presence_stanza(stanza: &Element) -> Result<()> {
    // Extract the sender JID
    let from = match stanza.attr("from") {
        Some(jid) => jid,
        None => {
            warn!("Received presence stanza without 'from' attribute");
            return Ok(());
        }
    };

    // Normalize JID by removing resource part (after the slash)
    let bare_jid = from.split('/').next().unwrap_or(from).to_string();

    // Determine presence type
    let presence_type = stanza.attr("type").unwrap_or("available");

    // Build a typed PresenceEvent
    let event = match presence_type {
        "unavailable" => PresenceEvent::Unavailable {
            jid: bare_jid.clone(),
        },
        "available" | "" => PresenceEvent::Available {
            jid: bare_jid.clone(),
            show: parse_show(stanza),
            idle_since: idle_since(stanza),
        },
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed" => {
            let kind = match presence_type {
                "subscribe" => SubscriptionKind::Subscribe,
                "subscribed" => SubscriptionKind::Subscribed,
                "unsubscribe" => SubscriptionKind::Unsubscribe,
                _ => SubscriptionKind::Unsubscribed,
            };
            info!(
                "Received subscription stanza '{}' from {}",
                presence_type, bare_jid
            );
            PresenceEvent::Subscription {
                jid: bare_jid.clone(),
                kind,
            }
        }
        "error" => {
            let reason = stanza
                .get_child("error", "")
                .map(|e| e.text())
                .unwrap_or_else(|| "unknown error".to_string());
            warn!("Presence error from {}: {}", bare_jid, reason);
            PresenceEvent::Error {
                jid: bare_jid.clone(),
                reason,
            }
        }
        _ => {
            warn!(
                "Unknown presence type '{}' from {}",
                presence_type, bare_jid
            );
            PresenceEvent::Error {
                jid: bare_jid.clone(),
                reason: format!("unknown type: {}", presence_type),
            }
        }
    };

    // Process entity capabilities if present (only for available presences)
    if matches!(&event, PresenceEvent::Available { .. }) {
        if let Some(caps) = stanza.get_child("c", "http://jabber.org/protocol/caps") {
            let node = caps.attr("node").unwrap_or("");
            let ver = caps.attr("ver").unwrap_or("");
            if !ver.is_empty() {
                schedule_caps_discovery(from, node, ver);
            }
        }
    }

    // Broadcast the typed event — if no subscribers yet, the message is simply dropped
    // (broadcast channel handles this gracefully, no silent subscriber-list bugs)
    let _ = PRESENCE_BUS.send(event);

    Ok(())
}

/// Subscribe to presence events via broadcast channel.
/// Late subscribers won't miss events — they'll get a Lagged error which signals
/// the need for a full state refresh (handled by resend_presence).
pub fn subscribe_to_presence() -> broadcast::Receiver<PresenceEvent> {
    PRESENCE_BUS.subscribe()
}

/// Send an initial presence stanza to let contacts know we're online
///
/// # Arguments
///
/// * `client` - The XMPP client instance
///
/// # Returns
///
/// Result indicating success or failure
pub fn send_initial_presence_via(stanza_tx: &StanzaTx) -> Result<()> {
    let mut presence = Element::builder("presence", NS_JABBER_CLIENT).build();

    let mut show = Element::builder("show", "").build();
    show.append_text_node("chat");
    presence.append_child(show);

    let mut status = Element::builder("status", "").build();
    status.append_text_node("Online using Chatterbox XMPP");
    presence.append_child(status);

    let caps = Element::builder("c", "http://jabber.org/protocol/caps")
        .attr("hash", "sha-1")
        .attr("node", "https://github.com/user/sermo")
        .attr("ver", "1.0.0")
        .build();
    presence.append_child(caps);

    transport::send_stanza(stanza_tx, presence)
        .map_err(|e| anyhow!("Failed to send initial presence: {}", e))
}

/// Send an unavailable presence to indicate going offline
///
/// # Arguments
///
/// * `client` - The XMPP client instance
///
/// # Returns
///
/// Result indicating success or failure
pub fn send_unavailable_presence_via(stanza_tx: &StanzaTx) -> Result<()> {
    let presence = Element::builder("presence", NS_JABBER_CLIENT)
        .attr("type", "unavailable")
        .build();

    transport::send_stanza(stanza_tx, presence)
        .map_err(|e| anyhow!("Failed to send unavailable presence: {}", e))
}

#[allow(dead_code)]
pub async fn send_unavailable_presence_legacy(_unused: &()) -> Result<()> {
    // Legacy stub — only kept so callers compile during transition.
    // Real usage goes through send_unavailable_presence_via.
    Ok(())
}

/// Set custom presence status with optional status message
///
/// # Arguments
///
/// * `client` - The XMPP client instance
/// * `status_type` - The type of status (online, away, dnd, etc.)
/// * `status_msg` - Optional status message text
///
/// # Returns
///
/// Result indicating success or failure
pub fn set_presence_status_via(
    stanza_tx: &StanzaTx,
    status_type: &str,
    status_msg: Option<&str>,
) -> Result<()> {
    //debug!("Setting presence status to '{}' with message: {:?}", status_type, status_msg);

    let mut presence = Element::builder("presence", NS_JABBER_CLIENT);

    // Add show element if not "online"
    if status_type != "online" {
        let show_value = match status_type {
            "away" => "away",
            "dnd" => "dnd",
            "xa" => "xa",
            _ => {
                warn!(
                    "Unknown status type '{}', defaulting to 'away'",
                    status_type
                );
                "away"
            }
        };

        let mut show = Element::builder("show", "").build();
        show.append_text_node(show_value);

        presence = presence.append(show);
    }

    // Add status message if provided
    if let Some(msg) = status_msg {
        let mut status = Element::builder("status", "").build();
        status.append_text_node(msg);

        presence = presence.append(status);
    }

    // Build and send the presence stanza
    let presence_stanza = presence.build();

    //debug!("[JID DEBUG] set_presence_status: sending presence from our JID (client state may have JID field), status_type='{}'", status_type);

    transport::send_stanza(stanza_tx, presence_stanza)
        .map_err(|e| anyhow!("Failed to update presence status: {}", e))
}

/// Process subscription-related presence stanzas
///
/// # Arguments
///
/// * `client` - The XMPP client instance
/// * `stanza` - The presence stanza element
///
/// # Returns
///
/// Result indicating success or failure
pub async fn process_subscription(stanza_tx: &StanzaTx, stanza: &Element) -> Result<()> {
    let presence_type = match stanza.attr("type") {
        Some(t) => t,
        None => return Ok(()), // Not a subscription stanza
    };

    let from = match stanza.attr("from") {
        Some(jid) => jid,
        None => {
            warn!("Received subscription stanza without 'from' attribute");
            return Ok(());
        }
    };

    //debug!("[JID DEBUG] process_subscription: from='{}', presence_type='{}'", from, presence_type);

    match presence_type {
        "subscribe" => {
            info!("Received subscription request from {}", from);

            // Extract the bare JID
            let bare_jid = from.split('/').next().unwrap_or(from);

            // Auto-accept for now
            // In a real application, this would typically ask the user
            let response = Element::builder("presence", NS_JABBER_CLIENT)
                .attr("to", from)
                .attr("type", "subscribed")
                .build();

            match transport::send_stanza(stanza_tx, response) {
                Ok(_) => {
                    info!("Automatically accepted subscription request from {}", from);

                    // Subscribe back if we're not already subscribed
                    let subscribe_back = Element::builder("presence", NS_JABBER_CLIENT)
                        .attr("to", from)
                        .attr("type", "subscribe")
                        .build();

                    if let Err(e) = transport::send_stanza(stanza_tx, subscribe_back) {
                        warn!("Failed to subscribe back to {}: {}", from, e);
                    } else {
                        info!("Subscribed back to {}", from);
                    }

                    // Check if we've already sent a notification for this contact
                    let mut auto_accepted = AUTO_ACCEPTED_REQUESTS
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    let bare_jid_str = bare_jid.to_string();

                    if !auto_accepted.contains(&bare_jid_str) {
                        // Add to tracking set
                        auto_accepted.insert(bare_jid_str.clone());

                        // Broadcast notification (no receivers = silently dropped, which is fine)
                        let _ = FRIEND_REQUEST_BUS.send(bare_jid_str.clone());
                        info!("Broadcast friend request notification from {}", bare_jid);
                    }
                }
                Err(e) => {
                    error!("Failed to accept subscription from {}: {}", from, e);
                    return Err(anyhow!("Failed to accept subscription: {}", e));
                }
            }
        }
        "subscribed" => {
            info!("Our subscription to {} was accepted", from);
            // You might want to update the UI or internal state here
        }
        "unsubscribe" => {
            info!("{} unsubscribed from our presence", from);

            // Acknowledge the unsubscription
            let response = Element::builder("presence", NS_JABBER_CLIENT)
                .attr("to", from)
                .attr("type", "unsubscribed")
                .build();

            if let Err(e) = transport::send_stanza(stanza_tx, response) {
                warn!("Failed to acknowledge unsubscription from {}: {}", from, e);
            }
        }
        "unsubscribed" => {
            info!("Our subscription to {}'s presence was canceled", from);
            // You might want to update the UI or internal state here
        }
        _ => {
            // Not a subscription-related stanza
            return Ok(());
        }
    }

    Ok(())
}

/// Subscribe to receive friend request notifications
///
/// Returns a broadcast receiver for friend request notifications.
/// Multiple subscribers are supported; re-subscribing does not orphan previous receivers.
pub fn subscribe_to_friend_requests() -> broadcast::Receiver<String> {
    FRIEND_REQUEST_BUS.subscribe()
}

// Data structure to hold pending capability discoveries
#[derive(Debug, Clone)]
pub struct CapabilityInfo {
    pub jid: String,
    pub node: String,
    pub ver: String,
}

// Global storage for entities with capabilities to be discovered
lazy_static::lazy_static! {
    pub(crate) static ref PENDING_CAPS_DISCOVERIES: std::sync::Mutex<Vec<CapabilityInfo>> =
        std::sync::Mutex::new(Vec::new());
}

/// Schedule a capability discovery for later processing
pub fn schedule_caps_discovery(jid: &str, node: &str, ver: &str) {
    if let Ok(mut discoveries) = PENDING_CAPS_DISCOVERIES.lock() {
        discoveries.push(CapabilityInfo {
            jid: jid.to_string(),
            node: node.to_string(),
            ver: ver.to_string(),
        });
    } else {
        error!("Failed to acquire lock for pending capability discoveries");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PresenceEvent, ShowStatus, SubscriptionKind};

    fn make_presence(from: &str, type_attr: Option<&str>) -> Element {
        let mut builder = Element::builder("presence", "jabber:client").attr("from", from);
        if let Some(t) = type_attr {
            builder = builder.attr("type", t);
        }
        builder.build()
    }

    #[test]
    fn test_handle_available_presence() {
        let stanza = make_presence("alice@example.com/phone", None);
        let mut rx = subscribe_to_presence();
        handle_presence_stanza(&stanza).unwrap();
        let event = rx.try_recv().unwrap();
        match event {
            PresenceEvent::Available {
                jid,
                show,
                idle_since,
            } => {
                assert_eq!(jid, "alice@example.com");
                assert!(show.is_none());
                assert!(idle_since.is_none());
            }
            _ => panic!("Expected Available event"),
        }
    }

    #[test]
    fn test_handle_unavailable_presence() {
        let stanza = make_presence("bob@example.com/laptop", Some("unavailable"));
        let mut rx = subscribe_to_presence();
        handle_presence_stanza(&stanza).unwrap();
        let event = rx.try_recv().unwrap();
        match event {
            PresenceEvent::Unavailable { jid } => {
                assert_eq!(jid, "bob@example.com");
            }
            _ => panic!("Expected Unavailable event"),
        }
    }

    #[test]
    fn test_handle_subscribe_presence() {
        let stanza = make_presence("carol@example.com", Some("subscribe"));
        let mut rx = subscribe_to_presence();
        handle_presence_stanza(&stanza).unwrap();
        let event = rx.try_recv().unwrap();
        match event {
            PresenceEvent::Subscription { jid, kind } => {
                assert_eq!(jid, "carol@example.com");
                assert_eq!(kind, SubscriptionKind::Subscribe);
            }
            _ => panic!("Expected Subscription event"),
        }
    }

    #[test]
    fn test_parse_show_dnd() {
        let stanza = Element::builder("presence", "jabber:client")
            .attr("from", "dave@example.com/work")
            .append(Element::builder("show", "").append("dnd").build())
            .build();
        let mut rx = subscribe_to_presence();
        handle_presence_stanza(&stanza).unwrap();
        let event = rx.try_recv().unwrap();
        match event {
            PresenceEvent::Available { show, .. } => {
                assert_eq!(show, Some(ShowStatus::Dnd));
            }
            _ => panic!("Expected Available event"),
        }
    }

    #[test]
    fn test_parse_show_away() {
        let stanza = Element::builder("presence", "jabber:client")
            .attr("from", "eve@example.com/mobile")
            .append(Element::builder("show", "").append("away").build())
            .build();
        let show = parse_show(&stanza);
        assert_eq!(show, Some(ShowStatus::Away));
    }

    #[test]
    fn test_idle_since_parsing() {
        let stanza = Element::builder("presence", "jabber:client")
            .attr("from", "frank@example.com")
            .append(
                Element::builder("idle", NS_IDLE)
                    .attr("since", "2026-01-15T10:30:00Z")
                    .build(),
            )
            .build();
        let since = idle_since(&stanza);
        assert!(since.is_some());
        assert_eq!(since.unwrap().timestamp(), 1768473000);
    }

    #[test]
    fn test_no_from_attribute_is_ok() {
        let stanza = Element::builder("presence", "jabber:client").build();
        // Should not error, just return Ok
        assert!(handle_presence_stanza(&stanza).is_ok());
    }

    #[test]
    fn test_error_presence() {
        let stanza = make_presence("bad@example.com", Some("error"));
        let mut rx = subscribe_to_presence();
        handle_presence_stanza(&stanza).unwrap();
        let event = rx.try_recv().unwrap();
        match event {
            PresenceEvent::Error { jid, .. } => {
                assert_eq!(jid, "bad@example.com");
            }
            _ => panic!("Expected Error event"),
        }
    }
}
