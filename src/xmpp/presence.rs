// XMPP Presence handling (RFC 6121)
// This module handles presence stanzas, presence subscriptions, and broadcasting status updates

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio_xmpp::AsyncClient as XMPPAsyncClient;
use xmpp_parsers::Element;
use std::collections::HashSet;

use crate::models::ContactStatus;

// Shared state for presence notifications
lazy_static::lazy_static! {
    pub static ref PRESENCE_SUBSCRIBERS: std::sync::Mutex<Vec<mpsc::Sender<(String, ContactStatus)>>> = 
        std::sync::Mutex::new(Vec::new());
    static ref FRIEND_REQUEST_TX: std::sync::RwLock<Option<mpsc::Sender<String>>> = 
        std::sync::RwLock::new(None);
    static ref PRESENCE_TX: std::sync::RwLock<Option<mpsc::Sender<(String, ContactStatus)>>> = 
        std::sync::RwLock::new(None);
    static ref AUTO_ACCEPTED_REQUESTS: std::sync::RwLock<HashSet<String>> = 
        std::sync::RwLock::new(HashSet::new());
}

// Presence-related namespaces
const NS_JABBER_CLIENT: &str = "jabber:client";

/// Handle a presence stanza received from a contact
/// 
/// # Arguments
/// 
/// * `stanza` - The presence stanza element
/// 
/// # Returns
/// 
/// Result indicating success or failure
pub fn handle_presence_stanza(stanza: &Element) -> Result<()> {
    //debug!("Processing presence stanza: {:?}", stanza);
    
    // Extract the sender JID
    let from = match stanza.attr("from") {
        Some(jid) => jid,
        None => {
            warn!("Received presence stanza without 'from' attribute");
            return Ok(());
        }
    };
    
    // Normalize JID by removing resource part (after the slash)
    let bare_jid = from.split('/').next().unwrap_or(from);
    
    //debug!("[JID DEBUG] handle_presence_stanza: from='{}', bare_jid='{}'", from, bare_jid);
    
    // Determine presence type
    let presence_type = match stanza.attr("type") {
        Some(typ) => typ,
        None => "available" // Default type is "available" when not specified
    };
    
    // Map presence type to ContactStatus
    let status = match presence_type {
        "unavailable" => ContactStatus::Offline,
        "available" | "" => {
            // Check for show element to determine more specific status
            if let Some(show) = stanza.get_child("show", "") {
                match show.text().as_str() {
                    "away" => ContactStatus::Away,
                    "xa" | "dnd" => ContactStatus::Away, // Map extended away and do not disturb to Away
                    _ => ContactStatus::Online,
                }
            } else {
                ContactStatus::Online
            }
        },
        "subscribe" => {
            info!("Received presence subscription request from {}", bare_jid);
            // Handle subscription request here
            // For now we just notify about the request
            ContactStatus::Online // Using Online as a placeholder since we don't have SubscriptionRequested
        },
        "subscribed" => {
            info!("Presence subscription to {} accepted", bare_jid);
            // We can continue with normal status
            ContactStatus::Online
        },
        "unsubscribe" => {
            info!("{} unsubscribed from our presence", bare_jid);
            ContactStatus::Offline
        },
        "unsubscribed" => {
            info!("Our subscription to {}'s presence was canceled", bare_jid);
            ContactStatus::Offline
        },
        _ => {
            warn!("Unknown presence type '{}' from {}", presence_type, bare_jid);
            ContactStatus::Offline // Using Offline as a default for unknown status
        }
    };
    
    // Process entity capabilities if present
    if let Some(caps) = stanza.get_child("c", "http://jabber.org/protocol/caps") {
        // We'll query the entity later when we get their full JID with resource
        //debug!("Entity {} advertises capabilities via presence", from);
        
        // Get capability details for delayed processing
        let node = caps.attr("node").unwrap_or("");
        let ver = caps.attr("ver").unwrap_or("");
        
        if !ver.is_empty() {
            // Store this for later capability discovery
            //debug!("Entity {} capabilities: node={}, ver={}", from, node, ver);
            
            // When we get a presence with capabilities, we'll handle this 
            // in the main client event loop to send a disco#info query
            schedule_caps_discovery(from, node, ver);
        }
    }
    
    // Send presence status to all subscribers
    send_presence_update(bare_jid.to_string(), status);
    
    Ok(())
}

/// Send a presence status update to all subscribers
/// 
/// # Arguments
/// 
/// * `jid` - The JID of the contact whose status changed
/// * `status` - The new status of the contact
pub fn send_presence_update(jid: String, status: ContactStatus) {
    //debug!("Broadcasting presence update: {} is now {:?}", jid, status);
    
    if let Ok(subscribers) = PRESENCE_SUBSCRIBERS.lock() {
        let mut to_remove = Vec::new();
        
        for (i, tx) in subscribers.iter().enumerate() {
            if let Err(e) = tx.try_send((jid.clone(), status.clone())) {
                match e {
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        // This subscriber has been dropped, mark for removal
                        to_remove.push(i);
                        //debug!("Subscriber channel closed, will be removed");
                    },
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        // Channel is full, this is unusual but not fatal
                        warn!("Failed to send presence update: channel full");
                    }
                }
            }
        }
        
        // If there are closed channels, we need to remove them
        // This is somewhat inefficient but presence updates are not high frequency
        if !to_remove.is_empty() {
            // We can't modify while holding the lock, so drop it first
            drop(subscribers);
            
            // Now try to acquire the lock again for modification
            if let Ok(mut subscribers) = PRESENCE_SUBSCRIBERS.lock() {
                // Remove in reverse order to avoid invalidating indices
                for i in to_remove.into_iter().rev() {
                    if i < subscribers.len() {
                        subscribers.remove(i);
                    }
                }
                
                //debug!("Removed closed subscriber channels. {} subscribers remaining", subscribers.len());
            }
        }
    } else {
        error!("Failed to lock PRESENCE_SUBSCRIBERS");
    }
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
pub async fn send_initial_presence(client: &mut XMPPAsyncClient) -> Result<()> {
    //debug!("Sending initial presence");
    
    let mut presence = Element::builder("presence", NS_JABBER_CLIENT).build();
    
    // Add show status (Optional)
    let mut show = Element::builder("show", "").build();
    show.append_text_node("chat"); // chat = Available for chat
    presence.append_child(show);
    
    // Add a status message (Optional)
    let mut status = Element::builder("status", "").build();
    status.append_text_node("Online using Chatterbox XMPP");
    presence.append_child(status);
    
    // Add caps (entity capabilities) advertisement
    // This advertises that we have capabilities that can be discovered via Service Discovery
    let caps = Element::builder("c", "http://jabber.org/protocol/caps")
        .attr("hash", "sha-1")
        .attr("node", "https://github.com/user/sermo")
        .attr("ver", "1.0.0")
        .build();
    presence.append_child(caps);
    
    //debug!("[JID DEBUG] send_initial_presence: sending presence from our JID (client state may have JID field)");
    
    match client.send_stanza(presence).await {
        Ok(_) => {
            //debug!("Initial presence sent successfully");
            Ok(())
        },
        Err(e) => {
            error!("Failed to send initial presence: {}", e);
            Err(anyhow!("Failed to send initial presence: {}", e))
        }
    }
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
pub async fn send_unavailable_presence(client: &mut XMPPAsyncClient) -> Result<()> {
    //debug!("Sending unavailable presence");
    
    let presence = Element::builder("presence", NS_JABBER_CLIENT)
        .attr("type", "unavailable")
        .build();
    
    //debug!("[JID DEBUG] send_unavailable_presence: sending unavailable presence from our JID (client state may have JID field)");
    
    match client.send_stanza(presence).await {
        Ok(_) => {
            //debug!("Unavailable presence sent successfully");
            Ok(())
        },
        Err(e) => {
            error!("Failed to send unavailable presence: {}", e);
            Err(anyhow!("Failed to send unavailable presence: {}", e))
        }
    }
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
pub async fn set_presence_status(
    client: &mut XMPPAsyncClient, 
    status_type: &str, 
    status_msg: Option<&str>
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
                warn!("Unknown status type '{}', defaulting to 'away'", status_type);
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
    
    match client.send_stanza(presence_stanza).await {
        Ok(_) => {
            //debug!("Presence status updated successfully");
            Ok(())
        },
        Err(e) => {
            error!("Failed to update presence status: {}", e);
            Err(anyhow!("Failed to update presence status: {}", e))
        }
    }
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
pub async fn process_subscription(client: &mut XMPPAsyncClient, stanza: &Element) -> Result<()> {
    let presence_type = match stanza.attr("type") {
        Some(t) => t,
        None => return Ok(()) // Not a subscription stanza
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
            
            match client.send_stanza(response).await {
                Ok(_) => {
                    info!("Automatically accepted subscription request from {}", from);
                    
                    // Subscribe back if we're not already subscribed
                    let subscribe_back = Element::builder("presence", NS_JABBER_CLIENT)
                        .attr("to", from)
                        .attr("type", "subscribe")
                        .build();
                    
                    if let Err(e) = client.send_stanza(subscribe_back).await {
                        warn!("Failed to subscribe back to {}: {}", from, e);
                    } else {
                        info!("Subscribed back to {}", from);
                    }
                    
                    // Check if we've already sent a notification for this contact
                    let mut auto_accepted = AUTO_ACCEPTED_REQUESTS.write().unwrap();
                    let bare_jid_str = bare_jid.to_string();
                    
                    if !auto_accepted.contains(&bare_jid_str) {
                        // Add to tracking set
                        auto_accepted.insert(bare_jid_str.clone());
                        
                        // Send notification through channel
                        if let Some(tx) = FRIEND_REQUEST_TX.read().unwrap().as_ref() {
                            match tx.try_send(bare_jid_str.clone()) {
                                Ok(_) => {
                                    info!("Sent UI notification for auto-accepted friend request from {}", bare_jid);
                                },
                                Err(e) => {
                                    // Only log if it's not a disconnected channel error
                                    match e {
                                        tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                            warn!("Failed to send friend request notification: channel full");
                                        }
                                        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                            // Channel closed - this is expected when app is shutting down
                                            debug!("Friend request notification channel closed");
                                        }
                                    }
                                }
                            }
                        } else {
                            warn!("FRIEND_REQUEST_TX not initialized - cannot send friend request notification");
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to accept subscription from {}: {}", from, e);
                    return Err(anyhow!("Failed to accept subscription: {}", e));
                }
            }
        },
        "subscribed" => {
            info!("Our subscription to {} was accepted", from);
            // You might want to update the UI or internal state here
        },
        "unsubscribe" => {
            info!("{} unsubscribed from our presence", from);
            
            // Acknowledge the unsubscription
            let response = Element::builder("presence", NS_JABBER_CLIENT)
                .attr("to", from)
                .attr("type", "unsubscribed")
                .build();
            
            if let Err(e) = client.send_stanza(response).await {
                warn!("Failed to acknowledge unsubscription from {}: {}", from, e);
            }
        },
        "unsubscribed" => {
            info!("Our subscription to {}'s presence was canceled", from);
            // You might want to update the UI or internal state here
        },
        _ => {
            // Not a subscription-related stanza
            return Ok(());
        }
    }
    
    Ok(())
}

/// Subscribe to presence notifications for contacts
pub fn subscribe_to_presence() -> mpsc::Receiver<(String, ContactStatus)> {
    let (presence_tx, presence_rx) = mpsc::channel(100);
    
    // Store in a static collection for the message handler to access
    PRESENCE_SUBSCRIBERS.lock().unwrap().push(presence_tx);
    
    presence_rx
}

/// Subscribe to receive friend request notifications
/// 
/// Returns a channel to receive friend request notifications
pub fn subscribe_to_friend_requests() -> mpsc::Receiver<String> {
    let (friend_req_tx, friend_req_rx) = mpsc::channel(100);
    FRIEND_REQUEST_TX.write().unwrap().replace(friend_req_tx);
    friend_req_rx
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