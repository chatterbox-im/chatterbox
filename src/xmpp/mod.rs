// XMPP client module for Sermo
// This file serves as the entry point for all XMPP-related functionality
// Organized by XEP (XMPP Extension Protocol)

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};

// Import the core xmpp libraries
use tokio_xmpp::AsyncClient as XMPPAsyncClient;

// Import our submodules - making them public
pub mod delivery_receipts;
pub mod chat_states;
pub mod message_archive;
pub mod message_carbons;
pub mod omemo_integration;
pub mod presence;
pub mod roster;
pub mod introspection;
pub mod connection;
pub mod discovery;
mod event_loop;
mod omemo_handler;
mod send;

// Re-export our submodules
pub use chat_states::*;
pub use presence::*;
pub use discovery::ServiceDiscovery;

// Import models
use crate::models::{Message, DeliveryStatus, PendingMessage, PresenceEvent};

// Custom namespaces
pub mod custom_ns {
    pub const CHATSTATES: &str = "http://jabber.org/protocol/chatstates";
    pub const MAM: &str = "urn:xmpp:mam:2";
    pub const RECEIPTS: &str = "urn:xmpp:receipts";
    pub const OMEMO: &str = "eu.siacs.conversations.axolotl";
    pub const OMEMO_V1: &str = "eu.siacs.conversations.axolotl";
    pub const PUBSUB: &str = "http://jabber.org/protocol/pubsub";
    pub const STANZAS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
    pub const CARBONS: &str = "urn:xmpp:carbons:2";
    pub const FORWARD: &str = "urn:xmpp:forward:0";
    pub const HINTS: &str = "urn:xmpp:hints";
}

// XEP namespaces (core and extensions)
const NS_JABBER_CLIENT: &str = "jabber:client";

// XMPPClient struct - main client implementation
pub struct XMPPClient {
    pub(crate) jid: String,
    pub(crate) client: Option<Arc<TokioMutex<XMPPAsyncClient>>>,
    pub(crate) msg_tx: mpsc::Sender<Message>,
    pub(crate) pending_receipts: Arc<TokioMutex<HashMap<String, PendingMessage>>>,
    pub(crate) connected: bool,
    pub(crate) omemo_manager: Option<Arc<TokioMutex<crate::omemo::OmemoManager>>>,
    pub(crate) carbons_enabled: Arc<AtomicBool>,
}

// Make the typing notification channel accessible from outside
lazy_static::lazy_static! {
    pub static ref TYPING_TX: std::sync::Mutex<Option<mpsc::Sender<(String, crate::xmpp::chat_states::TypingStatus)>>> = 
        std::sync::Mutex::new(None);
}

// Enum for representing client state
#[derive(Debug, Clone, PartialEq)]
pub enum ClientState {
    Connected,
    Disconnected,
    Connecting,
    Error,
    Unknown,
}

// Core XMPPClient implementation
impl XMPPClient {
    pub fn new() -> (Self, mpsc::Receiver<Message>) {
        let (msg_tx, msg_rx) = mpsc::channel(100);
        let pending_receipts = Arc::new(TokioMutex::new(HashMap::new()));

        (Self {
            jid: String::new(),
            client: None,
            msg_tx,
            pending_receipts,
            connected: false,
            omemo_manager: None,
            carbons_enabled: Arc::new(AtomicBool::new(true)),
        }, msg_rx)
    }

    // Update a message's status and notify the UI
    pub async fn update_message_status(&self, msg_id: &str, new_status: DeliveryStatus) {
        let pending_message;
        
        {
            let mut pending_receipts = self.pending_receipts.lock().await;
            if let Some(pending) = pending_receipts.get_mut(msg_id) {
                info!("Updating message {} status from {:?} to {:?}", msg_id, pending.status, new_status);
                pending.status = new_status.clone();
                pending_message = Some(pending.clone());
            } else {
                return;
            }
        }
        
        if let Some(pending) = pending_message {
            let ui_message = Message {
                id: pending.id.clone(),
                sender_id: "me".to_string(),
                recipient_id: pending.to.clone(),
                content: pending.content.clone(),
                timestamp: pending.timestamp,
                delivery_status: new_status,
            };
            
            match self.msg_tx.send(ui_message).await {
                Ok(_) => debug!("Sent message status update to UI"),
                Err(e) => error!("Failed to send message status update to UI: {}", e),
            }
        }
    }

    // Helper method to check if client is accessible
    pub fn is_client_accessible(&self) -> bool {
        if let Some(_client) = &self.client {
            true
        } else {
            error!("XMPP client does not exist");
            false
        }
    }

    // Get a clone of the message sender channel
    pub fn get_message_sender(&self) -> mpsc::Sender<Message> {
        self.msg_tx.clone()
    }

    pub fn get_jid(&self) -> &str {
        &self.jid
    }

    /// Implement the Clone trait for XMPPClient to allow making copies
    pub fn clone(&self) -> Self {
        Self {
            jid: self.jid.clone(),
            client: self.client.clone(),
            msg_tx: self.msg_tx.clone(),
            pending_receipts: self.pending_receipts.clone(),
            connected: self.connected,
            omemo_manager: self.omemo_manager.clone(),
            carbons_enabled: self.carbons_enabled.clone(),
        }
    }

    /// Subscribe to presence events via broadcast channel.
    /// Can be called at any time — the broadcast channel ensures no race conditions.
    pub fn subscribe_to_presence(&self) -> tokio::sync::broadcast::Receiver<PresenceEvent> {
        presence::subscribe_to_presence()
    }

    /// Re-send our presence to trigger the server to re-broadcast roster presences.
    /// Useful after subscribing if the broadcast buffer has already wrapped (Lagged).
    pub async fn resend_presence(&self) {
        if let Some(client_ref) = &self.client {
            let mut client_guard = client_ref.lock().await;
            if let Err(e) = presence::send_initial_presence(&mut client_guard).await {
                error!("Failed to resend presence: {}", e);
            }
        }
    }

    /// Subscribe to friend request notifications
    pub fn subscribe_to_friend_requests(&self) -> mpsc::Receiver<String> {
        presence::subscribe_to_friend_requests()
    }

    /// Process an OMEMO message carbon (sent or received via XEP-0280)
    pub async fn process_omemo_carbon(
        &self,
        stanza: &xmpp_parsers::Element,
    ) -> Result<()> {
        self.process_carbon(stanza).await
    }

    /// Set whether message carbons are enabled for this client
    pub fn set_carbons_enabled(&self, enabled: bool) {
        self.carbons_enabled.store(enabled, Ordering::SeqCst);
    }

    /// Check if carbons are currently enabled for this client
    pub fn is_carbons_enabled(&self) -> bool {
        self.carbons_enabled.load(Ordering::SeqCst)
    }

    /// Enable Message Carbons feature
    pub async fn enable_carbons(&self) -> Result<bool> {
        self.enable_carbons_protocol().await
    }

    /// Enable message carbons (XEP-0280) - compatibility shim
    pub async fn enable_carbons_compat(&self) -> Result<bool> {
        if let Some(_client_ref) = &self.client {
            return self.enable_carbons().await;
        }
        
        Err(anyhow!("XMPP client not initialized"))
    }

    /// Enable XML inspection for testing and debugging
    pub async fn enable_xml_inspection(&self, tx: mpsc::Sender<String>) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        let client_guard = client.lock().await;
        
        introspection::register_inspector(tx);
        
        info!("XML inspection enabled for XMPP stanzas");
        drop(client_guard);
        
        Ok(())
    }
}

// Global XMPP client instance for accessing from other modules
static GLOBAL_XMPP_CLIENT: tokio::sync::OnceCell<Arc<TokioMutex<XMPPClient>>> = tokio::sync::OnceCell::const_new();

/// Set the global XMPP client instance
pub async fn set_global_xmpp_client(client: XMPPClient) {
    let client_arc = Arc::new(TokioMutex::new(client));
    let _ = GLOBAL_XMPP_CLIENT.set(client_arc);
}

/// Get the global XMPP client instance
pub async fn get_global_xmpp_client() -> Option<Arc<TokioMutex<XMPPClient>>> {
    GLOBAL_XMPP_CLIENT.get().cloned()
}

/// Verify OMEMO stanza structure for security
pub fn verify_omemo_stanza(stanza: &xmpp_parsers::Element, _content: &str) -> Result<(), String> {
    debug!("Verifying OMEMO stanza structure for security compliance");
    
    let mut missing_elements = Vec::new();
    
    // Find the encrypted element
    let encrypted = stanza.get_child("encrypted", custom_ns::OMEMO)
        .or_else(|| stanza.get_child("encrypted", custom_ns::OMEMO_V1))
        .or_else(|| stanza.get_child("encrypted", ""));
    
    let encrypted = match encrypted {
        Some(encrypted) => encrypted,
        None => {
            error!("Missing encrypted element in OMEMO message");
            missing_elements.push("encrypted element");
            return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                              missing_elements.join(", ")));
        }
    };
    
    debug!("Found encrypted element with namespace: {}", encrypted.ns());
    
    // Check header element
    let header = encrypted.get_child("header", custom_ns::OMEMO)
        .or_else(|| encrypted.get_child("header", custom_ns::OMEMO_V1))
        .or_else(|| encrypted.get_child("header", ""));
    
    let header = match header {
        Some(header) => header,
        None => {
            error!("Missing header element in encrypted element");
            missing_elements.push("header");
            return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                              missing_elements.join(", ")));
        }
    };
    
    debug!("Found header element with namespace: {}", header.ns());
    
    // Check sender device ID (sid) attribute
    if header.attr("sid").is_none() {
        error!("Missing sender device ID (sid) attribute in header");
        missing_elements.push("sender device ID");
    } else {
        let sid = header.attr("sid").unwrap();
        debug!("Found sender device ID: {}", sid);
        
        match sid.parse::<u32>() {
            Ok(_) => debug!("Valid device ID format"),
            Err(_) => {
                error!("Invalid device ID format: {}", sid);
                missing_elements.push("valid device ID");
            }
        }
    }
    
    // Check initialization vector (iv) element
    let iv = header.get_child("iv", custom_ns::OMEMO)
        .or_else(|| header.get_child("iv", custom_ns::OMEMO_V1))
        .or_else(|| header.get_child("iv", ""));
    
    if let Some(iv_elem) = iv {
        debug!("Found iv element with namespace: {}", iv_elem.ns());
        let iv_text = iv_elem.text();
        debug!("IV content length: {}", iv_text.len());
        
        match base64::engine::general_purpose::STANDARD.decode(iv_text.trim()) {
            Ok(decoded) => debug!("Valid base64 IV content, decoded length: {} bytes", decoded.len()),
            Err(e) => error!("Invalid base64 in IV element: {}", e),
        }
    } else {
        error!("Missing initialization vector (iv) element in header");
        missing_elements.push("initialization vector");
    }
    
    // Check for at least one key element
    let key_elements: Vec<_> = header.children()
        .filter(|child| child.name() == "key")
        .collect();
    
    if key_elements.is_empty() {
        error!("No key elements found in header");
        missing_elements.push("encrypted key");
    } else {
        for (i, key) in key_elements.iter().enumerate() {
            let rid = key.attr("rid").unwrap_or("missing-rid");
            debug!("Key {}: rid={}, namespace={}, content_length={}", 
                  i, rid, key.ns(), key.text().len());
            
            match base64::engine::general_purpose::STANDARD.decode(key.text().trim()) {
                Ok(decoded) => debug!("Valid base64 key content, decoded length: {} bytes", decoded.len()),
                Err(e) => error!("Invalid base64 in key element: {}", e),
            }
        }
    }
    
    // Check payload element
    let payload = encrypted.get_child("payload", custom_ns::OMEMO)
        .or_else(|| encrypted.get_child("payload", ""));
    
    if let Some(payload_elem) = payload {
        let payload_text = payload_elem.text();
        
        match base64::engine::general_purpose::STANDARD.decode(payload_text.trim()) {
            Ok(decoded) => debug!("Valid base64 payload content, decoded length: {} bytes", decoded.len()),
            Err(e) => error!("Invalid base64 in payload element: {}", e),
        }
    } else {
        error!("Missing payload element in encrypted element");
        for child in encrypted.children() {
            debug!("  - {} (ns: {})", child.name(), child.ns());
        }
        missing_elements.push("encrypted payload");
    }
    
    // Return result
    if missing_elements.is_empty() {
        Ok(())
    } else {
        error!("OMEMO stanza verification failed - missing elements: {}", missing_elements.join(", "));
        Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                  missing_elements.join(", ")))
    }
}
