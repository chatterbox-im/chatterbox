// XMPP client module for Sermo
// This file serves as the entry point for all XMPP-related functionality
// Organized by XEP (XMPP Extension Protocol)

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex as TokioMutex};
use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

// Import the core xmpp libraries
#[allow(unused_imports)]
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
pub mod coordinator;
pub mod discovery;
pub mod iq_registry;
pub mod transport;
mod event_loop;
mod omemo_handler;
mod send;

// Re-export our submodules
pub use chat_states::*;
pub use coordinator::{CoordinatorHandle, CoordinatorCommand, spawn_coordinator};
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

/// Late-bound state published after OMEMO initialization completes.
/// Sent via a `watch` channel — the event loop reads it with a single
/// atomic borrow (no mutex locks needed).
#[derive(Clone, Default)]
pub(crate) struct LateState {
    pub omemo_manager: Option<Arc<TokioMutex<crate::omemo::OmemoManager>>>,
    pub pubsub_responses: Option<crate::xmpp::omemo_integration::PubSubResponses>,
    pub jid: String,
    pub typing_tx: Option<mpsc::Sender<(String, crate::xmpp::chat_states::TypingStatus)>>,
}

pub(crate) type LateStateTx = watch::Sender<LateState>;
pub(crate) type LateStateRx = watch::Receiver<LateState>;

// XMPPClient struct - main client implementation
pub struct XMPPClient {
    pub(crate) jid: String,
    /// Channel-based stanza sender — stanzas are forwarded to the transport actor.
    pub(crate) stanza_tx: Option<transport::StanzaTx>,
    pub(crate) msg_tx: mpsc::Sender<Message>,
    pub(crate) pending_receipts: Arc<TokioMutex<HashMap<String, PendingMessage>>>,
    pub(crate) connected: bool,
    pub(crate) omemo_manager: Option<Arc<TokioMutex<crate::omemo::OmemoManager>>>,
    pub(crate) carbons_enabled: Arc<AtomicBool>,
    pub(crate) iq_registry: Arc<TokioMutex<iq_registry::IqResponseRegistry>>,
    pub(crate) pubsub_responses: Option<crate::xmpp::omemo_integration::PubSubResponses>,
    /// Watch channel sender for publishing late-bound state to the event loop.
    /// `Some` on the real client, `None` on temporary clones.
    pub(crate) late_state_tx: Option<LateStateTx>,
    /// Typing notification sender — passed to the event loop for chat state notifications.
    pub typing_tx: Option<mpsc::Sender<(String, crate::xmpp::chat_states::TypingStatus)>>,
    /// Per-instance OMEMO storage directory override (for tests with multiple clients).
    pub omemo_dir: Option<std::path::PathBuf>,
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
        let (late_state_tx, _) = watch::channel(LateState::default());

        (Self {
            jid: String::new(),
            stanza_tx: None,
            msg_tx,
            pending_receipts,
            connected: false,
            omemo_manager: None,
            carbons_enabled: Arc::new(AtomicBool::new(true)),
            iq_registry: Arc::new(TokioMutex::new(iq_registry::IqResponseRegistry::new())),
            pubsub_responses: None,
            late_state_tx: Some(late_state_tx),
            typing_tx: None,
            omemo_dir: None,
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
                encrypted: false,
            };
            
            match self.msg_tx.send(ui_message).await {
                Ok(_) => debug!("Sent message status update to UI"),
                Err(e) => error!("Failed to send message status update to UI: {}", e),
            }
        }
    }

    // Helper method to check if client is accessible
    pub fn is_client_accessible(&self) -> bool {
        if self.stanza_tx.is_some() {
            true
        } else {
            error!("XMPP client does not exist");
            false
        }
    }

    /// Send a stanza via the transport channel.
    pub(crate) fn send_stanza(&self, stanza: xmpp_parsers::Element) -> anyhow::Result<()> {
        let tx = self.stanza_tx.as_ref()
            .ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        transport::send_stanza(tx, stanza)
    }

    /// Send an IQ stanza and await the response with a timeout.
    ///
    /// Handles the full lifecycle: ID generation, registry registration,
    /// stanza construction, sending, timeout, and error checking.
    /// Returns the response `Element` on success (type="result").
    pub(crate) async fn send_iq_and_await(
        &self,
        iq_type: &str,
        child: xmpp_parsers::Element,
        timeout_secs: u64,
    ) -> Result<xmpp_parsers::Element> {
        let id = Uuid::new_v4().to_string();

        let rx = {
            let mut registry = self.iq_registry.lock().await;
            registry.register(id.clone())
        };

        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", iq_type)
            .attr("id", &id)
            .append(child)
            .build();

        self.send_stanza(iq)?;

        let response = tokio::time::timeout(Duration::from_secs(timeout_secs), rx)
            .await
            .map_err(|_| anyhow!("Timed out waiting for IQ response (id={})", id))?
            .map_err(|_| anyhow!("IQ response channel closed (id={})", id))?;

        match response.attr("type") {
            Some("result") => Ok(response),
            Some("error") => {
                let reason = response
                    .get_child("error", "jabber:client")
                    .and_then(|e| e.children().next())
                    .map(|c| c.name().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                Err(anyhow!("IQ error: {}", reason))
            }
            other => Err(anyhow!("Unexpected IQ response type: {:?}", other)),
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
            stanza_tx: self.stanza_tx.clone(),
            msg_tx: self.msg_tx.clone(),
            pending_receipts: self.pending_receipts.clone(),
            connected: self.connected,
            omemo_manager: self.omemo_manager.clone(),
            carbons_enabled: self.carbons_enabled.clone(),
            iq_registry: self.iq_registry.clone(),
            pubsub_responses: self.pubsub_responses.clone(),
            late_state_tx: None, // clones don't publish state
            typing_tx: self.typing_tx.clone(),
            omemo_dir: self.omemo_dir.clone(),
        }
    }

    /// Subscribe to presence events via broadcast channel.
    /// Can be called at any time — the broadcast channel ensures no race conditions.
    pub fn subscribe_to_presence(&self) -> tokio::sync::broadcast::Receiver<PresenceEvent> {
        presence::subscribe_to_presence()
    }

    /// Re-send our presence to trigger the server to re-broadcast roster presences.
    /// Useful after subscribing if the broadcast buffer has already wrapped (Lagged).
    pub fn resend_presence(&self) {
        if let Some(stanza_tx) = &self.stanza_tx {
            if let Err(e) = presence::send_initial_presence_via(stanza_tx) {
                error!("Failed to resend presence: {}", e);
            }
        }
    }

    /// Subscribe to friend request notifications
    pub fn subscribe_to_friend_requests(&self) -> tokio::sync::broadcast::Receiver<String> {
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
        if self.stanza_tx.is_some() {
            return self.enable_carbons().await;
        }
        
        Err(anyhow!("XMPP client not initialized"))
    }

    /// Enable XML inspection for testing and debugging
    pub async fn enable_xml_inspection(&self, tx: mpsc::Sender<String>) -> Result<()> {
        if self.stanza_tx.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        introspection::register_inspector(tx);
        
        info!("XML inspection enabled for XMPP stanzas");
        
        Ok(())
    }
}

/// Publish the fully-initialized late-bound state to the event loop via watch channel.
/// Called after OMEMO initialization and typing_tx setup are complete.
pub fn publish_late_state(client: &XMPPClient) {
    if let Some(ref tx) = client.late_state_tx {
        let state = LateState {
            omemo_manager: client.omemo_manager.clone(),
            pubsub_responses: client.pubsub_responses.clone(),
            jid: client.jid.clone(),
            typing_tx: client.typing_tx.clone(),
        };
        let _ = tx.send(state);
        info!("Published late state to event loop (OMEMO: {}, PubSub: {})",
            client.omemo_manager.is_some(),
            client.pubsub_responses.is_some());
    }
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
