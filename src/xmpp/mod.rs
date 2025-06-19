// XMPP client module for Sermo
// This file serves as the entry point for all XMPP-related functionality
// Organized by XEP (XMPP Extension Protocol)

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use futures_util::StreamExt; // Correct import for the next() method
use base64::Engine; // Import the Engine trait for base64 decoding
use crate::omemo::device_id::DeviceId; // Import the DeviceId type
use std::sync::atomic::{AtomicBool, Ordering};

// Import the core xmpp libraries
use tokio_xmpp::{AsyncClient as XMPPAsyncClient, Event as XMPPEvent};
use xmpp_parsers::Element;

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
pub mod discovery; // Add discovery module

// Re-export our submodules
pub use chat_states::*;
pub use presence::*;
pub use discovery::ServiceDiscovery; // Re-export ServiceDiscovery for easy access

// Import models
use crate::models::{ContactStatus, Message, DeliveryStatus, PendingMessage};

// Custom namespaces
pub mod custom_ns {
    pub const CHATSTATES: &str = "http://jabber.org/protocol/chatstates";
    pub const MAM: &str = "urn:xmpp:mam:2";
    pub const RECEIPTS: &str = "urn:xmpp:receipts";
    pub const OMEMO: &str = "urn:xmpp:omemo:1";
    pub const PUBSUB: &str = "http://jabber.org/protocol/pubsub";
    pub const STANZAS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
    pub const CARBONS: &str = "urn:xmpp:carbons:2";
    pub const FORWARD: &str = "urn:xmpp:forward:0";
    pub const HINTS: &str = "urn:xmpp:hints";
    // Add this alongside the existing OMEMO namespace
    pub const OMEMO_V1: &str = "eu.siacs.conversations.axolotl";
}

// XEP namespaces (core and extensions)
const NS_JABBER_CLIENT: &str = "jabber:client";

// XMPPClient struct - main client implementation
pub struct XMPPClient {
    jid: String,
    client: Option<Arc<TokioMutex<XMPPAsyncClient>>>,
    msg_tx: mpsc::Sender<Message>,
    pending_receipts: Arc<TokioMutex<HashMap<String, PendingMessage>>>,
    connected: bool,
    omemo_manager: Option<Arc<TokioMutex<crate::omemo::OmemoManager>>>, // Add OMEMO manager
    // Message ID tracking for delivery receipts
    message_id_map: Arc<TokioMutex<HashMap<String, String>>>, // Original ID -> Internal ID
    recipient_message_map: Arc<TokioMutex<HashMap<String, HashMap<String, String>>>>, // Recipient -> (Original ID -> Internal ID)
    carbons_enabled: Arc<AtomicBool>, // Thread-safe flag for carbons
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
            omemo_manager: None, // Initialize OMEMO manager as None
            message_id_map: Arc::new(TokioMutex::new(HashMap::new())), // Initialize message ID map
            recipient_message_map: Arc::new(TokioMutex::new(HashMap::new())), // Initialize recipient message map
            carbons_enabled: Arc::new(AtomicBool::new(true)), // Default to enabled
        }, msg_rx)
    }

    // Additional core client methods will go here

    // Update a message's status and notify the UI
    pub async fn update_message_status(&self, msg_id: &str, new_status: DeliveryStatus) {
        // Update the status in our tracking map
        let pending_message;
        
        {
            let mut pending_receipts = self.pending_receipts.lock().await;
            if let Some(pending) = pending_receipts.get_mut(msg_id) {
                info!("Updating message {} status from {:?} to {:?}", msg_id, pending.status, new_status);
                pending.status = new_status.clone();
                pending_message = Some(pending.clone());
            } else {
                //debug!("Tried to update status for unknown message ID: {}", msg_id);
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
            match self.msg_tx.send(ui_message).await {
                Ok(_) => debug!("Sent message status update to UI"),
                Err(e) => error!("Failed to send message status update to UI: {}", e),
            }
        }
    }

    // Helper method to check if client is accessible without fully acquiring the lock
    pub fn is_client_accessible(&self) -> bool {
        if let Some(_client) = &self.client {
            // First check - simply whether the client exists
            //debug!("XMPP client instance exists");
            
            // Instead of using try_lock which considers a locked mutex as "inaccessible",
            // we'll just check that the client exists and return true
            // This assumes that a locked mutex is normal and doesn't mean the client is unavailable
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
            omemo_manager: self.omemo_manager.clone(), // Clone OMEMO manager
            message_id_map: self.message_id_map.clone(), // Clone message ID map
            recipient_message_map: self.recipient_message_map.clone(), // Clone recipient message map
            carbons_enabled: self.carbons_enabled.clone(), // Clone carbons_enabled
        }
    }

    /// Subscribe to presence notifications for contacts
    pub fn subscribe_to_presence(&self) -> mpsc::Receiver<(String, ContactStatus)> {
        let (presence_tx, presence_rx) = mpsc::channel(100);
        
        // Store in a static collection for the message handler to access
        presence::PRESENCE_SUBSCRIBERS.lock().unwrap().push(presence_tx);
        
        presence_rx
    }

    /// Subscribe to friend request notifications
    pub fn subscribe_to_friend_requests(&self) -> mpsc::Receiver<String> {
        presence::subscribe_to_friend_requests()
    }

    // Primary message handling loop
    async fn handle_incoming_messages(
        client: Arc<TokioMutex<XMPPAsyncClient>>,
        msg_tx: mpsc::Sender<Message>,
        pending_receipts: Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
    ) {
        // Create a channel for typing notifications
        let (typing_tx, _typing_rx) = mpsc::channel::<(String, chat_states::TypingStatus)>(100);
        
        // Store in the global static
        if let Ok(mut typing_tx_guard) = TYPING_TX.lock() {
            *typing_tx_guard = Some(typing_tx);
        } else {
            error!("Failed to acquire lock for TYPING_TX");
        }
        
        // Flag to track if we've seen the online event
        let mut seen_online_event = false;
        
        // Create a ServiceDiscovery instance for handling disco responses
        let service_discovery = discovery::ServiceDiscovery::new(client.clone());
        
        // Main event loop
        loop {
            // Use a timeout when acquiring the lock to prevent indefinite blocking
            let event_result = tokio::time::timeout(
                Duration::from_secs(2),
                async {
                    let mut client_guard = client.lock().await;
                    client_guard.next().await
                }
            ).await;
            
            // Handle potential timeout when acquiring lock
            let event = match event_result {
                Ok(event) => event,
                Err(_) => {
                    // If we've already seen the online event, this is just normal operation
                    if seen_online_event {
                        //debug!("Timed out waiting for XMPP client event - this is normal");
                    } else {
                        //debug!("Timed out waiting for XMPP client lock or next event");
                    }
                    
                    // After multiple timeouts with no connection, check if we should ping the server
                    // to maintain the connection
                    
                    // Small sleep to avoid tight loop
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            match event {
                // Process each event type...
                // This will be refactored to call appropriate handlers in our submodules
                Some(XMPPEvent::Stanza(stanza)) => {
                    // The actual stanza processing will be implemented in the specific XEP modules
                    if stanza.name() == "presence" {
                        // Handle presence stanzas
                        //debug!("Received presence stanza: {:?}", stanza);
                        let from = stanza.attr("from").unwrap_or("");
                        let to = stanza.attr("to").unwrap_or("");
                        //debug!("[JID DEBUG] handle_incoming_messages: presence stanza from='{}', to='{}'", from, to);
                        
                        // Process presence updates using our dedicated handler in presence.rs
                        if let Err(e) = presence::handle_presence_stanza(&stanza) {
                            error!("Error processing presence stanza: {}", e);
                        }
                        
                        // Also process presence stanzas for entity capabilities
                        if let Err(e) = service_discovery.process_caps_in_presence(&stanza).await {
                            warn!("Error processing entity capabilities in presence: {}", e);
                        }
                        
                        // Also handle subscription-related presence stanzas asynchronously
                        let stanza_clone = stanza.clone();
                        let client_clone = client.clone();
                        tokio::spawn(async move {
                            let mut client_guard = client_clone.lock().await;
                            if let Err(e) = presence::process_subscription(&mut client_guard, &stanza_clone).await {
                                error!("Error processing presence subscription: {}", e);
                            }
                        });
                    } else if stanza.name() == "message" {
                        // Process message here or call into message handler
                        //debug!("Received message stanza: {:?}", stanza);
                        let from = stanza.attr("from").unwrap_or("");
                        let to = stanza.attr("to").unwrap_or("");
                        //debug!("[JID DEBUG] handle_incoming_messages: message stanza from='{}', to='{}'", from, to);
                        
                        // Check for OMEMO encrypted messages
                        if stanza.has_child("encrypted", custom_ns::OMEMO) {
                            //debug!("Detected OMEMO encrypted message");
                            
                            // Clone needed values for async task
                            let stanza_clone = stanza.clone();
                            let client_clone = client.clone();
                            let msg_tx_clone = msg_tx.clone();
                            let pending_receipts_clone = pending_receipts.clone();
                            
                            // Process encrypted message in a separate task to avoid blocking
                            tokio::spawn(async move {
                                // Get the global OMEMO manager if available
                                let omemo_manager = match get_global_xmpp_client().await {
                                    Some(global_client) => {
                                        let client_guard = global_client.lock().await;
                                        client_guard.omemo_manager.clone()
                                    },
                                    None => None,
                                };
                                
                                // Register the global client for OMEMO integration
                                if let Some(manager) = &omemo_manager {
                                    crate::xmpp::omemo_integration::set_current_client_arc(client_clone.clone());
                                }
                                
                                // Need to get an instance of XMPPClient to call handle_message_encrypted
                                // We can recreate a minimal instance since we only need the method
                                let mut temp_client = XMPPClient {
                                    jid: String::new(),
                                    client: Some(client_clone),
                                    msg_tx: msg_tx_clone,
                                    pending_receipts: pending_receipts_clone,
                                    connected: true,
                                    omemo_manager: omemo_manager, // Use the global OMEMO manager
                                    message_id_map: Arc::new(TokioMutex::new(HashMap::new())),
                                    recipient_message_map: Arc::new(TokioMutex::new(HashMap::new())),
                                    carbons_enabled: Arc::new(AtomicBool::new(true)),
                                };
                                
                                // Call the handle_message_encrypted method
                                if let Err(e) = temp_client.handle_message_encrypted(&stanza_clone).await {
                                    error!("Failed to process encrypted message: {}", e);
                                }
                            });
                        } else {
                            // Handle other message types: delivery receipts, chat states, etc.
                            
                            // Check for message delivery receipts
                            if let Err(e) = delivery_receipts::handle_receipt(&stanza, &pending_receipts, &msg_tx).await {
                                // Just log the error and continue
                                error!("Error processing delivery receipt: {}", e);
                            }
                            
                            // Check for chat state notifications (typing indicators)
                            if let Err(e) = chat_states::handle_chat_state(&stanza) {
                                // Just log the error and continue
                                error!("Error processing chat state: {}", e);
                            }
                            
                            // Process carbon copies of messages
                            if stanza.has_child("received", custom_ns::CARBONS) || 
                               stanza.has_child("sent", custom_ns::CARBONS) {
                                // Clone needed values for async task
                                let stanza_clone = stanza.clone();
                                let client_clone = client.clone();
                                let msg_tx_clone = msg_tx.clone();
                                let pending_receipts_clone = pending_receipts.clone();
                                
                                tokio::spawn(async move {
                                    // Get the global OMEMO manager if available
                                    let omemo_manager = match get_global_xmpp_client().await {
                                        Some(global_client) => {
                                            let client_guard = global_client.lock().await;
                                            client_guard.omemo_manager.clone()
                                        },
                                        None => None,
                                    };
                                    
                                    // Register the global client for OMEMO integration
                                    if let Some(manager) = &omemo_manager {
                                        crate::xmpp::omemo_integration::set_current_client_arc(client_clone.clone());
                                    }
                                    
                                    // Need an XMPPClient to process carbons
                                    let temp_client = XMPPClient {
                                        jid: String::new(),
                                        client: Some(client_clone),
                                        msg_tx: msg_tx_clone,
                                        pending_receipts: pending_receipts_clone,
                                        connected: true,
                                        omemo_manager: omemo_manager, // Use the global OMEMO manager
                                        message_id_map: Arc::new(TokioMutex::new(HashMap::new())),
                                        recipient_message_map: Arc::new(TokioMutex::new(HashMap::new())),
                                        carbons_enabled: Arc::new(AtomicBool::new(true)),
                                    };
                                    
                                    if let Err(e) = temp_client.process_carbon(&stanza_clone).await {
                                        error!("Failed to process message carbon: {}", e);
                                    }
                                });
                            }
                            
                            // Process regular chat messages (non-encrypted)
                            if let Some(body) = stanza.get_child("body", "") {
                                let from = stanza.attr("from").unwrap_or("unknown@server.example");
                                let id: String = stanza.attr("id").map(|s| s.to_string()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                                let content = body.text();
                                
                                if !content.is_empty() {
                                    // Create a message for the UI
                                    let message = Message {
                                        id: id.clone(),
                                        sender_id: from.to_string(),
                                        recipient_id: "me".to_string(),
                                        content,
                                        timestamp: chrono::Utc::now().timestamp() as u64,
                                        delivery_status: DeliveryStatus::Delivered,
                                    };
                                    
                                    // Send to UI
                                    if let Err(e) = msg_tx.send(message).await {
                                        error!("Failed to send message to UI: {}", e);
                                    }
                                    
                                    // Send a receipt if requested
                                    if stanza.has_child("request", custom_ns::RECEIPTS) {
                                        let mut client_guard = client.lock().await;
                                        if let Err(e) = delivery_receipts::send_receipt(&mut client_guard, from, &id).await {
                                            error!("Failed to send receipt: {}", e);
} else {
                                            //debug!("Successfully sent receipt for message {}", id);
                                        }
                                    }
                                }
                            }
                        }
                    } else if stanza.name() == "iq" {
                        // Process IQ stanzas here or call into IQ handler
                        //debug!("Received IQ stanza: {:?}", stanza);
                        
                        // Check if this is a service discovery response
                        if let Some(query) = stanza.get_child("query", "http://jabber.org/protocol/disco#info") {
                            //debug!("Received service discovery info response");
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery info response: {}", e);
                            }
                        } else if let Some(query) = stanza.get_child("query", "http://jabber.org/protocol/disco#items") {
                            //debug!("Received service discovery items response");
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery items response: {}", e);
                            }
                        }
                    }
                },
                Some(XMPPEvent::Online { bound_jid, resumed }) => {
                    if (!seen_online_event) {
                        info!("Connected to XMPP server as {}", bound_jid);
                        seen_online_event = true;
                        
                        // Get an Arc<TokioMutex<XMPPAsyncClient>> that can be shared with other tasks
                        let client_clone = client.clone();
                        
                        // Spawn a task to handle any initialization after connection
                        tokio::spawn(async move {
                            //debug!("Running post-connection initialization");
                            
                            // Wait a bit to let the server complete session setup
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            
                            let mut client_guard = client_clone.lock().await;
                            
                            // Send initial presence to let contacts know we're online
                            presence::send_initial_presence(&mut client_guard).await
                                .unwrap_or_else(|e| {
                                    error!("Failed to send initial presence: {}", e);
                                });
                            
                            //debug!("Post-connection initialization completed");
                        });
                    } else {
                        //debug!("Received additional 'online' event for {}", bound_jid);
                    }
                },
                Some(XMPPEvent::Disconnected(reason)) => {
                    error!("XMPP client is disconnected: {:?}", reason);
                    break;
                },
                None => {
                    info!("XMPP connection closed");
                    break;
                }
            }
            
            // Check for scheduled entity capabilities discoveries
            if let Ok(mut discoveries) = presence::PENDING_CAPS_DISCOVERIES.lock() {
                if !discoveries.is_empty() {
                    let discovery_batch = std::mem::take(&mut *discoveries);
                    
                    for cap_info in discovery_batch {
                        // Clone service discovery instance for async task
                        let service_disco = service_discovery.clone();
                        let jid = cap_info.jid.clone();
                        
                        // Send disco request in background task
                        tokio::spawn(async move {
                            //debug!("Processing scheduled capability discovery for {}", jid);
                            if let Err(e) = service_disco.send_disco_info_request(&jid).await {
                                warn!("Failed to send disco request to {}: {}", jid, e);
                            }
                        });
                    }
                }
            }
            
            // Brief pause to avoid tight loop that could consume too many resources
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Process an OMEMO encrypted message and attempt to decrypt it
    /// 
    /// This method examines a message stanza for OMEMO encryption elements,
    /// extracts the encrypted data, and attempts to decrypt it using our
    /// OMEMO session and keys.
    ///
    /// # Arguments
    ///
    /// * `stanza` - The message stanza containing encrypted data
    ///
    /// # Returns
    ///
    /// A Result containing either the decrypted message or an error
    pub async fn process_encrypted_message(stanza: &xmpp_parsers::Element) -> Result<Option<(String, String)>> {
        // First check if this is an OMEMO encrypted message
        if !stanza.name().eq("message") {
            return Ok(None); // Not a message stanza
        }

        let encrypted = match stanza.get_child("encrypted", custom_ns::OMEMO) {
            Some(elem) => elem,
            None => return Ok(None), // No OMEMO encrypted content
        };

        // Extract sender JID
        let from = match stanza.attr("from") {
            Some(from_str) => from_str.to_string(),
            None => return Err(anyhow!("No sender JID in encrypted message")),
        };

        info!("Processing OMEMO encrypted message from {}", from);

        // Extract the header and encrypted data
        let header = match encrypted.get_child("header", "") {
            Some(h) => h,
            None => return Err(anyhow!("Missing header in OMEMO message")),
        };

        // Get the sender device ID
        let sid = match header.attr("sid") {
            Some(sid_str) => match sid_str.parse::<u32>() {
                Ok(sid) => sid,
                Err(_) => return Err(anyhow!("Invalid device ID in OMEMO message")),
            },
            None => return Err(anyhow!("Missing device ID in OMEMO message")),
        };

        //debug!("Message from device ID: {}", sid);

        // Extract the key information
        let key_element = match header.get_child("key", "") {
            Some(k) => k,
            None => return Err(anyhow!("Missing key element in OMEMO message")),
        };

        // Check if this key is intended for us by checking the "rid" attribute
        let _recipient_device_id = match key_element.attr("rid") {
            Some(rid_str) => match rid_str.parse::<u32>() {
                Ok(rid) => {
                    //debug!("Key is intended for device ID: {}", rid);
                    rid
                },
                Err(_) => {
                    warn!("Invalid recipient device ID '{}' in key element", rid_str);
                    return Err(anyhow!("Invalid recipient device ID in OMEMO message"));
                }
            },
            None => {
                //debug!("Key element has no 'rid' attribute, assuming it's for us");
                // No specific device ID, assume it's for us
                0
            }
        };

        // Get the encrypted key data - text() returns a String
        let key_text = key_element.text();
        if key_text.is_empty() {
            return Err(anyhow!("Empty key data in OMEMO message"));
        }
        
        //debug!("Decoding base64 encrypted key");
        let encrypted_key = match base64::engine::general_purpose::STANDARD.decode(key_text.trim()) {
            Ok(decoded) => decoded,
            Err(e) => {
                error!("Failed to decode key data: {}", e);
                return Err(anyhow!("Failed to decode key data: {}", e));
            }
        };
        //debug!("Encrypted key length: {} bytes", encrypted_key.len());

        // Get the IV (initialization vector)
        let iv_data = match header.get_child("iv", "") {
            Some(iv_elem) => {
                let iv_text = iv_elem.text();
                if iv_text.is_empty() {
                    return Err(anyhow!("Empty IV in OMEMO message"));
                }
                
                //debug!("Decoding base64 IV");
                match base64::engine::general_purpose::STANDARD.decode(iv_text.trim()) {
                    Ok(decoded) => {
                        //debug!("IV length: {} bytes", decoded.len());
                        decoded
                    },
                    Err(e) => {
                        error!("Failed to decode IV: {}", e);
                        return Err(anyhow!("Failed to decode IV: {}", e));
                    }
                }
            },
            None => return Err(anyhow!("Missing IV in OMEMO message")),
        };

        // Extract the payload (actual encrypted content)
        let payload_data = match encrypted.get_child("payload", "") {
            Some(p) => {
                let payload_text = p.text();
                if payload_text.is_empty() {
                    return Err(anyhow!("Empty payload in OMEMO message"));
                }
                
                //debug!("Decoding base64 payload");
                match base64::engine::general_purpose::STANDARD.decode(payload_text.trim()) {
                    Ok(decoded) => {
                        //debug!("Payload length: {} bytes", decoded.len());
                        decoded
                    },
                    Err(e) => {
                        error!("Failed to decode payload: {}", e);
                        return Err(anyhow!("Failed to decode payload: {}", e));
                    }
                }
            },
            None => return Err(anyhow!("Missing payload in OMEMO message")),
        };

        // Get the associated data for authenticated encryption
        // In OMEMO, this is typically the authentication tag
        let auth_data = match encrypted.get_child("auth", "") {
            Some(a) => {
                let auth_text = a.text();
                if !auth_text.is_empty() {
                    //debug!("Decoding base64 auth tag");
                    match base64::engine::general_purpose::STANDARD.decode(auth_text.trim()) {
                        Ok(decoded) => {
                            //debug!("Auth tag length: {} bytes", decoded.len());
                            decoded
                        },
                        Err(e) => {
                            warn!("Failed to decode auth tag, proceeding without it: {}", e);
                            vec![]
                        }
                    }
                } else {
                    //debug!("Empty auth tag, proceeding without it");
                    vec![]
                }
            },
            None => {
                //debug!("No auth tag present, proceeding without it");
                vec![]
            }
        };

        // Now we need to:
        // 1. Retrieve our OMEMO session with the sender
        // 2. Decrypt the message key using our session
        // 3. Use the decrypted message key to decrypt the payload

        //debug!("Retrieving OMEMO session for device {} from {}", sid, from);
        // Create the OMEMO manager to access our sessions
        let sender_bare_jid = from.split('/').next().unwrap_or(&from).to_string();
        
        // Create an OMEMO manager for our device
        let device_id = 1; // Our device ID (should be retrieved from config)
        
        // Create a storage instance first
        let storage = match crate::omemo::storage::OmemoStorage::new_default() {
            Ok(storage) => storage,
            Err(e) => return Err(anyhow!("Failed to create OMEMO storage: {}", e)),
        };
        
        // Then create the OMEMO manager with the right parameters
        let _omemo_manager = match crate::omemo::OmemoManager::new(
            storage,
            "me".to_string(),
            Some(device_id)
        ).await {
            Ok(manager) => manager,
            Err(e) => return Err(anyhow!("Failed to create OMEMO manager: {}", e)),
        };

        // Try to retrieve our session with this sender, or log diagnostic info
        info!("Retrieving session state for {}, device {}", sender_bare_jid, sid);
        
        // Get the session key from storage
        let session_key = match Self::get_session_key(&sender_bare_jid, sid) {
            Ok(key) => {
                //debug!("Retrieved session key ({} bytes) for {}, device {}", key.len(), sender_bare_jid, sid);
                key
            },
            Err(e) => {
                error!("Failed to retrieve session key: {}", e);
                return Err(anyhow!("Failed to retrieve session key: {}", e));
            }
        };

        // Decrypt the message key
        info!("Decrypting message key");
        let message_key = match crate::omemo::crypto::decrypt(&encrypted_key, &session_key, &iv_data, &auth_data) {
            Ok(key) => {
                //debug!("Message key decrypted successfully ({} bytes)", key.len());
                key
            },
            Err(e) => {
                error!("Failed to decrypt message key: {}", e);
                return Err(anyhow!("Failed to decrypt message key: {}. Please make sure you have exchanged OMEMO keys with this contact.", e));
            }
        };

        // Now decrypt the actual message payload with the message key
        info!("Decrypting message payload");
        let decrypted_payload = match crate::omemo::crypto::decrypt(&payload_data, &message_key, &iv_data, &auth_data) {
            Ok(plaintext) => {
                //debug!("Message payload decrypted successfully ({} bytes)", plaintext.len());
                plaintext
            },
            Err(e) => {
                error!("Failed to decrypt message payload: {}", e);
                return Err(anyhow!("Failed to decrypt message payload: {}", e));
            }
        };

        // Convert the decrypted bytes to a UTF-8 string
        let decrypted_message = match String::from_utf8(decrypted_payload) {
            Ok(text) => text,
            Err(e) => {
                error!("Decrypted data is not valid UTF-8: {}", e);
                return Err(anyhow!("Decrypted data is not valid UTF-8: {}", e));
            }
        };

        info!("Successfully decrypted OMEMO message from {}", from);
        //debug!("Decrypted message content: {}", decrypted_message);

        // Return the sender JID and the decrypted message content
        Ok(Some((from, decrypted_message)))
    }

    // Helper function to get a session key for a sender
    fn get_session_key(sender_jid: &str, device_id: u32) -> Result<Vec<u8>> {
        // In a real implementation, retrieve from database
        // For now, check if we have a valid session or create one
        match crate::omemo::storage::OmemoStorage::new_default() {
            Ok(storage) => {
                match storage.get_session_ratchet_state(sender_jid, device_id) {
                    Ok(state) => {
                        // Use the root key from the ratchet state as our session key
                        //debug!("Using existing session with {} (device {})", sender_jid, device_id);
                        Ok(state.unwrap().root_key.clone())
                    },
                    Err(e) => {
                        error!("No valid session found for {} (device {}): {}", sender_jid, device_id, e);
                        // Instead of using zeros, try to establish a new session or return error
                        Err(anyhow!("No valid session found: {}. You may need to refresh your OMEMO keys.", e))
                    }
                }
            },
            Err(e) => {
                error!("Failed to create OMEMO storage: {}", e);
                Err(anyhow!("Failed to create OMEMO storage: {}", e))
            }
        }
    }

    /// Process an OMEMO message carbon (sent or received via XEP-0280)
    pub async fn process_omemo_carbon(
        &self,
        stanza: &xmpp_parsers::Element,
    ) -> Result<()> {
        //debug!("Processing OMEMO message carbon");
        
        // This is now just a gateway to the more comprehensive implementation in message_carbons.rs
        self.process_carbon(stanza).await
    }

    /// Set whether message carbons are enabled for this client
    pub fn set_carbons_enabled(&self, enabled: bool) {
        //debug!("Setting carbon status to {}", enabled);
        self.carbons_enabled.store(enabled, Ordering::SeqCst);
        if enabled {
            //debug!("Message carbons enabled");
        } else {
            //debug!("Message carbons disabled");
        }
    }

    /// Check if carbons are currently enabled for this client
    pub fn is_carbons_enabled(&self) -> bool {
        self.carbons_enabled.load(Ordering::SeqCst)
    }

    /// Enable Message Carbons feature
    pub async fn enable_carbons(&self) -> Result<bool> {
        //debug!("Using new enable_carbons method in mod.rs");
        
        // Call the implementation in message_carbons.rs
        self.enable_carbons_protocol().await
    }
    

    /// Enable message carbons (XEP-0280)
    /// This is a compatibility shim that uses the implementation from message_carbons.rs
    pub async fn enable_carbons_compat(&self) -> Result<bool> {
        //debug!("Using compatibility shim for enable_carbons");
        
        // Delegate to the actual implementation in message_carbons module
        if let Some(_client_ref) = &self.client {
            // The implementation from message_carbons.rs will be used
            // since that one is more complete and up-to-date
            return self.enable_carbons().await;
        }
        
        Err(anyhow!("XMPP client not initialized"))
    }

    /// Initialize the client
    pub async fn initialize_client(&mut self) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("Client not initialized"));
        }
        
        // Create the OMEMO manager
        let omemo_manager = match crate::omemo::OmemoManager::new(
            crate::omemo::storage::OmemoStorage::new_default()?,
            self.jid.clone(),
            None
        ).await {
            Ok(manager) => manager,
            Err(e) => {
                error!("Failed to initialize OMEMO manager: {}", e);
                return Err(anyhow!("Failed to initialize OMEMO manager: {}", e));
            }
        };
        
        // Initialize OMEMO for this client
        info!("Initializing OMEMO for {}", self.jid);
        
        // Set the current client for OMEMO operations
        if let Some(client_ref) = &self.client {
            //debug!("Setting current client for OMEMO integration during initialization");
            // We can't clone the guard directly, so use the Arc reference instead
            crate::xmpp::omemo_integration::set_current_client_arc(client_ref.clone());
            //debug!("Successfully set current client for OMEMO integration");
        }
        
        // Generate and publish device list if needed
        if let Err(e) = omemo_manager.ensure_device_list_published().await {
            error!("Failed to publish device list: {}", e);
            return Err(anyhow!("Failed to publish device list: {}", e));
        }
        
        // Generate and publish device bundle if needed
        if let Err(e) = omemo_manager.ensure_bundle_published().await {
            error!("Failed to publish device bundle: {}", e);
            return Err(anyhow!("Failed to publish device bundle: {}", e));
        }
        
        // Store the OMEMO manager in the client
        self.omemo_manager = Some(Arc::new(TokioMutex::new(omemo_manager)));
        info!("OMEMO initialized successfully");
        
        Ok(())
    }

    /// Handle an encrypted message using OMEMO
    pub async fn handle_message_encrypted(&mut self, element: &xmpp_parsers::Element) -> Result<()> {
        // Extract important attributes
        let from = element.attr("from").unwrap_or("unknown@server.example");
        let id = element.attr("id").unwrap_or("unknown");
        
        //debug!("Received encrypted message from {} with ID: {}", from, id);
        
        // Look for OMEMO encrypted element
        if let Some(encrypted) = element.get_child("encrypted", custom_ns::OMEMO) {
            if let Some(header) = encrypted.get_child("header", custom_ns::OMEMO) {
                // Extract sender device ID
                let sender_device_id = match header.attr("sid") {
                    Some(sid) => match sid.parse::<u32>() {
                        Ok(id) => id,
                        Err(e) => {
                            error!("Invalid sender device ID: {}", e);
                            return Err(anyhow!("Invalid sender device ID: {}", e));
                        }
                    },
                    None => {
                        error!("Missing sender device ID in OMEMO header");
                        return Err(anyhow!("Missing sender device ID in OMEMO header"));
                    }
                };
                
                // Get our OMEMO manager
                let omemo_manager = match &self.omemo_manager {
                    Some(manager) => manager.clone(),
                    None => {
                        error!("OMEMO manager not initialized");
                        return Err(anyhow!("OMEMO manager not initialized"));
                    }
                };
                
                // Process encrypted message using the OMEMO manager
                // Extract necessary information to create an OmemoMessage
                
                // Get IV
                let iv = match header.get_child("iv", "") {
                    Some(iv_elem) => {
                        match iv_elem.text() {
                            text => {
                                let iv_base64 = text;
                                match base64::engine::general_purpose::STANDARD.decode(iv_base64) {
                                    Ok(iv_bytes) => iv_bytes,
                                    Err(e) => {
                                        error!("Failed to decode IV: {}", e);
                                        return Err(anyhow!("Failed to decode IV: {}", e));
                                    }
                                }
                            }
                        }
                    },
                    None => {
                        error!("Missing IV in OMEMO header");
                        return Err(anyhow!("Missing IV in OMEMO header"));
                    }
                };
                
                // Collect encrypted keys for each device
                let mut encrypted_keys = std::collections::HashMap::new();
                for key_elem in header.children().filter(|e| e.name() == "key") {
                    if let (Some(rid_str), text) = (key_elem.attr("rid"), key_elem.text()) {
                        let key_base64 = text;
                        match rid_str.parse::<u32>() {
                            Ok(recipient_id) => {
                                match base64::engine::general_purpose::STANDARD.decode(key_base64) {
                                    Ok(key_bytes) => {
                                        encrypted_keys.insert(recipient_id, key_bytes);
                                    },
                                    Err(e) => {
                                        error!("Failed to decode key for device {}: {}", rid_str, e);
                                        // Continue with other keys
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Invalid recipient ID: {}", e);
                                // Continue with other keys
                            }
                        }
                    }
                }
                
                // Get payload
                let payload = match encrypted.get_child("payload", "") {
                    Some(payload_elem) => {
                        match payload_elem.text() {
                            text => {
                                let payload_base64 = text;
                                match base64::engine::general_purpose::STANDARD.decode(payload_base64) {
                                    Ok(payload_bytes) => payload_bytes,
                                    Err(e) => {
                                        error!("Failed to decode payload: {}", e);
                                        return Err(anyhow!("Failed to decode payload: {}", e));
                                    }
                                }
                            }
                        }
                    },
                    None => {
                        error!("Missing payload in OMEMO message");
                        return Err(anyhow!("Missing payload in OMEMO message"));
                    }
                };
                
                // Create the OMEMO message
                let omemo_message = crate::omemo::protocol::OmemoMessage {
                    sender_device_id,
                    ratchet_key: vec![],  // This will be handled by the session
                    previous_counter: 0,  // This will be handled by the session
                    counter: 0,           // This will be handled by the session
                    ciphertext: payload,
                    mac: vec![],          // This will be verified by the session
                    iv,
                    encrypted_keys,
                };
                
                // Decrypt the message
                let mut omemo_manager_guard = omemo_manager.lock().await;
                match omemo_manager_guard.decrypt_message(from, sender_device_id, &omemo_message).await {
                    Ok(plaintext) => {
                        // Create a message for the UI
                        let message = Message {
                            id: id.to_string(),
                            sender_id: from.to_string(),
                            recipient_id: self.jid.clone(),
                            content: plaintext,
                            timestamp: chrono::Utc::now().timestamp() as u64,
                            delivery_status: DeliveryStatus::Delivered,
                        };
                        
                        // Send to UI
                        if let Err(e) = self.msg_tx.send(message).await {
                            error!("Failed to send decrypted message to UI: {}", e);
                        } else {
                            //debug!("Sent decrypted message to UI");
                        }
                        
                        // Send a receipt if requested
                        if element.has_child("request", custom_ns::RECEIPTS) {
                            if let Some(client) = &self.client {
                                // Create a receipt stanza
                                let receipt = xmpp_parsers::Element::builder("message", NS_JABBER_CLIENT)
                                    .attr("to", from)
                                    .attr("id", &uuid::Uuid::new_v4().to_string())
                                    .append(
                                        xmpp_parsers::Element::builder("received", custom_ns::RECEIPTS)
                                            .attr("id", id)
                                            .build()
                                    )
                                    .build();
                                
                                let mut client_guard = client.lock().await;
                                if let Err(e) = client_guard.send_stanza(receipt).await {
                                    error!("Failed to send receipt: {}", e);
                                } else {
                                    //debug!("Sent receipt for message {}", id);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        // Enhanced error logging with more details
                        error!("Failed to decrypt message from {} (device {}): {}", from, sender_device_id, e);
                        error!("Message ID: {}, Decryption failure details: {:?}", id, e);
                        
                        // Log the OMEMO message structure for debugging (without sensitive keys)
                        debug!("OMEMO message structure - Sender device: {}, IV length: {}, Payload length: {}, Number of keys: {}", 
                            omemo_message.sender_device_id,
                            omemo_message.iv.len(),
                            omemo_message.ciphertext.len(),
                            omemo_message.encrypted_keys.len());
                        
                        // Create more informative error message for the UI
                        let message = Message {
                            id: id.to_string(),
                            sender_id: from.to_string(),
                            recipient_id: self.jid.clone(),
                            content: format!("[Encrypted message could not be decrypted: {}. You may need to refresh the OMEMO keys or verify device identity.]", e),
                            timestamp: chrono::Utc::now().timestamp() as u64,
                            delivery_status: DeliveryStatus::Delivered,
                        };
                        
                        // Send to UI
                        if let Err(e) = self.msg_tx.send(message).await {
                            error!("Failed to send error message to UI: {}", e);
                        }
                    }
                }
                
                return Ok(());
            }
        }
        
        error!("Could not find required OMEMO elements in encrypted message");
        Err(anyhow!("Could not find required OMEMO elements in encrypted message"))
    }

    /// Send an encrypted message using OMEMO
    pub async fn send_encrypted_message(&mut self, to: &str, content: &str) -> Result<()> {
        //debug!("Sending encrypted message to {}", to);
        //debug!("[JID DEBUG] send_encrypted_message: to='{}'", to);
        
        // Get our OMEMO manager
        let omemo_manager = match &self.omemo_manager {
            Some(manager) => manager.clone(),
            None => {
                // Initialize OMEMO manager if needed
                self.initialize_client().await?;
                match &self.omemo_manager {
                    Some(manager) => manager.clone(),
                    None => {
                        error!("Failed to initialize OMEMO manager");
                        return Err(anyhow!("Failed to initialize OMEMO manager"));
                    }
                }
            }
        };
        
        // Encrypt the message
        let mut omemo_manager_guard = omemo_manager.lock().await;
        let encrypted_message = match omemo_manager_guard.encrypt_message(to, content).await {
            Ok(message) => message,
            Err(e) => {
                error!("Failed to encrypt message: {}", e);
                return Err(anyhow!("Failed to encrypt message: {}", e));
            }
        };
        
        // Debug: Print the encrypted message structure
        //debug!("Encrypted message structure: {:?}", encrypted_message);
        
        // Use the verify_message_encryption function to check for plaintext leakage
        let omemo_verified = omemo_manager_guard.verify_message_encryption(&format!("{:?}", &encrypted_message), content);
        match &omemo_verified {
            Ok(_) => debug!("OMEMO encryption verification passed - no plaintext leaked"),
            Err(e) => {
                error!("OMEMO encryption verification failed: {}", e);
                return Err(anyhow!("OMEMO encryption verification failed: {}", e));
            }
        }

        drop(omemo_manager_guard);
        
        // Generate a message ID
        let id = uuid::Uuid::new_v4().to_string();
        
        // Create the OMEMO message stanza with explicit namespace handling
        let mut message_element = Element::builder("message", "jabber:client").build();
        message_element.set_attr("id", &id);
        message_element.set_attr("to", to);
        message_element.set_attr("type", "chat");
        
        // Add receipt request with correct namespace
        let request_element = Element::builder("request", custom_ns::RECEIPTS).build();
        message_element.append_child(request_element);
        
        // Add chat state with correct namespace
        let active_element = Element::builder("active", custom_ns::CHATSTATES).build();
        message_element.append_child(active_element);
        
        // Create encrypted element with OMEMO namespace
        let mut encrypted_element = Element::builder("encrypted", custom_ns::OMEMO).build();
        
        // Create header element with OMEMO namespace
        let mut header_element = Element::builder("header", custom_ns::OMEMO).build();
        header_element.set_attr("sid", &encrypted_message.sender_device_id.to_string());
        
        // Add key elements with OMEMO namespace
        for (device_id, encrypted_key) in &encrypted_message.encrypted_keys {
            let mut key_element = Element::builder("key", custom_ns::OMEMO).build();
            key_element.set_attr("rid", &device_id.to_string());
            key_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(encrypted_key));
            header_element.append_child(key_element);
        }
        
        // Add IV element with OMEMO namespace
        let mut iv_element = Element::builder("iv", custom_ns::OMEMO).build();
        iv_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.iv));
        header_element.append_child(iv_element);
        
        // Add payload element with OMEMO namespace
        let mut payload_element = Element::builder("payload", custom_ns::OMEMO).build();
        payload_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.ciphertext));
        
        // Assemble the elements
        encrypted_element.append_child(header_element);
        encrypted_element.append_child(payload_element);
        message_element.append_child(encrypted_element);
        
        // Use the message element
        let stanza = message_element;

        // Convert the stanza to string for inspection
        let stanza_str = introspection::stanza_to_string(&stanza);
        
        // Debug: Print the raw XML stanza
        //debug!("Raw OMEMO stanza XML: {}", stanza_str);
        
        // Verify the stanza structure with our dedicated function
        match verify_omemo_stanza(&stanza, content) {
            Ok(_) => debug!("OMEMO stanza structure verification passed - all required elements present"),
            Err(e) => {
                error!("{}", e);
                return Err(anyhow!("Failed to create valid OMEMO stanza: {}", e));
            }
        }
        
        // Directly send to XML inspectors for the test to verify
        introspection::inspect_outbound_xml(&stanza_str);
        
        // Send the message with XML inspection to verify encryption
        if let Some(client) = &self.client {
            // Debug: Print the client state before sending (just existence, as AsyncClient doesn't implement Debug)
            //debug!("Client exists and is ready to send message");
            
            // Then perform the actual send
            let mut client_guard = client.lock().await;
            match client_guard.send_stanza(stanza).await {
                Ok(_) => debug!("Successfully sent stanza to XMPP server"),
                Err(e) => {
                    error!("Failed to send stanza to XMPP server: {}", e);
                    return Err(anyhow!("Failed to send stanza: {}", e));
                }
            }
            
            //debug!("Sent encrypted message to {}", to);
            
            // Store message ID in pending receipts
            let mut pending_receipts_guard = self.pending_receipts.lock().await;
            let pending_message = PendingMessage {
                id: id.clone(),
                to: to.to_string(),
                content: content.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                status: DeliveryStatus::Sent,
            };
            pending_receipts_guard.insert(id.clone(), pending_message);
            
            // Create a "sent" message for the UI
            let message = Message {
                id: id.clone(),
                sender_id: "me".to_string(),  // Use "me" instead of self.jid to make UI show "You"
                recipient_id: to.to_string(),
                content: content.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                delivery_status: DeliveryStatus::Sent,
            };
            
            if let Err(e) = self.msg_tx.send(message).await {
                error!("Failed to send message to UI: {}", e);
            }
            
            Ok(())
        } else {
            error!("Client not initialized");
            Err(anyhow!("Client not initialized"))
        }
    }

    /// Get access to the OMEMO manager (primarily for testing)
    pub fn get_omemo_manager(&self) -> Option<Arc<TokioMutex<crate::omemo::OmemoManager>>> {
        self.omemo_manager.clone()
    }

    /// Store a message ID for tracking status updates
    /// 
    /// This method stores a message ID associated with a recipient so that
    /// delivery and read receipts can be matched to the original message.
    ///
    /// # Arguments
    ///
    /// * `recipient` - The JID of the message recipient
    /// * `message_id` - The unique ID of the message
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure
    pub async fn store_message_id(&self, recipient: &str, message_id: &str) -> Result<()> {
        //debug!("Storing message ID {} for recipient {}", message_id, recipient);
        
        // Store the message in our pending receipts map
        let mut pending_receipts = self.pending_receipts.lock().await;
        
        // Create a pending message entry - we don't have all the details but enough for tracking
        let pending_message = PendingMessage {
            id: message_id.to_string(),
            to: recipient.to_string(),
            content: String::new(), // Content no longer needed as we already have the message in UI
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: DeliveryStatus::Sent, // Initial status
        };
        
        // Insert into our tracking map
        pending_receipts.insert(message_id.to_string(), pending_message);
        
        Ok(())
    }

    /// Process a key verification response from the user
    /// 
    /// This is a UI-aware wrapper around the omemo_integration implementation
    pub async fn handle_key_verification_response(&self, contact: &str, response: &str) -> Result<()> {
        info!("Processing key verification response for {}: {}", contact, response);
        
        // Handle UI updates first
        match response {
            "__KEY_ACCEPTED__" => {
                info!("OMEMO key for {} has been accepted by user", contact);
                
                // Add a system message to the UI
                let system_message = Message {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender_id: "system".to_string(),
                    recipient_id: "me".to_string(),
                    content: format!("OMEMO key for {} has been accepted and marked as trusted", contact),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    delivery_status: DeliveryStatus::Unknown,
                };
                
                // Send the message to the UI
                if let Err(e) = self.msg_tx.send(system_message).await {
                    error!("Failed to send key acceptance message to UI: {}", e);
                }
                
                // Delegate to the implementation in omemo_integration for the actual trust operation
                if let Err(e) = self.process_omemo_verification_response(contact, response).await {
                    error!("Failed to process key verification in OMEMO: {}", e);
                    return Err(anyhow!("Failed to process key verification: {}", e));
                }
            },
            "__KEY_REJECTED__" => {
                info!("OMEMO key for {} has been rejected by user", contact);
                
                // Add a system message to the UI
                let system_message = Message {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender_id: "system".to_string(),
                    recipient_id: "me".to_string(),
                    content: format!("OMEMO key for {} has been rejected", contact),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    delivery_status: DeliveryStatus::Unknown,
                };
                
                // Send the message to the UI
                if let Err(e) = self.msg_tx.send(system_message).await {
                    error!("Failed to send key rejection message to UI: {}", e);
                }
                
                // Delegate to the implementation in omemo_integration for the actual untrust operation
                if let Err(e) = self.process_omemo_verification_response(contact, response).await {
                    error!("Failed to process key rejection in OMEMO: {}", e);
                    return Err(anyhow!("Failed to process key rejection: {}", e));
                }
            },
            _ => {
                // Unknown response
                warn!("Unknown key verification response: {}", response);
                return Err(anyhow!("Unknown key verification response: {}", response));
            }
        }
        
        Ok(())
    }

    /// Check OMEMO keys for a contact and request verification if needed
    pub async fn check_omemo_keys_for_contact(&self, contact: &str) -> Result<()> {
        //debug!("Checking OMEMO keys for contact: {}", contact);
        
        // Skip checks for special contacts
        if contact.starts_with('[') && contact.ends_with(']') {
            return Ok(());
        }

        // If we don't have an OMEMO manager, can't verify keys
        if self.omemo_manager.is_none() {
            warn!("No OMEMO manager available for key verification");
            return Ok(());
        }
        
        let omemo_manager = self.omemo_manager.as_ref().unwrap();
        
        // First, get the device IDs for this contact
        let device_ids = {
            let manager_guard = omemo_manager.lock().await;
            manager_guard.get_device_ids_for_test(contact).await?
        };
        
        if device_ids.is_empty() {
            //debug!("No OMEMO devices found for {}", contact);
            return Ok(());
        }
        
        info!("Found {} OMEMO devices for {}", device_ids.len(), contact);
        
        // Use the OMEMO storage to check if there's any pending verification for this contact
        let storage = crate::omemo::storage::OmemoStorage::new_default()?;
        let pending_verification = storage.get_pending_device_verification(contact);
        
        // If there's a pending verification, don't ask again
        if let Ok(Some(_)) = pending_verification {
            //debug!("There's already a pending verification for {}. Not asking again.", contact);
            return Ok(());
        }
        
        // Check each device to see if it's trusted
        for device_id in device_ids {
            // Check if this device is already trusted
            let trusted = {
                let manager_guard = omemo_manager.lock().await;
                manager_guard.is_device_identity_trusted(contact, device_id).await?
            };
            
            if !trusted {
                // This device is not trusted, get its fingerprint and request verification
                let fingerprint = {
                    let manager_guard = omemo_manager.lock().await;
                    manager_guard.get_device_fingerprint(contact, device_id).await?
                };
                
                // Double-check if this fingerprint is already trusted in the database
                // This handles cases where the trust state was updated but not properly reflected in memory
                let fingerprint_trusted = storage.is_device_trusted(contact, device_id)?;
                if fingerprint_trusted {
                    //debug!("Device {}:{} is already trusted in the database. Updating trust state in manager.", contact, device_id);
                    
                    // Update the trust state in the manager
                    let manager_guard = omemo_manager.lock().await;
                    if let Err(e) = manager_guard.trust_device_identity(contact, device_id).await {
                        warn!("Failed to update device trust state in manager: {}", e);
                    }
                    
                    // Continue to the next device
                    continue;
                }
                
                // Save this pending verification in the database so we don't ask again
                if let Err(e) = storage.store_pending_device_verification(contact, device_id, &fingerprint) {
                    warn!("Failed to store pending verification: {}", e);
                }
                
                // Request verification from the user
                info!("Requesting verification for untrusted device {}:{} with fingerprint {}", 
                     contact, device_id, fingerprint);
                
                // Request verification using detect_unrecognized_omemo_key which is the canonical implementation
                if let Err(e) = self.detect_unrecognized_omemo_key(contact, &fingerprint, Some(device_id)).await {
                    error!("Failed to request key verification: {}", e);
                    return Err(anyhow!("Failed to request key verification: {}", e));
                }
                
                // Only request verification for one device at a time to avoid overwhelming the user
                break;
            }
        }
        
        Ok(())
    }

    /// Request verification for an OMEMO key
    pub async fn process_key_verification_response(&self, sender: &str, key_fingerprint: &str, device_id: Option<u32>) -> Result<()> {
        // Create a special system message to trigger the verification UI
        let special_message = Message {
            id: uuid::Uuid::new_v4().to_string(),
            sender_id: "system".to_string(),
            recipient_id: "me".to_string(),
            // Format: __OMEMO_KEY_VERIFY__:contact:fingerprint:device_id
            content: format!("__OMEMO_KEY_VERIFY__:{}:{}:{}", 
                            sender, 
                            key_fingerprint, 
                            device_id.map(|id| id.to_string()).unwrap_or_default()),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
        };
        
        // Send the special message to the UI
        if let Err(e) = self.msg_tx.send(special_message).await {
            error!("Failed to send key verification request to UI: {}", e);
            return Err(anyhow!("Failed to send key verification request to UI: {}", e));
        }
        
        Ok(())
    }

    /// Check if OMEMO encryption is enabled
    pub async fn is_omemo_enabled(&self) -> bool {
        // Check if the OMEMO manager is initialized
        self.omemo_manager.is_some()
    }

    /// Get device IDs for a user
    pub async fn get_device_ids_for_user(&self, jid: &str) -> Result<Vec<DeviceId>> {
        if let Some(omemo_manager) = &self.omemo_manager {
            // First try to request the device list from the server
            if let Err(e) = self.request_omemo_devicelist(jid).await {
                warn!("Failed to request device list from server, using cached data: {}", e);
            }
            
            // Then get the device IDs from the manager
            let manager = omemo_manager.lock().await;
            match manager.get_device_ids_for_test(jid).await {
                Ok(devices) => Ok(devices),
                Err(e) => Err(anyhow!("Failed to get device IDs: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Get fingerprint for a device
    pub async fn get_device_fingerprint(&self, jid: &str, device_id: DeviceId) -> Result<String> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.get_device_fingerprint(jid, device_id).await {
                Ok(fingerprint) => Ok(fingerprint),
                Err(e) => Err(anyhow!("Failed to get device fingerprint: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    // Find the send_message function or similar where messages are processed

    pub async fn send_message(&mut self, recipient: &str, content: &str) -> Result<()> {
        // Add detailed logging
        info!("SEND_MESSAGE CALLED: recipient={}, content_starts_with={}", 
             recipient, content.chars().take(30).collect::<String>());
        //debug!("[JID DEBUG] send_message: recipient='{}'", recipient);
        
        // Check if this is a key verification message
        if content.starts_with("__CHECK_KEY_VERIFICATION__") {
            info!("DETECTED key verification prefix in message content");
            
            // Extract the actual message content
            let real_message = content.trim_start_matches("__CHECK_KEY_VERIFICATION__");
            info!("Extracted real message: {}", real_message);
            
            // Perform OMEMO key verification if needed
            info!("Checking OMEMO keys for contact: {}", recipient);
            self.check_omemo_keys_for_contact(recipient).await?;
            
            // Now send the actual message without the verification prefix
            info!("Sending cleaned message without prefix to: {}", recipient);
            return self.send_encrypted_message(recipient, real_message).await;
        }
        
        // Check if OMEMO is enabled - if it is, always use encrypted messaging
        let omemo_enabled = self.is_omemo_enabled().await;
        
        if omemo_enabled {
            info!("OMEMO is enabled, sending encrypted message to: {}", recipient);
            
            // Try with regular send_encrypted_message first
            match self.send_encrypted_message(recipient, content).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.to_string().contains("SECURITY VIOLATION") || 
                       e.to_string().contains("verification failed") {
                        // If verification failed, try with debug version that provides more details
                        warn!("Initial encryption failed, trying with debug version: {}", e);
                        self.debug_send_encrypted_message(recipient, content).await
                    } else {
                        // For other errors, return as is
                        Err(e)
                    }
                }
            }
        } else {
            // Fallback to unencrypted message only when OMEMO is disabled
            info!("OMEMO is disabled, sending plaintext message to: {}", recipient);
            warn!("⚠️ WARNING: Message is being sent in plaintext without encryption!");
            self.send_message_with_receipt(recipient, content).await
        }
    }

    /// Toggle the trust status for all of a contact's OMEMO devices
    /// 
    /// This method will fetch all device IDs for the contact, check their trust status,
    /// and toggle it (if all trusted, make all untrusted; if any untrusted, make all trusted)
    /// 
    /// # Arguments
    /// 
    /// * `contact` - The JID of the contact whose keys should be toggled
    /// 
    /// # Returns
    /// 
    /// A Result containing a boolean indicating whether all devices are now trusted
    pub async fn toggle_omemo_trust(&self, contact: &str) -> Result<bool> {
        //debug!("Toggling OMEMO trust for all devices of {}", contact);
        
        // If we don't have an OMEMO manager, can't toggle trust
        if self.omemo_manager.is_none() {
            warn!("No OMEMO manager available for key trust toggle");
            return Err(anyhow!("No OMEMO manager available"));
        }
        
        let omemo_manager = self.omemo_manager.as_ref().unwrap();
        
        // First, get the device IDs for this contact
        let device_ids = {
            let manager_guard = omemo_manager.lock().await;
            manager_guard.get_device_ids_for_test(contact).await?
        };
        
        if device_ids.is_empty() {
            //debug!("No OMEMO devices found for {}", contact);
            return Err(anyhow!("No OMEMO devices found"));
        }
        
        info!("Found {} OMEMO devices for {}", device_ids.len(), contact);
        
        // Check each device to determine their current trust status
        let mut all_trusted = true;
        let mut _any_trusted = false;
        let mut statuses = Vec::new();
        
        for device_id in &device_ids {
            let trusted = {
                let manager_guard = omemo_manager.lock().await;
                manager_guard.is_device_identity_trusted(contact, *device_id).await?
            };
            
            statuses.push((*device_id, trusted));
            if trusted {
                _any_trusted = true;
            } else {
                all_trusted = false;
            }
        }
        
        // Target state: if all devices are trusted, we'll untrust all of them
        // If any device is untrusted, we'll trust all of them
        // We could also use 'any_trusted' to implement more complex logic if needed in the future
        let set_trusted = !all_trusted;
        
        // Apply the new trust state to all devices
        for (device_id, current_trusted) in statuses {
            if current_trusted != set_trusted {
                let manager_guard = omemo_manager.lock().await;
                
                if set_trusted {
                    // Trust device
                    //debug!("Marking device {}:{} as trusted", contact, device_id);
                    if let Err(e) = manager_guard.trust_device_identity(contact, device_id).await {
                        error!("Failed to trust device: {}", e);
                        return Err(anyhow!("Failed to trust device: {}", e));
                    }
                } else {
                    // Untrust device
                    //debug!("Marking device {}:{} as untrusted", contact, device_id);
                    if let Err(e) = manager_guard.untrust_device_identity(contact, device_id).await {
                        error!("Failed to untrust device: {}", e);
                        return Err(anyhow!("Failed to untrust device: {}", e));
                    }
                }
            }
        }
        
        let status_desc = if set_trusted { "trusted" } else { "untrusted" };
        info!("Successfully toggled {} devices for {} to {}", device_ids.len(), contact, status_desc);
        
        Ok(set_trusted)
    }

    /// Enable XML inspection for testing and debugging
    /// 
    /// This is primarily used to verify encryption is working correctly
    /// by inspecting the raw XML stanzas
    pub async fn enable_xml_inspection(&self, tx: mpsc::Sender<String>) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        let client_guard = client.lock().await;
        
        // Store the sender in the client for later use
        // For now, we'll just return Ok and handle inspection elsewhere
        // In a real implementation, we would hook into the client's send method
        
        // Register the XML inspector in a global registry
        introspection::register_inspector(tx);
        
        info!("XML inspection enabled for XMPP stanzas");
        drop(client_guard);
        
        Ok(())
    }

    // Helper function for debugging OMEMO encryption verification issues
    pub async fn debug_send_encrypted_message(&mut self, to: &str, content: &str) -> Result<()> {
        //debug!("DEBUG: Starting encrypted message sending to {}", to);
        
        // Get our OMEMO manager
        let omemo_manager = match &self.omemo_manager {
            Some(manager) => manager.clone(),
            None => {
                // Initialize OMEMO manager if needed
                self.initialize_client().await?;
                match &self.omemo_manager {
                    Some(manager) => manager.clone(),
                    None => {
                        error!("Failed to initialize OMEMO manager");
                        return Err(anyhow!("Failed to initialize OMEMO manager"));
                    }
                }
            }
        };
        
        // Encrypt the message
        let mut omemo_manager_guard = omemo_manager.lock().await;
        let encrypted_message = match omemo_manager_guard.encrypt_message(to, content).await {
            Ok(message) => message,
            Err(e) => {
                error!("Failed to encrypt message: {}", e);
                return Err(anyhow!("Failed to encrypt message: {}", e));
            }
        };
        
        // Debug: Print the encrypted message structure
        //debug!("DEBUG: Encrypted message structure: {:?}", encrypted_message);
        
        // Use the verify_message_encryption function to check for plaintext leakage
        let omemo_verified = omemo_manager_guard.verify_message_encryption(&format!("{:?}", &encrypted_message), content);
        match &omemo_verified {
            Ok(_) => debug!("DEBUG: OMEMO encryption verification passed - no plaintext leaked"),
            Err(e) => {
                error!("DEBUG: OMEMO encryption verification failed: {}", e);
                return Err(anyhow!("OMEMO encryption verification failed: {}", e));
            }
        }

        drop(omemo_manager_guard);
        
        // Generate a message ID
        let id = uuid::Uuid::new_v4().to_string();
        //debug!("DEBUG: Generated message ID: {}", id);
        
        // Create the OMEMO message stanza with explicit namespace handling
        let mut message_element = Element::builder("message", "jabber:client").build();
        message_element.set_attr("id", &id);
        message_element.set_attr("to", to);
        message_element.set_attr("type", "chat");
        
        // Add receipt request with correct namespace
        let request_element = Element::builder("request", custom_ns::RECEIPTS).build();
        message_element.append_child(request_element);
        
        // Add chat state with correct namespace
        let active_element = Element::builder("active", custom_ns::CHATSTATES).build();
        message_element.append_child(active_element);
        
        // Create encrypted element with OMEMO namespace
        //debug!("DEBUG: Building encrypted element with namespace: {}", custom_ns::OMEMO);
        let mut encrypted_element = Element::builder("encrypted", custom_ns::OMEMO).build();
        
        // Create header element with OMEMO namespace
        //debug!("DEBUG: Building header element with namespace: {}", custom_ns::OMEMO);
        let mut header_element = Element::builder("header", custom_ns::OMEMO).build();
        header_element.set_attr("sid", &encrypted_message.sender_device_id.to_string());
        
        // Add key elements with OMEMO namespace
        //debug!("DEBUG: Adding {} key elements", encrypted_message.encrypted_keys.len());
        for (device_id, encrypted_key) in &encrypted_message.encrypted_keys {
            let mut key_element = Element::builder("key", custom_ns::OMEMO).build();
            key_element.set_attr("rid", &device_id.to_string());
            key_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(encrypted_key));
            header_element.append_child(key_element);
        }
        
        // Add IV element with OMEMO namespace
        let mut iv_element = Element::builder("iv", custom_ns::OMEMO).build();
        iv_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.iv));
        header_element.append_child(iv_element);
        
        // Add payload element with OMEMO namespace
        let mut payload_element = Element::builder("payload", custom_ns::OMEMO).build();
        payload_element.append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.ciphertext));
        
        // Assemble the elements
        encrypted_element.append_child(header_element);
        encrypted_element.append_child(payload_element);
        message_element.append_child(encrypted_element);
        
        // Use the message element
        let stanza = message_element;

        // Convert the stanza to string for inspection
        let stanza_str = introspection::stanza_to_string(&stanza);
        
        // Debug: Print the raw XML stanza
        //debug!("DEBUG: Raw OMEMO stanza XML: {}", stanza_str);
        
        // Verify the stanza structure with our dedicated function
        //debug!("DEBUG: Verifying stanza structure");
        match verify_omemo_stanza(&stanza, content) {
            Ok(_) => debug!("DEBUG: OMEMO stanza structure verification passed - all required elements present"),
            Err(e) => {
                error!("DEBUG: {}", e);
                
                // DETAILED ERROR DIAGNOSIS
                //debug!("DEBUG: Detailed stanza structure:");
                //debug!("DEBUG: Root element: {} (ns: {})", stanza.name(), stanza.ns());
                
                if let Some(encrypted) = stanza.get_child("encrypted", custom_ns::OMEMO) {
                    //debug!("DEBUG: Found encrypted element with namespace: {}", encrypted.ns());
                    
                    if let Some(header) = encrypted.get_child("header", custom_ns::OMEMO) {
                        //debug!("DEBUG: Found header element with namespace: {}", header.ns());
                        //debug!("DEBUG: Header attributes: sid={}", header.attr("sid").unwrap_or("MISSING"));
                        
                        let key_count = header.children().filter(|c| c.name() == "key").count();
                        //debug!("DEBUG: Found {} key elements", key_count);
                        
                        if let Some(iv) = header.get_child("iv", custom_ns::OMEMO) {
                            //debug!("DEBUG: Found IV element with namespace: {}", iv.ns());
                            //debug!("DEBUG: IV content length: {}", iv.text().len());
                        } else if let Some(iv) = header.get_child("iv", "") {
                            //debug!("DEBUG: Found IV element with empty namespace: {}", iv.ns());
                            //debug!("DEBUG: IV content length: {}", iv.text().len());
                        } else {
                            error!("DEBUG: IV element missing");
                        }
                        
                    } else if let Some(header) = encrypted.get_child("header", "") {
                        //debug!("DEBUG: Found header element with empty namespace: {}", header.ns());
                    } else {
                        error!("DEBUG: Header element missing");
                    }
                    
                    if let Some(payload) = encrypted.get_child("payload", custom_ns::OMEMO) {
                        //debug!("DEBUG: Found payload element with namespace: {}", payload.ns());
                        //debug!("DEBUG: Payload content length: {}", payload.text().len());
                    } else if let Some(payload) = encrypted.get_child("payload", "") {
                        //debug!("DEBUG: Found payload element with empty namespace: {}", payload.ns());
                        //debug!("DEBUG: Payload content length: {}", payload.text().len());
                    } else {
                        error!("DEBUG: Payload element missing");
                    }
                    
                } else {
                    error!("DEBUG: Encrypted element missing");
                    //debug!("DEBUG: Message children:");
                    for child in stanza.children() {
                        //debug!("  - {} (ns: {})", child.name(), child.ns());
                    }
                }
                
                return Err(anyhow!("Failed to create valid OMEMO stanza: {}", e));
            }
        }
        
        // Directly send to XML inspectors for the test to verify
        //debug!("DEBUG: Sending to XML inspectors");
        introspection::inspect_outbound_xml(&stanza_str);
        
        // Send the message with XML inspection to verify encryption
        if let Some(client) = &self.client {
            // Debug: Print the client state before sending (just existence, as AsyncClient doesn't implement Debug)
            //debug!("DEBUG: Client exists and is ready to send message");
            
            // Then perform the actual send
            let mut client_guard = client.lock().await;
            match client_guard.send_stanza(stanza).await {
                Ok(_) => debug!("DEBUG: Successfully sent stanza to XMPP server"),
                Err(e) => {
                    error!("DEBUG: Failed to send stanza to XMPP server: {}", e);
                    return Err(anyhow!("Failed to send stanza: {}", e));
                }
            }
            
            //debug!("DEBUG: Sent encrypted message to {}", to);
            
            // Store message ID in pending receipts
            let mut pending_receipts_guard = self.pending_receipts.lock().await;
            let pending_message = PendingMessage {
                id: id.clone(),
                to: to.to_string(),
                content: content.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                status: DeliveryStatus::Sent,
            };
            pending_receipts_guard.insert(id.clone(), pending_message);
            
            // Create a "sent" message for the UI
            let message = Message {
                id: id.clone(),
                sender_id: "me".to_string(),  // Use "me" instead of self.jid to make UI show "You"
                recipient_id: to.to_string(),
                content: content.to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                delivery_status: DeliveryStatus::Sent,
            };
            
            if let Err(e) = self.msg_tx.send(message).await {
                error!("DEBUG: Failed to send message to UI: {}", e);
            }
            
            Ok(())
        } else {
            error!("DEBUG: Client not initialized");
            Err(anyhow!("Client not initialized"))
        }
    }

    /// Force refresh OMEMO device list for a user
    pub async fn force_refresh_device_list(&self, jid: &str) -> Result<Vec<DeviceId>> {
        info!("Forcing refresh of OMEMO device list for {}", jid);
        
        if let Some(omemo_manager) = &self.omemo_manager {
            // First explicitly request the device list from the server
            if let Err(e) = self.request_omemo_devicelist(jid).await {
                warn!("Failed to request device list from server: {}", e);
                // Continue anyway, we'll try with cached data
            }
            
            // Then get the device IDs from the manager
            let manager = omemo_manager.lock().await;
            match manager.get_device_ids_for_test(jid).await {
                Ok(devices) => {
                    info!("Found {} devices for {}: {:?}", devices.len(), jid, devices);
                    Ok(devices)
                },
                Err(e) => Err(anyhow!("Failed to get device IDs: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Publish our device list to the server and ensure it includes our current device
    pub async fn publish_our_device_list(&self) -> Result<()> {
        info!("Publishing our device list to the server");
        
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            manager.ensure_device_list_published().await?;
            info!("Successfully published our device list");
            Ok(())
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Sync devices with a contact without changing trust status
    pub async fn sync_devices_with_contact(&self, contact: &str) -> Result<bool> {
        info!("Syncing OMEMO devices with contact: {}", contact);
        
        // Step 1: Get our device ID
        let our_device_id = match &self.omemo_manager {
            Some(manager) => {
                let manager_guard = manager.lock().await;
                manager_guard.get_device_id()
            },
            None => return Err(anyhow!("OMEMO manager not initialized")),
        };
        
        info!("Our device ID is: {}", our_device_id);
        
        // Step 2: Force publish our device list to make sure it's up to date
        self.publish_our_device_list().await?;
        
        // Step 3: Force refresh the contact's device list
        let contact_devices = self.force_refresh_device_list(contact).await?;
        
        if contact_devices.is_empty() {
            info!("Contact {} has no OMEMO devices", contact);
            return Ok(false);
        }
        
        // Step 4: For each of the contact's devices, get or create a session if needed
        // but don't modify trust status - that should only happen via user interaction
        let mut established_sessions = false;
        
        if let Some(omemo_manager) = &self.omemo_manager {
            let mut manager = omemo_manager.lock().await;
            
            for device_id in contact_devices {
                info!("Checking/creating session with {}:{}", contact, device_id);
                
                match manager.get_or_create_session(contact, device_id).await {
                    Ok(_) => {
                        info!("Session established or already exists with {}:{}", contact, device_id);
                        established_sessions = true;
                    },
                    Err(e) => {
                        warn!("Failed to establish session with {}:{}: {}", contact, device_id, e);
                    }
                }
            }
        }
        
        // If we haven't established any sessions, we'll return an error
        if !established_sessions {
            warn!("Failed to establish any sessions with {}", contact);
            return Ok(false);
        }
        
        // Request key verification through the UI if needed
        match self.check_omemo_keys_for_contact(contact).await {
            Ok(_) => info!("Key verification requested for {}", contact),
            Err(e) => warn!("Failed to request key verification: {}", e),
        }
        
        info!("Device sync with {} completed successfully", contact);
        Ok(true)
    }

    /// Get the internal client as an Arc for service discovery
    pub fn get_client_arc(&self) -> Option<Arc<TokioMutex<XMPPAsyncClient>>> {
        self.client.clone()
    }
    
    /// Get the global OMEMO manager
    /// This is used by the message carbons implementation to decrypt OMEMO messages
    pub async fn get_global_omemo_manager() -> Option<Arc<TokioMutex<crate::omemo::OmemoManager>>> {
        if let Some(client) = get_global_xmpp_client().await {
            let client_guard = client.lock().await;
            client_guard.omemo_manager.clone()
        } else {
            None
        }
    }

    /// Request items from a PubSub node
    /// This is needed for OMEMO to fetch device lists and bundles
    pub async fn request_pubsub_items(&self, from: &str, node: &str) -> Result<String> {
        //debug!("Requesting PubSub items from {} for node {}", from, node);
        
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        
        // Generate a unique ID for this request
        let request_id = uuid::Uuid::new_v4().to_string();
        
        // Create the pubsub element
        let mut pubsub_element = xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub").build();
        
    // Create the items element with the same namespace as pubsub
    let items_element = xmpp_parsers::Element::builder("items", "http://jabber.org/protocol/pubsub")
        .attr("node", node)
        .build();
        
        // Add to pubsub element
        pubsub_element.append_child(items_element);
        
        // Create the IQ stanza
        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "get")
            .attr("id", &request_id)
            .attr("to", from)
            .append(pubsub_element)
            .build();
        
        // Send the stanza
        //debug!("Sending PubSub request stanza: {:?}", iq);
        let mut client_guard = client.lock().await;
        
        match client_guard.send_stanza(iq).await {
            Ok(_) => {
                //debug!("PubSub request sent successfully for node {}", node);
                
                // Wait for the response with a timeout
                let response_timeout = std::time::Duration::from_secs(5);
                let start_time = tokio::time::Instant::now();
                
                while tokio::time::Instant::now() - start_time < response_timeout {
                    // Try to get the next event with a timeout
                    let event_result = tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        client_guard.next()
                    ).await;
                    
                    match event_result {
                        Ok(Some(event)) => {
                            if let XMPPEvent::Stanza(stanza) = event {
                                if stanza.name() == "iq" && stanza.attr("id") == Some(&request_id) {
                                    //debug!("Received PubSub response for ID: {}", request_id);
                                    
                                    // Convert the stanza to a string
                                    let response = introspection::stanza_to_string(&stanza);
                                    
                                    //debug!("PubSub response: {}", response);
                                    return Ok(response);
                                }
                            }
                        },
                        Ok(None) => {
                            error!("Connection closed while waiting for PubSub response");
                            return Err(anyhow!("Connection closed while waiting for PubSub response"));
                        },
                        Err(_) => {
                            // Timeout waiting for event, continue in the loop
                            continue;
                        },
                    }
                }
                
                // If we reach here, timeout occurred
                warn!("Timed out waiting for PubSub response for node {}", node);
                
                // For device list requests, if we timeout, respond with an empty list
                // This allows us to handle cases where the device list doesn't exist yet
                if node.contains("devicelist") {
                    //debug!("Returning empty device list response since none was found on server");
                    let empty_list_response = format!(r#"<?xml version="1.0" encoding="utf-8"?>
    <iq type="result" id="{}">
      <pubsub xmlns="http://jabber.org/protocol/pubsub">
        <items node="{}">
          <item id="current">
            <list xmlns="eu.siacs.conversations.axolotl"/>
          </item>
        </items>
      </pubsub>
    </iq>"#, request_id, node);
                    return Ok(empty_list_response);
                }
                
                return Err(anyhow!("Timed out waiting for PubSub response"));
            },
            Err(e) => {
                error!("Failed to send PubSub request: {}", e);
                return Err(anyhow!("Failed to send PubSub request: {}", e));
            }
        }
    }
}

// Global client registry for OMEMO integration
lazy_static::lazy_static! {
    static ref GLOBAL_CLIENT: std::sync::RwLock<Option<Arc<TokioMutex<XMPPClient>>>> = std::sync::RwLock::new(None);
}

/// Register the current client as the global instance
/// This allows other parts of the app to access it when needed
pub fn register_global_client(client: XMPPClient) {
    if let Ok(mut global_client) = GLOBAL_CLIENT.write() {
        info!("Registering global XMPP client instance with JID: {}", client.get_jid());
        *global_client = Some(Arc::new(TokioMutex::new(client)));
    } else {
        error!("Failed to acquire write lock for global client registry");
    }
}

/// Get the global XMPP client instance
/// This is used by the OMEMO implementation and other modules that need access to the client
pub async fn get_global_xmpp_client() -> Option<Arc<TokioMutex<XMPPClient>>> {
    if let Ok(global_client) = GLOBAL_CLIENT.read() {
        global_client.clone()
    } else {
        error!("Failed to acquire read lock for global client registry");
        None
    }
}

/// Helper function to verify OMEMO stanza structure
fn verify_omemo_stanza(stanza: &xmpp_parsers::Element, content: &str) -> Result<(), String> {
    //debug!("Starting OMEMO stanza verification...");
    //debug!("Stanza name: {}, namespace: {}", stanza.name(), stanza.ns());
    
    // First, check if the plaintext appears anywhere in the stanza string representation
    let stanza_str = format!("{:?}", stanza);
    if stanza_str.contains(content) {
        error!("SECURITY VIOLATION: Plaintext content found in encrypted message");
        return Err(format!("SECURITY VIOLATION: Plaintext content found in encrypted message"));
    }
    
    // Verify that all required OMEMO elements are present with proper namespaces
    let mut missing_elements = Vec::new();
    
    // Check message element exists with jabber:client namespace
    if stanza.name() != "message" || stanza.ns() != "jabber:client" {
        missing_elements.push("message element with jabber:client namespace");
        error!("Message element namespace issue: expected 'jabber:client', got '{}'", stanza.ns());
        return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                         missing_elements.join(", ")));
    }
    
    // Debug attributes
    //debug!("Message attributes:");
    for (name, value) in stanza.attrs() {
        //debug!("  - {}: {}", name, value);
    }
    
    // Check the encrypted element exists and has the right namespace
    let encrypted = match stanza.get_child("encrypted", custom_ns::OMEMO) {
        Some(elem) => {
            //debug!("Found encrypted element with namespace: {}", elem.ns());
            elem
        },
        None => {
            error!("Missing encrypted element with proper namespace");
            //debug!("Direct children of message element:");
            for child in stanza.children() {
                //debug!("  - {} (ns: {})", child.name(), child.ns());
            }
            missing_elements.push("OMEMO namespace, encrypted element");
            return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                             missing_elements.join(", ")));
        }
    };
    
    // Check header element - note that child elements may inherit namespace from parent
    let header = match encrypted.get_child("header", custom_ns::OMEMO) {
        Some(elem) => {
            //debug!("Found header element with explicit OMEMO namespace: {}", elem.ns());
            elem
        },
        None => {
            // Try again with empty namespace since it might inherit from parent
            match encrypted.get_child("header", "") {
                Some(elem) => {
                    //debug!("Found header element with inherited namespace from parent: {}", elem.ns());
                    elem
                },
                None => {
                    error!("Missing header element in encrypted element");
                    //debug!("Direct children of encrypted element:");
                    for child in encrypted.children() {
                        //debug!("  - {} (ns: {})", child.name(), child.ns());
                    }
                    missing_elements.push("header element");
                    return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                                     missing_elements.join(", ")));
                }
            }
        }
    };
    
    // Check sender device ID
    if let Some(sid) = header.attr("sid") {
        //debug!("Found sender device ID: {}", sid);
    } else {
        error!("Missing sender device ID in header element");
        missing_elements.push("sender device ID");
    }
    
    // Check IV element - try both with OMEMO namespace and empty namespace
    let iv = header.get_child("iv", custom_ns::OMEMO)
        .or_else(|| header.get_child("iv", ""));
    
    if let Some(iv_elem) = iv {
        //debug!("Found IV element with namespace: {}", iv_elem.ns());
        let iv_text = iv_elem.text();
        //debug!("IV content length: {}", iv_text.len());
        // Check if IV content is valid base64
        match base64::engine::general_purpose::STANDARD.decode(iv_text.trim()) {
            Ok(decoded) => debug!("Valid base64 IV content, decoded length: {} bytes", decoded.len()),
            Err(e) => error!("Invalid base64 in IV element: {}", e),
        }
    } else {
        error!("Missing initialization vector (iv) element in header");
        //debug!("Header children:");
        for child in header.children() {
            //debug!("  - {} (ns: {})", child.name(), child.ns());
        }
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
        //debug!("Found {} key elements", key_elements.len());
        for (i, key) in key_elements.iter().enumerate() {
            let rid = key.attr("rid").unwrap_or("missing-rid");
            debug!("Key {}: rid={}, namespace={}, content_length={}", 
                  i, rid, key.ns(), key.text().len());
            
            // Check if key content is valid base64
            match base64::engine::general_purpose::STANDARD.decode(key.text().trim()) {
                Ok(decoded) => debug!("Valid base64 key content, decoded length: {} bytes", decoded.len()),
                Err(e) => error!("Invalid base64 in key element: {}", e),
            }
        }
    }
    
    // Check payload element - try both with OMEMO namespace and empty namespace
    let payload = encrypted.get_child("payload", custom_ns::OMEMO)
        .or_else(|| encrypted.get_child("payload", ""));
    
    if let Some(payload_elem) = payload {
        //debug!("Found payload element with namespace: {}", payload_elem.ns());
        let payload_text = payload_elem.text();
        //debug!("Payload content length: {}", payload_text.len());
        
        // Check if payload content is valid base64
        match base64::engine::general_purpose::STANDARD.decode(payload_text.trim()) {
            Ok(decoded) => debug!("Valid base64 payload content, decoded length: {} bytes", decoded.len()),
            Err(e) => error!("Invalid base64 in payload element: {}", e),
        }
    } else {
        error!("Missing payload element in encrypted element");
        //debug!("Encrypted element children:");
        for child in encrypted.children() {
            debug!("  - {} (ns: {})", child.name(), child.ns());
        }
        missing_elements.push("encrypted payload");
    }
    
    // Return result based on missing elements
    if missing_elements.is_empty() {
        //debug!("OMEMO stanza verification successful - all required elements present");
        Ok(())
    } else {
        error!("OMEMO stanza verification failed - missing elements: {}", missing_elements.join(", "));
        Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", 
                  missing_elements.join(", ")))
    }
}
