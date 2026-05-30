// src/xmpp/event_loop.rs
//! Main XMPP event loop for handling incoming stanzas

use log::{debug, error, info, warn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use std::sync::atomic::AtomicBool;
use futures_util::Stream;

use tokio_xmpp::{AsyncClient as XMPPAsyncClient, Event as XMPPEvent};

use crate::models::{Message, DeliveryStatus, PendingMessage};
use super::{XMPPClient, custom_ns, get_global_xmpp_client, TYPING_TX};
use super::{chat_states, delivery_receipts, discovery, presence};

impl XMPPClient {
    // Primary message handling loop
    pub(super) async fn handle_incoming_messages(
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
            // Acquire lock with timeout, then do a non-blocking poll of the stream.
            // IMPORTANT: We must not wrap client_guard.next() in tokio::time::timeout,
            // because dropping that future mid-poll corrupts tokio_xmpp's internal state
            // machine (leaves it in ClientState::Invalid, causing a panic on next poll).
            let event = {
                let lock_result = tokio::time::timeout(
                    Duration::from_secs(2),
                    client.lock()
                ).await;
                
                match lock_result {
                    Ok(mut client_guard) => {
                        futures_util::future::poll_fn(|cx| {
                            match Pin::new(&mut *client_guard).poll_next(cx) {
                                Poll::Ready(event) => Poll::Ready(Some(event)),
                                Poll::Pending => Poll::Ready(None),
                            }
                        }).await
                    },
                    Err(_) => {
                        // Timed out acquiring lock
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            };
            
            // If no event was ready (Pending), sleep briefly and retry
            let event = match event {
                Some(event) => event,
                None => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            match event {
                Some(XMPPEvent::Stanza(stanza)) => {
                    if stanza.name() == "presence" {
                        // Handle presence stanzas
                        let _from = stanza.attr("from").unwrap_or("");
                        let _to = stanza.attr("to").unwrap_or("");
                        
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
                        let from = stanza.attr("from").unwrap_or("");
                        let to = stanza.attr("to").unwrap_or("");
                        info!("Received message stanza from='{}', to='{}'", from, to);
                        debug!("Message stanza content: {:?}", stanza);
                        
                        // Helper function to check for OMEMO elements in a message stanza
                        fn has_omemo_encryption(msg_stanza: &xmpp_parsers::Element) -> (bool, bool, bool, bool) {
                            let has_omemo_v1 = msg_stanza.has_child("encrypted", custom_ns::OMEMO);
                            let has_omemo_axolotl = msg_stanza.has_child("encrypted", custom_ns::OMEMO_V1);
                            let has_omemo_empty = msg_stanza.has_child("encrypted", "");
                            let has_omemo_explicit = msg_stanza.has_child("encrypted", "eu.siacs.conversations.axolotl");
                            (has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit)
                        }
                        
                        // Check for OMEMO encrypted messages in the outer stanza
                        let (has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit) = has_omemo_encryption(&stanza);
                        
                        // Also check for MAM forwarded messages that might contain OMEMO
                        let mut mam_message_stanza = None;
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if let Some(forwarded) = result.get_child("forwarded", custom_ns::FORWARD) {
                                if let Some(inner_msg) = forwarded.get_child("message", "jabber:client") {
                                    mam_message_stanza = Some(inner_msg);
                                }
                            }
                        }
                        
                        // Check for OMEMO in MAM forwarded message if present
                        let (mam_has_omemo_v1, mam_has_omemo_axolotl, mam_has_omemo_empty, mam_has_omemo_explicit) = 
                            if let Some(mam_msg) = &mam_message_stanza {
                                has_omemo_encryption(mam_msg)
                            } else {
                                (false, false, false, false)
                            };
                        
                        let has_any_omemo = has_omemo_v1 || has_omemo_axolotl || has_omemo_empty || has_omemo_explicit;
                        let has_mam_omemo = mam_has_omemo_v1 || mam_has_omemo_axolotl || mam_has_omemo_empty || mam_has_omemo_explicit;
                        
                        warn!("OMEMO detection: outer(v1={}, axolotl={}, empty={}, explicit={}), MAM(v1={}, axolotl={}, empty={}, explicit={})", 
                            has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit,
                            mam_has_omemo_v1, mam_has_omemo_axolotl, mam_has_omemo_empty, mam_has_omemo_explicit);
                        
                        // Debug logging for found encrypted elements
                        if has_any_omemo {
                            if let Some(encrypted) = stanza.get_child("encrypted", "") {
                                warn!("Found encrypted element in outer stanza with empty namespace: {:?}", encrypted);
                            }
                            if let Some(encrypted) = stanza.get_child("encrypted", "eu.siacs.conversations.axolotl") {
                                warn!("Found encrypted element in outer stanza with axolotl namespace: {:?}", encrypted);
                            }
                        }
                        if has_mam_omemo {
                            if let Some(mam_msg) = &mam_message_stanza {
                                if let Some(encrypted) = mam_msg.get_child("encrypted", "") {
                                    warn!("Found encrypted element in MAM message with empty namespace: {:?}", encrypted);
                                }
                                if let Some(encrypted) = mam_msg.get_child("encrypted", "eu.siacs.conversations.axolotl") {
                                    warn!("Found encrypted element in MAM message with axolotl namespace: {:?}", encrypted);
                                }
                            }
                        }
                        
                        if has_any_omemo || has_mam_omemo {
                            info!("Detected OMEMO encrypted message (outer: v1={}, axolotl={}, MAM: v1={}, axolotl={})", 
                                has_omemo_v1, has_omemo_axolotl, mam_has_omemo_v1, mam_has_omemo_axolotl);
                            
                            // Determine which stanza to process: MAM message takes priority if present
                            let target_stanza = if has_mam_omemo && mam_message_stanza.is_some() {
                                warn!("Processing OMEMO from MAM forwarded message");
                                mam_message_stanza.unwrap().clone()
                            } else {
                                warn!("Processing OMEMO from outer message stanza");
                                stanza.clone()
                            };
                            
                            // Clone needed values for async task
                            let target_stanza_clone = target_stanza.clone();
                            let client_clone = client.clone();
                            let msg_tx_clone = msg_tx.clone();
                            let pending_receipts_clone = pending_receipts.clone();
                            
                            warn!("OMEMO message detected - spawning async task for processing");
                            
                            // Process encrypted message in a separate task to avoid blocking
                            tokio::spawn(async move {
                                warn!("Inside OMEMO async task - starting processing");
                                
                                // Get the global OMEMO manager and JID
                                let (omemo_manager, jid) = match get_global_xmpp_client().await {
                                    Some(global_client) => {
                                        let client_guard = global_client.lock().await;
                                        let manager = client_guard.omemo_manager.clone();
                                        let jid = client_guard.jid.clone();
                                        warn!("Retrieved global OMEMO manager: {:?}", manager.is_some());
                                        (manager, jid)
                                    },
                                    None => {
                                        warn!("No global XMPP client available");
                                        (None, String::new())
                                    },
                                };
                                
                                // Register the global client for OMEMO integration
                                if let Some(_manager) = &omemo_manager {
                                    warn!("Setting current client arc for OMEMO integration");
                                    crate::xmpp::omemo_integration::set_current_client_arc(client_clone.clone());
                                }
                                
                                // Need to get an instance of XMPPClient to call handle_message_encrypted
                                let mut temp_client = XMPPClient {
                                    jid,
                                    client: Some(client_clone),
                                    msg_tx: msg_tx_clone,
                                    pending_receipts: pending_receipts_clone,
                                    connected: true,
                                    omemo_manager: omemo_manager,
                                    carbons_enabled: Arc::new(AtomicBool::new(true)),
                                };
                                
                                warn!("Calling handle_message_encrypted method");
                                if let Err(e) = temp_client.handle_message_encrypted(&target_stanza_clone).await {
                                    error!("Failed to process encrypted message: {}", e);
                                } else {
                                    warn!("Successfully processed encrypted message");
                                }
                            });
                        } else {
                            // Handle other message types: delivery receipts, chat states, etc.
                            info!("Processing non-OMEMO message from {}", from);
                            debug!("Non-OMEMO message content: {:?}", stanza);
                            
                            // Check if there's a body element with different namespace attempts
                            debug!("Checking for body element...");
                            if stanza.get_child("body", "jabber:client").is_some() {
                                debug!("Found body with jabber:client namespace");
                            } else if stanza.get_child("body", "").is_some() {
                                debug!("Found body with empty namespace");
                            } else {
                                debug!("No body element found");
                            }
                            
                            // Check for message delivery receipts
                            if let Err(e) = delivery_receipts::handle_receipt(&stanza, &pending_receipts, &msg_tx).await {
                                error!("Error processing delivery receipt: {}", e);
                            }
                            
                            // Check for chat state notifications (typing indicators)
                            if let Err(e) = chat_states::handle_chat_state(&stanza) {
                                error!("Error processing chat state: {}", e);
                            }
                            
                            // Process carbon copies of messages
                            // XEP-0280 §6: Carbons MUST have from=user's bare JID (server-originated)
                            let carbon_from = stanza.attr("from").unwrap_or("");
                            let carbon_from_is_valid = if carbon_from.is_empty() {
                                // No from attribute = implicitly from server (valid per RFC 6120)
                                true
                            } else if let Some(global) = get_global_xmpp_client().await {
                                let guard = global.lock().await;
                                let our_bare = guard.jid.split('/').next().unwrap_or("");
                                let their_bare = carbon_from.split('/').next().unwrap_or("");
                                our_bare == their_bare
                            } else {
                                // Can't verify — reject to be safe
                                false
                            };
                            
                            if carbon_from_is_valid && (stanza.has_child("received", custom_ns::CARBONS) || 
                               stanza.has_child("sent", custom_ns::CARBONS)) {
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
                                    if let Some(_manager) = &omemo_manager {
                                        crate::xmpp::omemo_integration::set_current_client_arc(client_clone.clone());
                                    }
                                    
                                    // Need an XMPPClient to process carbons
                                    let temp_client = XMPPClient {
                                        jid: String::new(),
                                        client: Some(client_clone),
                                        msg_tx: msg_tx_clone,
                                        pending_receipts: pending_receipts_clone,
                                        connected: true,
                                        omemo_manager: omemo_manager,
                                        carbons_enabled: Arc::new(AtomicBool::new(true)),
                                    };
                                    
                                    if let Err(e) = temp_client.process_carbon(&stanza_clone).await {
                                        error!("Failed to process message carbon: {}", e);
                                    }
                                });
                            }
                            
                            // Process regular chat messages (non-encrypted)
                            if let Some(body) = stanza.get_child("body", "jabber:client").or_else(|| stanza.get_child("body", "")) {
                                let from = stanza.attr("from").unwrap_or("unknown@server.example");
                                let id: String = stanza.attr("id").map(|s| s.to_string()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                                let content = body.text();
                                
                                debug!("Found message body from {}: '{}'", from, content);
                                
                                if !content.is_empty() {
                                    // Strip resource from JID to get bare JID (user@domain)
                                    let sender_bare_jid = from.split('/').next().unwrap_or(from).to_string();
                                    
                                    // Create a message for the UI
                                    let message = Message {
                                        id: id.clone(),
                                        sender_id: sender_bare_jid.clone(),
                                        recipient_id: "me".to_string(),
                                        content: content.clone(),
                                        timestamp: chrono::Utc::now().timestamp() as u64,
                                        delivery_status: DeliveryStatus::Delivered,
                                    };
                                    
                                    info!("Sending message to UI: from='{}' (bare: '{}'), content='{}'", from, sender_bare_jid, content);
                                    
                                    // Send to UI
                                    if let Err(e) = msg_tx.send(message).await {
                                        error!("Failed to send message to UI: {}", e);
                                    } else {
                                        info!("Successfully sent message to UI channel");
                                    }
                                    
                                    // Send a receipt if requested
                                    if stanza.has_child("request", custom_ns::RECEIPTS) {
                                        let mut client_guard = client.lock().await;
                                        if let Err(e) = delivery_receipts::send_receipt(&mut client_guard, from, &id).await {
                                            error!("Failed to send receipt: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("Message body was empty after extraction from {}", from);
                                }
                            }
                        }
                    } else if stanza.name() == "iq" {
                        // Check if this is a service discovery response
                        if let Some(_query) = stanza.get_child("query", "http://jabber.org/protocol/disco#info") {
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery info response: {}", e);
                            }
                        } else if let Some(_query) = stanza.get_child("query", "http://jabber.org/protocol/disco#items") {
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery items response: {}", e);
                            }
                        } else if let Some(_pubsub) = stanza.get_child("pubsub", "http://jabber.org/protocol/pubsub") {
                            // Handle pubsub requests and responses
                            if stanza.attr("type") == Some("get") {
                                let _stanza_clone = stanza.clone();
                                let _client_clone = client.clone();
                                
                                tokio::spawn(async move {
                                    // Get the global OMEMO manager if available
                                    let omemo_manager = match get_global_xmpp_client().await {
                                        Some(global_client) => {
                                            let _client_guard = global_client.lock().await;
                                            _client_guard.omemo_manager.clone()
                                        },
                                        None => None,
                                    };
                                    
                                    if let Some(_manager) = omemo_manager {
                                        debug!("Received pubsub request, but handling not implemented yet");
                                    } else {
                                        warn!("Received pubsub request but OMEMO manager not available");
                                    }
                                });
                            } else if stanza.attr("type") == Some("result") {
                                // Handle pubsub responses
                                if let Some(stanza_id) = stanza.attr("id") {
                                    debug!("Received pubsub response with ID: {}", stanza_id);
                                    
                                    let xml_string = crate::xmpp::omemo_integration::element_to_xml_string(&stanza);
                                    crate::xmpp::omemo_integration::store_pubsub_response(stanza_id.to_string(), xml_string).await;
                                }
                            }
                        }
                    }
                },
                Some(XMPPEvent::Online { bound_jid, resumed: _ }) => {
                    if !seen_online_event {
                        info!("Connected to XMPP server as {}", bound_jid);
                        seen_online_event = true;
                        
                        let client_clone = client.clone();
                        
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            
                            let mut client_guard = client_clone.lock().await;
                            
                            presence::send_initial_presence(&mut client_guard).await
                                .unwrap_or_else(|e| {
                                    error!("Failed to send initial presence: {}", e);
                                });
                        });
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
                        let service_disco = service_discovery.clone();
                        let jid = cap_info.jid.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = service_disco.send_disco_info_request(&jid).await {
                                warn!("Failed to send disco request to {}: {}", jid, e);
                            }
                        });
                    }
                }
            }
            
            // Brief pause to avoid tight loop
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
