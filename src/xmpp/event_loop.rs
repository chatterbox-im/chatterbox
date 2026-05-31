// src/xmpp/event_loop.rs
//! Main XMPP event processing loop.
//!
//! Receives events from the transport actor via an unbounded channel.
//! No mutex contention, no poll-sleep-retry — events arrive instantly.

use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use std::sync::atomic::AtomicBool;

use tokio_xmpp::Event as XMPPEvent;

use crate::models::{Message, DeliveryStatus, PendingMessage};
use super::{XMPPClient, custom_ns, SharedClientRef};
use super::{chat_states, delivery_receipts, discovery, presence};
use super::transport::StanzaTx;

impl XMPPClient {
    /// Primary event processing loop.
    /// Receives events from the transport actor and dispatches them.
    pub(super) async fn handle_incoming_messages(
        stanza_tx: StanzaTx,
        mut event_rx: mpsc::UnboundedReceiver<XMPPEvent>,
        msg_tx: mpsc::Sender<Message>,
        pending_receipts: Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
        iq_registry: Arc<TokioMutex<crate::xmpp::iq_registry::IqResponseRegistry>>,
        shared_client: SharedClientRef,
        online_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) {
        let mut seen_online_event = false;
        let mut online_tx = online_tx;
        let mut typing_tx_cache: Option<mpsc::Sender<(String, chat_states::TypingStatus)>> = None;
        let mut our_bare_jid: Option<String> = None;
        
        let service_discovery = discovery::ServiceDiscovery::new(stanza_tx.clone());
        
        // Main event loop — blocks on channel recv, wakes instantly on new events
        while let Some(event) = event_rx.recv().await {
            match event {
                XMPPEvent::Stanza(stanza) => {
                    if stanza.name() == "presence" {
                        if let Err(e) = presence::handle_presence_stanza(&stanza) {
                            error!("Error processing presence stanza: {}", e);
                        }
                        
                        if let Err(e) = service_discovery.process_caps_in_presence(&stanza).await {
                            warn!("Error processing entity capabilities in presence: {}", e);
                        }
                        
                        let stanza_tx_clone = stanza_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = presence::process_subscription(&stanza_tx_clone, &stanza).await {
                                error!("Error processing presence subscription: {}", e);
                            }
                        });
                    } else if stanza.name() == "message" {
                        // Check if this is a MAM result that should be routed to a collector
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if let Some(query_id) = result.attr("queryid") {
                                let registry = iq_registry.lock().await;
                                if registry.try_route_mam(query_id, stanza.clone()) {
                                    debug!("Routed MAM message to collector for query {}", query_id);
                                    continue;
                                }
                            }
                        }
                        
                        let from = stanza.attr("from").unwrap_or("");
                        let to = stanza.attr("to").unwrap_or("");
                        info!("Received message stanza from='{}', to='{}'", from, to);
                        debug!("Message stanza content: {:?}", stanza);
                        
                        fn has_omemo_encryption(msg_stanza: &xmpp_parsers::Element) -> (bool, bool, bool, bool) {
                            let has_omemo_v1 = msg_stanza.has_child("encrypted", custom_ns::OMEMO);
                            let has_omemo_axolotl = msg_stanza.has_child("encrypted", custom_ns::OMEMO_V1);
                            let has_omemo_empty = msg_stanza.has_child("encrypted", "");
                            let has_omemo_explicit = msg_stanza.has_child("encrypted", "eu.siacs.conversations.axolotl");
                            (has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit)
                        }
                        
                        let (has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit) = has_omemo_encryption(&stanza);
                        
                        let mut mam_message_stanza = None;
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if let Some(forwarded) = result.get_child("forwarded", custom_ns::FORWARD) {
                                if let Some(inner_msg) = forwarded.get_child("message", "jabber:client") {
                                    mam_message_stanza = Some(inner_msg);
                                }
                            }
                        }
                        
                        let (mam_has_omemo_v1, mam_has_omemo_axolotl, mam_has_omemo_empty, mam_has_omemo_explicit) = 
                            if let Some(mam_msg) = &mam_message_stanza {
                                has_omemo_encryption(mam_msg)
                            } else {
                                (false, false, false, false)
                            };
                        
                        let has_any_omemo = has_omemo_v1 || has_omemo_axolotl || has_omemo_empty || has_omemo_explicit;
                        let has_mam_omemo = mam_has_omemo_v1 || mam_has_omemo_axolotl || mam_has_omemo_empty || mam_has_omemo_explicit;
                        
                        debug!("OMEMO detection: outer(v1={}, axolotl={}, empty={}, explicit={}), MAM(v1={}, axolotl={}, empty={}, explicit={})", 
                            has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit,
                            mam_has_omemo_v1, mam_has_omemo_axolotl, mam_has_omemo_empty, mam_has_omemo_explicit);
                        
                        if has_any_omemo {
                            if let Some(encrypted) = stanza.get_child("encrypted", "") {
                                debug!("Found encrypted element in outer stanza with empty namespace: {:?}", encrypted);
                            }
                            if let Some(encrypted) = stanza.get_child("encrypted", "eu.siacs.conversations.axolotl") {
                                debug!("Found encrypted element in outer stanza with axolotl namespace: {:?}", encrypted);
                            }
                        }
                        if has_mam_omemo {
                            if let Some(mam_msg) = &mam_message_stanza {
                                if let Some(encrypted) = mam_msg.get_child("encrypted", "") {
                                    debug!("Found encrypted element in MAM message with empty namespace: {:?}", encrypted);
                                }
                                if let Some(encrypted) = mam_msg.get_child("encrypted", "eu.siacs.conversations.axolotl") {
                                    debug!("Found encrypted element in MAM message with axolotl namespace: {:?}", encrypted);
                                }
                            }
                        }
                        
                        if has_any_omemo || has_mam_omemo {
                            info!("Detected OMEMO encrypted message (outer: v1={}, axolotl={}, MAM: v1={}, axolotl={})", 
                                has_omemo_v1, has_omemo_axolotl, mam_has_omemo_v1, mam_has_omemo_axolotl);
                            
                            let target_stanza = if has_mam_omemo && mam_message_stanza.is_some() {
                                debug!("Processing OMEMO from MAM forwarded message");
                                mam_message_stanza.unwrap().clone()
                            } else {
                                debug!("Processing OMEMO from outer message stanza");
                                stanza.clone()
                            };
                            
                            let stanza_tx_clone = stanza_tx.clone();
                            let msg_tx_clone = msg_tx.clone();
                            let pending_receipts_clone = pending_receipts.clone();
                            let shared_client_clone = shared_client.clone();
                            let iq_registry_clone = iq_registry.clone();
                            
                            debug!("OMEMO message detected - spawning async task for processing");
                            
                            tokio::spawn(async move {
                                debug!("Inside OMEMO async task - starting processing");
                                
                                let (omemo_manager, jid) = match shared_client_clone.lock().await.as_ref() {
                                    Some(global_client) => {
                                        let client_guard = global_client.lock().await;
                                        let manager = client_guard.omemo_manager.clone();
                                        let jid = client_guard.jid.clone();
                                        debug!("Retrieved global OMEMO manager: {:?}", manager.is_some());
                                        (manager, jid)
                                    },
                                    None => {
                                        error!("No global XMPP client available");
                                        (None, String::new())
                                    },
                                };
                                
                                let mut temp_client = XMPPClient {
                                    jid,
                                    stanza_tx: Some(stanza_tx_clone),
                                    msg_tx: msg_tx_clone,
                                    pending_receipts: pending_receipts_clone,
                                    connected: true,
                                    omemo_manager,
                                    carbons_enabled: Arc::new(AtomicBool::new(true)),
                                    iq_registry: iq_registry_clone,
                                    pubsub_responses: None,
                                    shared_self: shared_client_clone.clone(),
                                    typing_tx: None,
                                };
                                
                                debug!("Calling handle_message_encrypted method");
                                if let Err(e) = temp_client.handle_message_encrypted(&target_stanza).await {
                                    error!("Failed to process encrypted message: {}", e);
                                } else {
                                    debug!("Successfully processed encrypted message");
                                }
                            });
                        } else {
                            info!("Processing non-OMEMO message from {}", from);
                            debug!("Non-OMEMO message content: {:?}", stanza);
                            
                            if let Err(e) = delivery_receipts::handle_receipt(&stanza, &pending_receipts, &msg_tx).await {
                                error!("Error processing delivery receipt: {}", e);
                            }
                            
                            if typing_tx_cache.is_none() {
                                if let Some(global) = shared_client.lock().await.as_ref() {
                                    let guard = global.lock().await;
                                    typing_tx_cache = guard.typing_tx.clone();
                                }
                            }
                            if let Err(e) = chat_states::handle_chat_state(&stanza, typing_tx_cache.as_ref()) {
                                error!("Error processing chat state: {}", e);
                            }
                            
                            let carbon_from = stanza.attr("from").unwrap_or("");
                            let carbon_from_is_valid = if carbon_from.is_empty() {
                                true
                            } else if let Some(ref our_jid) = our_bare_jid {
                                let their_bare = carbon_from.split('/').next().unwrap_or("");
                                our_jid == their_bare
                            } else {
                                false
                            };
                            
                            if carbon_from_is_valid && (stanza.has_child("received", custom_ns::CARBONS) || 
                               stanza.has_child("sent", custom_ns::CARBONS)) {
                                let stanza_clone = stanza.clone();
                                let stanza_tx_clone = stanza_tx.clone();
                                let msg_tx_clone = msg_tx.clone();
                                let pending_receipts_clone = pending_receipts.clone();
                                let shared_client_clone2 = shared_client.clone();
                                let iq_registry_clone2 = iq_registry.clone();
                                
                                tokio::spawn(async move {
                                    let omemo_manager = match shared_client_clone2.lock().await.as_ref() {
                                        Some(global_client) => {
                                            let client_guard = global_client.lock().await;
                                            client_guard.omemo_manager.clone()
                                        },
                                        None => None,
                                    };
                                    
                                    let temp_client = XMPPClient {
                                        jid: String::new(),
                                        stanza_tx: Some(stanza_tx_clone),
                                        msg_tx: msg_tx_clone,
                                        pending_receipts: pending_receipts_clone,
                                        connected: true,
                                        omemo_manager,
                                        carbons_enabled: Arc::new(AtomicBool::new(true)),
                                        iq_registry: iq_registry_clone2,
                                        pubsub_responses: None,
                                        shared_self: shared_client_clone2.clone(),
                                        typing_tx: None,
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
                                    let sender_bare_jid = from.split('/').next().unwrap_or(from).to_string();
                                    
                                    let message = Message {
                                        id: id.clone(),
                                        sender_id: sender_bare_jid.clone(),
                                        recipient_id: "me".to_string(),
                                        content: content.clone(),
                                        timestamp: chrono::Utc::now().timestamp() as u64,
                                        delivery_status: DeliveryStatus::Delivered,
                                    };
                                    
                                    info!("Sending message to UI: from='{}' (bare: '{}'), content='{}'", from, sender_bare_jid, content);
                                    
                                    if let Err(e) = msg_tx.send(message).await {
                                        error!("Failed to send message to UI: {}", e);
                                    } else {
                                        info!("Successfully sent message to UI channel");
                                    }
                                    
                                    // Send a receipt if requested
                                    if stanza.has_child("request", custom_ns::RECEIPTS) {
                                        if let Err(e) = delivery_receipts::send_receipt(&stanza_tx, from, &id) {
                                            error!("Failed to send receipt: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("Message body was empty after extraction from {}", from);
                                }
                            }
                        }
                    } else if stanza.name() == "iq" {
                        // Route IQ responses through the registry FIRST
                        if let Some(stanza_id) = stanza.attr("id") {
                            let mut registry = iq_registry.lock().await;
                            if registry.try_route(stanza_id, stanza.clone()) {
                                debug!("Routed IQ response {} to waiting caller", stanza_id);
                                registry.evict_stale(std::time::Duration::from_secs(60));
                                continue;
                            }
                        }
                        
                        if let Some(_query) = stanza.get_child("query", "http://jabber.org/protocol/disco#info") {
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery info response: {}", e);
                            }
                        } else if let Some(_query) = stanza.get_child("query", "http://jabber.org/protocol/disco#items") {
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery items response: {}", e);
                            }
                        } else if let Some(_pubsub) = stanza.get_child("pubsub", "http://jabber.org/protocol/pubsub") {
                            if stanza.attr("type") == Some("get") {
                                let shared_client_clone3 = shared_client.clone();
                                tokio::spawn(async move {
                                    let omemo_manager = match shared_client_clone3.lock().await.as_ref() {
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
                                if let Some(stanza_id) = stanza.attr("id") {
                                    debug!("Received pubsub response with ID: {}", stanza_id);
                                    let xml_string = crate::xmpp::omemo_integration::element_to_xml_string(&stanza);
                                    if let Some(global) = shared_client.lock().await.as_ref() {
                                        let guard = global.lock().await;
                                        if let Some(ref responses) = guard.pubsub_responses {
                                            crate::xmpp::omemo_integration::store_pubsub_response_to(responses, stanza_id.to_string(), xml_string).await;
                                        }
                                    }
                                }
                            }
                        } else if stanza.attr("type") == Some("error") {
                            if let Some(stanza_id) = stanza.attr("id") {
                                let xml_string = crate::xmpp::omemo_integration::element_to_xml_string(&stanza);
                                if let Some(global) = shared_client.lock().await.as_ref() {
                                    let guard = global.lock().await;
                                    if let Some(ref responses) = guard.pubsub_responses {
                                        crate::xmpp::omemo_integration::store_pubsub_response_to(responses, stanza_id.to_string(), xml_string).await;
                                    }
                                }
                            }
                        }
                    }
                },
                XMPPEvent::Online { bound_jid, resumed: _ } => {
                    if !seen_online_event {
                        info!("Connected to XMPP server as {}", bound_jid);
                        seen_online_event = true;
                        our_bare_jid = Some(bound_jid.to_string().split('/').next().unwrap_or("").to_string());

                        if typing_tx_cache.is_none() {
                            if let Some(global) = shared_client.lock().await.as_ref() {
                                let guard = global.lock().await;
                                typing_tx_cache = guard.typing_tx.clone();
                            }
                        }

                        if let Some(tx) = online_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                },
                XMPPEvent::Disconnected(reason) => {
                    error!("XMPP client is disconnected: {:?}", reason);
                    break;
                },
            }
            
            // Check for scheduled entity capabilities discoveries
            if let Ok(mut discoveries) = presence::PENDING_CAPS_DISCOVERIES.try_lock() {
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
        }
        
        info!("Event loop exiting (transport channel closed)");
    }
}

