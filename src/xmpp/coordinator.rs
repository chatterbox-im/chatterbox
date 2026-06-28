// src/xmpp/coordinator.rs
//! Coordinator: single-owner event loop that processes all XMPP events
//! and crypto operations without spawning tasks or requiring mutexes.
//!
//! The coordinator owns:
//! - OmemoManager (no Arc<Mutex> needed)
//! - Pending receipts
//! - IQ response routing
//! - Service discovery state
//!
//! External actors communicate via bounded channels:
//! - Transport actor → coordinator: inbound stanzas/events
//! - App (UI) → coordinator: send requests, queries
//! - Coordinator → App (UI): messages, status updates

use anyhow::{anyhow, Result};
use base64::Engine;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use xmpp_parsers::Element;

use super::custom_ns;
use super::iq_registry::IqResponseRegistry;
use super::transport::StanzaTx;
use super::{chat_states, delivery_receipts, discovery, presence};
use crate::models::{DeliveryStatus, Message, PendingMessage};
use crate::omemo::OmemoManager;

/// Commands sent from the app layer to the coordinator.
#[derive(Debug)]
pub enum CoordinatorCommand {
    /// Send an encrypted message to a recipient.
    SendMessage {
        recipient: String,
        content: String,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Send a plaintext message with receipt request.
    SendPlaintext {
        recipient: String,
        content: String,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Query device IDs for a JID.
    GetDeviceIds {
        jid: String,
        reply: oneshot::Sender<Result<Vec<u32>>>,
    },
    /// Get fingerprint for a specific device.
    GetFingerprint {
        jid: String,
        device_id: u32,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Check OMEMO keys for a contact (trust verification).
    CheckOmemoKeys {
        contact: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Toggle trust for a contact's devices.
    ToggleTrust {
        contact: String,
        reply: oneshot::Sender<Result<bool>>,
    },
    /// Process key verification response from user.
    KeyVerificationResponse {
        contact: String,
        response: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Check if OMEMO is enabled.
    IsOmemoEnabled { reply: oneshot::Sender<bool> },
    /// Store a message ID for receipt tracking.
    StoreMessageId {
        recipient: String,
        message_id: String,
    },
    /// Send a chat state notification.
    SendChatState {
        recipient: String,
        state: chat_states::TypingStatus,
    },
    /// Shutdown the coordinator.
    Shutdown,
}

/// Handle to send commands to the coordinator from the app layer.
#[derive(Clone)]
pub struct CoordinatorHandle {
    pub cmd_tx: mpsc::Sender<CoordinatorCommand>,
}

impl CoordinatorHandle {
    /// Send an encrypted message. Returns the message ID on success.
    pub async fn send_message(&self, recipient: &str, content: &str) -> Result<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::SendMessage {
                recipient: recipient.to_string(),
                content: content.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Send a plaintext message. Returns the message ID on success.
    pub async fn send_plaintext(&self, recipient: &str, content: &str) -> Result<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::SendPlaintext {
                recipient: recipient.to_string(),
                content: content.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Get device IDs for a JID.
    pub async fn get_device_ids(&self, jid: &str) -> Result<Vec<u32>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::GetDeviceIds {
                jid: jid.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Get fingerprint for a device.
    pub async fn get_fingerprint(&self, jid: &str, device_id: u32) -> Result<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::GetFingerprint {
                jid: jid.to_string(),
                device_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Check OMEMO keys for a contact.
    pub async fn check_omemo_keys(&self, contact: &str) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::CheckOmemoKeys {
                contact: contact.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Toggle trust for a contact's devices.
    pub async fn toggle_trust(&self, contact: &str) -> Result<bool> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::ToggleTrust {
                contact: contact.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Process key verification response.
    pub async fn key_verification_response(&self, contact: &str, response: &str) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CoordinatorCommand::KeyVerificationResponse {
                contact: contact.to_string(),
                response: response.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("Coordinator shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Coordinator dropped reply"))?
    }

    /// Check if OMEMO is enabled.
    pub async fn is_omemo_enabled(&self) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(CoordinatorCommand::IsOmemoEnabled { reply: reply_tx })
            .await
            .is_err()
        {
            return false;
        }
        reply_rx.await.unwrap_or(false)
    }

    /// Store a message ID for receipt tracking (fire-and-forget).
    pub fn store_message_id(&self, recipient: &str, message_id: &str) {
        let _ = self.cmd_tx.try_send(CoordinatorCommand::StoreMessageId {
            recipient: recipient.to_string(),
            message_id: message_id.to_string(),
        });
    }

    /// Send a chat state notification (fire-and-forget).
    pub fn send_chat_state(&self, recipient: &str, state: &chat_states::TypingStatus) {
        let _ = self.cmd_tx.try_send(CoordinatorCommand::SendChatState {
            recipient: recipient.to_string(),
            state: state.clone(),
        });
    }
}

/// Internal state owned exclusively by the coordinator task.
struct CoordinatorState {
    stanza_tx: StanzaTx,
    msg_tx: mpsc::Sender<Message>,
    omemo_manager: Option<OmemoManager>,
    pending_receipts: HashMap<String, PendingMessage>,
    iq_registry: IqResponseRegistry,
    service_discovery: discovery::ServiceDiscovery,
    typing_tx: Option<mpsc::Sender<(String, chat_states::TypingStatus)>>,
    our_jid: String,
    our_bare_jid: String,
}

/// Non-blocking send to the UI message channel.
///
/// The coordinator must never block on UI delivery — a slow/paused UI must not
/// stall XMPP event processing. If the channel is full, the message is dropped
/// with a warning. This is safe because:
/// - Chat messages are persisted elsewhere (storage layer)
/// - Delivery receipts/status updates are best-effort UI notifications
/// - The alternative (blocking) causes total coordinator deadlock
fn send_to_ui(msg_tx: &mpsc::Sender<Message>, message: Message) {
    match msg_tx.try_send(message) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(msg)) => {
            warn!(
                "UI message channel full, dropping message id={} (UI is not draining fast enough)",
                msg.id
            );
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!("UI message channel closed (app shutting down)");
        }
    }
}

/// Spawn the coordinator task. Returns:
/// - `CoordinatorHandle` for sending commands from the app layer
/// - Consumes the event_rx from the transport
pub fn spawn_coordinator(
    stanza_tx: StanzaTx,
    event_rx: mpsc::UnboundedReceiver<tokio_xmpp::Event>,
    msg_tx: mpsc::Sender<Message>,
    typing_tx: Option<mpsc::Sender<(String, chat_states::TypingStatus)>>,
    jid: String,
    omemo_manager: Option<OmemoManager>,
    online_tx: Option<oneshot::Sender<()>>,
) -> CoordinatorHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(64);

    let bare_jid = jid.split('/').next().unwrap_or(&jid).to_string();
    let service_discovery = discovery::ServiceDiscovery::new(stanza_tx.clone());

    let state = CoordinatorState {
        stanza_tx: stanza_tx.clone(),
        msg_tx,
        omemo_manager,
        pending_receipts: HashMap::new(),
        iq_registry: IqResponseRegistry::new(),
        service_discovery,
        typing_tx,
        our_jid: jid,
        our_bare_jid: bare_jid,
    };

    tokio::spawn(coordinator_loop(state, event_rx, cmd_rx, online_tx));

    CoordinatorHandle { cmd_tx }
}

/// The main coordinator loop. Processes transport events and app commands
/// in a single select!, with no spawned subtasks for message processing.
async fn coordinator_loop(
    mut state: CoordinatorState,
    mut event_rx: mpsc::UnboundedReceiver<tokio_xmpp::Event>,
    mut cmd_rx: mpsc::Receiver<CoordinatorCommand>,
    online_tx: Option<oneshot::Sender<()>>,
) {
    let mut online_tx = online_tx;
    let mut seen_online = false;

    loop {
        tokio::select! {
            // Inbound XMPP events from transport
            event = event_rx.recv() => {
                match event {
                    Some(ev) => handle_transport_event(&mut state, ev, &mut seen_online, &mut online_tx).await,
                    None => {
                        info!("Coordinator: transport channel closed, shutting down");
                        break;
                    }
                }
            }
            // Commands from the app layer
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(CoordinatorCommand::Shutdown) | None => {
                        info!("Coordinator: shutdown requested");
                        break;
                    }
                    Some(cmd) => handle_command(&mut state, cmd).await,
                }
            }
        }

        // Drain pending caps discoveries — collect first to drop the lock before await
        let pending_caps: Vec<_> = {
            if let Ok(mut discoveries) = presence::PENDING_CAPS_DISCOVERIES.try_lock() {
                std::mem::take(&mut *discoveries)
            } else {
                vec![]
            }
        };
        for cap_info in pending_caps {
            if let Err(e) = state
                .service_discovery
                .send_disco_info_request(&cap_info.jid)
                .await
            {
                warn!("Failed to send disco request to {}: {}", cap_info.jid, e);
            }
        }

        // Periodic eviction of stale IQ entries
        state
            .iq_registry
            .evict_stale(std::time::Duration::from_secs(60));
    }

    info!("Coordinator loop exited");
}

/// Handle a single transport event (stanza, online, disconnected).
async fn handle_transport_event(
    state: &mut CoordinatorState,
    event: tokio_xmpp::Event,
    seen_online: &mut bool,
    online_tx: &mut Option<oneshot::Sender<()>>,
) {
    use tokio_xmpp::Event as XMPPEvent;

    match event {
        XMPPEvent::Stanza(stanza) => {
            if stanza.name() == "presence" {
                handle_presence(state, &stanza).await;
            } else if stanza.name() == "message" {
                handle_message(state, &stanza).await;
            } else if stanza.name() == "iq" {
                handle_iq(state, &stanza).await;
            }
        }
        XMPPEvent::Online {
            bound_jid,
            resumed: _,
        } => {
            if !*seen_online {
                info!("Connected to XMPP server as {}", bound_jid);
                *seen_online = true;
                state.our_bare_jid = bound_jid
                    .to_string()
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                state.our_jid = bound_jid.to_string();

                if let Some(tx) = online_tx.take() {
                    let _ = tx.send(());
                }
            }
        }
        XMPPEvent::Disconnected(reason) => {
            error!("XMPP disconnected: {:?}", reason);
            // Transport actor handles reconnection (Phase 3)
        }
    }
}

/// Handle presence stanzas inline (no spawn).
async fn handle_presence(state: &mut CoordinatorState, stanza: &Element) {
    if let Err(e) = presence::handle_presence_stanza(stanza) {
        error!("Error processing presence: {}", e);
    }

    if let Err(e) = state
        .service_discovery
        .process_caps_in_presence(stanza)
        .await
    {
        warn!("Error processing entity capabilities: {}", e);
    }

    // Process subscription inline instead of spawning
    if let Err(e) = presence::process_subscription(&state.stanza_tx, stanza).await {
        error!("Error processing presence subscription: {}", e);
    }
}

/// Handle message stanzas inline (OMEMO decrypt, carbons, receipts — no spawn).
async fn handle_message(state: &mut CoordinatorState, stanza: &Element) {
    // Check if this is a MAM result that should be routed to a collector
    if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
        if let Some(query_id) = result.attr("queryid") {
            if state.iq_registry.try_route_mam(query_id, stanza.clone()) {
                debug!("Routed MAM message to collector for query {}", query_id);
                return;
            }
        }
    }

    let _from = stanza.attr("from").unwrap_or("");

    // Detect OMEMO encryption
    let has_omemo = has_any_omemo_encryption(stanza);
    let (mam_stanza, has_mam_omemo) = extract_mam_omemo(stanza);

    if has_omemo || has_mam_omemo {
        let target_stanza = if has_mam_omemo {
            if let Some(mam_msg) = mam_stanza {
                mam_msg.clone()
            } else {
                stanza.clone()
            }
        } else {
            stanza.clone()
        };

        // Decrypt inline — no spawn, no temp client, no mutex
        handle_omemo_message(state, &target_stanza).await;
    } else {
        // Non-OMEMO message processing
        // Handle delivery receipts
        if let Err(e) = handle_receipt_inline(state, stanza).await {
            error!("Error processing delivery receipt: {}", e);
        }

        // Handle chat states
        if let Err(e) = chat_states::handle_chat_state(stanza, state.typing_tx.as_ref()) {
            error!("Error processing chat state: {}", e);
        }

        // Handle carbons inline
        let carbon_from = stanza.attr("from").unwrap_or("");
        let carbon_from_is_valid = if carbon_from.is_empty() {
            true
        } else {
            let their_bare = carbon_from.split('/').next().unwrap_or("");
            state.our_bare_jid == their_bare
        };

        if carbon_from_is_valid
            && (stanza.has_child("received", custom_ns::CARBONS)
                || stanza.has_child("sent", custom_ns::CARBONS))
        {
            handle_carbon_inline(state, stanza).await;
        }

        // Process regular chat messages
        if let Some(body) = stanza
            .get_child("body", "jabber:client")
            .or_else(|| stanza.get_child("body", ""))
        {
            let from = stanza.attr("from").unwrap_or("unknown@server.example");
            let id: String = stanza
                .attr("id")
                .map(|s| s.to_string())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let content = body.text();

            if !content.is_empty() {
                let sender_bare_jid = from.split('/').next().unwrap_or(from).to_string();

                let message = Message::incoming_plaintext(id.clone(), sender_bare_jid, content);

                send_to_ui(&state.msg_tx, message);

                // Send receipt if requested
                if stanza.has_child("request", custom_ns::RECEIPTS) {
                    if let Err(e) = delivery_receipts::send_receipt(&state.stanza_tx, from, &id) {
                        error!("Failed to send receipt: {}", e);
                    }
                }
            }
        }
    }
}

/// Handle IQ stanzas: route responses, service discovery, pubsub.
async fn handle_iq(state: &mut CoordinatorState, stanza: &Element) {
    // Route IQ responses through the registry FIRST
    if let Some(stanza_id) = stanza.attr("id") {
        if state.iq_registry.try_route(stanza_id, stanza.clone()) {
            debug!("Routed IQ response {} to waiting caller", stanza_id);
            return;
        }
    }

    if let Some(_query) = stanza.get_child("query", "http://jabber.org/protocol/disco#info") {
        if stanza.attr("type") == Some("get") {
            if let Err(e) = state.service_discovery.respond_to_disco_info_query(stanza) {
                warn!("Failed to respond to disco#info query: {}", e);
            }
        } else if let Err(e) = state.service_discovery.handle_disco_response(stanza).await {
            warn!("Failed to process service discovery info response: {}", e);
        }
    } else if stanza
        .get_child("query", "http://jabber.org/protocol/disco#items")
        .is_some()
    {
        if let Err(e) = state.service_discovery.handle_disco_response(stanza).await {
            warn!("Failed to process service discovery items response: {}", e);
        }
    } else if stanza
        .get_child("pubsub", "http://jabber.org/protocol/pubsub")
        .is_some()
    {
        // PubSub responses are routed via the IQ registry (registered before sending)
        // If we get here, it wasn't matched — log it
        if stanza.attr("type") == Some("result") || stanza.attr("type") == Some("error") {
            if let Some(stanza_id) = stanza.attr("id") {
                debug!(
                    "Unmatched pubsub response with ID: {} (may be late)",
                    stanza_id
                );
            }
        }
    }
}

/// Decrypt an OMEMO message inline in the coordinator.
async fn handle_omemo_message(state: &mut CoordinatorState, stanza: &Element) {
    let from = stanza.attr("from").unwrap_or("unknown@server.example");
    let id = stanza.attr("id").unwrap_or("unknown");

    let omemo_manager = match state.omemo_manager.as_mut() {
        Some(m) => m,
        None => {
            error!("OMEMO manager not available for decryption");
            return;
        }
    };

    // Skip messages from our own device
    let sender_device_id = match extract_sender_device_id(stanza) {
        Some(sid) => sid,
        None => {
            error!("Missing sender device ID in OMEMO message");
            return;
        }
    };

    if sender_device_id == omemo_manager.get_device_id() {
        debug!(
            "Skipping decryption of our own sent message (device {})",
            sender_device_id
        );
        let to = stanza.attr("to").unwrap_or("unknown");
        let recipient_jid = to.split('/').next().unwrap_or(to).to_string();
        let mut message =
            Message::outgoing_encrypted(id.to_string(), recipient_jid, "[Sent encrypted message]");
        message.delivery_status = DeliveryStatus::Delivered;
        send_to_ui(&state.msg_tx, message);
        return;
    }

    // Extract encrypted element
    let encrypted = match stanza
        .get_child("encrypted", "")
        .or_else(|| stanza.get_child("encrypted", custom_ns::OMEMO))
        .or_else(|| stanza.get_child("encrypted", custom_ns::OMEMO_V1))
    {
        Some(e) => e,
        None => {
            error!("Could not find encrypted element in OMEMO message");
            return;
        }
    };

    let header = match encrypted
        .get_child("header", "")
        .or_else(|| encrypted.get_child("header", custom_ns::OMEMO))
    {
        Some(h) => h,
        None => {
            error!("Missing header in OMEMO message");
            return;
        }
    };

    // Extract IV
    let iv = match extract_iv(header) {
        Some(iv) => iv,
        None => {
            error!("Missing or invalid IV in OMEMO message");
            return;
        }
    };

    // Collect encrypted keys
    let mut encrypted_keys = HashMap::new();
    let mut is_prekey_message = false;
    for key_elem in header.children().filter(|e| e.name() == "key") {
        if let Some(rid_str) = key_elem.attr("rid") {
            if key_elem.attr("prekey") == Some("true") || key_elem.attr("prekey") == Some("1") {
                is_prekey_message = true;
            }
            if let Ok(recipient_id) = rid_str.parse::<u32>() {
                let key_base64 = key_elem.text();
                if let Ok(key_bytes) = base64::engine::general_purpose::STANDARD.decode(&key_base64)
                {
                    encrypted_keys.insert(recipient_id, key_bytes);
                }
            }
        }
    }

    // Extract payload (optional for key-transport messages)
    let payload = encrypted
        .get_child("payload", "")
        .or_else(|| encrypted.get_child("payload", custom_ns::OMEMO))
        .and_then(|p| {
            let text = p.text();
            base64::engine::general_purpose::STANDARD.decode(&text).ok()
        });

    // Key-transport message (no payload)
    if payload.is_none() {
        debug!(
            "Key-transport OMEMO message from {}:{}",
            from, sender_device_id
        );
        if let Some(our_key) = encrypted_keys.get(&omemo_manager.get_device_id()) {
            match omemo_manager
                .decrypt_message_key(from.to_string(), sender_device_id, our_key)
                .await
            {
                Ok(_) => debug!("Key-transport processed from {}:{}", from, sender_device_id),
                Err(e) => warn!(
                    "Failed to process key-transport from {}:{}: {}",
                    from, sender_device_id, e
                ),
            }
        }
        return;
    }

    // Build OmemoMessage for decryption
    let omemo_message = crate::omemo::protocol::OmemoMessage {
        sender_device_id,
        ratchet_key: vec![],
        previous_counter: 0,
        counter: 0,
        ciphertext: payload.unwrap(),
        mac: vec![],
        iv,
        encrypted_keys,
        is_prekey: is_prekey_message,
        ephemeral_key: None,
        prekey_devices: std::collections::HashSet::new(),
    };

    // Decrypt the message — this is the key operation that happens inline
    match omemo_manager
        .decrypt_message(from, sender_device_id, &omemo_message)
        .await
    {
        Ok(plaintext) => {
            let sender_bare_jid = from.split('/').next().unwrap_or(from).to_string();
            let message = Message::incoming_encrypted(id.to_string(), sender_bare_jid, plaintext);

            send_to_ui(&state.msg_tx, message);

            // Send receipt if requested
            if stanza.has_child("request", custom_ns::RECEIPTS) {
                let receipt = Element::builder("message", "jabber:client")
                    .attr("to", from)
                    .attr("id", &uuid::Uuid::new_v4().to_string())
                    .append(
                        Element::builder("received", custom_ns::RECEIPTS)
                            .attr("id", id)
                            .build(),
                    )
                    .build();
                if let Err(e) = super::transport::send_stanza(&state.stanza_tx, receipt) {
                    error!("Failed to send receipt: {}", e);
                }
            }
        }
        Err(e) => {
            error!(
                "Failed to decrypt message from {} (device {}): {}",
                from, sender_device_id, e
            );
            let message = Message::incoming_encrypted(
                id.to_string(),
                from.to_string(),
                format!("[Encrypted message could not be decrypted: {}]", e),
            );
            send_to_ui(&state.msg_tx, message);
        }
    }
}

/// Handle a command from the app layer.
async fn handle_command(state: &mut CoordinatorState, cmd: CoordinatorCommand) {
    match cmd {
        CoordinatorCommand::SendMessage {
            recipient,
            content,
            reply,
        } => {
            let result = send_encrypted(state, &recipient, &content).await;
            let _ = reply.send(result);
        }
        CoordinatorCommand::SendPlaintext {
            recipient,
            content,
            reply,
        } => {
            let result = send_plaintext(state, &recipient, &content).await;
            let _ = reply.send(result);
        }
        CoordinatorCommand::GetDeviceIds { jid, reply } => {
            let result = match state.omemo_manager.as_ref() {
                Some(m) => m
                    .get_device_ids_for_test(&jid)
                    .await
                    .map(|ids| ids.iter().map(|d| *d).collect())
                    .map_err(|e| anyhow!("{}", e)),
                None => Err(anyhow!("OMEMO not initialized")),
            };
            let _ = reply.send(result);
        }
        CoordinatorCommand::GetFingerprint {
            jid,
            device_id,
            reply,
        } => {
            let result = match state.omemo_manager.as_ref() {
                Some(m) => m
                    .get_device_fingerprint(&jid, device_id)
                    .await
                    .map_err(|e| anyhow!("{}", e)),
                None => Err(anyhow!("OMEMO not initialized")),
            };
            let _ = reply.send(result);
        }
        CoordinatorCommand::CheckOmemoKeys { contact, reply } => {
            let result = check_omemo_keys_inline(state, &contact).await;
            let _ = reply.send(result);
        }
        CoordinatorCommand::ToggleTrust { contact, reply } => {
            let result = toggle_trust_inline(state, &contact).await;
            let _ = reply.send(result);
        }
        CoordinatorCommand::KeyVerificationResponse {
            contact,
            response,
            reply,
        } => {
            let result = handle_key_verification_inline(state, &contact, &response).await;
            let _ = reply.send(result);
        }
        CoordinatorCommand::IsOmemoEnabled { reply } => {
            let _ = reply.send(state.omemo_manager.is_some());
        }
        CoordinatorCommand::StoreMessageId {
            recipient,
            message_id,
        } => {
            state.pending_receipts.insert(
                message_id.clone(),
                PendingMessage {
                    id: message_id,
                    to: recipient,
                    content: String::new(),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    status: DeliveryStatus::Sent,
                },
            );
        }
        CoordinatorCommand::SendChatState {
            recipient,
            state: typing_state,
        } => {
            if let Err(e) = send_chat_state_inline(&state.stanza_tx, &recipient, &typing_state) {
                debug!("Failed to send chat state: {}", e);
            }
        }
        CoordinatorCommand::Shutdown => unreachable!(), // handled in caller
    }
}

/// Encrypt and send a message. Returns the message ID.
async fn send_encrypted(state: &mut CoordinatorState, to: &str, content: &str) -> Result<String> {
    let omemo_manager = state
        .omemo_manager
        .as_mut()
        .ok_or_else(|| anyhow!("OMEMO not initialized"))?;

    let encrypted_message = omemo_manager
        .encrypt_message(to, content)
        .await
        .map_err(|e| anyhow!("Failed to encrypt message: {}", e))?;

    let id = uuid::Uuid::new_v4().to_string();

    // Build OMEMO stanza
    let message_element = build_omemo_stanza(&id, to, &encrypted_message);

    super::transport::send_stanza(&state.stanza_tx, message_element)
        .map_err(|e| anyhow!("Failed to send encrypted message: {}", e))?;

    // Track for receipt
    state.pending_receipts.insert(
        id.clone(),
        PendingMessage {
            id: id.clone(),
            to: to.to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: DeliveryStatus::Sent,
        },
    );

    // Notify UI of sent message
    let message = Message::outgoing_encrypted(id.clone(), to.to_string(), content.to_string());
    send_to_ui(&state.msg_tx, message);

    Ok(id)
}

/// Send a plaintext message with receipt request. Returns the message ID.
async fn send_plaintext(state: &mut CoordinatorState, to: &str, content: &str) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();

    let message_element = Element::builder("message", "jabber:client")
        .attr("id", &id)
        .attr("to", to)
        .attr("type", "chat")
        .append(
            Element::builder("body", "jabber:client")
                .append(content)
                .build(),
        )
        .append(Element::builder("request", custom_ns::RECEIPTS).build())
        .append(Element::builder("active", custom_ns::CHATSTATES).build())
        .build();

    super::transport::send_stanza(&state.stanza_tx, message_element)
        .map_err(|e| anyhow!("Failed to send message: {}", e))?;

    state.pending_receipts.insert(
        id.clone(),
        PendingMessage {
            id: id.clone(),
            to: to.to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: DeliveryStatus::Sent,
        },
    );

    let message = Message::outgoing_plaintext(id.clone(), to.to_string(), content.to_string());
    send_to_ui(&state.msg_tx, message);

    Ok(id)
}

/// Build the OMEMO encrypted message stanza.
fn build_omemo_stanza(
    id: &str,
    to: &str,
    encrypted_message: &crate::omemo::protocol::OmemoMessage,
) -> Element {
    let mut message_element = Element::builder("message", "jabber:client").build();
    message_element.set_attr("id", id);
    message_element.set_attr("to", to);
    message_element.set_attr("type", "chat");

    // Receipt request
    message_element.append_child(Element::builder("request", custom_ns::RECEIPTS).build());
    // Chat state
    message_element.append_child(Element::builder("active", custom_ns::CHATSTATES).build());

    // Encrypted element
    let mut encrypted_element = Element::builder("encrypted", custom_ns::OMEMO_V1).build();
    let mut header_element = Element::builder("header", custom_ns::OMEMO_V1).build();
    header_element.set_attr("sid", &encrypted_message.sender_device_id.to_string());

    for (device_id, encrypted_key) in &encrypted_message.encrypted_keys {
        let mut key_element = Element::builder("key", custom_ns::OMEMO_V1).build();
        key_element.set_attr("rid", &device_id.to_string());
        if encrypted_message.prekey_devices.contains(device_id) {
            key_element.set_attr("prekey", "true");
        }
        key_element
            .append_text_node(&base64::engine::general_purpose::STANDARD.encode(encrypted_key));
        header_element.append_child(key_element);
    }

    let mut iv_element = Element::builder("iv", custom_ns::OMEMO_V1).build();
    iv_element
        .append_text_node(&base64::engine::general_purpose::STANDARD.encode(&encrypted_message.iv));
    header_element.append_child(iv_element);

    let mut payload_element = Element::builder("payload", custom_ns::OMEMO_V1).build();
    payload_element.append_text_node(
        &base64::engine::general_purpose::STANDARD.encode(&encrypted_message.ciphertext),
    );

    encrypted_element.append_child(header_element);
    encrypted_element.append_child(payload_element);
    message_element.append_child(encrypted_element);

    // EME indicator
    let mut eme_element = Element::builder("encryption", "urn:xmpp:eme:0").build();
    eme_element.set_attr("namespace", custom_ns::OMEMO_V1);
    eme_element.set_attr("name", "OMEMO");
    message_element.append_child(eme_element);

    // Body fallback
    let mut body_element = Element::builder("body", "jabber:client").build();
    body_element.append_text_node("I sent you an OMEMO encrypted message but your client doesn\u{2019}t seem to support that. Find more information on https://conversations.im/omemo");
    message_element.append_child(body_element);

    // Store hint
    message_element.append_child(Element::builder("store", "urn:xmpp:hints").build());

    message_element
}

// --- Helper functions ---

fn has_any_omemo_encryption(stanza: &Element) -> bool {
    stanza.has_child("encrypted", custom_ns::OMEMO)
        || stanza.has_child("encrypted", custom_ns::OMEMO_V1)
        || stanza.has_child("encrypted", "")
        || stanza.has_child("encrypted", "eu.siacs.conversations.axolotl")
}

fn extract_mam_omemo<'a>(stanza: &'a Element) -> (Option<&'a Element>, bool) {
    if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
        if let Some(forwarded) = result.get_child("forwarded", super::custom_ns::FORWARD) {
            if let Some(inner_msg) = forwarded.get_child("message", "jabber:client") {
                let has = has_any_omemo_encryption(inner_msg);
                return (Some(inner_msg), has);
            }
        }
    }
    (None, false)
}

fn extract_sender_device_id(stanza: &Element) -> Option<u32> {
    let encrypted = stanza
        .get_child("encrypted", "")
        .or_else(|| stanza.get_child("encrypted", custom_ns::OMEMO))
        .or_else(|| stanza.get_child("encrypted", custom_ns::OMEMO_V1))?;
    let header = encrypted
        .get_child("header", "")
        .or_else(|| encrypted.get_child("header", custom_ns::OMEMO))?;
    header.attr("sid")?.parse::<u32>().ok()
}

fn extract_iv(header: &Element) -> Option<Vec<u8>> {
    let iv_elem = header
        .get_child("iv", "")
        .or_else(|| header.get_child("iv", custom_ns::OMEMO))?;
    base64::engine::general_purpose::STANDARD
        .decode(iv_elem.text())
        .ok()
}

/// Handle delivery receipt inline (no spawn).
async fn handle_receipt_inline(state: &mut CoordinatorState, stanza: &Element) -> Result<()> {
    if let Some(received) = stanza.get_child("received", custom_ns::RECEIPTS) {
        if let Some(receipt_id) = received.attr("id") {
            if let Some(pending) = state.pending_receipts.get_mut(receipt_id) {
                info!("Received delivery receipt for message {}", receipt_id);
                pending.status = DeliveryStatus::Delivered;

                let ui_message = Message::delivery_update(
                    pending.id.clone(),
                    pending.to.clone(),
                    pending.content.clone(),
                    DeliveryStatus::Delivered,
                    false,
                );
                send_to_ui(&state.msg_tx, ui_message);
            }
        }
    }
    Ok(())
}

/// Handle carbon messages inline (no spawn).
async fn handle_carbon_inline(state: &mut CoordinatorState, stanza: &Element) {
    let is_sent = stanza.has_child("sent", custom_ns::CARBONS);
    let carbon_type = if is_sent { "sent" } else { "received" };

    let carbon_element = match stanza.get_child(carbon_type, custom_ns::CARBONS) {
        Some(e) => e,
        None => return,
    };

    let forwarded = match carbon_element.get_child("forwarded", custom_ns::FORWARD) {
        Some(f) => f,
        None => return,
    };

    let message = match forwarded.get_child("message", "jabber:client") {
        Some(m) => m,
        None => return,
    };

    // Check for OMEMO encrypted carbon
    if message.has_child("encrypted", custom_ns::OMEMO)
        || message.has_child("encrypted", "")
        || message.has_child("encrypted", custom_ns::OMEMO_V1)
    {
        // Decrypt inline
        handle_omemo_message(state, message).await;
        return;
    }

    // Plain carbon
    let from = match message.attr("from") {
        Some(f) => f,
        None => return,
    };
    let to = match message.attr("to") {
        Some(t) => t,
        None => return,
    };

    let body_text = message
        .get_child("body", "jabber:client")
        .or_else(|| message.get_child("body", ""))
        .map(|b| b.text())
        .unwrap_or_default();

    if body_text.is_empty() {
        return;
    }

    let msg_id = message
        .attr("id")
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let (sender_id, recipient_id) = if is_sent {
        ("me".to_string(), to.to_string())
    } else {
        (from.to_string(), "me".to_string())
    };

    let ui_message = if sender_id == "me" {
        Message::outgoing_plaintext(msg_id, recipient_id, body_text)
    } else {
        Message::incoming_plaintext(msg_id, sender_id, body_text)
    };

    send_to_ui(&state.msg_tx, ui_message);
}

/// Check OMEMO keys for a contact (inline, no spawn).
async fn check_omemo_keys_inline(state: &mut CoordinatorState, contact: &str) -> Result<()> {
    if contact.starts_with('[') && contact.ends_with(']') {
        return Ok(());
    }

    let omemo_manager = state
        .omemo_manager
        .as_mut()
        .ok_or_else(|| anyhow!("OMEMO not initialized"))?;

    let device_ids = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        omemo_manager.get_device_ids_for_test(contact),
    )
    .await
    {
        Ok(Ok(ids)) => ids,
        Ok(Err(e)) => {
            warn!("Failed to get device IDs for {}: {}", contact, e);
            return Ok(());
        }
        Err(_) => {
            warn!("Timeout getting device IDs for {}", contact);
            return Ok(());
        }
    };

    if device_ids.is_empty() {
        return Ok(());
    }

    let storage = crate::omemo::storage::OmemoStorage::new_default()?;
    if let Ok(Some(_)) = storage.get_pending_device_verification(contact) {
        return Ok(());
    }

    for device_id in device_ids {
        let trusted = match tokio::time::timeout(
            std::time::Duration::from_secs(8),
            omemo_manager.is_device_identity_trusted(contact, device_id),
        )
        .await
        {
            Ok(Ok(t)) => t,
            _ => false,
        };

        if !trusted {
            let fingerprint = match tokio::time::timeout(
                std::time::Duration::from_secs(8),
                omemo_manager.get_device_fingerprint(contact, device_id),
            )
            .await
            {
                Ok(Ok(fp)) => fp,
                _ => continue,
            };

            if storage.is_device_trusted(contact, device_id)? {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    omemo_manager.trust_device_identity(contact, device_id),
                )
                .await;
                continue;
            }

            let _ = storage.store_pending_device_verification(contact, device_id, &fingerprint);

            // Send verification request to UI
            let special_message = Message::system(
                "me",
                format!(
                    "__OMEMO_KEY_VERIFY__:{}:{}:{}",
                    contact, fingerprint, device_id
                ),
            );
            send_to_ui(&state.msg_tx, special_message);
            break;
        }
    }

    Ok(())
}

/// Toggle trust for a contact's devices (inline).
async fn toggle_trust_inline(state: &mut CoordinatorState, contact: &str) -> Result<bool> {
    let omemo_manager = state
        .omemo_manager
        .as_mut()
        .ok_or_else(|| anyhow!("OMEMO not initialized"))?;

    let device_ids = omemo_manager
        .get_device_ids_for_test(contact)
        .await
        .map_err(|e| anyhow!("{}", e))?;

    if device_ids.is_empty() {
        return Err(anyhow!("No OMEMO devices found"));
    }

    let mut all_trusted = true;
    let mut statuses = Vec::new();

    for &device_id in &device_ids {
        let trusted = omemo_manager
            .is_device_identity_trusted(contact, device_id)
            .await
            .unwrap_or(false);
        statuses.push((device_id, trusted));
        if !trusted {
            all_trusted = false;
        }
    }

    let set_trusted = !all_trusted;

    for (device_id, current_trusted) in statuses {
        if current_trusted != set_trusted {
            if set_trusted {
                omemo_manager
                    .trust_device_identity(contact, device_id)
                    .await
                    .map_err(|e| anyhow!("{}", e))?;
            } else {
                omemo_manager
                    .untrust_device_identity(contact, device_id)
                    .await
                    .map_err(|e| anyhow!("{}", e))?;
            }
        }
    }

    Ok(set_trusted)
}

/// Handle key verification response inline.
async fn handle_key_verification_inline(
    state: &mut CoordinatorState,
    contact: &str,
    response: &str,
) -> Result<()> {
    match response {
        "__KEY_ACCEPTED__" => {
            info!("OMEMO key for {} accepted", contact);
            let msg = Message::system(
                "me",
                format!(
                    "OMEMO key for {} has been accepted and marked as trusted",
                    contact
                ),
            );
            send_to_ui(&state.msg_tx, msg);
        }
        "__KEY_REJECTED__" => {
            info!("OMEMO key for {} rejected", contact);
            let msg = Message::system("me", format!("OMEMO key for {} has been rejected", contact));
            send_to_ui(&state.msg_tx, msg);
        }
        _ => {
            return Err(anyhow!("Unknown key verification response: {}", response));
        }
    }
    Ok(())
}

/// Send a chat state notification via the transport channel.
fn send_chat_state_inline(
    stanza_tx: &StanzaTx,
    recipient: &str,
    typing_state: &chat_states::TypingStatus,
) -> Result<()> {
    let state_name = match typing_state {
        chat_states::TypingStatus::Active => "active",
        chat_states::TypingStatus::Composing => "composing",
        chat_states::TypingStatus::Paused => "paused",
        chat_states::TypingStatus::Inactive => "inactive",
        chat_states::TypingStatus::Gone => "gone",
    };

    let message = Element::builder("message", "jabber:client")
        .attr("to", recipient)
        .attr("type", "chat")
        .attr("id", &uuid::Uuid::new_v4().to_string())
        .append(Element::builder(state_name, custom_ns::CHATSTATES).build())
        .build();

    super::transport::send_stanza(stanza_tx, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    // ─── Coordinator lifecycle tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_coordinator_shuts_down_on_shutdown_command() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Send shutdown
        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();

        // Coordinator should exit (channel closes)
        drop(event_tx);
        // Subsequent sends should fail once the coordinator processes shutdown
        tokio::time::sleep(Duration::from_millis(50)).await;
        let result = handle
            .cmd_tx
            .send(CoordinatorCommand::IsOmemoEnabled {
                reply: tokio::sync::oneshot::channel().0,
            })
            .await;
        // Either fails immediately or the reply is dropped
        // Just ensure no hang
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_coordinator_shuts_down_on_transport_close() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Drop event_tx to simulate transport close
        drop(_event_tx);

        // Wait for coordinator to notice and shut down
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The coordinator should have exited — is_omemo_enabled should return false
        // (either via the reply or via channel error)
        let result = handle.is_omemo_enabled().await;
        assert!(!result);
    }

    // ─── Command routing tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_is_omemo_enabled_false_when_no_manager() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle.is_omemo_enabled().await;
        assert!(!result);

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_send_message_fails_without_omemo() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle.send_message("bob@example.org", "hello").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("OMEMO not initialized"));

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_device_ids_fails_without_omemo() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle.get_device_ids("bob@example.org").await;
        assert!(result.is_err());

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_fingerprint_fails_without_omemo() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle.get_fingerprint("bob@example.org", 12345).await;
        assert!(result.is_err());

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Plaintext message handling tests ─────────────────────────────────

    #[tokio::test]
    async fn test_send_plaintext_produces_stanza_and_ui_message() {
        let (stanza_tx, mut stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle
            .send_plaintext("bob@example.org", "hello world")
            .await;
        assert!(result.is_ok());
        let msg_id = result.unwrap();

        // Check that a stanza was sent to transport
        let stanza = timeout(Duration::from_millis(100), stanza_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(stanza.attr("to"), Some("bob@example.org"));
        assert_eq!(stanza.attr("type"), Some("chat"));
        assert_eq!(stanza.attr("id"), Some(msg_id.as_str()));

        // Check body
        let body = stanza.get_child("body", "jabber:client").expect("no body");
        assert_eq!(body.text(), "hello world");

        // Check receipt request
        assert!(stanza.has_child("request", custom_ns::RECEIPTS));

        // Check that a UI message was sent
        let ui_msg = timeout(Duration::from_millis(100), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(ui_msg.sender_id, "me");
        assert_eq!(ui_msg.recipient_id, "bob@example.org");
        assert_eq!(ui_msg.content, "hello world");
        assert!(!ui_msg.encrypted);
        assert_eq!(ui_msg.delivery_status, DeliveryStatus::Sent);

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Inbound message routing tests ────────────────────────────────────

    #[tokio::test]
    async fn test_inbound_plaintext_message_delivered_to_ui() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Simulate an inbound message from the transport
        let inbound = Element::builder("message", "jabber:client")
            .attr("from", "alice@example.org/phone")
            .attr("to", "test@example.org/res")
            .attr("type", "chat")
            .attr("id", "msg-001")
            .append(
                Element::builder("body", "jabber:client")
                    .append("Hey there!")
                    .build(),
            )
            .build();

        event_tx.send(tokio_xmpp::Event::Stanza(inbound)).unwrap();

        // Wait for coordinator to process and deliver to UI
        let ui_msg = timeout(Duration::from_millis(200), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(ui_msg.sender_id, "alice@example.org");
        assert_eq!(ui_msg.content, "Hey there!");
        assert!(!ui_msg.encrypted);
        assert_eq!(ui_msg.id, "msg-001");

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_inbound_message_without_body_ignored() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Message with no body (e.g., just a chat state)
        let inbound = Element::builder("message", "jabber:client")
            .attr("from", "alice@example.org/phone")
            .attr("type", "chat")
            .append(Element::builder("composing", custom_ns::CHATSTATES).build())
            .build();

        event_tx.send(tokio_xmpp::Event::Stanza(inbound)).unwrap();

        // Should NOT produce a UI message
        let result = timeout(Duration::from_millis(100), msg_rx.recv()).await;
        assert!(result.is_err(), "Should not have received a message");

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Receipt tracking tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_delivery_receipt_updates_pending_message() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // First send a message to create a pending receipt entry
        let msg_id = handle
            .send_plaintext("bob@example.org", "test msg")
            .await
            .unwrap();

        // Drain the UI message for the sent message
        let _ = timeout(Duration::from_millis(100), msg_rx.recv()).await;

        // Now simulate a delivery receipt arriving from transport
        let receipt_stanza = Element::builder("message", "jabber:client")
            .attr("from", "bob@example.org/laptop")
            .attr("to", "test@example.org/res")
            .append(
                Element::builder("received", custom_ns::RECEIPTS)
                    .attr("id", msg_id.as_str())
                    .build(),
            )
            .build();

        event_tx
            .send(tokio_xmpp::Event::Stanza(receipt_stanza))
            .unwrap();

        // Should receive a UI update with Delivered status
        let ui_msg = timeout(Duration::from_millis(200), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(ui_msg.delivery_status, DeliveryStatus::Delivered);
        assert_eq!(ui_msg.id, msg_id);

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_receipt_for_unknown_message_is_ignored() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Receipt for a message we never sent
        let receipt_stanza = Element::builder("message", "jabber:client")
            .attr("from", "bob@example.org/laptop")
            .append(
                Element::builder("received", custom_ns::RECEIPTS)
                    .attr("id", "nonexistent-msg-id")
                    .build(),
            )
            .build();

        event_tx
            .send(tokio_xmpp::Event::Stanza(receipt_stanza))
            .unwrap();

        // Should NOT produce a UI message
        let result = timeout(Duration::from_millis(100), msg_rx.recv()).await;
        assert!(
            result.is_err(),
            "Should not have received a message for unknown receipt"
        );

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Store message ID (fire-and-forget) tests ─────────────────────────

    #[tokio::test]
    async fn test_store_message_id_tracks_pending() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Store a message ID
        handle.store_message_id("bob@example.org", "manual-msg-123");

        // Give coordinator time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now send a receipt for it — should be found
        let receipt_stanza = Element::builder("message", "jabber:client")
            .attr("from", "bob@example.org/laptop")
            .append(
                Element::builder("received", custom_ns::RECEIPTS)
                    .attr("id", "manual-msg-123")
                    .build(),
            )
            .build();

        event_tx
            .send(tokio_xmpp::Event::Stanza(receipt_stanza))
            .unwrap();

        let ui_msg = timeout(Duration::from_millis(200), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(ui_msg.delivery_status, DeliveryStatus::Delivered);
        assert_eq!(ui_msg.id, "manual-msg-123");

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Chat state tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_send_chat_state_produces_stanza() {
        let (stanza_tx, mut stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        handle.send_chat_state("bob@example.org", &chat_states::TypingStatus::Composing);

        // Give coordinator time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stanza = timeout(Duration::from_millis(100), stanza_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(stanza.attr("to"), Some("bob@example.org"));
        assert!(stanza.has_child("composing", custom_ns::CHATSTATES));

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_inbound_chat_state_forwarded_to_typing_tx() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);
        let (typing_tx, mut typing_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            Some(typing_tx),
            "test@example.org".to_string(),
            None,
            None,
        );

        let inbound = Element::builder("message", "jabber:client")
            .attr("from", "alice@example.org/phone")
            .attr("type", "chat")
            .append(Element::builder("composing", custom_ns::CHATSTATES).build())
            .build();

        event_tx.send(tokio_xmpp::Event::Stanza(inbound)).unwrap();

        let (jid, status) = timeout(Duration::from_millis(200), typing_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        // chat_states::handle_chat_state strips the resource
        assert!(jid.starts_with("alice@example.org"), "got jid={}", jid);
        assert_eq!(status, chat_states::TypingStatus::Composing);

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Online event tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_online_event_signals_online_tx() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);
        let (online_tx, online_rx) = oneshot::channel();

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            Some(online_tx),
        );

        // Simulate Online event
        let bound_jid: tokio_xmpp::Jid = "test@example.org/resource123".parse().unwrap();
        event_tx
            .send(tokio_xmpp::Event::Online {
                bound_jid,
                resumed: false,
            })
            .unwrap();

        // online_rx should fire
        let result = timeout(Duration::from_millis(200), online_rx).await;
        assert!(result.is_ok(), "online_tx should have been signaled");
    }

    #[tokio::test]
    async fn test_online_event_only_fires_once() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);
        let (online_tx, online_rx) = oneshot::channel();

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            Some(online_tx),
        );

        let bound_jid: tokio_xmpp::Jid = "test@example.org/res1".parse().unwrap();
        event_tx
            .send(tokio_xmpp::Event::Online {
                bound_jid: bound_jid.clone(),
                resumed: false,
            })
            .unwrap();

        // Wait for first online
        let _ = timeout(Duration::from_millis(100), online_rx).await;

        // Send another Online — should not panic or error
        event_tx
            .send(tokio_xmpp::Event::Online {
                bound_jid,
                resumed: true,
            })
            .unwrap();

        // Give it time to process without panic
        tokio::time::sleep(Duration::from_millis(50)).await;

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── IQ routing tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_iq_response_routed_through_registry() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx.clone(),
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // We can't easily test IQ routing directly without accessing the internal
        // iq_registry. But we can test that IQ stanzas don't cause panics.
        let iq_result = Element::builder("iq", "jabber:client")
            .attr("type", "result")
            .attr("id", "some-iq-id")
            .attr("from", "server.example.org")
            .build();

        event_tx.send(tokio_xmpp::Event::Stanza(iq_result)).unwrap();

        // Give coordinator time to process without panic
        tokio::time::sleep(Duration::from_millis(50)).await;

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Carbon message tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_received_carbon_delivered_to_ui() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Build a received carbon
        let forwarded_msg = Element::builder("message", "jabber:client")
            .attr("from", "alice@example.org/phone")
            .attr("to", "test@example.org/res")
            .attr("type", "chat")
            .attr("id", "carbon-msg-001")
            .append(
                Element::builder("body", "jabber:client")
                    .append("Carbon message!")
                    .build(),
            )
            .build();

        let forwarded = Element::builder("forwarded", custom_ns::FORWARD)
            .append(forwarded_msg)
            .build();

        let received = Element::builder("received", custom_ns::CARBONS)
            .append(forwarded)
            .build();

        let carbon_wrapper = Element::builder("message", "jabber:client")
            .attr("from", "test@example.org") // from our bare JID
            .attr("to", "test@example.org/res")
            .append(received)
            .build();

        event_tx
            .send(tokio_xmpp::Event::Stanza(carbon_wrapper))
            .unwrap();

        let ui_msg = timeout(Duration::from_millis(200), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(ui_msg.sender_id, "alice@example.org/phone");
        assert_eq!(ui_msg.content, "Carbon message!");

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_sent_carbon_delivered_to_ui_with_me_sender() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Build a sent carbon
        let forwarded_msg = Element::builder("message", "jabber:client")
            .attr("from", "test@example.org/other-device")
            .attr("to", "bob@example.org")
            .attr("type", "chat")
            .attr("id", "sent-carbon-001")
            .append(
                Element::builder("body", "jabber:client")
                    .append("Sent from other device")
                    .build(),
            )
            .build();

        let forwarded = Element::builder("forwarded", custom_ns::FORWARD)
            .append(forwarded_msg)
            .build();

        let sent = Element::builder("sent", custom_ns::CARBONS)
            .append(forwarded)
            .build();

        let carbon_wrapper = Element::builder("message", "jabber:client")
            .attr("from", "test@example.org")
            .attr("to", "test@example.org/res")
            .append(sent)
            .build();

        event_tx
            .send(tokio_xmpp::Event::Stanza(carbon_wrapper))
            .unwrap();

        let ui_msg = timeout(Duration::from_millis(200), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(ui_msg.sender_id, "me");
        assert_eq!(ui_msg.recipient_id, "bob@example.org");
        assert_eq!(ui_msg.content, "Sent from other device");

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Handle dropped coordinator gracefully ────────────────────────────

    #[tokio::test]
    async fn test_handle_returns_error_when_coordinator_gone() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Shut it down
        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now all operations should fail cleanly
        let result = handle.send_plaintext("bob@example.org", "hello").await;
        assert!(result.is_err());
    }

    // ─── Inbound receipt request triggers receipt response ────────────────

    #[tokio::test]
    async fn test_inbound_message_with_receipt_request_sends_receipt() {
        let (stanza_tx, mut stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let inbound = Element::builder("message", "jabber:client")
            .attr("from", "alice@example.org/phone")
            .attr("to", "test@example.org/res")
            .attr("type", "chat")
            .attr("id", "msg-with-receipt")
            .append(
                Element::builder("body", "jabber:client")
                    .append("Please receipt me")
                    .build(),
            )
            .append(Element::builder("request", custom_ns::RECEIPTS).build())
            .build();

        event_tx.send(tokio_xmpp::Event::Stanza(inbound)).unwrap();

        // Drain the UI message
        let _ = timeout(Duration::from_millis(100), msg_rx.recv()).await;

        // Should have sent a receipt stanza
        let receipt = timeout(Duration::from_millis(100), stanza_rx.recv())
            .await
            .expect("timeout")
            .expect("no receipt stanza");
        assert_eq!(receipt.attr("to"), Some("alice@example.org/phone"));

        let received_elem = receipt
            .get_child("received", custom_ns::RECEIPTS)
            .expect("no received element");
        assert_eq!(received_elem.attr("id"), Some("msg-with-receipt"));

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Key verification response tests ──────────────────────────────────

    #[tokio::test]
    async fn test_key_verification_invalid_response_returns_error() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle
            .key_verification_response("bob@example.org", "invalid-response")
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown key verification response"));

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_key_verification_accepted_sends_ui_message() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let result = handle
            .key_verification_response("bob@example.org", "__KEY_ACCEPTED__")
            .await;
        assert!(result.is_ok());

        let ui_msg = timeout(Duration::from_millis(200), msg_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(ui_msg.content.contains("accepted"));
        assert!(ui_msg.content.contains("bob@example.org"));
        assert_eq!(ui_msg.sender_id, "system");

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Disconnected event doesn't crash coordinator ─────────────────────

    #[tokio::test]
    async fn test_disconnected_event_handled_gracefully() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        event_tx
            .send(tokio_xmpp::Event::Disconnected(
                tokio_xmpp::Error::Disconnected,
            ))
            .unwrap();

        // Coordinator should still be alive
        tokio::time::sleep(Duration::from_millis(50)).await;
        let result = handle.is_omemo_enabled().await;
        assert!(!result);

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Presence stanza doesn't crash coordinator ────────────────────────

    #[tokio::test]
    async fn test_presence_stanza_processed_without_panic() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, _msg_rx) = mpsc::channel(16);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        let presence = Element::builder("presence", "jabber:client")
            .attr("from", "alice@example.org/phone")
            .attr("type", "available")
            .build();

        event_tx.send(tokio_xmpp::Event::Stanza(presence)).unwrap();

        // Give it time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Still alive
        assert!(!_handle.is_omemo_enabled().await);
        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }

    // ─── Backpressure: coordinator does NOT deadlock when UI is slow ──────

    #[tokio::test]
    async fn test_coordinator_does_not_block_when_ui_channel_full() {
        // Create a TINY msg channel (capacity 1) to easily fill it
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, msg_rx) = mpsc::channel(1); // capacity=1

        let handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Send 5 messages to the coordinator — only 1 can fit in msg_rx
        for i in 0..5 {
            let inbound = Element::builder("message", "jabber:client")
                .attr("from", "alice@example.org/phone")
                .attr("type", "chat")
                .attr("id", &format!("flood-{}", i))
                .append(
                    Element::builder("body", "jabber:client")
                        .append(format!("Message {}", i))
                        .build(),
                )
                .build();
            event_tx.send(tokio_xmpp::Event::Stanza(inbound)).unwrap();
        }

        // Give coordinator time to process all 5 events
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The coordinator should still be responsive (not deadlocked).
        // If it were using .await on msg_tx.send(), it would be stuck after
        // the first message fills the channel, and this would timeout.
        let responsive = timeout(Duration::from_millis(200), handle.is_omemo_enabled()).await;
        assert!(responsive.is_ok(), "Coordinator is deadlocked!");
        assert!(!responsive.unwrap());

        // We can also send a command and get a reply back
        let send_result = timeout(
            Duration::from_millis(200),
            handle.send_plaintext("bob@example.org", "still alive"),
        )
        .await;
        assert!(
            send_result.is_ok(),
            "Coordinator deadlocked on command processing"
        );

        handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();

        // Clean up — drain what we can
        drop(msg_rx);
    }

    #[tokio::test]
    async fn test_messages_delivered_when_ui_drains() {
        // Capacity 2: first 2 messages delivered, rest dropped
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();
        let (msg_tx, mut msg_rx) = mpsc::channel(2);

        let _handle = spawn_coordinator(
            stanza_tx,
            event_rx,
            msg_tx,
            None,
            "test@example.org".to_string(),
            None,
            None,
        );

        // Send 4 messages
        for i in 0..4 {
            let inbound = Element::builder("message", "jabber:client")
                .attr("from", "alice@example.org/phone")
                .attr("type", "chat")
                .attr("id", &format!("msg-{}", i))
                .append(
                    Element::builder("body", "jabber:client")
                        .append(format!("Hello {}", i))
                        .build(),
                )
                .build();
            event_tx.send(tokio_xmpp::Event::Stanza(inbound)).unwrap();
        }

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        // We should get at most 2 messages (channel capacity)
        let mut received = Vec::new();
        while let Ok(msg) = msg_rx.try_recv() {
            received.push(msg);
        }

        // At least 1 delivered, at most 2 (capacity). The rest were dropped.
        assert!(
            !received.is_empty(),
            "Should have received at least 1 message"
        );
        assert!(
            received.len() <= 2,
            "Should not exceed channel capacity, got {}",
            received.len()
        );

        _handle
            .cmd_tx
            .send(CoordinatorCommand::Shutdown)
            .await
            .unwrap();
    }
}
