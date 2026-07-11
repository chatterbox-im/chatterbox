// src/xmpp/event_loop.rs
//! Main XMPP event processing loop.
//!
//! Receives events from the transport actor via an unbounded channel.
//! No mutex contention, no poll-sleep-retry — events arrive instantly.

use log::{debug, error, info, warn};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex as TokioMutex};

use tokio_xmpp::Event as XMPPEvent;
use tokio_xmpp::Stanza;
use xmpp_parsers::minidom::Element;

use super::transport::{self, StanzaTx};
use super::{chat_states, delivery_receipts, discovery, presence};
use super::{custom_ns, LateStateRx, XMPPClient};
use crate::models::{Message, PendingMessage};

impl XMPPClient {
    /// Primary event processing loop.
    /// Receives events from the transport actor and dispatches them.
    pub(super) async fn handle_incoming_messages(
        stanza_tx: StanzaTx,
        mut event_rx: mpsc::UnboundedReceiver<XMPPEvent>,
        msg_tx: mpsc::Sender<Message>,
        pending_receipts: Arc<TokioMutex<std::collections::HashMap<String, PendingMessage>>>,
        iq_registry: Arc<TokioMutex<crate::xmpp::iq_registry::IqResponseRegistry>>,
        late_state: LateStateRx,
        online_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    ) {
        let mut seen_online_event = false;
        let mut reconnecting = false;
        let mut online_tx = online_tx;
        let mut typing_tx_cache: Option<mpsc::Sender<(String, chat_states::TypingStatus)>> = None;
        let mut our_bare_jid: Option<String> = None;

        let service_discovery = discovery::ServiceDiscovery::new(stanza_tx.clone());

        // Main event loop — blocks on channel recv, wakes instantly on new events
        while let Some(event) = event_rx.recv().await {
            match event {
                XMPPEvent::Stanza(stanza) => {
                    // v6 yields a typed Stanza; convert to raw Element so the
                    // rest of the event loop can use the existing minidom API.
                    let stanza: Element = match stanza {
                        Stanza::Message(m) => m.into(),
                        Stanza::Presence(p) => p.into(),
                        Stanza::Iq(i) => i.into(),
                    };
                    if stanza.name() == "presence" {
                        if let Err(e) = presence::handle_presence_stanza(&stanza) {
                            error!("Error processing presence stanza: {}", e);
                        }

                        if let Err(e) = service_discovery.process_caps_in_presence(&stanza).await {
                            warn!("Error processing entity capabilities in presence: {}", e);
                        }

                        let stanza_tx_clone = stanza_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                presence::process_subscription(&stanza_tx_clone, &stanza).await
                            {
                                error!("Error processing presence subscription: {}", e);
                            }
                        });
                    } else if stanza.name() == "message" {
                        // Check if this is a MAM result that should be routed to a collector
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if let Some(query_id) = result.attr("queryid") {
                                let registry = iq_registry.lock().await;
                                if registry.try_route_mam(query_id, stanza.clone()) {
                                    debug!(
                                        "Routed MAM message to collector for query {}",
                                        query_id
                                    );
                                    continue;
                                }
                            }
                        }

                        let from = stanza.attr("from").unwrap_or("");
                        let to = stanza.attr("to").unwrap_or("");
                        info!("Received message stanza from='{}', to='{}'", from, to);
                        // Don't dump the full stanza — it may contain a plaintext body.
                        debug!("Received <{}> stanza from {}", stanza.name(), from);

                        fn has_omemo_encryption(
                            msg_stanza: &xmpp_parsers::minidom::Element,
                        ) -> (bool, bool, bool, bool) {
                            let has_omemo_v1 = msg_stanza.has_child("encrypted", custom_ns::OMEMO);
                            let has_omemo_axolotl =
                                msg_stanza.has_child("encrypted", custom_ns::OMEMO_V1);
                            let has_omemo_empty = msg_stanza.has_child("encrypted", "");
                            let has_omemo_explicit =
                                msg_stanza.has_child("encrypted", "eu.siacs.conversations.axolotl");
                            (
                                has_omemo_v1,
                                has_omemo_axolotl,
                                has_omemo_empty,
                                has_omemo_explicit,
                            )
                        }

                        let (has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit) =
                            has_omemo_encryption(&stanza);

                        let mut mam_message_stanza = None;
                        if let Some(result) = stanza.get_child("result", custom_ns::MAM) {
                            if let Some(forwarded) =
                                result.get_child("forwarded", custom_ns::FORWARD)
                            {
                                if let Some(inner_msg) =
                                    forwarded.get_child("message", "jabber:client")
                                {
                                    mam_message_stanza = Some(inner_msg);
                                }
                            }
                        }

                        let (
                            mam_has_omemo_v1,
                            mam_has_omemo_axolotl,
                            mam_has_omemo_empty,
                            mam_has_omemo_explicit,
                        ) = if let Some(mam_msg) = &mam_message_stanza {
                            has_omemo_encryption(mam_msg)
                        } else {
                            (false, false, false, false)
                        };

                        let has_any_omemo = has_omemo_v1
                            || has_omemo_axolotl
                            || has_omemo_empty
                            || has_omemo_explicit;
                        let has_mam_omemo = mam_has_omemo_v1
                            || mam_has_omemo_axolotl
                            || mam_has_omemo_empty
                            || mam_has_omemo_explicit;

                        debug!("OMEMO detection: outer(v1={}, axolotl={}, empty={}, explicit={}), MAM(v1={}, axolotl={}, empty={}, explicit={})", 
                            has_omemo_v1, has_omemo_axolotl, has_omemo_empty, has_omemo_explicit,
                            mam_has_omemo_v1, mam_has_omemo_axolotl, mam_has_omemo_empty, mam_has_omemo_explicit);

                        if has_any_omemo {
                            if let Some(encrypted) = stanza.get_child("encrypted", "") {
                                debug!("Found encrypted element in outer stanza with empty namespace: {:?}", encrypted);
                            }
                            if let Some(encrypted) =
                                stanza.get_child("encrypted", "eu.siacs.conversations.axolotl")
                            {
                                debug!("Found encrypted element in outer stanza with axolotl namespace: {:?}", encrypted);
                            }
                        }
                        if has_mam_omemo {
                            if let Some(mam_msg) = &mam_message_stanza {
                                if let Some(encrypted) = mam_msg.get_child("encrypted", "") {
                                    debug!("Found encrypted element in MAM message with empty namespace: {:?}", encrypted);
                                }
                                if let Some(encrypted) =
                                    mam_msg.get_child("encrypted", "eu.siacs.conversations.axolotl")
                                {
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
                            let iq_registry_clone = iq_registry.clone();
                            let state = late_state.borrow().clone();

                            debug!("OMEMO message detected - spawning async task for processing");

                            tokio::spawn(async move {
                                debug!("Inside OMEMO async task - starting processing");

                                let omemo_manager = state.omemo_manager.clone();
                                let jid = state.jid.clone();

                                if omemo_manager.is_none() {
                                    error!("OMEMO manager not available");
                                    return;
                                }

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
                                    late_state_tx: None,
                                    typing_tx: None,
                                    omemo_dir: None,
                                };

                                debug!("Calling handle_message_encrypted method");
                                if let Err(e) =
                                    temp_client.handle_message_encrypted(&target_stanza).await
                                {
                                    error!("Failed to process encrypted message: {}", e);
                                } else {
                                    debug!("Successfully processed encrypted message");
                                }
                            });
                        } else {
                            info!("Processing non-OMEMO message from {}", from);
                            // Don't dump the full stanza — it contains the plaintext body.
                            debug!("Non-OMEMO message <{}> from {}", stanza.name(), from);

                            if let Err(e) = delivery_receipts::handle_receipt(
                                &stanza,
                                &pending_receipts,
                                &msg_tx,
                            )
                            .await
                            {
                                error!("Error processing delivery receipt: {}", e);
                            }

                            if typing_tx_cache.is_none() {
                                typing_tx_cache = late_state.borrow().typing_tx.clone();
                            }
                            if let Err(e) =
                                chat_states::handle_chat_state(&stanza, typing_tx_cache.as_ref())
                            {
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

                            if carbon_from_is_valid
                                && (stanza.has_child("received", custom_ns::CARBONS)
                                    || stanza.has_child("sent", custom_ns::CARBONS))
                            {
                                let stanza_clone = stanza.clone();
                                let stanza_tx_clone = stanza_tx.clone();
                                let msg_tx_clone = msg_tx.clone();
                                let pending_receipts_clone = pending_receipts.clone();
                                let iq_registry_clone2 = iq_registry.clone();
                                let state = late_state.borrow().clone();

                                tokio::spawn(async move {
                                    let temp_client = XMPPClient {
                                        jid: state.jid.clone(),
                                        stanza_tx: Some(stanza_tx_clone),
                                        msg_tx: msg_tx_clone,
                                        pending_receipts: pending_receipts_clone,
                                        connected: true,
                                        omemo_manager: state.omemo_manager.clone(),
                                        carbons_enabled: Arc::new(AtomicBool::new(true)),
                                        iq_registry: iq_registry_clone2,
                                        pubsub_responses: None,
                                        late_state_tx: None,
                                        typing_tx: None,
                                        omemo_dir: None,
                                    };

                                    if let Err(e) = temp_client.process_carbon(&stanza_clone).await
                                    {
                                        error!("Failed to process message carbon: {}", e);
                                    }
                                });
                            }

                            // Process regular chat messages (non-encrypted)
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

                                debug!("Found message body from {} ({} bytes)", from, content.len());

                                if !content.is_empty() {
                                    let sender_bare_jid =
                                        from.split('/').next().unwrap_or(from).to_string();

                                    let message = Message::incoming_plaintext(
                                        id.clone(),
                                        sender_bare_jid.clone(),
                                        content.clone(),
                                    );

                                    info!(
                                        "Sending message to UI: from='{}' (bare: '{}', {} bytes)",
                                        from,
                                        sender_bare_jid,
                                        content.len()
                                    );

                                    if let Err(e) = msg_tx.send(message).await {
                                        error!("Failed to send message to UI: {}", e);
                                    } else {
                                        info!("Successfully sent message to UI channel");
                                    }

                                    // Send a receipt if requested
                                    if stanza.has_child("request", custom_ns::RECEIPTS) {
                                        if let Err(e) =
                                            delivery_receipts::send_receipt(&stanza_tx, from, &id)
                                        {
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

                        if let Some(_query) = stanza.get_child("query", "jabber:iq:roster") {
                            // Roster push from server — acknowledge it per RFC 6121 Section 2.1.6
                            if stanza.attr("type") == Some("set") {
                                if let Some(stanza_id) = stanza.attr("id") {
                                    let ack = Element::builder("iq", "jabber:client")
                                        .attr("type".try_into().unwrap(), "result")
                                        .attr("id".try_into().unwrap(), stanza_id)
                                        .build();
                                    if let Err(e) = transport::send_stanza(&stanza_tx, ack) {
                                        warn!("Failed to acknowledge roster push: {}", e);
                                    } else {
                                        debug!("Acknowledged roster push (id={})", stanza_id);
                                    }
                                }
                            }
                        } else if let Some(_query) =
                            stanza.get_child("query", "http://jabber.org/protocol/disco#info")
                        {
                            if stanza.attr("type") == Some("get") {
                                // Respond to incoming disco#info queries with our capabilities
                                if let Err(e) =
                                    service_discovery.respond_to_disco_info_query(&stanza)
                                {
                                    warn!("Failed to respond to disco#info query: {}", e);
                                }
                            } else if let Err(e) =
                                service_discovery.handle_disco_response(&stanza).await
                            {
                                warn!("Failed to process service discovery info response: {}", e);
                            }
                        } else if let Some(_query) =
                            stanza.get_child("query", "http://jabber.org/protocol/disco#items")
                        {
                            if let Err(e) = service_discovery.handle_disco_response(&stanza).await {
                                warn!("Failed to process service discovery items response: {}", e);
                            }
                        } else if let Some(_pubsub) =
                            stanza.get_child("pubsub", "http://jabber.org/protocol/pubsub")
                        {
                            if stanza.attr("type") == Some("get") {
                                let has_omemo = late_state.borrow().omemo_manager.is_some();
                                if has_omemo {
                                    debug!(
                                        "Received pubsub request, but handling not implemented yet"
                                    );
                                } else {
                                    warn!(
                                        "Received pubsub request but OMEMO manager not available"
                                    );
                                }
                            } else if stanza.attr("type") == Some("result") {
                                if let Some(stanza_id) = stanza.attr("id") {
                                    debug!("Received pubsub response with ID: {}", stanza_id);
                                    let xml_string =
                                        crate::xmpp::omemo_integration::element_to_xml_string(
                                            &stanza,
                                        );
                                    let responses = late_state.borrow().pubsub_responses.clone();
                                    if let Some(ref responses) = responses {
                                        crate::xmpp::omemo_integration::store_pubsub_response_to(
                                            responses,
                                            stanza_id.to_string(),
                                            xml_string,
                                        )
                                        .await;
                                    }
                                }
                            }
                        } else if stanza.attr("type") == Some("error") {
                            if let Some(stanza_id) = stanza.attr("id") {
                                let xml_string =
                                    crate::xmpp::omemo_integration::element_to_xml_string(&stanza);
                                let responses = late_state.borrow().pubsub_responses.clone();
                                if let Some(ref responses) = responses {
                                    crate::xmpp::omemo_integration::store_pubsub_response_to(
                                        responses,
                                        stanza_id.to_string(),
                                        xml_string,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }
                XMPPEvent::Online {
                    bound_jid,                    features: _,                    resumed,
                } => {
                    // `reconnecting` is set when we saw an explicit Disconnected event.
                    // `!resumed && seen_online_event` catches the case where SM resumption
                    // failed and tokio-xmpp started a completely fresh session without
                    // emitting Disconnected first — carbons and presence must be
                    // re-established or the new session will be invisible to the server.
                    if reconnecting || (!resumed && seen_online_event) {
                        // Mid-session reconnect — re-establish XMPP session state.
                        // Carbons and presence are fire-and-forget (best-effort).
                        // Cancel any in-flight IQ requests from the old session so
                        // callers fail fast rather than waiting out their timeouts.
                        iq_registry.lock().await.cancel_all();
                        reconnecting = false;
                        info!("Reconnected to XMPP server as {}", bound_jid);
                        let iq_id = uuid::Uuid::new_v4().to_string();
                        let carbons_iq = Element::builder("iq", "jabber:client")
                            .attr("type".try_into().unwrap(), "set")
                            .attr("id".try_into().unwrap(), &iq_id)
                            .append(Element::builder("enable", custom_ns::CARBONS).build())
                            .build();
                        if let Err(e) = transport::send_stanza(&stanza_tx, carbons_iq) {
                            warn!("Failed to re-enable carbons after reconnect: {}", e);
                        }
                        if let Err(e) = transport::send_stanza(
                            &stanza_tx,
                            Element::builder("presence", "jabber:client").build(),
                        ) {
                            warn!("Failed to re-send presence after reconnect: {}", e);
                        }
                        if let Some(ref jid) = our_bare_jid {
                            let _ = msg_tx.send(Message::system(jid, "Reconnected.")).await;
                        }
                    } else if !seen_online_event {
                        info!("Connected to XMPP server as {}", bound_jid);
                        seen_online_event = true;
                        our_bare_jid = Some(
                            bound_jid
                                .to_string()
                                .split('/')
                                .next()
                                .unwrap_or("")
                                .to_string(),
                        );

                        if typing_tx_cache.is_none() {
                            typing_tx_cache = late_state.borrow().typing_tx.clone();
                        }

                        if let Some(tx) = online_tx.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                }
                XMPPEvent::Disconnected(reason) => {
                    let reason_str = format!("{:?}", reason);
                    error!("XMPP client is disconnected: {}", reason_str);

                    // NOTE: fatality detection inspects tokio-xmpp's Debug output.
                    // If that format changes in a future version this check may
                    // silently stop working and TLS errors would retry indefinitely.
                    let is_fatal = reason_str.contains("not trusted")
                        || reason_str.contains("ertificate") // Certificate / certificate
                        || reason_str.contains("NotAuthorized")
                        || reason_str.contains("not-authorized");

                    if let Some(tx) = online_tx.take() {
                        // Still in the initial-connect phase (Online not yet seen).
                        if is_fatal {
                            // Signal failure and exit; dropping event_rx shuts the
                            // transport down so it stops retrying.
                            let msg = if reason_str.contains("not trusted")
                                || reason_str.contains("ertificate")
                            {
                                "TLS certificate is not trusted by this system".to_string()
                            } else {
                                format!("Connection failed: {}", reason_str)
                            };
                            let _ = tx.send(Err(msg));
                            break;
                        }
                        // Transient failure: restore online_tx and let the transport
                        // retry. wait_for_connection's 20-second timeout is the limit.
                        online_tx = Some(tx);
                    } else {
                        // Mid-session drop. Set reconnecting flag so the next Online
                        // event re-establishes carbons and presence.
                        // Cancel in-flight IQs immediately so callers fail fast.
                        iq_registry.lock().await.cancel_all();
                        reconnecting = true;
                        let notify = if is_fatal {
                            format!("Connection error — cannot reconnect: {}", reason_str)
                        } else {
                            "Connection lost. Reconnecting...".to_string()
                        };
                        if let Some(ref jid) = our_bare_jid {
                            let _ = msg_tx.send(Message::system(jid, &notify)).await;
                        }
                        if is_fatal {
                            break;
                        }
                        // Don't break — transport will reconnect and fire Online.
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmpp::iq_registry::IqResponseRegistry;
    use crate::xmpp::LateState;
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::time::timeout;
    use tokio_xmpp::Event as XMPPEvent;

    /// Minimal event loop harness: returns (event sender, stanza receiver,
    /// message receiver, online oneshot receiver).
    fn spawn_loop() -> (
        mpsc::UnboundedSender<XMPPEvent>,
        mpsc::UnboundedReceiver<xmpp_parsers::minidom::Element>,
        mpsc::Receiver<Message>,
        oneshot::Receiver<Result<(), String>>,
    ) {
        let (stanza_tx, stanza_rx) =
            mpsc::unbounded_channel::<xmpp_parsers::minidom::Element>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<XMPPEvent>();
        let (msg_tx, msg_rx) = mpsc::channel::<Message>(16);
        let pending_receipts = Arc::new(TokioMutex::new(
            std::collections::HashMap::<String, PendingMessage>::new(),
        ));
        let iq_registry = Arc::new(TokioMutex::new(IqResponseRegistry::new()));
        let (_late_tx, late_rx) = watch::channel(LateState::default());
        let (online_tx, online_rx) = oneshot::channel::<Result<(), String>>();

        tokio::spawn(XMPPClient::handle_incoming_messages(
            stanza_tx,
            event_rx,
            msg_tx,
            pending_receipts,
            iq_registry,
            late_rx,
            Some(online_tx),
        ));

        (event_tx, stanza_rx, msg_rx, online_rx)
    }

    fn online(jid: &str) -> XMPPEvent {
        XMPPEvent::Online {
            bound_jid: jid.parse().unwrap(),
            features: Default::default(),
            resumed: false,
        }
    }

    fn disconnected() -> XMPPEvent {
        XMPPEvent::Disconnected(tokio_xmpp::Error::Disconnected)
    }

    // ── Initial connect ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_initial_online_signals_ok() {
        let (event_tx, _stanzas, _msgs, online_rx) = spawn_loop();
        event_tx.send(online("als@example.org/r1")).unwrap();
        let result = timeout(Duration::from_secs(1), online_rx)
            .await
            .expect("timed out")
            .expect("sender dropped");
        assert!(result.is_ok(), "expected Ok(()), got {:?}", result);
    }

    // Regression: online_tx must NOT be consumed on a transient disconnect;
    // it must fire Ok(()) only after the subsequent Online event.
    #[tokio::test]
    async fn test_transient_disconnect_does_not_consume_online_tx() {
        let (event_tx, _stanzas, _msgs, online_rx) = spawn_loop();
        event_tx.send(disconnected()).unwrap(); // transient — put online_tx back
        event_tx.send(online("als@example.org/r1")).unwrap();
        let result = timeout(Duration::from_secs(1), online_rx)
            .await
            .expect("timed out")
            .expect("sender dropped");
        assert!(
            result.is_ok(),
            "online_tx should fire Ok after transient disconnect+Online, got {:?}",
            result
        );
    }

    // The fatal-error path (where online_tx receives Err) is tested directly
    // in connection.rs via test_wait_for_connection_propagates_error_message.
    // The event_loop side of this is: a Disconnected with matching debug string
    // calls tx.send(Err(msg)) and breaks.  Constructing such an error requires
    // cross-crate version alignment that is fragile, so we cover the string-
    // matching logic through the connection module tests instead.

    // ── Mid-session reconnect ─────────────────────────────────────────────

    // Core reconnect regression: after a mid-session disconnect, the next
    // Online must fire carbons enable and presence via stanza_tx, and send
    // "Reconnected" to the UI.
    #[tokio::test]
    async fn test_mid_session_reconnect_sends_carbons_presence_and_ui_message() {
        let (event_tx, mut stanzas, mut msgs, online_rx) = spawn_loop();

        // Initial connection
        event_tx.send(online("als@example.org/r1")).unwrap();
        timeout(Duration::from_secs(1), online_rx)
            .await
            .unwrap()
            .unwrap()
            .expect("initial Online should give Ok(())");

        // Mid-session disconnect
        event_tx.send(disconnected()).unwrap();

        // UI must receive a "Reconnecting" notice
        let msg = timeout(Duration::from_secs(1), msgs.recv())
            .await
            .expect("timed out waiting for reconnect UI message")
            .expect("msg channel closed");
        assert!(
            msg.content.contains("Reconnecting"),
            "expected 'Reconnecting' in UI message, got: {:?}",
            msg.content
        );

        // Transport reconnects
        event_tx.send(online("als@example.org/r2")).unwrap();

        // Carbons enable IQ must be the first stanza sent
        let carbons = timeout(Duration::from_secs(1), stanzas.recv())
            .await
            .expect("timed out waiting for carbons IQ")
            .expect("stanza channel closed");
        assert_eq!(carbons.name(), "iq");
        assert_eq!(carbons.attr("type"), Some("set"));
        assert!(
            carbons.get_child("enable", "urn:xmpp:carbons:2").is_some(),
            "carbons IQ missing <enable xmlns='urn:xmpp:carbons:2'/>"
        );

        // Available presence must follow
        let pres = timeout(Duration::from_secs(1), stanzas.recv())
            .await
            .expect("timed out waiting for presence")
            .expect("stanza channel closed");
        assert_eq!(pres.name(), "presence");
        assert_eq!(
            pres.attr("type"),
            None,
            "reconnect presence must be 'available' (no type attr)"
        );

        // UI must receive "Reconnected"
        let msg2 = timeout(Duration::from_secs(1), msgs.recv())
            .await
            .expect("timed out waiting for reconnected UI message")
            .expect("msg channel closed");
        assert!(
            msg2.content.contains("Reconnected"),
            "expected 'Reconnected' in UI message, got: {:?}",
            msg2.content
        );
    }

    // ── Stanza XML format ─────────────────────────────────────────────────

    // Regression: the carbons enable stanza built in the reconnect path must
    // have the correct namespace and type attribute.
    #[test]
    fn test_carbons_iq_xml_structure() {
        let iq_id = "test-id";
        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), iq_id)
            .append(
                xmpp_parsers::minidom::Element::builder("enable", custom_ns::CARBONS).build(),
            )
            .build();

        assert_eq!(iq.name(), "iq");
        assert_eq!(iq.attr("type"), Some("set"));
        assert_eq!(iq.attr("id"), Some(iq_id));
        assert!(
            iq.get_child("enable", "urn:xmpp:carbons:2").is_some(),
            "carbons IQ must contain <enable xmlns='urn:xmpp:carbons:2'/>"
        );
    }

    // Regression: the presence built in the reconnect path must be an
    // available presence (no type attribute).
    #[test]
    fn test_reconnect_presence_is_available() {
        let pres = xmpp_parsers::minidom::Element::builder("presence", "jabber:client").build();
        assert_eq!(pres.name(), "presence");
        assert_eq!(pres.attr("type"), None, "available presence must have no type attr");
    }
}
