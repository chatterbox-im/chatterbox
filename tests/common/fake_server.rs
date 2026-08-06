//! In-process XMPP server for integration tests.
//!
//! `FakeServer` provides a full XMPP session environment with no network I/O.
//! Call `register()` to obtain a `TransportHandle` and pass it to
//! `XMPPClient::connect_with_transport()`.  A background task handles
//! stanza routing, IQ responses, and PEP state.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chatterbox::xmpp::transport::TransportHandle;
use tokio::sync::mpsc;
use tokio_xmpp::Event as XMPPEvent;
use xmpp_parsers::minidom::Element;

// ── Internal shared state ─────────────────────────────────────────────────────

#[derive(Default)]
struct State {
    /// Last-published item per (jid, node): raw XML string of the <item> element.
    pep_nodes: HashMap<(String, String), String>,
    /// All stanzas received from each client, for assertions.
    transcript: Vec<(String, Element)>,
}

// ── FakeServer public API ─────────────────────────────────────────────────────

/// Handle returned to the test, used for assertions and fault injection.
pub struct FakeServer {
    state: Arc<Mutex<State>>,
    // Command channel into the background processor task.
    cmd_tx: mpsc::UnboundedSender<Cmd>,
}

enum Cmd {
    /// A new client registered with this JID.
    Register {
        jid: String,
        event_tx: mpsc::UnboundedSender<XMPPEvent>,
        stanza_rx: mpsc::UnboundedReceiver<Element>,
    },
}

impl FakeServer {
    /// Create a new FakeServer and spawn its background processor.
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let state_bg = state.clone();
        tokio::spawn(run_server(state_bg, cmd_rx));

        FakeServer { state, cmd_tx }
    }

    /// Register a client JID with the server.
    ///
    /// Returns a `TransportHandle` to pass to `XMPPClient::connect_with_transport`.
    /// An `Online` event is injected immediately so `connect_with_transport` completes
    /// without a real network connection.
    pub fn register(&self, jid: &str) -> TransportHandle {
        let (stanza_tx, stanza_rx) = mpsc::unbounded_channel::<Element>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<XMPPEvent>();

        // Inject Online event before the event loop starts so wait_for_connection
        // succeeds immediately.
        let full_jid = if jid.contains('/') {
            jid.to_string()
        } else {
            format!("{}/fake", jid)
        };
        let _ = event_tx.send(XMPPEvent::Online {
            bound_jid: full_jid.parse().expect("invalid JID in FakeServer::register"),
            features: Default::default(),
            resumed: false,
        });

        let _ = self.cmd_tx.send(Cmd::Register {
            jid: jid.to_string(),
            event_tx,
            stanza_rx,
        });

        TransportHandle { stanza_tx, event_rx }
    }

    // ── Assertion helpers ─────────────────────────────────────────────────

    /// All stanzas received from all clients since the server started.
    pub fn transcript(&self) -> Vec<(String, Element)> {
        self.state.lock().unwrap().transcript.clone()
    }

    /// Stanzas received from a specific JID.
    pub fn stanzas_from(&self, jid: &str) -> Vec<Element> {
        let bare = bare_jid(jid);
        self.state
            .lock()
            .unwrap()
            .transcript
            .iter()
            .filter(|(j, _)| bare_jid(j) == bare)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Current content of a PEP node for the given owner JID and node name.
    pub fn pep_node(&self, jid: &str, node: &str) -> Option<String> {
        let key = (bare_jid(jid), node.to_string());
        self.state.lock().unwrap().pep_nodes.get(&key).cloned()
    }
}

// ── Background processor ──────────────────────────────────────────────────────

struct Account {
    jid: String,
    event_tx: mpsc::UnboundedSender<XMPPEvent>,
}

async fn run_server(
    state: Arc<Mutex<State>>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
) {
    let mut accounts: HashMap<String, Account> = HashMap::new();
    // Per-client inbound channels — polled with tokio::select!
    // We accumulate them here so we can add dynamically.
    let mut client_rxs: Vec<(String, mpsc::UnboundedReceiver<Element>)> = Vec::new();

    loop {
        // Build a dynamic select over all client receivers + the command channel.
        // Since tokio::select! is compile-time and we have a dynamic set, we use
        // a poll approach: check each receiver with try_recv, then yield.
        let mut any = false;

        // Process pending commands first.
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Register { jid, event_tx, stanza_rx } => {
                    let bare = bare_jid(&jid);
                    accounts.insert(bare.clone(), Account { jid: bare.clone(), event_tx });
                    client_rxs.push((bare, stanza_rx));
                    any = true;
                }
            }
        }

        // Process pending stanzas from each client.
        for (jid, rx) in &mut client_rxs {
            while let Ok(element) = rx.try_recv() {
                {
                    let mut st = state.lock().unwrap();
                    st.transcript.push((jid.clone(), element.clone()));
                }
                handle_stanza(&state, &accounts, jid, &element);
                any = true;
            }
        }

        if !any {
            tokio::task::yield_now().await;
        }
    }
}

fn handle_stanza(
    state: &Arc<Mutex<State>>,
    accounts: &HashMap<String, Account>,
    from_jid: &str,
    element: &Element,
) {
    match element.name() {
        "iq"  => handle_iq(state, accounts, from_jid, element),
        "message" => handle_message(accounts, from_jid, element),
        "presence" => {} // ignore for now
        _ => {}
    }
}

// ── IQ handling ───────────────────────────────────────────────────────────────

fn handle_iq(
    state: &Arc<Mutex<State>>,
    accounts: &HashMap<String, Account>,
    from_jid: &str,
    iq: &Element,
) {
    let iq_type = iq.attr("type").unwrap_or("");
    let iq_id = iq.attr("id").unwrap_or("").to_string();
    let to = iq.attr("to").map(String::from);

    // IQ addressed to another JID → route it
    if let Some(ref to_jid) = to {
        let bare_to = bare_jid(to_jid);
        if bare_to != bare_jid(from_jid) {
            if let Some(acc) = accounts.get(&bare_to) {
                if let Ok(stanza) = tokio_xmpp::Stanza::try_from(iq.clone()) {
                    let _ = acc.event_tx.send(XMPPEvent::Stanza(stanza));
                }
            }
            return;
        }
    }

    // IQ addressed to self / server — respond
    let from = from_jid.to_string();
    let acc = match accounts.get(&bare_jid(from_jid)) {
        Some(a) => a,
        None => return,
    };

    if let Some(pubsub) = iq.get_child("pubsub", "http://jabber.org/protocol/pubsub") {
        handle_pubsub_iq(state, acc, from_jid, iq_type, &iq_id, pubsub);
    } else if iq.get_child("enable", "urn:xmpp:carbons:2").is_some()
        || iq.get_child("disable", "urn:xmpp:carbons:2").is_some()
    {
        // Carbons enable/disable — always succeed
        let _ = acc.event_tx.send(iq_result(&from, &iq_id));
    } else if iq.get_child("query", "http://jabber.org/protocol/disco#info").is_some()
        || iq.get_child("query", "http://jabber.org/protocol/disco#items").is_some()
    {
        // Minimal disco response
        let _ = acc.event_tx.send(iq_result_with_body(&from, &iq_id,
            iq.children().next().cloned().unwrap_or_else(|| empty_query())));
    } else if iq_type == "get" || iq_type == "set" {
        // Unknown IQ — item-not-found error
        let _ = acc.event_tx.send(iq_error(&from, &iq_id, "item-not-found"));
    }
}

fn handle_pubsub_iq(
    state: &Arc<Mutex<State>>,
    acc: &Account,
    owner_jid: &str,
    iq_type: &str,
    iq_id: &str,
    pubsub: &Element,
) {
    let from = owner_jid.to_string();

    if iq_type == "set" {
        if let Some(publish) = pubsub.get_child("publish", "http://jabber.org/protocol/pubsub") {
            let node = publish.attr("node").unwrap_or("").to_string();
            // Store the first <item> child as the node content.
            if let Some(item) = publish.get_child("item", "http://jabber.org/protocol/pubsub") {
                let xml = element_to_string(item);
                state.lock().unwrap().pep_nodes.insert((bare_jid(owner_jid), node), xml);
            }
            let _ = acc.event_tx.send(iq_result(&from, iq_id));
        } else if let Some(retract) = pubsub.get_child("retract", "http://jabber.org/protocol/pubsub") {
            let node = retract.attr("node").unwrap_or("").to_string();
            state.lock().unwrap().pep_nodes.remove(&(bare_jid(owner_jid), node));
            let _ = acc.event_tx.send(iq_result(&from, iq_id));
        } else {
            let _ = acc.event_tx.send(iq_result(&from, iq_id));
        }
    } else if iq_type == "get" {
        if let Some(items) = pubsub.get_child("items", "http://jabber.org/protocol/pubsub") {
            let node = items.attr("node").unwrap_or("").to_string();
            // Use 'to' JID as owner for cross-account PEP fetches
            let owner = bare_jid(owner_jid);
            let stored = state.lock().unwrap().pep_nodes.get(&(owner.clone(), node.clone())).cloned();

            if let Some(xml) = stored {
                // Build <iq type="result"><pubsub><items node="..."><item>...</item></items></pubsub></iq>
                let result_body = format!(
                    "<pubsub xmlns='http://jabber.org/protocol/pubsub'>\
                        <items node='{}'>{}</items>\
                    </pubsub>",
                    node, xml
                );
                let result_iq = format!(
                    "<iq xmlns='jabber:client' type='result' id='{}' to='{}'>{}</iq>",
                    iq_id, owner_jid, result_body
                );
                if let Ok(el) = result_iq.parse::<Element>() {
                    if let Ok(stanza) = tokio_xmpp::Stanza::try_from(el) {
                        let _ = acc.event_tx.send(XMPPEvent::Stanza(stanza));
                    }
                }
            } else {
                let _ = acc.event_tx.send(iq_error(&owner_jid, iq_id, "item-not-found"));
            }
        } else {
            let _ = acc.event_tx.send(iq_error(&owner_jid, iq_id, "feature-not-implemented"));
        }
    }
}

// ── Message routing ───────────────────────────────────────────────────────────

fn handle_message(accounts: &HashMap<String, Account>, _from_jid: &str, msg: &Element) {
    let to = match msg.attr("to") {
        Some(t) => bare_jid(t),
        None => return,
    };
    if let Some(acc) = accounts.get(&to) {
        if let Ok(stanza) = tokio_xmpp::Stanza::try_from(msg.clone()) {
            let _ = acc.event_tx.send(XMPPEvent::Stanza(stanza));
        }
    }
}

// ── Stanza builders ───────────────────────────────────────────────────────────

fn iq_result(to: &str, id: &str) -> XMPPEvent {
    let xml = format!("<iq xmlns='jabber:client' type='result' id='{}' to='{}'/>", id, to);
    let el: Element = xml.parse().unwrap();
    XMPPEvent::Stanza(tokio_xmpp::Stanza::try_from(el).expect("iq_result: failed to convert"))
}

fn iq_result_with_body(to: &str, id: &str, child: Element) -> XMPPEvent {
    let child_str = element_to_string(&child);
    let xml = format!(
        "<iq xmlns='jabber:client' type='result' id='{}' to='{}'>{}</iq>",
        id, to, child_str
    );
    let el: Element = xml.parse().unwrap();
    XMPPEvent::Stanza(tokio_xmpp::Stanza::try_from(el).expect("iq_result_with_body: failed to convert"))
}

fn iq_error(to: &str, id: &str, condition: &str) -> XMPPEvent {
    let xml = format!(
        "<iq xmlns='jabber:client' type='error' id='{}' to='{}'>\
            <error type='cancel'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>\
        </iq>",
        id, to, condition
    );
    let el: Element = xml.parse().unwrap();
    XMPPEvent::Stanza(tokio_xmpp::Stanza::try_from(el).expect("iq_error: failed to convert"))
}

fn empty_query() -> Element {
    "<query xmlns='http://jabber.org/protocol/disco#info'/>".parse().unwrap()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bare_jid(jid: &str) -> String {
    jid.split('/').next().unwrap_or(jid).to_string()
}

fn element_to_string(el: &Element) -> String {
    // Serialize the element using minidom's Display impl via a simple approach.
    // We write it to a string buffer.
    let mut buf = Vec::new();
    el.write_to(&mut buf).unwrap_or_default();
    String::from_utf8_lossy(&buf).into_owned()
}
