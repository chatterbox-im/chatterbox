// src/xmpp/iq_registry.rs
//! IQ Response Registry - routes IQ responses to waiting callers.
//!
//! This solves the event stream consumption conflict: only the event loop
//! reads from the XMPP stream. Other code that sends IQ requests registers
//! a pending request here and awaits the response via a oneshot channel.
//!
//! Also supports MAM (Message Archive Management) queries which receive
//! multiple `<message>` stanzas before a final IQ result.

use std::collections::HashMap;
use tokio::sync::{oneshot, mpsc};
use tokio::time::Instant;
use log::debug;

/// A pending IQ request waiting for its response.
struct PendingRequest {
    sender: oneshot::Sender<xmpp_parsers::Element>,
    registered_at: Instant,
}

/// A MAM query collector that receives intermediate message stanzas.
struct MamCollector {
    sender: mpsc::UnboundedSender<xmpp_parsers::Element>,
    registered_at: Instant,
}

/// Registry for routing IQ responses to their waiting callers.
pub struct IqResponseRegistry {
    pending: HashMap<String, PendingRequest>,
    mam_collectors: HashMap<String, MamCollector>,
}

impl IqResponseRegistry {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            mam_collectors: HashMap::new(),
        }
    }

    /// Register interest in an IQ response with the given ID.
    /// Returns a receiver that will get the response stanza.
    pub fn register(&mut self, id: String) -> oneshot::Receiver<xmpp_parsers::Element> {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id, PendingRequest {
            sender: tx,
            registered_at: Instant::now(),
        });
        rx
    }

    /// Register a MAM query. Returns:
    /// - An unbounded receiver for intermediate `<message>` stanzas
    /// - A oneshot receiver for the final IQ result
    pub fn register_mam(&mut self, query_id: String) -> (mpsc::UnboundedReceiver<xmpp_parsers::Element>, oneshot::Receiver<xmpp_parsers::Element>) {
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let (iq_tx, iq_rx) = oneshot::channel();
        self.mam_collectors.insert(query_id.clone(), MamCollector {
            sender: msg_tx,
            registered_at: Instant::now(),
        });
        self.pending.insert(query_id, PendingRequest {
            sender: iq_tx,
            registered_at: Instant::now(),
        });
        (msg_rx, iq_rx)
    }

    /// Try to route a MAM message stanza to a waiting collector.
    /// Returns true if the stanza was consumed.
    pub fn try_route_mam(&self, query_id: &str, stanza: xmpp_parsers::Element) -> bool {
        if let Some(collector) = self.mam_collectors.get(query_id) {
            // Send may fail if the receiver was dropped — that's fine
            let _ = collector.sender.send(stanza);
            true
        } else {
            false
        }
    }

    /// Try to route an IQ stanza to a waiting caller.
    /// Returns true if the stanza was consumed (matched a pending request).
    pub fn try_route(&mut self, id: &str, stanza: xmpp_parsers::Element) -> bool {
        if let Some(request) = self.pending.remove(id) {
            // Also clean up the MAM collector for this query if present
            self.mam_collectors.remove(id);
            // Send may fail if the receiver was dropped (caller timed out) — that's fine
            let _ = request.sender.send(stanza);
            true
        } else {
            false
        }
    }

    /// Remove stale entries older than the given duration.
    /// Call periodically to prevent memory leaks from abandoned requests.
    pub fn evict_stale(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        self.pending.retain(|id, req| {
            let keep = now.duration_since(req.registered_at) < max_age;
            if !keep {
                debug!("Evicting stale IQ request: {}", id);
            }
            keep
        });
        self.mam_collectors.retain(|id, collector| {
            let keep = now.duration_since(collector.registered_at) < max_age;
            if !keep {
                debug!("Evicting stale MAM collector: {}", id);
            }
            keep
        });
    }

    /// Number of pending requests (for diagnostics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
