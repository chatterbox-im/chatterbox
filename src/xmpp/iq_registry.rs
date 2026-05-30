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

#[cfg(test)]
mod tests {
    use super::*;
    use xmpp_parsers::Element;

    fn make_iq_result(id: &str) -> Element {
        Element::builder("iq", "jabber:client")
            .attr("type", "result")
            .attr("id", id)
            .build()
    }

    #[tokio::test]
    async fn test_register_and_route() {
        let mut registry = IqResponseRegistry::new();
        let rx = registry.register("req-1".to_string());

        assert_eq!(registry.pending_count(), 1);

        let stanza = make_iq_result("req-1");
        assert!(registry.try_route("req-1", stanza.clone()));
        assert_eq!(registry.pending_count(), 0);

        let received = rx.await.unwrap();
        assert_eq!(received.attr("id").unwrap(), "req-1");
    }

    #[test]
    fn test_route_unknown_id_returns_false() {
        let mut registry = IqResponseRegistry::new();
        let stanza = make_iq_result("unknown");
        assert!(!registry.try_route("unknown", stanza));
    }

    #[tokio::test]
    async fn test_mam_register_and_route_messages() {
        let mut registry = IqResponseRegistry::new();
        let (mut msg_rx, iq_rx) = registry.register_mam("mam-q1".to_string());

        // Route intermediate MAM messages
        let msg1 = Element::builder("message", "jabber:client").attr("id", "m1").build();
        let msg2 = Element::builder("message", "jabber:client").attr("id", "m2").build();
        assert!(registry.try_route_mam("mam-q1", msg1));
        assert!(registry.try_route_mam("mam-q1", msg2));

        // Route final IQ result
        let iq = make_iq_result("mam-q1");
        assert!(registry.try_route("mam-q1", iq));

        // Verify messages received in order
        let r1 = msg_rx.recv().await.unwrap();
        assert_eq!(r1.attr("id").unwrap(), "m1");
        let r2 = msg_rx.recv().await.unwrap();
        assert_eq!(r2.attr("id").unwrap(), "m2");

        // Verify IQ result received
        let result = iq_rx.await.unwrap();
        assert_eq!(result.attr("id").unwrap(), "mam-q1");
    }

    #[test]
    fn test_evict_stale_removes_old_entries() {
        let mut registry = IqResponseRegistry::new();
        let _rx = registry.register("old-req".to_string());
        assert_eq!(registry.pending_count(), 1);

        // Evict with zero duration — everything is stale
        registry.evict_stale(std::time::Duration::from_secs(0));
        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn test_evict_stale_keeps_fresh_entries() {
        let mut registry = IqResponseRegistry::new();
        let _rx = registry.register("fresh-req".to_string());

        // Evict with generous duration — nothing is stale
        registry.evict_stale(std::time::Duration::from_secs(60));
        assert_eq!(registry.pending_count(), 1);
    }

    #[tokio::test]
    async fn test_dropped_receiver_doesnt_panic() {
        let mut registry = IqResponseRegistry::new();
        let rx = registry.register("dropped".to_string());
        drop(rx); // Receiver dropped (caller timed out)

        // Routing should succeed (returns true) but not panic
        let stanza = make_iq_result("dropped");
        assert!(registry.try_route("dropped", stanza));
    }
}
