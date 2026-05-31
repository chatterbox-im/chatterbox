// src/xmpp/transport.rs
//! XMPP Transport Actor — owns the AsyncClient exclusively.
//!
//! Multiplexes outbound stanza sends and inbound event delivery without
//! mutex contention. The event loop and all senders communicate via channels,
//! eliminating the poll-sleep-retry pattern and the shared Arc<Mutex<AsyncClient>>.

use std::pin::Pin;
use std::task::Poll;
use futures_util::Stream;
use log::{debug, error, info};
use tokio::sync::mpsc;
use tokio_xmpp::{AsyncClient as XMPPAsyncClient, Event as XMPPEvent};
use xmpp_parsers::Element;

/// A cheaply-cloneable handle for sending stanzas to the transport task.
pub type StanzaTx = mpsc::UnboundedSender<Element>;

/// Handle returned by [`spawn_transport`]. Provides send/receive channels.
pub struct TransportHandle {
    /// Send stanzas to the XMPP server (non-blocking, unbounded).
    pub stanza_tx: StanzaTx,
    /// Receive XMPP events (Online, Stanza, Disconnected) from the server.
    pub event_rx: mpsc::UnboundedReceiver<XMPPEvent>,
}

/// Spawn the transport actor task. Ownership of `client` is transferred to
/// the task — no mutex needed.
///
/// Returns a [`TransportHandle`] for communicating with the transport.
pub fn spawn_transport(client: XMPPAsyncClient) -> TransportHandle {
    let (stanza_tx, stanza_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    tokio::spawn(transport_loop(client, event_tx, stanza_rx));

    TransportHandle { stanza_tx, event_rx }
}

/// Internal action produced by the poll loop.
enum Action {
    Send(Element),
    Received(XMPPEvent),
    Shutdown,
}

/// The transport loop. Runs until the XMPP stream ends or all senders are dropped.
async fn transport_loop(
    mut client: XMPPAsyncClient,
    event_tx: mpsc::UnboundedSender<XMPPEvent>,
    mut outbound_rx: mpsc::UnboundedReceiver<Element>,
) {
    debug!("Transport: started");

    loop {
        // Wait for either an outbound stanza or an inbound event.
        // Both wakers are registered in the same poll_fn, so we wake instantly
        // when either source has data — zero polling, zero sleeping.
        let action = futures_util::future::poll_fn(|cx| {
            // Priority: drain outbound first (keeps send latency low)
            match outbound_rx.poll_recv(cx) {
                Poll::Ready(Some(stanza)) => return Poll::Ready(Action::Send(stanza)),
                Poll::Ready(None) => return Poll::Ready(Action::Shutdown),
                Poll::Pending => {}
            }

            // Then check for inbound events
            match Pin::new(&mut client).poll_next(cx) {
                Poll::Ready(Some(event)) => return Poll::Ready(Action::Received(event)),
                Poll::Ready(None) => return Poll::Ready(Action::Shutdown),
                Poll::Pending => {}
            }

            Poll::Pending
        })
        .await;

        match action {
            Action::Send(stanza) => {
                // Drain any additional queued stanzas to batch sends
                let mut batch = vec![stanza];
                while let Ok(s) = outbound_rx.try_recv() {
                    batch.push(s);
                }
                for s in batch {
                    if let Err(e) = client.send_stanza(s).await {
                        error!("Transport: send failed: {}", e);
                        return;
                    }
                }
            }
            Action::Received(event) => {
                if event_tx.send(event).is_err() {
                    info!("Transport: event receiver dropped, shutting down");
                    return;
                }
            }
            Action::Shutdown => {
                info!("Transport: shutting down (stream ended or senders dropped)");
                return;
            }
        }
    }
}

/// Send a stanza via the transport channel, returning an error if the transport is closed.
pub fn send_stanza(tx: &StanzaTx, stanza: Element) -> anyhow::Result<()> {
    tx.send(stanza)
        .map_err(|_| anyhow::anyhow!("XMPP transport closed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_stanza_closed_channel() {
        let (tx, rx) = mpsc::unbounded_channel::<Element>();
        drop(rx); // simulate transport shutdown
        let stanza = Element::builder("message", "jabber:client").build();
        let result = send_stanza(&tx, stanza);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("transport closed"));
    }
}
