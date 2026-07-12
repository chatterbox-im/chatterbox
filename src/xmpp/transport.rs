// src/xmpp/transport.rs
//! XMPP Transport Actor — owns the Client exclusively.
//!
//! Multiplexes outbound stanza sends and inbound event delivery without
//! mutex contention. Reconnection and Stream Management (XEP-0198) are
//! handled transparently by the tokio-xmpp v6 Client.

use futures_util::stream::Stream;
use log::{debug, error, info, warn};
use std::pin::Pin;
use std::task::Poll;
use tokio::sync::mpsc;
use tokio_xmpp::{Client as XMPPAsyncClient, Event as XMPPEvent, Stanza};
use xmpp_parsers::minidom::Element;

/// A cheaply-cloneable handle for sending stanzas to the transport task.
pub type StanzaTx = mpsc::UnboundedSender<Element>;

/// Handle returned by [`spawn_transport`]. Provides send/receive channels.
pub struct TransportHandle {
    /// Send stanzas to the XMPP server (non-blocking, unbounded).
    pub stanza_tx: StanzaTx,
    /// Receive XMPP events (Online, Stanza, Disconnected) from the server.
    pub event_rx: mpsc::UnboundedReceiver<XMPPEvent>,
}

/// Send a stanza via the transport channel.
pub fn send_stanza(tx: &StanzaTx, element: Element) -> anyhow::Result<()> {
    tx.send(element).map_err(|e| anyhow::anyhow!("{}", e))
}

/// Spawn the transport actor task. Ownership of `client` is transferred to
/// the task — no mutex needed.
///
/// Returns a [`TransportHandle`] for communicating with the transport.
pub fn spawn_transport(client: XMPPAsyncClient) -> TransportHandle {
    let (stanza_tx, stanza_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    tokio::spawn(transport_loop(client, event_tx, stanza_rx));

    TransportHandle {
        stanza_tx,
        event_rx,
    }
}

// Kept for compatibility — v6 Client handles reconnection internally so the
// config is ignored; this just calls spawn_transport.
pub use self::spawn_transport as spawn_transport_with_reconnect_compat;

/// Internal action produced by the poll loop.
enum Action {
    Send(Element),
    Received(XMPPEvent),
    Shutdown,
}

/// The transport loop. Runs until the stream ends or all senders are dropped.
async fn transport_loop(
    mut client: XMPPAsyncClient,
    event_tx: mpsc::UnboundedSender<XMPPEvent>,
    mut outbound_rx: mpsc::UnboundedReceiver<Element>,
) {
    debug!("Transport: started");

    loop {
        let action = futures_util::future::poll_fn(|cx| {
            // Priority: drain outbound first (keeps send latency low).
            match outbound_rx.poll_recv(cx) {
                Poll::Ready(Some(element)) => return Poll::Ready(Action::Send(element)),
                Poll::Ready(None) => return Poll::Ready(Action::Shutdown),
                Poll::Pending => {}
            }

            // Then check for inbound events.
            match Pin::new(&mut client).poll_next(cx) {
                Poll::Ready(Some(event)) => return Poll::Ready(Action::Received(event)),
                Poll::Ready(None) => return Poll::Ready(Action::Shutdown),
                Poll::Pending => {}
            }

            Poll::Pending
        })
        .await;

        match action {
            Action::Send(element) => {
                // Convert raw Element to typed Stanza (v6 API).
                // IqPayload preserves unknown children as raw Element so all
                // custom stanzas round-trip without data loss.
                let stanza = match Stanza::try_from(element) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Transport: could not convert element to Stanza: {:?}", e);
                        continue;
                    }
                };
                if let Err(e) = client.send_stanza(stanza).await {
                    error!("Transport: send failed: {}", e);
                    // The Client handles reconnection internally; just log.
                }
            }
            Action::Received(event) => {
                if event_tx.send(event).is_err() {
                    info!("Transport: event receiver dropped, shutting down");
                    break;
                }
            }
            Action::Shutdown => {
                info!("Transport: shutting down (stream ended or senders dropped)");
                break;
            }
        }
    }

    info!("Transport loop exited");
}
