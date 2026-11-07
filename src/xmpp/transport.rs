// src/xmpp/transport.rs
//! XMPP Transport Actor — owns the Client exclusively.
//!
//! Multiplexes outbound stanza sends and inbound event delivery without
//! mutex contention. Reconnection and Stream Management (XEP-0198) are
//! handled transparently by the tokio-xmpp v6 Client.

use futures_util::StreamExt;
use log::{debug, error, info, warn};
use tokio::sync::{mpsc, oneshot};
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
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TransportHandle {
    /// Build a handle around externally managed channels, primarily for tests.
    pub fn from_channels(
        stanza_tx: StanzaTx,
        event_rx: mpsc::UnboundedReceiver<XMPPEvent>,
    ) -> Self {
        Self {
            stanza_tx,
            event_rx,
            shutdown_tx: None,
        }
    }

    pub(crate) fn take_shutdown_tx(&mut self) -> Option<oneshot::Sender<()>> {
        self.shutdown_tx.take()
    }
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
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    tokio::spawn(transport_loop(client, event_tx, stanza_rx, shutdown_rx));

    TransportHandle {
        stanza_tx,
        event_rx,
        shutdown_tx: Some(shutdown_tx),
    }
}

// Kept for compatibility — v6 Client handles reconnection internally so the
// config is ignored; this just calls spawn_transport.
pub use self::spawn_transport as spawn_transport_with_reconnect_compat;

/// The transport loop. Runs until the stream ends, all senders are dropped,
/// or the owning client explicitly requests shutdown.
async fn transport_loop(
    mut client: XMPPAsyncClient,
    event_tx: mpsc::UnboundedSender<XMPPEvent>,
    mut outbound_rx: mpsc::UnboundedReceiver<Element>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    debug!("Transport: started");

    loop {
        tokio::select! {
            biased;

            // Drain an already-queued unavailable presence before shutdown.
            element = outbound_rx.recv() => {
                let Some(element) = element else {
                    info!("Transport: shutting down (all senders dropped)");
                    break;
                };

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

            _ = &mut shutdown_rx => {
                info!("Transport: explicit shutdown requested");
                break;
            }

            event = client.next() => {
                let Some(event) = event else {
                    info!("Transport: shutting down (stream ended)");
                    break;
                };
                if event_tx.send(event).is_err() {
                    info!("Transport: event receiver dropped, shutting down");
                    break;
                }
            }
        }
    }

    info!("Transport loop exited");
}
