// src/xmpp/transport.rs
//! XMPP Transport Actor — owns the AsyncClient exclusively.
//!
//! Multiplexes outbound stanza sends and inbound event delivery without
//! mutex contention. The event loop and all senders communicate via channels,
//! eliminating the poll-sleep-retry pattern and the shared Arc<Mutex<AsyncClient>>.
//!
//! Supports automatic reconnection with exponential backoff when the stream
//! disconnects unexpectedly.

use futures_util::Stream;
use log::{debug, error, info, warn};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_xmpp::{AsyncClient as XMPPAsyncClient, BareJid, Event as XMPPEvent};
use xmpp_parsers::Element;

/// A cheaply-cloneable handle for sending stanzas to the transport task.
pub type StanzaTx = mpsc::UnboundedSender<Element>;

/// Bounded stanza sender for backpressure-aware sending.
pub type BoundedStanzaTx = mpsc::Sender<Element>;

/// Handle returned by [`spawn_transport`]. Provides send/receive channels.
pub struct TransportHandle {
    /// Send stanzas to the XMPP server (non-blocking, unbounded).
    pub stanza_tx: StanzaTx,
    /// Receive XMPP events (Online, Stanza, Disconnected) from the server.
    pub event_rx: mpsc::UnboundedReceiver<XMPPEvent>,
}

/// Handle with bounded channels for backpressure support.
pub struct BoundedTransportHandle {
    /// Send stanzas to the XMPP server (bounded, provides backpressure).
    pub stanza_tx: BoundedStanzaTx,
    /// Receive XMPP events with bounded buffer.
    pub event_rx: mpsc::Receiver<XMPPEvent>,
}

/// Channel capacity constants.
pub const STANZA_CHANNEL_CAPACITY: usize = 64;
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Configuration for reconnection behavior.
#[derive(Clone)]
pub struct ReconnectConfig {
    /// Initial backoff delay after first disconnect.
    pub initial_backoff: Duration,
    /// Maximum backoff delay.
    pub max_backoff: Duration,
    /// Maximum number of reconnection attempts (0 = unlimited).
    pub max_attempts: u32,
    /// JID for reconnection.
    pub jid: BareJid,
    /// Password for reconnection.
    pub password: String,
}

/// Spawn the transport actor task. Ownership of `client` is transferred to
/// the task — no mutex needed.
///
/// Returns a [`TransportHandle`] for communicating with the transport.
pub fn spawn_transport(client: XMPPAsyncClient) -> TransportHandle {
    let (stanza_tx, stanza_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    tokio::spawn(transport_loop(client, event_tx, stanza_rx, None));

    TransportHandle {
        stanza_tx,
        event_rx,
    }
}

/// Spawn the transport actor with automatic reconnection support.
///
/// On disconnect, the transport will attempt to reconnect using the provided
/// credentials with exponential backoff. The coordinator sees Disconnected
/// followed by Online events transparently.
pub fn spawn_transport_with_reconnect(
    client: XMPPAsyncClient,
    config: ReconnectConfig,
) -> TransportHandle {
    let (stanza_tx, stanza_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    tokio::spawn(transport_loop(client, event_tx, stanza_rx, Some(config)));

    TransportHandle {
        stanza_tx,
        event_rx,
    }
}

/// Spawn the transport actor with bounded channels and reconnection.
///
/// Provides natural backpressure: if the coordinator is slow to process events,
/// the transport will pause reading from the XMPP stream. If the coordinator
/// sends stanzas faster than the network can deliver, the send will await.
pub fn spawn_transport_bounded(
    client: XMPPAsyncClient,
    config: Option<ReconnectConfig>,
) -> BoundedTransportHandle {
    let (stanza_tx, stanza_rx) = mpsc::channel(STANZA_CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

    tokio::spawn(transport_loop_bounded(client, event_tx, stanza_rx, config));

    BoundedTransportHandle {
        stanza_tx,
        event_rx,
    }
}

/// Internal action produced by the poll loop.
enum Action {
    Send(Element),
    Received(XMPPEvent),
    Shutdown,
}

/// The transport loop. Runs until the XMPP stream ends or all senders are dropped.
/// With `reconnect_config`, automatically reconnects on disconnect.
async fn transport_loop(
    mut client: XMPPAsyncClient,
    event_tx: mpsc::UnboundedSender<XMPPEvent>,
    mut outbound_rx: mpsc::UnboundedReceiver<Element>,
    reconnect_config: Option<ReconnectConfig>,
) {
    debug!("Transport: started");
    let mut reconnect_attempts: u32 = 0;

    'outer: loop {
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
                        // Notify coordinator of disconnect
                        let _ =
                            event_tx.send(XMPPEvent::Disconnected(tokio_xmpp::Error::Disconnected));
                        // Attempt reconnection
                        if let Some(ref config) = reconnect_config {
                            match try_reconnect(config, &mut reconnect_attempts, &event_tx).await {
                                Some(new_client) => {
                                    client = new_client;
                                    continue 'outer;
                                }
                                None => break 'outer,
                            }
                        } else {
                            break 'outer;
                        }
                    }
                }
                // Reset attempts on successful activity
                reconnect_attempts = 0;
            }
            Action::Received(event) => {
                let is_disconnect = matches!(&event, XMPPEvent::Disconnected(_));
                if event_tx.send(event).is_err() {
                    info!("Transport: event receiver dropped, shutting down");
                    break 'outer;
                }
                if is_disconnect {
                    // Attempt reconnection
                    if let Some(ref config) = reconnect_config {
                        match try_reconnect(config, &mut reconnect_attempts, &event_tx).await {
                            Some(new_client) => {
                                client = new_client;
                                continue 'outer;
                            }
                            None => break 'outer,
                        }
                    } else {
                        break 'outer;
                    }
                }
                // Reset attempts on successful receive
                reconnect_attempts = 0;
            }
            Action::Shutdown => {
                info!("Transport: shutting down (stream ended or senders dropped)");
                // Attempt reconnection if configured
                if let Some(ref config) = reconnect_config {
                    let _ = event_tx.send(XMPPEvent::Disconnected(tokio_xmpp::Error::Disconnected));
                    match try_reconnect(config, &mut reconnect_attempts, &event_tx).await {
                        Some(new_client) => {
                            client = new_client;
                            continue 'outer;
                        }
                        None => break 'outer,
                    }
                } else {
                    break 'outer;
                }
            }
        }
    }

    info!("Transport loop exited");
}

/// Attempt to reconnect with exponential backoff.
/// Returns Some(new_client) on success, None if max attempts exceeded.
async fn try_reconnect(
    config: &ReconnectConfig,
    attempts: &mut u32,
    _event_tx: &mpsc::UnboundedSender<XMPPEvent>,
) -> Option<XMPPAsyncClient> {
    *attempts += 1;

    if config.max_attempts > 0 && *attempts > config.max_attempts {
        error!(
            "Transport: max reconnection attempts ({}) exceeded",
            config.max_attempts
        );
        return None;
    }

    let backoff = std::cmp::min(
        config.initial_backoff * 2u32.pow((*attempts - 1).min(6)),
        config.max_backoff,
    );

    warn!(
        "Transport: reconnecting in {:?} (attempt {})",
        backoff, attempts
    );
    tokio::time::sleep(backoff).await;

    let new_client = XMPPAsyncClient::new(config.jid.clone(), &config.password);
    info!("Transport: reconnected (attempt {})", attempts);

    Some(new_client)
}

/// Bounded transport loop — provides backpressure via bounded channels.
async fn transport_loop_bounded(
    mut client: XMPPAsyncClient,
    event_tx: mpsc::Sender<XMPPEvent>,
    mut outbound_rx: mpsc::Receiver<Element>,
    reconnect_config: Option<ReconnectConfig>,
) {
    debug!("Transport (bounded): started");
    let mut reconnect_attempts: u32 = 0;

    'outer: loop {
        let action = futures_util::future::poll_fn(|cx| {
            match outbound_rx.poll_recv(cx) {
                Poll::Ready(Some(stanza)) => return Poll::Ready(Action::Send(stanza)),
                Poll::Ready(None) => return Poll::Ready(Action::Shutdown),
                Poll::Pending => {}
            }

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
                let mut batch = vec![stanza];
                while let Ok(s) = outbound_rx.try_recv() {
                    batch.push(s);
                }
                for s in batch {
                    if let Err(e) = client.send_stanza(s).await {
                        error!("Transport (bounded): send failed: {}", e);
                        let _ = event_tx
                            .send(XMPPEvent::Disconnected(tokio_xmpp::Error::Disconnected))
                            .await;
                        if let Some(ref config) = reconnect_config {
                            match try_reconnect_bounded(config, &mut reconnect_attempts).await {
                                Some(new_client) => {
                                    client = new_client;
                                    continue 'outer;
                                }
                                None => break 'outer,
                            }
                        } else {
                            break 'outer;
                        }
                    }
                }
                reconnect_attempts = 0;
            }
            Action::Received(event) => {
                let is_disconnect = matches!(&event, XMPPEvent::Disconnected(_));
                // Bounded send — provides backpressure if coordinator is slow
                if event_tx.send(event).await.is_err() {
                    info!("Transport (bounded): event receiver dropped, shutting down");
                    break 'outer;
                }
                if is_disconnect {
                    if let Some(ref config) = reconnect_config {
                        match try_reconnect_bounded(config, &mut reconnect_attempts).await {
                            Some(new_client) => {
                                client = new_client;
                                continue 'outer;
                            }
                            None => break 'outer,
                        }
                    } else {
                        break 'outer;
                    }
                }
                reconnect_attempts = 0;
            }
            Action::Shutdown => {
                info!("Transport (bounded): shutting down");
                if let Some(ref config) = reconnect_config {
                    let _ = event_tx
                        .send(XMPPEvent::Disconnected(tokio_xmpp::Error::Disconnected))
                        .await;
                    match try_reconnect_bounded(config, &mut reconnect_attempts).await {
                        Some(new_client) => {
                            client = new_client;
                            continue 'outer;
                        }
                        None => break 'outer,
                    }
                } else {
                    break 'outer;
                }
            }
        }
    }

    info!("Transport (bounded) loop exited");
}

/// Reconnect helper for bounded transport loop.
async fn try_reconnect_bounded(
    config: &ReconnectConfig,
    attempts: &mut u32,
) -> Option<XMPPAsyncClient> {
    *attempts += 1;

    if config.max_attempts > 0 && *attempts > config.max_attempts {
        error!(
            "Transport: max reconnection attempts ({}) exceeded",
            config.max_attempts
        );
        return None;
    }

    let backoff = std::cmp::min(
        config.initial_backoff * 2u32.pow((*attempts - 1).min(6)),
        config.max_backoff,
    );

    warn!(
        "Transport: reconnecting in {:?} (attempt {})",
        backoff, attempts
    );
    tokio::time::sleep(backoff).await;

    let new_client = XMPPAsyncClient::new(config.jid.clone(), &config.password);
    info!("Transport: reconnected (attempt {})", attempts);

    Some(new_client)
}

/// Send a stanza via the transport channel, returning an error if the transport is closed.
pub fn send_stanza(tx: &StanzaTx, stanza: Element) -> anyhow::Result<()> {
    tx.send(stanza)
        .map_err(|_| anyhow::anyhow!("XMPP transport closed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_send_stanza_closed_channel() {
        let (tx, rx) = mpsc::unbounded_channel::<Element>();
        drop(rx); // simulate transport shutdown
        let stanza = Element::builder("message", "jabber:client").build();
        let result = send_stanza(&tx, stanza);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("transport closed"));
    }

    // ─── ReconnectConfig tests ────────────────────────────────────────────

    #[test]
    fn test_reconnect_config_defaults_are_sane() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            max_attempts: 5,
            jid: "test@example.org".parse().unwrap(),
            password: "secret".to_string(),
        };
        assert!(config.initial_backoff < config.max_backoff);
        assert!(config.max_attempts > 0);
    }

    // ─── Exponential backoff calculation tests ────────────────────────────

    #[test]
    fn test_backoff_calculation_exponential() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_secs(10);

        // attempt 1: 100ms * 2^0 = 100ms
        let b1 = std::cmp::min(initial * 2u32.pow(0), max);
        assert_eq!(b1, Duration::from_millis(100));

        // attempt 2: 100ms * 2^1 = 200ms
        let b2 = std::cmp::min(initial * 2u32.pow(1), max);
        assert_eq!(b2, Duration::from_millis(200));

        // attempt 3: 100ms * 2^2 = 400ms
        let b3 = std::cmp::min(initial * 2u32.pow(2), max);
        assert_eq!(b3, Duration::from_millis(400));

        // attempt 7: 100ms * 2^6 = 6400ms (capped by min(6) in real code)
        let b7 = std::cmp::min(initial * 2u32.pow(6), max);
        assert_eq!(b7, Duration::from_millis(6400));

        // attempt 8+: still capped at 2^6 by .min(6) then max_backoff
        let b_high = std::cmp::min(initial * 2u32.pow(6), max);
        assert!(b_high <= max);
    }

    #[test]
    fn test_backoff_caps_at_max() {
        let initial = Duration::from_secs(2);
        let max = Duration::from_secs(5);

        // 2s * 2^6 = 128s, but capped at 5s
        let b = std::cmp::min(initial * 2u32.pow(6), max);
        assert_eq!(b, max);
    }

    // ─── Bounded channel capacity tests ───────────────────────────────────

    #[tokio::test]
    async fn test_bounded_stanza_channel_capacity() {
        let (tx, _rx) = mpsc::channel::<Element>(STANZA_CHANNEL_CAPACITY);

        // Fill the channel up to capacity
        for i in 0..STANZA_CHANNEL_CAPACITY {
            let stanza = Element::builder("message", "jabber:client")
                .attr("id", &format!("msg-{}", i))
                .build();
            tx.try_send(stanza).expect("should succeed within capacity");
        }

        // Next send should fail (channel full)
        let stanza = Element::builder("message", "jabber:client").build();
        let result = tx.try_send(stanza);
        assert!(
            result.is_err(),
            "channel should be full at capacity {}",
            STANZA_CHANNEL_CAPACITY
        );
    }

    #[tokio::test]
    async fn test_bounded_event_channel_capacity() {
        let (tx, _rx) = mpsc::channel::<()>(EVENT_CHANNEL_CAPACITY);

        // Fill the channel
        for _ in 0..EVENT_CHANNEL_CAPACITY {
            tx.try_send(()).expect("should succeed within capacity");
        }

        // Next send should fail
        let result = tx.try_send(());
        assert!(
            result.is_err(),
            "channel should be full at capacity {}",
            EVENT_CHANNEL_CAPACITY
        );
    }

    #[tokio::test]
    async fn test_bounded_sender_awaits_when_full() {
        let (tx, mut rx) = mpsc::channel::<u32>(2);

        // Fill channel
        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();

        // Spawn a sender that will block
        let tx2 = tx.clone();
        let send_task = tokio::spawn(async move {
            let start = Instant::now();
            tx2.send(3).await.unwrap();
            start.elapsed()
        });

        // Let it block for a bit
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Drain one item — unblocks the sender
        let val = rx.recv().await.unwrap();
        assert_eq!(val, 1);

        let elapsed = send_task.await.unwrap();
        // The sender should have been blocked for at least ~50ms
        assert!(
            elapsed >= Duration::from_millis(40),
            "sender should have been blocked, but elapsed was {:?}",
            elapsed
        );
    }

    // ─── Transport handle channel semantics ───────────────────────────────

    #[test]
    fn test_unbounded_transport_handle_types() {
        let (stanza_tx, _stanza_rx) = mpsc::unbounded_channel::<Element>();
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<tokio_xmpp::Event>();

        let handle = TransportHandle {
            stanza_tx,
            event_rx,
        };

        // Can send without blocking
        let stanza = Element::builder("message", "jabber:client").build();
        assert!(handle.stanza_tx.send(stanza).is_ok());
    }

    #[tokio::test]
    async fn test_bounded_transport_handle_types() {
        let (stanza_tx, _stanza_rx) = mpsc::channel::<Element>(STANZA_CHANNEL_CAPACITY);
        let (_event_tx, event_rx) = mpsc::channel::<tokio_xmpp::Event>(EVENT_CHANNEL_CAPACITY);

        let handle = BoundedTransportHandle {
            stanza_tx,
            event_rx,
        };

        // Can send (channel not full)
        let stanza = Element::builder("message", "jabber:client").build();
        assert!(handle.stanza_tx.send(stanza).await.is_ok());
    }

    // ─── try_reconnect_bounded respects max_attempts ──────────────────────

    #[tokio::test]
    async fn test_reconnect_bounded_respects_max_attempts() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_millis(1), // tiny for test speed
            max_backoff: Duration::from_millis(10),
            max_attempts: 2,
            jid: "test@example.org".parse().unwrap(),
            password: "pass".to_string(),
        };

        let mut attempts = 0u32;

        // First attempt succeeds (returns new client)
        let result1 = try_reconnect_bounded(&config, &mut attempts).await;
        assert!(result1.is_some());
        assert_eq!(attempts, 1);

        // Second attempt succeeds
        let result2 = try_reconnect_bounded(&config, &mut attempts).await;
        assert!(result2.is_some());
        assert_eq!(attempts, 2);

        // Third attempt: exceeds max_attempts, returns None
        let result3 = try_reconnect_bounded(&config, &mut attempts).await;
        assert!(result3.is_none());
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn test_reconnect_unbounded_respects_max_attempts() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_attempts: 1,
            jid: "test@example.org".parse().unwrap(),
            password: "pass".to_string(),
        };
        let (_event_tx, _) = mpsc::unbounded_channel::<tokio_xmpp::Event>();

        let mut attempts = 0u32;

        // First attempt: ok
        let result1 = try_reconnect(&config, &mut attempts, &_event_tx).await;
        assert!(result1.is_some());

        // Second attempt: exceeds max
        let result2 = try_reconnect(&config, &mut attempts, &_event_tx).await;
        assert!(result2.is_none());
    }

    #[tokio::test]
    async fn test_reconnect_unlimited_attempts_never_gives_up() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            max_attempts: 0, // unlimited
            jid: "test@example.org".parse().unwrap(),
            password: "pass".to_string(),
        };

        let mut attempts = 0u32;

        // Even at high attempt counts, should never return None
        for _ in 0..10 {
            let result = try_reconnect_bounded(&config, &mut attempts).await;
            assert!(result.is_some());
        }
        assert_eq!(attempts, 10);
    }

    // ─── Backoff timing verification ─────────────────────────────────────

    #[tokio::test]
    async fn test_reconnect_actually_waits() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(10),
            max_attempts: 0,
            jid: "test@example.org".parse().unwrap(),
            password: "pass".to_string(),
        };

        let mut attempts = 0u32;

        let start = Instant::now();
        let _ = try_reconnect_bounded(&config, &mut attempts).await;
        let elapsed = start.elapsed();

        // Should have waited approximately 50ms (first attempt: 50 * 2^0 = 50ms)
        assert!(
            elapsed >= Duration::from_millis(40),
            "should wait at least ~50ms, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_backoff_grows_between_attempts() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_secs(10),
            max_attempts: 0,
            jid: "test@example.org".parse().unwrap(),
            password: "pass".to_string(),
        };

        let mut attempts = 0u32;

        let start1 = Instant::now();
        let _ = try_reconnect_bounded(&config, &mut attempts).await;
        let elapsed1 = start1.elapsed();

        let start2 = Instant::now();
        let _ = try_reconnect_bounded(&config, &mut attempts).await;
        let elapsed2 = start2.elapsed();

        // Second attempt should take longer than first
        assert!(
            elapsed2 > elapsed1,
            "backoff should grow: first={:?}, second={:?}",
            elapsed1,
            elapsed2
        );
    }
}
