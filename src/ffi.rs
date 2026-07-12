// src/ffi.rs
//! UniFFI-based FFI layer for the iOS Swift frontend.
//!
//! Build the static library for iOS with:
//!   cargo build --lib --release --no-default-features --features ffi \
//!     --target aarch64-apple-ios
//!
//! Generate Swift bindings with:
//!   cargo run --bin uniffi-bindgen generate \
//!     --library target/aarch64-apple-ios/release/libchatterbox.a \
//!     --language swift --out-dir ios/Sources/ChatterboxFFI
//!
//! Swift usage:
//!   let client = ChatterboxClient()
//!   try await client.connect(server: "example.com", username: "alice", password: "s3cr3t")
//!   Task {
//!       while let event = await client.nextEvent() {
//!           switch event { ... }
//!       }
//!   }

use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::{
    models::Message,
    xmpp::XMPPClient,
};

// A dedicated Tokio runtime for all FFI async operations.
// UniFFI drives Rust futures from a thread that may not have a runtime set as
// "current"; entering this runtime fixes `tokio::spawn` and I/O operations
// (e.g. TCP connections) that require a reactor to be present on the thread.
static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("chatterbox-ffi")
        .build()
        .expect("Failed to build Tokio runtime for FFI layer")
});

// ---------------------------------------------------------------------------
// Public data types exposed to Swift
// ---------------------------------------------------------------------------

/// A contact as seen by the iOS UI.
#[derive(uniffi::Record)]
pub struct FfiContact {
    pub jid: String,
    pub display_name: String,
    /// "online" | "offline" | "away"
    pub status: String,
}

/// A chat message as seen by the iOS UI.
#[derive(uniffi::Record)]
pub struct FfiMessage {
    pub id: String,
    pub from_jid: String,
    pub to_jid: String,
    pub body: String,
    /// Unix timestamp (seconds since epoch)
    pub timestamp: i64,
    pub is_encrypted: bool,
    /// "sent" | "delivered" | "read" | "failed"
    pub status: String,
}

/// Events the Swift layer receives via `nextEvent()`.
#[derive(uniffi::Enum)]
pub enum FfiEvent {
    /// A new message arrived (or an outgoing message was echoed back).
    Message { msg: FfiMessage },
    /// A contact's presence changed.
    ContactUpdate { contact: FfiContact },
    /// The connection was lost.
    Disconnected { reason: String },
}

// ---------------------------------------------------------------------------
// Main client object
// ---------------------------------------------------------------------------

/// Entry point for the iOS app.
///
/// Construct once, call `connect()`, then drive `nextEvent()` in a Swift Task.
#[derive(uniffi::Object)]
pub struct ChatterboxClient {
    /// Locked state — `None` before connect, `Some` while connected.
    inner: Arc<Mutex<Option<ClientState>>>,
    /// Channel on which the background pump sends events to `nextEvent()`.
    event_tx: mpsc::Sender<FfiEvent>,
    event_rx: Arc<Mutex<mpsc::Receiver<FfiEvent>>>,
}

struct ClientState {
    xmpp: XMPPClient,
}

#[uniffi::export]
impl ChatterboxClient {
    /// Create a new (disconnected) client.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let (event_tx, event_rx) = mpsc::channel(256);
        Arc::new(Self {
            inner: Arc::new(Mutex::new(None)),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        })
    }

    /// Connect and authenticate. Initialises OMEMO. Throws on failure.
    pub async fn connect(
        &self,
        server: String,
        username: String,
        password: String,
    ) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();

        // Spawn onto our dedicated runtime so that tokio::spawn / I/O inside
        // xmpp.connect() can find a reactor.  JoinHandle<T> is Send, so the
        // outer UniFFI future stays Send even though the work runs elsewhere.
        RUNTIME.spawn(async move {
            let (mut xmpp, msg_rx) = XMPPClient::new();

            let bare_jid = username.split('/').next().unwrap_or(&username).to_string();
            crate::omemo::device_id::set_omemo_jid(&bare_jid);

            xmpp.connect(&server, &username, &password)
                .await
                .map_err(|e| FfiError::Connection { reason: e.to_string() })?;

            xmpp.initialize_client()
                .await
                .map_err(|e| FfiError::Omemo { reason: e.to_string() })?;

            crate::xmpp::publish_late_state(&xmpp);

            *inner.lock().await = Some(ClientState { xmpp });

            // Background pump: forward incoming messages as FfiEvents.
            tokio::spawn(async move {
                let mut rx = msg_rx;
                loop {
                    match rx.recv().await {
                        Some(m) => {
                            let _ = event_tx.send(FfiEvent::Message { msg: to_ffi_message(m) }).await;
                        }
                        None => {
                            let _ = event_tx
                                .send(FfiEvent::Disconnected {
                                    reason: "Connection closed".to_string(),
                                })
                                .await;
                            break;
                        }
                    }
                }
            });

            Ok::<(), FfiError>(())
        })
        .await
        .map_err(|e| FfiError::Connection { reason: e.to_string() })?
    }

    /// Send an OMEMO-encrypted (or plaintext-fallback) message to `to_jid`.
    pub async fn send_message(&self, to_jid: String, body: String) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let mut guard = inner.lock().await;
            let state = guard.as_mut().ok_or(FfiError::NotConnected)?;
            state
                .xmpp
                .send_message(&to_jid, &body)
                .await
                .map_err(|e| FfiError::Send { reason: e.to_string() })
        })
        .await
        .map_err(|e| FfiError::Send { reason: e.to_string() })?
    }

    /// Fetch the roster (contact list) from the server.
    pub async fn get_contacts(&self) -> Result<Vec<FfiContact>, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            let jids = state
                .xmpp
                .get_roster()
                .await
                .map_err(|e| FfiError::Roster { reason: e.to_string() })?
                .unwrap_or_default();
            Ok(jids
                .into_iter()
                .map(|jid| FfiContact {
                    display_name: jid.split('@').next().unwrap_or(&jid).to_string(),
                    jid,
                    status: "offline".to_string(),
                })
                .collect())
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
    }

    /// Wait for the next event (message, presence update, or disconnect).
    ///
    /// Returns `None` only after `disconnect()` is called and the channel drains.
    /// Drive this in a Swift Task:
    ///
    /// ```swift
    /// Task {
    ///     while let event = await client.nextEvent() {
    ///         switch event { ... }
    ///     }
    /// }
    /// ```
    pub async fn next_event(&self) -> Option<FfiEvent> {
        let event_rx = Arc::clone(&self.event_rx);
        RUNTIME.spawn(async move {
            event_rx.lock().await.recv().await
        })
        .await
        .unwrap_or(None)
    }

    /// Gracefully disconnect and close the event stream.
    pub async fn disconnect(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = RUNTIME.spawn(async move {
            *inner.lock().await = None;
        })
        .await;
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("Not connected — call connect() first")]
    NotConnected,
    #[error("Connection failed: {reason}")]
    Connection { reason: String },
    #[error("OMEMO initialisation failed: {reason}")]
    Omemo { reason: String },
    #[error("Send failed: {reason}")]
    Send { reason: String },
    #[error("Roster fetch failed: {reason}")]
    Roster { reason: String },
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn to_ffi_message(m: Message) -> FfiMessage {
    FfiMessage {
        id: m.id,
        from_jid: m.sender_id,
        to_jid: m.recipient_id,
        body: m.content,
        timestamp: m.timestamp as i64,
        is_encrypted: m.encrypted,
        status: format!("{:?}", m.delivery_status).to_lowercase(),
    }
}
