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
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    models::{DeliveryStatus, Message},
    storage::MessageStore,
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

/// An OMEMO device fingerprint as seen by the iOS UI.
#[derive(uniffi::Record)]
pub struct FfiFingerprint {
    pub device_id: u32,
    /// 64-char hex string, space-grouped for display: "AABB CCDD …"
    pub fingerprint: String,
    pub is_trusted: bool,
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
    /// The delivery status of a previously sent message changed.
    StatusUpdate { msg_id: String, status: String },
    /// A contact started or stopped composing a message.
    /// `is_typing` = true → composing; false → paused/inactive/gone.
    TypingUpdate { jid: String, is_typing: bool },
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
    /// SQLite message store — None if the DB failed to open (graceful degradation).
    store: Option<Arc<StdMutex<MessageStore>>>,
}

#[uniffi::export]
impl ChatterboxClient {
    /// Create a new (disconnected) client.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        // Initialise the log backend once.  env_logger writes to stderr, which
        // Xcode captures and shows in the debug console when running from Xcode
        // or via `make run` (--console-pty).  try_init is a no-op on subsequent
        // calls so it is safe to call from every ChatterboxClient::new().
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .try_init();

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

            // XEP-0280: receive copies of messages sent from your other clients
            if let Err(e) = xmpp.enable_carbons_compat().await {
                log::warn!("Failed to enable message carbons: {e}");
            }

            // Clear any stale ignore/failure state for our own OMEMO device.
            // Self-session replay failures from previous MAM catch-ups are always
            // false positives — they must never block outgoing messages.
            if let Some(ref mgr) = xmpp.omemo_manager {
                if let Ok((own_device_id, _)) = crate::omemo::device_id::load_or_generate_device_id() {
                    let mut manager = mgr.lock().await;
                    let _ = manager.reset_failure_count(&bare_jid, own_device_id).await;
                    let _ = manager.clear_device_ignore(&bare_jid, own_device_id).await;
                }
            }

            // XEP-0085: wire up typing state notifications
            let (typing_tx, mut typing_rx) =
                tokio::sync::mpsc::channel::<(String, crate::xmpp::chat_states::TypingStatus)>(64);
            xmpp.typing_tx = Some(typing_tx);
            crate::xmpp::publish_late_state(&xmpp);

            // Pump typing events into the FfiEvent stream
            let event_tx_typing = event_tx.clone();
            tokio::spawn(async move {
                while let Some((jid, status)) = typing_rx.recv().await {
                    use crate::xmpp::chat_states::TypingStatus;
                    let is_typing = matches!(status, TypingStatus::Composing);
                    let _ = event_tx_typing
                        .send(FfiEvent::TypingUpdate { jid, is_typing })
                        .await;
                }
            });

            // Open (or create) the message database for this JID.
            let store: Option<Arc<StdMutex<MessageStore>>> =
                match MessageStore::open(&bare_jid) {
                    Ok(s) => Some(Arc::new(StdMutex::new(s))),
                    Err(e) => {
                        log::warn!("Failed to open message store: {e}. History will not be persisted.");
                        None
                    }
                };

            *inner.lock().await = Some(ClientState { xmpp, store: store.clone() });

            // Background pump: store + forward incoming messages as FfiEvents.
            tokio::spawn(async move {
                let mut rx = msg_rx;
                loop {
                    match rx.recv().await {
                        Some(m) => {
                            // A delivery_update reuses the original message ID with
                            // sender_id = "me".  If the store already has that ID, treat
                            // it as a status update rather than a new message.
                            let is_update = if let Some(ref s) = store {
                                s.lock().ok().map_or(false, |guard| {
                                    // Check if this ID already exists by trying to load it.
                                    // A single-row query is cheap; we reuse load_messages
                                    // with limit=1 and filter by id via SQL.
                                    guard
                                        .load_messages(&m.recipient_id, 1)
                                        .ok()
                                        .map_or(false, |msgs| {
                                            msgs.iter().any(|existing| existing.id == m.id)
                                        })
                                })
                            } else {
                                false
                            };

                            if is_update {
                                // Update the stored row's delivery status
                                if let Some(ref s) = store {
                                    if let Ok(guard) = s.lock() {
                                        let _ = guard.update_delivery_status(
                                            &m.id,
                                            m.delivery_status.clone(),
                                        );
                                    }
                                }
                                let status = format!("{:?}", m.delivery_status).to_lowercase();
                                let _ = event_tx
                                    .send(FfiEvent::StatusUpdate { msg_id: m.id, status })
                                    .await;
                            } else {
                                if let Some(ref s) = store {
                                    if let Ok(guard) = s.lock() {
                                        let _ = guard.store_message(&m);
                                    }
                                }
                                let _ = event_tx
                                    .send(FfiEvent::Message { msg: to_ffi_message(m) })
                                    .await;
                            }
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
    /// Returns the stored `FfiMessage` so the caller can display it immediately.
    pub async fn send_message(&self, to_jid: String, body: String) -> Result<FfiMessage, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let mut guard = inner.lock().await;
            let state = guard.as_mut().ok_or(FfiError::NotConnected)?;

            // Generate the ID first — it is used BOTH on the wire and in storage so
            // that when the echo comes back through msg_rx the deduplication catches it.
            let msg_id = Uuid::new_v4().to_string();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            state
                .xmpp
                .send_message_with_id(&to_jid, &body, &msg_id)
                .await
                .map_err(|e| FfiError::Send { reason: e.to_string() })?;

            let record = Message {
                id: msg_id,
                sender_id: "me".to_string(),
                recipient_id: to_jid.clone(),
                content: body.clone(),
                timestamp: now,
                delivery_status: DeliveryStatus::Sent,
                encrypted: true,
            };
            if let Some(ref s) = state.store {
                if let Ok(guard) = s.lock() {
                    let _ = guard.store_message(&record);
                }
            }
            Ok(to_ffi_message(record))
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

    /// Load the most recent `limit` messages for a conversation partner.
    /// Returns oldest-first so the UI can append them in order.
    pub async fn load_history(&self, jid: String, limit: u32) -> Result<Vec<FfiMessage>, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            let msgs = match &state.store {
                Some(s) => s
                    .lock()
                    .map_err(|_| FfiError::Roster { reason: "store lock poisoned".into() })?
                    .load_messages(&jid, limit as usize)
                    .map_err(|e| FfiError::Roster { reason: e.to_string() })?,
                None => vec![],
            };
            Ok(msgs.into_iter().map(to_ffi_message).collect())
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
    }

    /// Return all contact JIDs that have stored message history, newest-first.
    /// Call this after `connect()` to restore previous conversations.
    pub async fn list_conversations(&self) -> Result<Vec<String>, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            match &state.store {
                Some(s) => s
                    .lock()
                    .map_err(|_| FfiError::Roster { reason: "store lock poisoned".into() })?
                    .list_contacts()
                    .map_err(|e| FfiError::Roster { reason: e.to_string() }),
                None => Ok(vec![]),
            }
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
    }

    /// Fetch server-side message archive (MAM, XEP-0313) for `jid` and store
    /// any messages newer than `since_unix_secs`.  Returns the new messages
    /// oldest-first so the caller can append them to local history.
    pub async fn fetch_mam(&self, jid: String, since_unix_secs: i64) -> Result<Vec<FfiMessage>, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;

            let start = chrono::DateTime::from_timestamp(since_unix_secs, 0)
                .unwrap_or_else(chrono::Utc::now);
            let opts = crate::xmpp::message_archive::MAMQueryOptions {
                with: Some(jid.clone()),
                start: Some(start),
                end: None,
                ..crate::xmpp::message_archive::MAMQueryOptions::new()
            };

            let msgs = state
                .xmpp
                .get_message_history(opts)
                .await
                .map_err(|e| FfiError::Roster { reason: e.to_string() })?;

            // Store new messages; dedup is handled by INSERT OR IGNORE in SQLite
            let mut new_msgs = Vec::new();
            if let Some(ref s) = state.store {
                if let Ok(guard) = s.lock() {
                    for m in &msgs {
                        let _ = guard.store_message(m);
                        new_msgs.push(to_ffi_message(m.clone()));
                    }
                }
            } else {
                new_msgs = msgs.into_iter().map(to_ffi_message).collect();
            }
            Ok(new_msgs)
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
    }

    /// Send an XEP-0085 chat state: `is_typing = true` → Composing, false → Paused.
    pub async fn send_typing(&self, jid: String, is_typing: bool) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            use crate::xmpp::chat_states::TypingStatus;
            let status = if is_typing { TypingStatus::Composing } else { TypingStatus::Paused };
            state
                .xmpp
                .send_chat_state(&jid, &status)
                .map_err(|e| FfiError::Send { reason: e.to_string() })
        })
        .await
        .map_err(|e| FfiError::Send { reason: e.to_string() })?
    }

    /// Mark an OMEMO device as trusted.
    pub async fn trust_device(&self, jid: String, device_id: u32) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            state
                .xmpp
                .mark_device_trusted(&jid, device_id)
                .await
                .map_err(|e| FfiError::Omemo { reason: e.to_string() })
        })
        .await
        .map_err(|e| FfiError::Omemo { reason: e.to_string() })?
    }

    /// Mark an OMEMO device as untrusted.
    pub async fn distrust_device(&self, jid: String, device_id: u32) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            state
                .xmpp
                .mark_device_untrusted(&jid, device_id)
                .await
                .map_err(|e| FfiError::Omemo { reason: e.to_string() })
        })
        .await
        .map_err(|e| FfiError::Omemo { reason: e.to_string() })?
    }

    /// Delete all stored messages for a conversation partner.
    pub async fn delete_conversation(&self, jid: String) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            if let Some(ref s) = state.store {
                s.lock()
                    .map_err(|_| FfiError::Roster { reason: "store lock poisoned".into() })?
                    .delete_conversation(&jid)
                    .map_err(|e| FfiError::Roster { reason: e.to_string() })?;
            }
            Ok(())
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
    }

    /// Gracefully disconnect and close the event stream.
    pub async fn disconnect(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = RUNTIME.spawn(async move {
            *inner.lock().await = None;
        })
        .await;
    }

    /// Fetch OMEMO fingerprints for every known device of `jid`.
    ///
    /// Returns an empty list if OMEMO is not yet initialised or the contact
    /// has no known devices.
    pub async fn get_fingerprints(&self, jid: String) -> Result<Vec<FfiFingerprint>, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let guard = inner.lock().await;
            let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
            let bare_jid = jid.split('/').next().unwrap_or(&jid).to_string();

            let device_ids = match state.xmpp.get_omemo_manager() {
                Some(mgr) => mgr
                    .lock()
                    .await
                    .get_device_ids_for_test(&bare_jid)
                    .await
                    .unwrap_or_default(),
                None => return Ok(vec![]),
            };

            let mut result = Vec::new();
            for device_id in device_ids {
                let fp = state.xmpp.get_device_fingerprint(&bare_jid, device_id).await;
                let trusted = state
                    .xmpp
                    .is_device_trusted(&bare_jid, device_id)
                    .await
                    .unwrap_or(false);
                if let Ok(raw) = fp {
                    result.push(FfiFingerprint {
                        device_id,
                        fingerprint: format_fingerprint(&raw),
                        is_trusted: trusted,
                    });
                }
            }
            Ok(result)
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
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

/// Group a hex fingerprint into 4-char blocks separated by spaces for readability.
/// e.g. "aabbccddeeff…" → "AABB CCDD EEFF …"
fn format_fingerprint(raw: &str) -> String {
    raw.chars()
        .enumerate()
        .fold(String::new(), |mut s, (i, c)| {
            if i > 0 && i % 4 == 0 { s.push(' '); }
            s.push(c.to_ascii_uppercase());
            s
        })
}
