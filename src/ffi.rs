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
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    jid::BareJid,
    models::{DeliveryStatus, Direction, Message},
    storage::MessageStore,
    units::Millis,
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
    /// Unix timestamp in **seconds** since the epoch.
    ///
    /// `Message::timestamp` is milliseconds internally (see the SQLite
    /// migration in `storage.rs`); the conversion happens in
    /// `to_ffi_message` so Swift can feed this straight into
    /// `Date(timeIntervalSince1970:)`.
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
    /// Full trust level: "undecided" | "trusted" | "verified" | "untrusted"
    pub trust_level: String,
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
// In-memory log buffer — ring buffer of the last N formatted log lines,
// accessible via get_log_contents() so the iOS app can export them.
// ---------------------------------------------------------------------------

const LOG_BUFFER_CAP: usize = 10_000;

static LOG_BUFFER: Lazy<StdMutex<VecDeque<String>>> =
    Lazy::new(|| StdMutex::new(VecDeque::with_capacity(LOG_BUFFER_CAP)));

/// The persistent log file opened by `set_log_file()`.  Written on every log
/// call so the file is useful even if the process is killed before the user
/// taps "Export".
static LOG_FILE: Lazy<StdMutex<Option<std::fs::File>>> =
    Lazy::new(|| StdMutex::new(None));

/// Open (and truncate) the persistent log file at `path`.  Call this once at
/// app startup, before `connect()`.  All subsequent log lines will be written
/// to that file AND to the in-memory buffer.  Any lines already in the buffer
/// are flushed to the file first so no early logs are lost.
///
/// The file is kept open for the lifetime of the process so every log line
/// reaches disk even if the app is killed, unlike an in-memory buffer.
#[uniffi::export]
pub fn set_log_file(path: String) {
    use std::io::Write;
    let result = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path);
    match result {
        Ok(mut file) => {
            let header = format!(
                "=== Chatterbox session started {} ===\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            );
            let _ = file.write_all(header.as_bytes());
            // Write any lines buffered before the file was opened (early init logs).
            if let Ok(buf) = LOG_BUFFER.lock() {
                for line in buf.iter() {
                    let _ = writeln!(file, "{}", line);
                }
            }
            let _ = file.flush();
            if let Ok(mut guard) = LOG_FILE.lock() {
                *guard = Some(file);
            }
        }
        Err(e) => {
            eprintln!("ChatterboxLogger: failed to open log file '{}': {}", path, e);
        }
    }
}

/// Custom log backend: writes to stderr (Xcode console) AND the in-memory
/// ring buffer so the iOS app can export the logs at any time.
struct ChatterboxLogger {
    /// Handles filtering and stderr formatting.
    inner: env_logger::Logger,
}

impl log::Log for ChatterboxLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        static LOG_CALL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if LOG_CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 20 {
            eprintln!("LOGGER_DEBUG: log called level={} target={} msg={}",
                      record.level(), record.target(), record.args());
        }

        if !self.enabled(record.metadata()) {
            eprintln!("LOGGER_DEBUG: NOT enabled, returning early");
            return;
        }
        // Forward to env_logger so Xcode console output is unchanged.
        self.inner.log(record);

        let line = format!(
            "{} [{:<5}] {} — {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            record.target(),
            record.args()
        );

        // Append to in-memory ring buffer.
        if let Ok(mut buf) = LOG_BUFFER.try_lock() {
            if buf.len() == LOG_BUFFER_CAP {
                buf.pop_front();
            }
            buf.push_back(line.clone());
        }

        // Append to the persistent log file.  try_lock avoids stalling when
        // the logger is called from within set_log_file() itself.
        match LOG_FILE.try_lock() {
            Ok(mut guard) => {
                if let Some(ref mut file) = *guard {
                    use std::io::Write;
                    if let Err(e) = writeln!(file, "{}", line) {
                        eprintln!("LOGGER_DEBUG: file write error: {}", e);
                    }
                    if let Err(e) = file.flush() {
                        eprintln!("LOGGER_DEBUG: file flush error: {}", e);
                    }
                } else {
                    eprintln!("LOGGER_DEBUG: LOG_FILE is None");
                }
            }
            Err(e) => {
                eprintln!("LOGGER_DEBUG: LOG_FILE try_lock failed: {:?}", e);
            }
        }
    }

    fn flush(&self) {
        self.inner.flush();
        if let Ok(mut guard) = LOG_FILE.try_lock() {
            if let Some(ref mut file) = *guard {
                use std::io::Write;
                let _ = file.flush();
            }
        }
    }
}

/// Return all buffered log lines as a single newline-separated string.
/// Call from Swift to get the full in-session log for export.
#[uniffi::export]
pub fn get_log_contents() -> String {
    LOG_BUFFER
        .lock()
        .map(|buf| {
            buf.iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
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
    /// The event stream for the current connection.  It is created per
    /// connection and removed on disconnect so `next_event()` can finish.
    event_stream: Arc<Mutex<Option<EventStream>>>,
}

struct ClientState {
    /// Shared reference — all XMPPClient methods used at runtime take `&self`
    /// so no outer lock is needed; inner mutable state uses its own Arc<Mutex<...>>.
    xmpp: Arc<XMPPClient>,
    /// SQLite message store — None if the DB failed to open (graceful degradation).
    store: Option<Arc<StdMutex<MessageStore>>>,
}

struct EventStream {
    sender: mpsc::Sender<FfiEvent>,
    receiver: Arc<Mutex<mpsc::Receiver<FfiEvent>>>,
}

#[uniffi::export]
impl ChatterboxClient {
    /// Create a new (disconnected) client.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        // Initialise the log backend once. We install a custom logger that
        // writes to stderr (Xcode console) AND our in-memory ring buffer.
        static LOGGER_ONCE: std::sync::Once = std::sync::Once::new();
        LOGGER_ONCE.call_once(|| {
            let inner = env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or("info"),
            )
            .build();
            let max_level = inner.filter();
            eprintln!("FFI_DEBUG: Logger initialized max_level={:?} RUST_LOG={:?}",
                      max_level, std::env::var("RUST_LOG"));
            let logger = ChatterboxLogger { inner };
            // session header so exported logs are easy to orientate
            if let Ok(mut buf) = LOG_BUFFER.try_lock() {
                buf.push_back(format!(
                    "=== Chatterbox session started {} ===",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                ));
            }
            let _ = log::set_boxed_logger(Box::new(logger));
            log::set_max_level(max_level);
        });

        Arc::new(Self {
            inner: Arc::new(Mutex::new(None)),
            event_stream: Arc::new(Mutex::new(None)),
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
        let event_stream = Arc::clone(&self.event_stream);

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

            // A client can be connected again after a disconnect.  Give each
            // connection its own channel so dropping it wakes any old
            // `next_event()` call instead of leaving it suspended forever.
            let (event_tx, event_rx) = mpsc::channel(256);
            *event_stream.lock().await = Some(EventStream {
                sender: event_tx.clone(),
                receiver: Arc::new(Mutex::new(event_rx)),
            });

            // Clear any stale ignore/failure state for our own OMEMO device.
            // Self-session replay failures from previous MAM catch-ups are always
            // false positives — they must never block outgoing messages.
            if let Some(ref mgr) = xmpp.omemo_manager {
                if let Ok((own_device_id, _)) = crate::omemo::device_id::load_or_generate_device_id() {
                    let mut manager = mgr.lock().await;
                    let _ = manager.reset_failure_count(&bare_jid, own_device_id.into()).await;
                    let _ = manager.clear_device_ignore(&bare_jid, own_device_id.into()).await;
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

            *inner.lock().await = Some(ClientState {
                xmpp: Arc::new(xmpp),
                store: store.clone(),
            });

            // Background pump: store + forward incoming messages as FfiEvents.
            let event_stream_pump = Arc::clone(&event_stream);
            tokio::spawn(async move {
                let mut rx = msg_rx;
                loop {
                    match rx.recv().await {
                        Some(crate::models::AppEvent::KeyVerifyRequest { sender, fingerprint, device_id: _ }) => {
                            let body = format!("Key verification request from {} — fingerprint: {}", sender, fingerprint);
                            let sys = crate::models::Message::system(&sender, body);
                            let _ = event_tx.send(FfiEvent::Message { msg: to_ffi_message(sys) }).await;
                        }
                        Some(crate::models::AppEvent::Chat(m)) => {
                            // Try to store; INSERT OR IGNORE returns false when the id already exists.
                            let newly_inserted = if let Some(ref s) = store {
                                s.lock().ok().map_or(true, |guard| {
                                    guard.store_message(&m).unwrap_or(true)
                                })
                            } else {
                                true
                            };

                            // Empty content is a delivery-status update from our own-device path;
                            // never emit it as a new bubble regardless of whether the id is new.
                            if newly_inserted && !m.content.is_empty() {
                                let _ = event_tx
                                    .send(FfiEvent::Message { msg: to_ffi_message(m) })
                                    .await;
                            } else {
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
                            }
                        }
                        None => {
                            let _ = event_tx
                                .send(FfiEvent::Disconnected {
                                    reason: "Connection closed".to_string(),
                                })
                                .await;
                            // Close this connection's stream after publishing its
                            // final event.  Do not remove a newer stream if a
                            // reconnect has already installed one.
                            let mut current_stream = event_stream_pump.lock().await;
                            if let Some(stream) = current_stream.as_ref() {
                                if stream.sender.same_channel(&event_tx) {
                                    current_stream.take();
                                }
                            }
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
        eprintln!("FFI_DEBUG: send_message called to_jid={}", to_jid);
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            eprintln!("FFI_DEBUG: send_message task started to_jid={}", to_jid);

            // Extract shared references — inner MUST NOT be held across OMEMO
            // encrypt because other FFI calls (get_fingerprints etc.) would
            // block for the entire send duration (up to 15-45 s).
            let (xmpp, store) = {
                let mut guard = inner.lock().await;
                eprintln!("FFI_DEBUG: send_message inner locked");
                let state = guard.as_mut().ok_or_else(|| {
                    eprintln!("FFI_DEBUG: inner state is NONE!");
                    FfiError::NotConnected
                })?;
                (Arc::clone(&state.xmpp), state.store.clone())
            }; // inner lock released here

            eprintln!("FFI_DEBUG: send_message got xmpp Arc");

            let msg_id = Uuid::new_v4().to_string();
            eprintln!("FFI_DEBUG: send_message msg_id={}", msg_id);
            // Milliseconds, matching every other producer of `Message` and the
            // `timestamp * 1000` migration in `storage.rs`.  Writing seconds
            // here put mixed units in one table: freshly sent messages rendered
            // correctly while everything else rendered in the year 58536.
            let now = Millis::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64
            );

            eprintln!("FFI_DEBUG: send_message calling send_message_with_id (no lock held)");
            xmpp.send_message_with_id(&to_jid, &body, &msg_id)
                .await
                .map_err(|e| {
                    eprintln!("FFI_DEBUG: send_message_with_id error: {}", e);
                    FfiError::Send { reason: e.to_string() }
                })?;
            eprintln!("FFI_DEBUG: send_message_with_id returned ok");

            let record = Message {
                id: msg_id,
                sender_id: "me".to_string(),
                recipient_id: to_jid.clone(),
                content: body.clone(),
                timestamp: now,
                delivery_status: DeliveryStatus::Sent,
                encrypted: true,
                direction: Direction::Outgoing {
                    to: BareJid::parse(&to_jid).expect("expected valid JID"),
                },
            };
            if let Some(ref s) = store {
                if let Ok(guard) = s.lock() {
                    let _ = guard.store_message(&record);
                }
            }
            Ok(to_ffi_message(record))
        })
        .await
        .map_err(|e| FfiError::Send { reason: e.to_string() })?
    }

    /// Reset the OMEMO session for a specific contact and device ID.
    ///
    /// This is used to recover from cryptographic desynchronization.
    /// It deletes the existing session state for the given device ID.
    pub async fn reset_omemo_session(&self, jid: String, device_id: u32) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let xmpp = {
                let mut guard = inner.lock().await;
                let state = guard.as_mut().ok_or(FfiError::NotConnected)?;
                Arc::clone(&state.xmpp)
            };
            if let Some(ref mgr) = xmpp.omemo_manager {
                let mut mgr_guard = mgr.lock().await;
                let bare = BareJid::parse(&jid).expect("expected valid JID");
                mgr_guard.reset_session(&bare, device_id).await
                    .map_err(|e| FfiError::Omemo { reason: e.to_string() })?;
            }
            Ok(())
        })
        .await
        .map_err(|e| FfiError::Omemo { reason: e.to_string() })?
    }

    /// Fetch the roster (contact list) from the server.
    pub async fn get_contacts(&self) -> Result<Vec<FfiContact>, FfiError> {
        eprintln!("FFI_DEBUG: get_contacts called");
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            eprintln!("FFI_DEBUG: get_contacts task started");
            let xmpp = {
                let guard = inner.lock().await;
                eprintln!("FFI_DEBUG: get_contacts inner locked");
                let state = guard.as_ref().ok_or_else(|| {
                    eprintln!("FFI_DEBUG: get_contacts inner state NONE!");
                    FfiError::NotConnected
                })?;
                Arc::clone(&state.xmpp)
            };
            eprintln!("FFI_DEBUG: get_contacts got xmpp Arc");
            eprintln!("FFI_DEBUG: get_contacts calling get_roster (no lock held)");
            let jids = xmpp
                .get_roster()
                .await
                .map_err(|e| {
                    eprintln!("FFI_DEBUG: get_roster error: {}", e);
                    FfiError::Roster { reason: e.to_string() }
                })?
                .unwrap_or_default();
            eprintln!("FFI_DEBUG: get_roster returned {} contacts: {:?}", jids.len(), jids);
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
    /// Returns `None` after `disconnect()` closes the current event stream.
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
        let event_rx = self
            .event_stream
            .lock()
            .await
            .as_ref()
            .map(|stream| Arc::clone(&stream.receiver));
        let event_rx = event_rx?;
        RUNTIME.spawn(async move {
            // try_lock() returns Err immediately if another caller already holds the
            // guard (i.e. is parked inside recv()). This enforces single-consumer
            // semantics: a second concurrent call returns None instead of hanging
            // permanently waiting for the mutex to be released.
            match event_rx.try_lock() {
                Ok(mut rx) => rx.recv().await,
                Err(_) => None,
            }
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
    /// any messages newer than `since_unix_secs` (**seconds** since the epoch).
    /// Returns only messages that were not already present locally, oldest-first,
    /// so the caller can append them to local history and count them as unread.
    pub async fn fetch_mam(&self, jid: String, since_unix_secs: i64) -> Result<Vec<FfiMessage>, FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let (xmpp, store) = {
                let guard = inner.lock().await;
                let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
                (Arc::clone(&state.xmpp), state.store.clone())
            };

            // Tolerate callers that pass milliseconds: an unconverted ms value
            // fed to `from_timestamp` lands in the year 58536, which the server
            // answers with an empty archive.  That is why foreground catch-up
            // silently returned nothing while background refresh (using a real
            // seconds window) kept reporting new messages.
            let start_millis = crate::units::Secs(since_unix_secs).to_millis().get();
            let start = chrono::DateTime::from_timestamp_millis(start_millis)
                .unwrap_or_else(chrono::Utc::now);
            let opts = crate::xmpp::message_archive::MAMQueryOptions {
                with: Some(jid.clone()),
                start: Some(start),
                end: None,
                ..crate::xmpp::message_archive::MAMQueryOptions::new()
            };

            let msgs = xmpp
                .get_message_history(opts)
                .await
                .map_err(|e| FfiError::Roster { reason: e.to_string() })?;

            // Return only messages that were not already in the local store.
            // MAM re-sends everything in the requested window, so echoing all of
            // it back made the caller treat already-read messages as new.
            let mut new_msgs = Vec::new();
            if let Some(ref s) = store {
                if let Ok(guard) = s.lock() {
                    for m in &msgs {
                        match guard.store_message(m) {
                            Ok(true) => new_msgs.push(to_ffi_message(m.clone())),
                            Ok(false) => {} // already stored on a prior fetch
                            Err(e) => {
                                log::warn!("Failed to store MAM message {}: {}", m.id, e);
                            }
                        }
                    }
                }
            } else {
                // No local store: we cannot tell new from old, so return everything.
                new_msgs = msgs.into_iter().map(to_ffi_message).collect();
            }
            new_msgs.sort_by_key(|m| m.timestamp);
            Ok(new_msgs)
        })
        .await
        .map_err(|e| FfiError::Roster { reason: e.to_string() })?
    }

    /// Send an XEP-0085 chat state: `is_typing = true` → Composing, false → Paused.
    pub async fn send_typing(&self, jid: String, is_typing: bool) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let xmpp = {
                let guard = inner.lock().await;
                let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
                Arc::clone(&state.xmpp)
            };
            use crate::xmpp::chat_states::TypingStatus;
            let status = if is_typing { TypingStatus::Composing } else { TypingStatus::Paused };
            xmpp.send_chat_state(&jid, &status)
                .map_err(|e| FfiError::Send { reason: e.to_string() })
        })
        .await
        .map_err(|e| FfiError::Send { reason: e.to_string() })?
    }

    /// Mark an OMEMO device as trusted.
    pub async fn trust_device(&self, jid: String, device_id: u32) -> Result<(), FfiError> {
        let inner = Arc::clone(&self.inner);
        RUNTIME.spawn(async move {
            let xmpp = {
                let guard = inner.lock().await;
                let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
                Arc::clone(&state.xmpp)
            };
            xmpp
                .mark_device_trusted(&jid, crate::omemo::device_id::DeviceId::from(device_id))
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
            let xmpp = {
                let guard = inner.lock().await;
                let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
                Arc::clone(&state.xmpp)
            };
            xmpp
                .mark_device_untrusted(&jid, crate::omemo::device_id::DeviceId::from(device_id))
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
        let event_stream = Arc::clone(&self.event_stream);
        let _ = RUNTIME.spawn(async move {
            // Drop the client-owned sender first.  Once the XMPP/typing pumps
            // are dropped with `inner`, any waiter on this receiver observes
            // the closed channel and returns `None`.
            event_stream.lock().await.take();
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
            let xmpp = {
                let guard = inner.lock().await;
                let state = guard.as_ref().ok_or(FfiError::NotConnected)?;
                Arc::clone(&state.xmpp)
            };
            let bare_jid = jid.split('/').next().unwrap_or(&jid).to_string();

            let device_ids = {
                match xmpp.get_omemo_manager() {
                    Some(mgr) => mgr
                        .lock()
                        .await
                        .get_device_ids_for_test(&bare_jid)
                        .await
                        .unwrap_or_default(),
                    None => return Ok(vec![]),
                }
            };

            let mut result = Vec::new();
            for device_id in device_ids {
                let fp = xmpp.get_device_fingerprint(&bare_jid, device_id).await;
                let trust = match xmpp.get_omemo_manager() {
                    Some(mgr) => mgr.lock().await
                        .get_device_trust_level(&bare_jid, device_id)
                        .await
                        .unwrap_or(crate::omemo::storage::TrustLevel::Undecided),
                    None => crate::omemo::storage::TrustLevel::Undecided,
                };
                if let Ok(raw) = fp {
                    result.push(FfiFingerprint {
                        device_id: device_id.into(),
                        fingerprint: format_fingerprint(&raw),
                        is_trusted: trust.is_trusted(),
                        trust_level: trust.as_str().to_string(),
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
        timestamp: m.timestamp.to_secs().get(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod timestamp_tests {
    use super::*;
    use crate::models::{DeliveryStatus, Message};
    use chatterbox::units::Millis;
    use chrono::Datelike;

    /// A real millisecond timestamp: 2026-07-26T07:22:04Z.
    const SAMPLE_MS: i64 = 1_785_050_524_800;
    /// The same instant in seconds.
    const SAMPLE_SECS: i64 = 1_785_050_524;

    fn msg_with_timestamp(ts: Millis) -> Message {
        Message {
            id: "test-id".to_string(),
            sender_id: "me".to_string(),
            recipient_id: "alice@example.com".to_string(),
            content: "hello".to_string(),
            timestamp: ts,
            delivery_status: DeliveryStatus::Sent,
            encrypted: true,
        }
    }

    #[test]
    fn to_ffi_message_emits_seconds_not_millis() {
        let ffi = to_ffi_message(msg_with_timestamp(Millis(SAMPLE_MS)));
        assert_eq!(ffi.timestamp, SAMPLE_SECS);
    }

    #[test]
    fn to_ffi_message_timestamp_renders_in_a_sane_year() {
        let ffi = to_ffi_message(msg_with_timestamp(Millis(SAMPLE_MS)));
        let year = chrono::DateTime::from_timestamp(ffi.timestamp, 0)
            .expect("timestamp must be representable")
            .year();
        assert!(
            (2000..=2100).contains(&year),
            "timestamp rendered as year {year}, expected a present-day year"
        );
    }

    #[test]
    fn mam_window_start_is_a_present_day_date() {
        let start = chrono::DateTime::from_timestamp_millis(
            chatterbox::units::Secs(SAMPLE_SECS).to_millis().get(),
        )
        .expect("MAM start must be representable");
        assert_eq!(start.format("%Y-%m-%d").to_string(), "2026-07-26");
    }
}
