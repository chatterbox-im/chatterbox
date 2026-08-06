// src/omemo/mod.rs
//! OMEMO encryption module
//!
//! This module implements the OMEMO encryption protocol (XEP-0384) for XMPP.
//! OMEMO provides end-to-end encryption with the Double Ratchet algorithm.

use anyhow::Result;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::jid::BareJid;
use crate::omemo::crypto::CryptoError;
use crate::omemo::device_id::DeviceId;
use crate::omemo::session::{OmemoSessionState, SessionError};
use crate::omemo::storage::OmemoStorage;
pub use crate::omemo::storage::TrustLevel;

pub mod bundle;
pub mod crypto;
mod decrypt;
pub mod device_discovery;
pub mod device_id;
mod encrypt;
#[cfg(test)]
mod encrypt_decrypt_test;
pub mod keys;
mod lifecycle;
pub mod protocol;
pub mod session;
#[cfg(test)]
mod session_proptest;
pub mod storage;
mod store_migrate;
pub mod store_sqlite;
#[cfg(test)]
mod security_tests;
pub mod wire;

/// The OMEMO namespace used in XMPP stanzas
pub const OMEMO_NAMESPACE: &str = "eu.siacs.conversations.axolotl";

/// Primary PEP node for device lists (legacy Conversations format).
pub fn devicelist_node() -> String {
    format!("{}.devicelist", OMEMO_NAMESPACE)
}

/// Primary PEP node for a device's bundle.
pub fn bundle_node(device_id: crate::omemo::device_id::DeviceId) -> String {
    format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id)
}

/// All node-name variants tried when fetching a device list (primary first).
pub fn devicelist_node_variants() -> [String; 3] {
    [
        format!("{}.devicelist", OMEMO_NAMESPACE),
        format!("{}:devices",    OMEMO_NAMESPACE),
        format!("{}:devicelist", OMEMO_NAMESPACE),
    ]
}

/// All node-name variants tried when fetching a bundle (primary first).
pub fn bundle_node_variants(device_id: crate::omemo::device_id::DeviceId) -> [String; 2] {
    [
        format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id),
        format!("{}:bundles:{}", OMEMO_NAMESPACE, device_id),
    ]
}

/// Trait abstracting the XMPP PubSub operations that OMEMO needs.
/// This breaks the circular dependency: OmemoManager depends on this trait,
/// and the XMPP layer implements it. No globals needed.
#[async_trait]
pub trait OmemoPubSub: Send + Sync {
    /// Request items from a PubSub node (fetch device lists, bundles, etc.)
    async fn request_items(&self, from: &str, node: &str) -> Result<String>;

    /// Publish an item to a PubSub node (bundles, device lists)
    async fn publish_item(
        &self,
        to: Option<&str>,
        node: &str,
        id: &str,
        payload: &str,
    ) -> Result<()>;

    /// Publish using alternative XML format (fallback for servers that reject standard format)
    async fn publish_item_alternative(
        &self,
        to: Option<&str>,
        node: &str,
        id: &str,
        payload: &str,
    ) -> Result<()>;

    /// Publish the OMEMO device list
    async fn publish_device_list(&self, device_ids: &[DeviceId]) -> Result<()>;

    /// Delete the bundle PubSub node for a device (used for cleanup)
    async fn delete_bundle(&self, device_id: DeviceId) -> Result<()>;
}

/// Errors that can occur in OMEMO operations
#[derive(Debug, Error)]
pub enum OmemoError {
    /// Error in cryptographic operations
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    /// Error in double ratchet operations
    #[error("Double ratchet error: {0}")]
    DoubleRatchetError(#[from] crate::omemo::protocol::DoubleRatchetError),

    /// Error in session operations
    #[error("Session error: {0}")]
    SessionError(#[from] SessionError),

    /// No session found
    #[error("No session found for {0}:{1}")]
    NoSessionError(String, u32),

    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Missing data
    #[error("Missing data: {0}")]
    MissingDataError(String),

    /// No device found
    #[error("No device found for {0}")]
    NoDeviceError(String),

    /// No key bundle found
    #[error("No key bundle found for device {0}")]
    NoKeyBundleError(u32),

    /// No valid one-time prekey
    #[error("No valid one-time prekey found")]
    NoValidOneTimePreKeyError,

    /// Device not trusted
    #[error("Device {0}:{1} is not trusted")]
    DeviceNotTrustedError(String, u32),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Invalid header error
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// Invalid message error
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Publication error
    #[error("Publication error: {0}")]
    PublicationError(String),

    /// Timeout error
    #[error("Timeout error: {0}")]
    TimeoutError(String),
}

/// Structure for PreKey rotation configuration
pub struct PreKeyRotationConfig {
    /// Maximum age of a signed PreKey in seconds
    pub max_signed_prekey_age: u64,

    /// Number of one-time PreKeys to maintain
    pub min_one_time_prekeys: u32,

    /// How often to check for PreKey rotation (in seconds)
    pub check_interval: u64,

    /// Last rotation timestamp (in seconds since epoch)
    pub last_rotation: u64,
}

impl Default for PreKeyRotationConfig {
    fn default() -> Self {
        Self {
            max_signed_prekey_age: 7 * 24 * 60 * 60, // 7 days
            min_one_time_prekeys: 20,
            check_interval: 24 * 60 * 60, // 1 day
            last_rotation: 0,
        }
    }
}

/// OMEMO manager for handling encryption and sessions
pub struct OmemoManager {
    /// The storage for OMEMO data
    pub(crate) storage: Arc<Mutex<OmemoStorage>>,

    /// The device ID for this client
    pub(crate) device_id: DeviceId,

    /// The JID of the local user
    pub(crate) local_jid: String,

    /// The key bundle for this device
    pub(crate) key_bundle: Option<protocol::X3DHKeyBundle>,

    /// Active sessions with other devices.
    /// Each entry is an `OmemoSessionState` rather than a bare `OmemoSession` so
    /// that pending-rebuild markers (`PeerResetPending`) can be stored in the same
    /// map, eliminating the old `pending_session_rebuilds: HashSet` side-channel.
    pub(crate) sessions: HashMap<(BareJid, DeviceId), OmemoSessionState>,

    /// PreKey rotation configuration
    pub prekey_rotation_config: PreKeyRotationConfig,

    /// Devices whose trust level should be restored to Trusted after a session rebuild.
    /// This prevents identity-key-pinning from overriding an explicit user trust decision
    /// when the remote device has a new identity (e.g. fresh install).
    pub(crate) pending_trust_restorations: HashSet<(BareJid, DeviceId)>,

    /// Ephemeral keys for pending PreKey messages to specific devices.
    /// Value is (key_bytes, insertion_time) for TTL eviction.
    pub(crate) prekey_ephemeral_keys: HashMap<(BareJid, DeviceId), (Vec<u8>, Instant)>,

    /// Remote device PreKey IDs captured during session creation:
    /// (jid, device_id) → (signed_pre_key_id, Option<one_time_pre_key_id>, insertion_time)
    pub(crate) remote_prekey_ids: HashMap<(BareJid, DeviceId), (u32, Option<u32>, Instant)>,

    /// Message IDs that have been successfully decrypted. Used to skip duplicate
    /// decryption attempts when the same OMEMO message arrives both as a direct
    /// stanza delivery and as a message-carbon copy (e.g. self-messages to als@).
    pub(crate) recently_decrypted_ids: std::collections::VecDeque<String>,

    /// Message IDs whose decryption has already failed. Used to suppress the
    /// carbon copy of a message from also incrementing the failure counter when
    /// the direct delivery already failed — without this, a single bad message
    /// counts as two failures and prematurely resets the session.
    pub(crate) recently_failed_ids: std::collections::VecDeque<String>,

    /// PubSub operations — injected dependency instead of global access
    pub(crate) pubsub: Arc<dyn OmemoPubSub>,
}

impl OmemoManager {
    /// Create a new OMEMO manager
    pub async fn new(
        storage: OmemoStorage,
        local_jid: String,
        device_id: Option<u32>,
        pubsub: Arc<dyn OmemoPubSub>,
    ) -> Result<Self, OmemoError> {
        let storage = Arc::new(Mutex::new(storage));

        // Determine the device ID — prefer the one already loaded by OmemoStorage
        // (which respects per-instance paths), falling back to the global path.
        let device_id = match device_id {
            Some(id) => {
                info!("Using explicitly provided device ID: {}", id);

                let mut storage_guard = storage.lock().await;
                storage_guard
                    .store_device_id(DeviceId::from(id))
                    .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                drop(storage_guard);

                device_id::save_device_id(DeviceId::from(id)).map_err(|e| {
                    OmemoError::StorageError(format!(
                        "Failed to save device ID to filesystem: {}",
                        e
                    ))
                })?;

                DeviceId::from(id)
            }
            None => {
                // Use the device ID from OmemoStorage (already loaded from the correct path)
                let storage_guard = storage.lock().await;
                let storage_device_id = storage_guard.get_device_id();
                drop(storage_guard);

                if storage_device_id.get() > 0 {
                    info!("Loaded existing device ID: {}", storage_device_id);
                    storage_device_id
                } else {
                    // Storage had no device ID — generate a new one
                    let id = device_id::generate_device_id();
                    info!("Generated new device ID: {}", id);

                    let mut storage_guard = storage.lock().await;
                    storage_guard
                        .store_device_id(id)
                        .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                    drop(storage_guard);

                    id
                }
            }
        };

        info!(
            "Initializing OMEMO manager for {} with device ID {}",
            local_jid, device_id
        );

        let mut manager = Self {
            storage: storage.clone(),
            device_id,
            local_jid,
            key_bundle: None,
            sessions: HashMap::new(),
            prekey_rotation_config: PreKeyRotationConfig::default(),
            pending_trust_restorations: HashSet::new(),
            prekey_ephemeral_keys: HashMap::new(),
            remote_prekey_ids: HashMap::new(),
            recently_decrypted_ids: std::collections::VecDeque::new(),
            recently_failed_ids: std::collections::VecDeque::new(),
            pubsub,
        };

        // Load the last PreKey rotation time from storage
        let last_rotation = {
            let storage_guard = storage.lock().await;
            match storage_guard.load_prekey_rotation_time() {
                Ok(timestamp) => {
                    debug!("Loaded last PreKey rotation time: {}", timestamp);
                    timestamp as u64
                }
                Err(e) => {
                    warn!("Failed to load PreKey rotation time: {}, using default", e);
                    0
                }
            }
        };
        manager.prekey_rotation_config.last_rotation = last_rotation;

        // Initialize the key bundle with the persistent identity key
        manager
            .initialize_key_bundle_with_persistent_identity()
            .await?;

        // Load existing sessions from storage
        manager.load_sessions().await?;

        // Restore in-memory flags from persistent storage so they survive restarts.
        // Collect all data while holding the lock, then release it before the
        // mutable `mark_message_failed` call (which also tries to lock storage).
        const FAILED_ID_TTL_SECS: u64 = 24 * 3600;
        let (rebuild_pending, prekey_pending, failed_ids) = {
            let storage_guard = manager.storage.lock().await;
            (
                storage_guard.load_all_rebuild_pending(),
                storage_guard.load_all_prekey_pending(),
                storage_guard.load_recent_failed_message_ids(FAILED_ID_TTL_SECS),
            )
        };
        for (jid, device_id) in rebuild_pending {
            manager
                .sessions
                .insert((BareJid::parse(&jid).expect("expected valid JID"), device_id), OmemoSessionState::PeerResetPending);
        }
        for (jid, device_id) in prekey_pending {
            manager
                .sessions
                .entry((BareJid::parse(&jid).expect("expected valid JID"), device_id))
                .or_insert(OmemoSessionState::RecoveryPreKeySent { attempt: 0 });
        }
        for msg_id in failed_ids {
            manager.mark_message_failed(&msg_id);
        }

        // Immediately check if PreKeys need rotation
        if manager.check_and_rotate_prekeys().await? {
            info!("PreKeys were rotated during initialization");
        }

        info!("OMEMO manager initialized successfully");

        Ok(manager)
    }

    /// Get the device ID for this OMEMO manager
    pub fn get_device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Get a reference to the pubsub bridge
    pub fn pubsub(&self) -> &dyn OmemoPubSub {
        &*self.pubsub
    }

    /// Get a reference to the storage Arc
    pub fn get_storage(&self) -> Arc<Mutex<OmemoStorage>> {
        self.storage.clone()
    }

    /// Maximum number of recently-decrypted message IDs to remember (ring buffer).
    const RECENTLY_DECRYPTED_CAP: usize = 200;

    /// Record that a message was successfully decrypted. Subsequent decryption
    /// attempts for the same ID (e.g. a carbon copy of a direct delivery) will
    /// be short-circuited to avoid advancing the ratchet a second time.
    pub fn mark_message_decrypted(&mut self, msg_id: &str) {
        if msg_id.is_empty() || msg_id == "unknown" {
            return;
        }
        if !self.recently_decrypted_ids.contains(&msg_id.to_string()) {
            if self.recently_decrypted_ids.len() >= Self::RECENTLY_DECRYPTED_CAP {
                self.recently_decrypted_ids.pop_front();
            }
            self.recently_decrypted_ids.push_back(msg_id.to_string());
        }
    }

    /// Returns `true` if we already successfully decrypted this message ID.
    pub fn was_message_decrypted(&self, msg_id: &str) -> bool {
        if msg_id.is_empty() || msg_id == "unknown" {
            return false;
        }
        self.recently_decrypted_ids.contains(&msg_id.to_string())
    }

    /// Maximum number of recently-failed message IDs to remember (ring buffer).
    const RECENTLY_FAILED_CAP: usize = 200;

    /// Record that decryption failed for this message ID. The carbon copy of the
    /// same message will then be skipped so the failure is counted only once.
    /// The ID is also persisted to storage so MAM replays after a restart do
    /// not re-count the same failure.
    pub fn mark_message_failed(&mut self, msg_id: &str) {
        if msg_id.is_empty() || msg_id == "unknown" {
            return;
        }
        if !self.recently_failed_ids.contains(&msg_id.to_string()) {
            if self.recently_failed_ids.len() >= Self::RECENTLY_FAILED_CAP {
                self.recently_failed_ids.pop_front();
            }
            self.recently_failed_ids.push_back(msg_id.to_string());
            // Best-effort persist; failure here only means the TTL-window
            // deduplication won't survive a restart for this message.
            if let Ok(storage_guard) = self.storage.try_lock() {
                if let Err(e) = storage_guard.persist_failed_message_id(msg_id) {
                    warn!("Failed to persist failed message id {}: {}", msg_id, e);
                }
            }
        }
    }

    /// Returns `true` if decryption of this message ID has already failed once.
    pub fn was_message_failed(&self, msg_id: &str) -> bool {
        if msg_id.is_empty() || msg_id == "unknown" {
            return false;
        }
        self.recently_failed_ids.contains(&msg_id.to_string())
    }

    /// Maximum age for pending prekey entries before eviction (1 hour).
    const PENDING_TTL_SECS: u64 = 3600;
    /// Maximum entries in pending collections before forced eviction.
    const PENDING_CAP: usize = 1000;

    /// Evict stale entries from bounded collections.
    /// Call periodically (e.g., before each encrypt) to prevent unbounded growth.
    /// Reset the consecutive-failure counter for a device.
    /// Called after MAM replay failures to prevent false-positive session resets.
    pub async fn reset_failure_count(&mut self, jid: &str, device_id: u32) -> Result<(), crate::omemo::OmemoError> {
        let bare = Self::normalize_jid_to_bare(jid);
        let storage = self.storage.lock().await;
        let _ = storage.reset_device_failure_count(&bare, DeviceId::from(device_id));
        Ok(())
    }

    /// Clear the ignore status for a device so it is eligible for encryption again.
    pub async fn clear_device_ignore(&mut self, jid: &str, device_id: u32) -> Result<(), crate::omemo::OmemoError> {
        let bare = Self::normalize_jid_to_bare(jid);
        let storage = self.storage.lock().await;
        let _ = storage.clear_device_ignore_status(&bare, DeviceId::from(device_id));
        Ok(())
    }

    pub fn evict_stale_entries(&mut self) {
        use std::time::Duration;
        let ttl = Duration::from_secs(Self::PENDING_TTL_SECS);
        let now = Instant::now();

        self.prekey_ephemeral_keys
            .retain(|_, (_, inserted)| now.duration_since(*inserted) < ttl);
        self.remote_prekey_ids
            .retain(|_, (_, _, inserted)| now.duration_since(*inserted) < ttl);

        // Hard cap: drop oldest prekey_ephemeral_keys entries if over limit
        if self.prekey_ephemeral_keys.len() > Self::PENDING_CAP {
            let mut entries: Vec<_> = self.prekey_ephemeral_keys.drain().collect();
            entries.sort_by_key(|(_, (_, t))| *t);
            entries.truncate(Self::PENDING_CAP);
            self.prekey_ephemeral_keys = entries.into_iter().collect();
        }
    }

    /// Normalize a JID to bare JID (without resource) for OMEMO session storage
    pub(crate) fn normalize_jid_to_bare(jid: &str) -> BareJid {
        BareJid::parse(jid).expect("expected valid JID")
    }
}

/// OMEMO Encryption Verification Error
#[derive(Debug, Error)]
pub enum EncryptionVerificationError {
    /// Message contains plaintext content
    #[error("SECURITY VIOLATION: Message contains plaintext content that should be encrypted")]
    PlaintextDetected,

    /// Missing OMEMO elements
    #[error("SECURITY VIOLATION: Message missing required OMEMO elements: {0}")]
    MissingOmemoElements(String),

    /// Invalid OMEMO message format
    #[error("SECURITY VIOLATION: Invalid OMEMO message format: {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omemo::device_id::generate_device_id;
    use tempfile::tempdir;

    /// No-op PubSub implementation for unit tests (no real XMPP connection)
    struct NoOpPubSub;

    #[async_trait]
    impl OmemoPubSub for NoOpPubSub {
        async fn request_items(&self, _from: &str, _node: &str) -> Result<String> {
            Ok(String::new())
        }
        async fn publish_item(
            &self,
            _to: Option<&str>,
            _node: &str,
            _id: &str,
            _payload: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn publish_item_alternative(
            &self,
            _to: Option<&str>,
            _node: &str,
            _id: &str,
            _payload: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn publish_device_list(&self, _device_ids: &[DeviceId]) -> Result<()> {
            Ok(())
        }
        async fn delete_bundle(&self, _device_id: DeviceId) -> Result<()> {
            Ok(())
        }
    }

    fn test_pubsub() -> Arc<dyn OmemoPubSub> {
        Arc::new(NoOpPubSub)
    }

    async fn create_test_storage() -> Result<OmemoStorage, anyhow::Error> {
        let temp_dir = tempdir()?;
        let storage_path = temp_dir.path().to_path_buf();
        let storage = OmemoStorage::new(Some(storage_path))?;
        Ok(storage)
    }

    #[tokio::test]
    async fn test_device_id_generation() {
        let device_id = generate_device_id();
        assert!(device_id.get() > 0, "Device ID should be non-zero");

        let device_id2 = generate_device_id();
        assert!(device_id2.get() > 0, "Second device ID should be non-zero");
        assert_ne!(
            device_id, device_id2,
            "Two generated device IDs should likely be different"
        );
    }

    #[tokio::test]
    async fn test_omemo_manager_device_id() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;

        let manager =
            OmemoManager::new(storage, "test@example.com".to_string(), None, test_pubsub())
                .await
                .expect("Failed to create OmemoManager");

        let device_id = manager.get_device_id();
        assert!(device_id.get() > 0, "Manager's device ID should be non-zero");

        // Use a TempDir so cleanup is automatic and remove_dir_all is not needed.
        let persist_dir = tempdir()?;
        let storage_path = persist_dir.path().to_path_buf();

        let storage1 = OmemoStorage::new(Some(storage_path.clone()))?;
        let manager1 = OmemoManager::new(
            storage1,
            "test@example.com".to_string(),
            None,
            test_pubsub(),
        )
        .await
        .expect("Failed to create first manager");

        let device_id1 = manager1.get_device_id();
        assert!(
            device_id1.get() > 0,
            "First manager's device ID should be non-zero"
        );

        let storage2 = OmemoStorage::new(Some(storage_path.clone()))?;
        let manager2 = OmemoManager::new(
            storage2,
            "test@example.com".to_string(),
            None,
            test_pubsub(),
        )
        .await
        .expect("Failed to create second manager");

        let device_id2 = manager2.get_device_id();
        assert_eq!(
            device_id1, device_id2,
            "Device ID should persist in storage"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_explicit_device_id() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;

        let explicit_id = DeviceId::from(12345u32);
        let manager = OmemoManager::new(
            storage,
            "test@example.com".to_string(),
            Some(explicit_id.get()),
            test_pubsub(),
        )
        .await
        .expect("Failed to create OmemoManager with explicit ID");

        let device_id = manager.get_device_id();
        assert_eq!(
            device_id, explicit_id,
            "Manager should use the explicitly provided device ID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_evict_stale_entries_removes_expired() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;
        let mut manager = OmemoManager::new(
            storage,
            "evict@test.com".to_string(),
            Some(99),
            test_pubsub(),
        )
        .await?;

        let old_time = Instant::now() - std::time::Duration::from_secs(7200); // 2 hours ago
        let fresh_time = Instant::now();

        // prekey_ephemeral_keys and remote_prekey_ids are TTL-evicted
        manager.prekey_ephemeral_keys.insert(
            (BareJid::parse("old@peer.com").expect("expected valid JID"), DeviceId::from(1u32)),
            (vec![0xAA; 32], old_time),
        );
        manager.prekey_ephemeral_keys.insert(
            (BareJid::parse("fresh@peer.com").expect("expected valid JID"), DeviceId::from(2u32)),
            (vec![0xBB; 32], fresh_time),
        );
        manager
            .remote_prekey_ids
            .insert((BareJid::parse("old@peer.com").expect("expected valid JID"), DeviceId::from(1u32)), (1, Some(2), old_time));

        assert_eq!(manager.prekey_ephemeral_keys.len(), 2);
        manager.evict_stale_entries();

        assert_eq!(manager.prekey_ephemeral_keys.len(), 1);
        assert!(manager
            .prekey_ephemeral_keys
            .contains_key(&(BareJid::parse("fresh@peer.com").expect("expected valid JID"), DeviceId::from(2u32))));
        assert!(manager.remote_prekey_ids.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_evict_stale_entries_cap() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;
        let mut manager =
            OmemoManager::new(storage, "cap@test.com".to_string(), Some(99), test_pubsub()).await?;

        // Insert more than PENDING_CAP prekey_ephemeral_keys entries
        let now = Instant::now();
        for i in 0..1050u32 {
            manager.prekey_ephemeral_keys.insert(
                (BareJid::parse(&format!("peer{}@test.com", i)).expect("expected valid JID"), DeviceId::from(i)),
                (vec![0u8; 32], now),
            );
        }
        assert_eq!(manager.prekey_ephemeral_keys.len(), 1050);

        manager.evict_stale_entries();

        assert_eq!(
            manager.prekey_ephemeral_keys.len(),
            OmemoManager::PENDING_CAP
        );
        Ok(())
    }
}
