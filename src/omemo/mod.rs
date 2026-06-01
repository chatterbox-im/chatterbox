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

use crate::omemo::crypto::CryptoError;
use crate::omemo::device_id::DeviceId;
use crate::omemo::session::{OmemoSession, SessionError};
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
mod lifecycle;
pub mod protocol;
pub mod session;
pub mod storage;
pub mod wire;

/// The OMEMO namespace used in XMPP stanzas
pub const OMEMO_NAMESPACE: &str = "eu.siacs.conversations.axolotl";

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

    /// Active sessions with other devices
    pub(crate) sessions: HashMap<(String, u32), OmemoSession>,

    /// PreKey rotation configuration
    pub prekey_rotation_config: PreKeyRotationConfig,

    /// Set of devices that need fresh session establishment after reset
    pub pending_session_rebuilds: HashSet<(String, DeviceId)>,

    /// Devices that we've reset sessions with and need to send PreKey messages to.
    /// Value is the time when the entry was added (for TTL eviction).
    pub pending_prekey_sends: HashMap<(String, DeviceId), Instant>,

    /// Ephemeral keys for pending PreKey messages to specific devices.
    /// Value is (key_bytes, insertion_time) for TTL eviction.
    pub(crate) prekey_ephemeral_keys: HashMap<(String, DeviceId), (Vec<u8>, Instant)>,

    /// Remote device PreKey IDs captured during session creation:
    /// (jid, device_id) → (signed_pre_key_id, Option<one_time_pre_key_id>, insertion_time)
    pub(crate) remote_prekey_ids: HashMap<(String, DeviceId), (u32, Option<u32>, Instant)>,

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
                    .store_device_id(id)
                    .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                drop(storage_guard);

                device_id::save_device_id(id).map_err(|e| {
                    OmemoError::StorageError(format!(
                        "Failed to save device ID to filesystem: {}",
                        e
                    ))
                })?;

                id
            }
            None => {
                // Use the device ID from OmemoStorage (already loaded from the correct path)
                let storage_guard = storage.lock().await;
                let storage_device_id = storage_guard.get_device_id();
                drop(storage_guard);

                if storage_device_id > 0 {
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
            pending_session_rebuilds: HashSet::new(),
            pending_prekey_sends: HashMap::new(),
            prekey_ephemeral_keys: HashMap::new(),
            remote_prekey_ids: HashMap::new(),
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

    /// Maximum age for pending prekey entries before eviction (1 hour).
    const PENDING_TTL_SECS: u64 = 3600;
    /// Maximum entries in pending collections before forced eviction.
    const PENDING_CAP: usize = 1000;

    /// Evict stale entries from bounded collections.
    /// Call periodically (e.g., before each encrypt) to prevent unbounded growth.
    pub fn evict_stale_entries(&mut self) {
        use std::time::Duration;
        let ttl = Duration::from_secs(Self::PENDING_TTL_SECS);
        let now = Instant::now();

        self.pending_prekey_sends
            .retain(|_, inserted| now.duration_since(*inserted) < ttl);
        self.prekey_ephemeral_keys
            .retain(|_, (_, inserted)| now.duration_since(*inserted) < ttl);
        self.remote_prekey_ids
            .retain(|_, (_, _, inserted)| now.duration_since(*inserted) < ttl);

        // Hard cap: if still over limit, drop oldest entries
        if self.pending_prekey_sends.len() > Self::PENDING_CAP {
            let mut entries: Vec<_> = self.pending_prekey_sends.drain().collect();
            entries.sort_by_key(|(_, t)| *t);
            entries.truncate(Self::PENDING_CAP);
            self.pending_prekey_sends = entries.into_iter().collect();
        }
    }

    /// Normalize a JID to bare JID (without resource) for OMEMO session storage
    pub(crate) fn normalize_jid_to_bare(jid: &str) -> String {
        let clean_jid = jid.to_lowercase().trim().to_string();

        if let Some(slash_pos) = clean_jid.rfind('/') {
            clean_jid[..slash_pos].to_string()
        } else {
            clean_jid
        }
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
        assert!(device_id > 0, "Device ID should be non-zero");

        let device_id2 = generate_device_id();
        assert!(device_id2 > 0, "Second device ID should be non-zero");
        assert_ne!(
            device_id, device_id2,
            "Two generated device IDs should likely be different"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_omemo_manager_device_id() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;

        let manager =
            OmemoManager::new(storage, "test@example.com".to_string(), None, test_pubsub())
                .await
                .expect("Failed to create OmemoManager");

        let device_id = manager.get_device_id();
        assert!(device_id > 0, "Manager's device ID should be non-zero");

        let storage_path = std::env::temp_dir().join("omemo_device_id_test.db");
        if storage_path.exists() {
            std::fs::remove_file(&storage_path)?;
        }

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
            device_id1 > 0,
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

        if storage_path.exists() {
            std::fs::remove_file(&storage_path)?;
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_explicit_device_id() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;

        let explicit_id: DeviceId = 12345;
        let manager = OmemoManager::new(
            storage,
            "test@example.com".to_string(),
            Some(explicit_id),
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

        // Insert an entry with a fake old timestamp (simulate expired)
        let old_time = Instant::now() - std::time::Duration::from_secs(7200); // 2 hours ago
        let fresh_time = Instant::now();

        manager
            .pending_prekey_sends
            .insert(("old@peer.com".to_string(), 1u32), old_time);
        manager
            .pending_prekey_sends
            .insert(("fresh@peer.com".to_string(), 2u32), fresh_time);
        manager.prekey_ephemeral_keys.insert(
            ("old@peer.com".to_string(), 1u32),
            (vec![0xAA; 32], old_time),
        );
        manager
            .remote_prekey_ids
            .insert(("old@peer.com".to_string(), 1u32), (1, Some(2), old_time));

        assert_eq!(manager.pending_prekey_sends.len(), 2);
        manager.evict_stale_entries();

        assert_eq!(manager.pending_prekey_sends.len(), 1);
        assert!(manager
            .pending_prekey_sends
            .contains_key(&("fresh@peer.com".to_string(), 2u32)));
        assert!(manager.prekey_ephemeral_keys.is_empty());
        assert!(manager.remote_prekey_ids.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_evict_stale_entries_cap() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;
        let mut manager =
            OmemoManager::new(storage, "cap@test.com".to_string(), Some(99), test_pubsub()).await?;

        // Insert more than PENDING_CAP entries, all fresh
        let now = Instant::now();
        for i in 0..1050u32 {
            manager
                .pending_prekey_sends
                .insert((format!("peer{}@test.com", i), DeviceId::from(i)), now);
        }
        assert_eq!(manager.pending_prekey_sends.len(), 1050);

        manager.evict_stale_entries();

        assert_eq!(
            manager.pending_prekey_sends.len(),
            OmemoManager::PENDING_CAP
        );
        Ok(())
    }
}
