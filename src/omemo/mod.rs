// src/omemo/mod.rs
//! OMEMO encryption module
//!
//! This module implements the OMEMO encryption protocol (XEP-0384) for XMPP.
//! OMEMO provides end-to-end encryption with the Double Ratchet algorithm.

use anyhow::Result;
use thiserror::Error;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use async_trait::async_trait;

use crate::omemo::storage::OmemoStorage;
pub use crate::omemo::storage::TrustLevel;
use crate::omemo::session::{OmemoSession, SessionError};
use crate::omemo::crypto::CryptoError;
use crate::omemo::device_id::DeviceId;

pub mod crypto;
pub mod protocol;
pub mod session;
pub mod storage;
pub mod device_id;
pub mod bundle;
pub mod device_discovery;
pub mod wire;
mod encrypt;
mod decrypt;
mod lifecycle;

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
    async fn publish_item(&self, to: Option<&str>, node: &str, id: &str, payload: &str) -> Result<()>;

    /// Publish using alternative XML format (fallback for servers that reject standard format)
    async fn publish_item_alternative(&self, to: Option<&str>, node: &str, id: &str, payload: &str) -> Result<()>;

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
    
    /// Set of devices that we've reset sessions with and need to send PreKey messages to
    pub pending_prekey_sends: HashSet<(String, DeviceId)>,
    
    /// Ephemeral keys for pending PreKey messages to specific devices
    pub(crate) prekey_ephemeral_keys: HashMap<(String, DeviceId), Vec<u8>>,

    /// Remote device PreKey IDs captured during session creation:
    /// (jid, device_id) → (signed_pre_key_id, Option<one_time_pre_key_id>)
    pub(crate) remote_prekey_ids: HashMap<(String, DeviceId), (u32, Option<u32>)>,

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
        
        // Determine the device ID
        let device_id = match device_id {
            Some(id) => {
                info!("Using explicitly provided device ID: {}", id);
                
                let mut storage_guard = storage.lock().await;
                storage_guard.store_device_id(id)
                    .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                drop(storage_guard);
                
                device_id::save_device_id(id)
                    .map_err(|e| OmemoError::StorageError(format!("Failed to save device ID to filesystem: {}", e)))?;
                
                id
            },
            None => {
                match device_id::load_or_generate_device_id() {
                    Ok((id, was_generated)) => {
                        if was_generated {
                            info!("Generated new device ID: {}", id);
                        } else {
                            info!("Loaded existing device ID: {}", id);
                        }
                        
                        let mut storage_guard = storage.lock().await;
                        storage_guard.store_device_id(id)
                            .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                        drop(storage_guard);
                        
                        id
                    },
                    Err(e) => {
                        warn!("Failed to load/generate device ID from file: {}, falling back to database", e);
                        
                        let mut storage_guard = storage.lock().await;
                        let db_device_id = storage_guard.get_device_id();
                        
                        if db_device_id > 0 {
                            info!("Using existing device ID from database: {}", db_device_id);
                            db_device_id
                        } else {
                            let id = device_id::generate_device_id();
                            info!("Generated new device ID: {}", id);
                            
                            storage_guard.store_device_id(id)
                                .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                            
                            id
                        }
                    }
                }
            }
        };
        
        info!("Initializing OMEMO manager for {} with device ID {}", local_jid, device_id);
        
        let mut manager = Self {
            storage: storage.clone(),
            device_id,
            local_jid,
            key_bundle: None,
            sessions: HashMap::new(),
            prekey_rotation_config: PreKeyRotationConfig::default(),
            pending_session_rebuilds: HashSet::new(),
            pending_prekey_sends: HashSet::new(),
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
                },
                Err(e) => {
                    warn!("Failed to load PreKey rotation time: {}, using default", e);
                    0
                }
            }
        };
        manager.prekey_rotation_config.last_rotation = last_rotation;
        
        // Initialize the key bundle with the persistent identity key
        manager.initialize_key_bundle_with_persistent_identity().await?;
        
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
        async fn publish_item(&self, _to: Option<&str>, _node: &str, _id: &str, _payload: &str) -> Result<()> {
            Ok(())
        }
        async fn publish_item_alternative(&self, _to: Option<&str>, _node: &str, _id: &str, _payload: &str) -> Result<()> {
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
        assert_ne!(device_id, device_id2, "Two generated device IDs should likely be different");
    }

    #[tokio::test]
    #[ignore]
    async fn test_omemo_manager_device_id() -> Result<(), anyhow::Error> {
        let storage = create_test_storage().await?;
        
        let manager = OmemoManager::new(storage, "test@example.com".to_string(), None, test_pubsub()).await
            .expect("Failed to create OmemoManager");
        
        let device_id = manager.get_device_id();
        assert!(device_id > 0, "Manager's device ID should be non-zero");
        
        let storage_path = std::env::temp_dir().join("omemo_device_id_test.db");
        if storage_path.exists() {
            std::fs::remove_file(&storage_path)?;
        }
        
        let storage1 = OmemoStorage::new(Some(storage_path.clone()))?;
        let manager1 = OmemoManager::new(storage1, "test@example.com".to_string(), None, test_pubsub()).await
            .expect("Failed to create first manager");
        
        let device_id1 = manager1.get_device_id();
        assert!(device_id1 > 0, "First manager's device ID should be non-zero");
        
        let storage2 = OmemoStorage::new(Some(storage_path.clone()))?;
        let manager2 = OmemoManager::new(storage2, "test@example.com".to_string(), None, test_pubsub()).await
            .expect("Failed to create second manager");
        
        let device_id2 = manager2.get_device_id();
        assert_eq!(device_id1, device_id2, "Device ID should persist in storage");
        
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
        let manager = OmemoManager::new(storage, "test@example.com".to_string(), Some(explicit_id), test_pubsub()).await
            .expect("Failed to create OmemoManager with explicit ID");
        
        let device_id = manager.get_device_id();
        assert_eq!(device_id, explicit_id, "Manager should use the explicitly provided device ID");
        
        Ok(())
    }
}
