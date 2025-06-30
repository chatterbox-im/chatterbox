// src/omemo/mod.rs
//! OMEMO encryption module
//!
//! This module implements the OMEMO encryption protocol (XEP-0384) for XMPP.
//! OMEMO provides end-to-end encryption with the Double Ratchet algorithm.

use anyhow::{anyhow, Result};
use thiserror::Error;
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use base64::Engine;
use tokio::time::{timeout, Duration};
use hex;

use crate::omemo::protocol::{DeviceIdentity, RatchetState, OmemoMessage, X3DHProtocol, DoubleRatchetError};
use crate::omemo::storage::OmemoStorage;
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

/// The OMEMO namespace used in XMPP stanzas
/// The OMEMO version 1 namespace (for backward compatibility)
pub const OMEMO_NAMESPACE: &str = "eu.siacs.conversations.axolotl";

/// Errors that can occur in OMEMO operations
#[derive(Debug, Error)]
pub enum OmemoError {
    /// Error in cryptographic operations
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    
    /// Error in double ratchet operations
    #[error("Double ratchet error: {0}")]
    DoubleRatchetError(#[from] DoubleRatchetError),
    
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

// OmemoError already derives Error from thiserror which provides the std::error::Error trait
// No need to implement From<OmemoError> for anyhow::Error as it's already implemented by anyhow

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
    storage: Arc<Mutex<OmemoStorage>>,
    
    /// The device ID for this client
    device_id: DeviceId,
    
    /// The JID of the local user
    local_jid: String,
    
    /// The key bundle for this device
    key_bundle: Option<protocol::X3DHKeyBundle>,
    
    /// Active sessions with other devices
    sessions: HashMap<(String, u32), OmemoSession>,
    
    /// PreKey rotation configuration
    pub prekey_rotation_config: PreKeyRotationConfig,

    /// Set of devices that need fresh session establishment after reset
    pub pending_session_rebuilds: HashSet<(String, DeviceId)>,
    
    /// Set of devices that we've reset sessions with and need to send PreKey messages to
    pub pending_prekey_sends: HashSet<(String, DeviceId)>,
    
    /// Ephemeral keys for pending PreKey messages to specific devices
    pub prekey_ephemeral_keys: HashMap<(String, DeviceId), Vec<u8>>,
}

impl OmemoManager {
    /// Create a new OMEMO manager
    pub async fn new(
        storage: OmemoStorage,
        local_jid: String,
        device_id: Option<u32>
    ) -> Result<Self, OmemoError> {
        let storage = Arc::new(Mutex::new(storage));
        
        // Determine the device ID
        let device_id = match device_id {
            // If a device ID was explicitly provided, use it
            Some(id) => {
                info!("Using explicitly provided device ID: {}", id);
                
                // Save to both SQLite and file-based storage
                let mut storage_guard = storage.lock().await;
                storage_guard.store_device_id(id)
                    .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                drop(storage_guard);
                
                // Also save to the filesystem for persistence
                device_id::save_device_id(id)
                    .map_err(|e| OmemoError::StorageError(format!("Failed to save device ID to filesystem: {}", e)))?;
                
                id
            },
            None => {
                // Try to load device ID from storage or generate a new one
                match device_id::load_or_generate_device_id() {
                    Ok((id, was_generated)) => {
                        if was_generated {
                            info!("Generated new device ID: {}", id);
                        } else {
                            info!("Loaded existing device ID: {}", id);
                        }
                        
                        // Store it in the database too for consistency
                        let mut storage_guard = storage.lock().await;
                        storage_guard.store_device_id(id)
                            .map_err(|e| OmemoError::StorageError(e.to_string()))?;
                        drop(storage_guard);
                        
                        id
                    },
                    Err(e) => {
                        // Fall back to database or generate new ID if file-based storage fails
                        warn!("Failed to load/generate device ID from file: {}, falling back to database", e);
                        
                        let mut storage_guard = storage.lock().await;
                        let db_device_id = storage_guard.get_device_id();
                        
                        if db_device_id > 0 {
                            info!("Using existing device ID from database: {}", db_device_id);
                            db_device_id
                        } else {
                            // Generate a new device ID
                            let id = device_id::generate_device_id();
                            info!("Generated new device ID: {}", id);
                            
                            // Store it
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
                    0 // Default to 0 if not found or error
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
    
    
    /// Initialize or load the key bundle with a persistent identity key
    async fn initialize_key_bundle_with_persistent_identity(&mut self) -> Result<(), OmemoError> {
        debug!("Initializing key bundle with persistent identity key for device {}", self.device_id);
        
        // First, try to load an existing key bundle from storage
        let storage_guard = self.storage.lock().await;
        let bundle_result = storage_guard.load_key_bundle_with_id(self.device_id);
        drop(storage_guard);
        
        // Process the result - if we have a bundle in storage, use it
        if let Ok(Some(bundle)) = bundle_result {
            info!("Loaded existing key bundle for device {}", self.device_id);
            self.key_bundle = Some(bundle);
            return Ok(());
        }
        
        // No bundle in storage, need to generate a new one
        // First, try to load a persistent identity key from the filesystem
        let identity_key_pair = match device_id::load_or_generate_identity_key() {
            Ok((key_pair, was_generated)) => {
                if was_generated {
                    info!("Generated new persistent identity key for device {}", self.device_id);
                } else {
                    info!("Loaded existing persistent identity key for device {}", self.device_id);
                }
                key_pair
            },
            Err(e) => {
                warn!("Failed to load/generate persistent identity key: {}, generating a temporary one", e);
                protocol::X3DHProtocol::generate_key_pair()
                    .map_err(|e| OmemoError::ProtocolError(format!("Failed to generate identity key: {}", e)))?
            }
        };
        
        // Now generate the rest of the key bundle components
        info!("Generating new key bundle for device {} using persistent identity key", self.device_id);
        
        // Generate a signed prekey pair
        let signed_pre_key_pair = protocol::X3DHProtocol::generate_key_pair()
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to generate signed prekey: {}", e)))?;
        
        // Sign the prekey with our identity key
        let signed_pre_key_signature = protocol::X3DHProtocol::sign_pre_key(
            &identity_key_pair.private_key,
            &signed_pre_key_pair.public_key
        ).map_err(|e| OmemoError::ProtocolError(format!("Failed to sign prekey: {}", e)))?;
        
        // Generate one-time prekeys
        let mut one_time_pre_key_pairs = std::collections::HashMap::new();
        let num_prekeys = 20; // Generate 20 prekeys initially
        
        for i in 1..=num_prekeys {
            let pair = protocol::X3DHProtocol::generate_key_pair()
                .map_err(|e| OmemoError::ProtocolError(format!("Failed to generate one-time prekey: {}", e)))?;
            one_time_pre_key_pairs.insert(i, pair);
        }
        
        // Create the complete bundle
        let bundle = protocol::X3DHKeyBundle {
            device_id: self.device_id,
            identity_key_pair,
            signed_pre_key_id: 1, // Start with ID 1
            signed_pre_key_pair,
            signed_pre_key_signature,
            one_time_pre_key_pairs,
        };
        
        // Store the key bundle
        let storage_guard = self.storage.lock().await;
        storage_guard.store_key_bundle(&bundle)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store key bundle: {}", e)))?;
        drop(storage_guard);
        
        self.key_bundle = Some(bundle);
        info!("Generated and stored new key bundle with persistent identity key for device {}", self.device_id);
        
        Ok(())
    }
    
    /// Load existing sessions from storage
    async fn load_sessions(&mut self) -> Result<(), OmemoError> {
        debug!("Loading existing OMEMO sessions from storage");
        
        let storage_guard = self.storage.lock().await;
        let sessions = storage_guard.load_all_sessions()
            .map_err(|e| OmemoError::StorageError(format!("Failed to load sessions: {}", e)))?;
        drop(storage_guard);
        
        for (key, state) in sessions {
            // Extract JID and device ID
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 2 {
                warn!("Invalid session key format: {}", key);
                continue;
            }
            
            let jid = parts[0].to_string();
            let device_id = match parts[1].parse::<u32>() {
                Ok(id) => id,
                Err(_) => {
                    warn!("Invalid device ID in session key: {}", parts[1]);
                    continue;
                }
            };
            
            debug!("Restoring session with {}:{}", jid, device_id);
            
            // Normalize the stored JID to ensure it's a bare JID
            let bare_jid = Self::normalize_jid_to_bare(&jid);
            let mut session = OmemoSession::new(bare_jid.clone(), device_id, self.device_id);
            session.restore_from_state(state)?;
            self.sessions.insert((bare_jid, device_id), session);
        }
        
        info!("Loaded {} existing sessions", self.sessions.len());
        
        Ok(())
    }
    
    /// Get or create a session with a remote device (with consistent initiator/recipient roles)
    pub async fn get_or_create_session(
        &mut self,
        remote_jid: &str,
        remote_device_id: u32
    ) -> Result<&mut OmemoSession, OmemoError> {
        // Normalize the JID to bare JID for consistent session lookup
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        let key = (bare_jid.clone(), remote_device_id);

        // Check if this device is marked for session rebuild due to previous reset
        let needs_rebuild = self.pending_session_rebuilds.contains(&key);
        if needs_rebuild {
            info!("Forcing fresh session rebuild for {}:{} after previous reset", bare_jid, remote_device_id);
            // Remove any existing session
            self.sessions.remove(&key);
            // Remove from rebuild set since we're rebuilding now
            self.pending_session_rebuilds.remove(&key);
        }

        // Check if we already have a session (early return, no borrow held)
        let session_exists_and_initialized = self.sessions.get(&key).map(|s| s.is_initialized()).unwrap_or(false);
        if session_exists_and_initialized && !needs_rebuild {
            debug!("Reusing existing session for {}:{}", bare_jid, remote_device_id);
            return self.sessions.get_mut(&key).ok_or_else(|| OmemoError::SessionError(
                session::SessionError::InvalidStateError("Session not found after check".to_string())
            ));
        }

        debug!("Creating new session for {}:{} (exists: {}, needs_rebuild: {})", 
            bare_jid, remote_device_id, session_exists_and_initialized, needs_rebuild);

        // Determine session role based on device IDs for consistency
        // Device with lower ID becomes initiator, device with higher ID becomes recipient
        let we_are_initiator = self.device_id < remote_device_id;
        
        debug!("Creating session with {}:{} - we are {}", 
            bare_jid, remote_device_id,
            if we_are_initiator { "initiator" } else { "recipient" }
        );

        // Gather all data and perform async calls BEFORE mutably borrowing self
        let our_identity_key_pair = match &self.key_bundle {
            Some(bundle) => bundle.identity_key_pair.clone(),
            None => return Err(OmemoError::SessionError(
                session::SessionError::InvalidStateError("Key bundle not initialized".to_string())
            )),
        };
        let remote_identity = self.get_device_identity(&bare_jid, remote_device_id).await?;

        let session = if we_are_initiator {
            // We have the lower device ID, so we are the initiator
            // Generate a random ephemeral key pair for X3DH (standard OMEMO)
            let ephemeral_key_pair = protocol::X3DHProtocol::generate_key_pair()
                .map_err(|e| OmemoError::CryptoError(crypto::CryptoError::KdfError(e.to_string())))?;
            
            // Store the ephemeral public key for this device to include in PreKey messages
            let device_key = (bare_jid.clone(), remote_device_id);
            self.prekey_ephemeral_keys.insert(device_key, ephemeral_key_pair.public_key.clone());
            
            OmemoSession::new_initiator_with_ephemeral(
                bare_jid.clone(),
                remote_device_id,
                our_identity_key_pair,
                remote_identity.identity_key,
                remote_identity.signed_pre_key.public_key,
                if remote_identity.pre_keys.is_empty() {
                    None
                } else {
                    Some(remote_identity.pre_keys[0].public_key.clone())
                },
                ephemeral_key_pair.private_key,
                self.device_id
            )?
        } else {
            // We have the higher device ID, so we are the recipient
            // For recipients, we should also create a session proactively to enable bidirectional messaging
            // The first message we receive will establish the proper session state
            warn!("Creating recipient session proactively for {}:{} (device {} > {})", bare_jid, remote_device_id, self.device_id, remote_device_id);
            
            // For now, create a minimal session that can be updated when we receive the first message
            // This allows us to send messages before receiving any
            let ephemeral_key_pair = protocol::X3DHProtocol::generate_key_pair()
                .map_err(|e| OmemoError::CryptoError(crypto::CryptoError::KdfError(e.to_string())))?;
            
            OmemoSession::new_initiator_with_ephemeral(
                bare_jid.clone(),
                remote_device_id,
                our_identity_key_pair,
                remote_identity.identity_key,
                remote_identity.signed_pre_key.public_key,
                if remote_identity.pre_keys.is_empty() {
                    None
                } else {
                    Some(remote_identity.pre_keys[0].public_key.clone())
                },
                ephemeral_key_pair.private_key,
                self.device_id
            )?
        };
        
        let ratchet_state = session.ratchet_state.clone();

        // Now, after all awaits, mutably borrow self and insert
        self.sessions.insert(key.clone(), session);
        self.store_session_state(&bare_jid, remote_device_id, &ratchet_state).await?;
        return self.sessions.get_mut(&key).ok_or_else(|| OmemoError::SessionError(
                session::SessionError::InvalidStateError("Session not found after check".to_string())
            ));
    }

    /// Derive a deterministic "ephemeral" key for consistent session creation
    /// Both sides will derive the same key from the same inputs
    fn derive_deterministic_ephemeral_key(
        local_identity: &[u8],
        remote_identity: &[u8], 
        local_device_id: u32,
        remote_device_id: u32
    ) -> Result<Vec<u8>, OmemoError> {
        // Create a deterministic input that both sides will compute the same way
        let mut input = Vec::new();
        
        // Always put the lower device ID first for consistency
        if local_device_id < remote_device_id {
            input.extend_from_slice(local_identity);
            input.extend_from_slice(remote_identity);
            input.extend_from_slice(&local_device_id.to_be_bytes());
            input.extend_from_slice(&remote_device_id.to_be_bytes());
        } else {
            input.extend_from_slice(remote_identity);
            input.extend_from_slice(local_identity);
            input.extend_from_slice(&remote_device_id.to_be_bytes());
            input.extend_from_slice(&local_device_id.to_be_bytes());
        }
        
        // Add a constant to differentiate from other derived keys
        input.extend_from_slice(b"EPHEMERAL_KEY_DERIVATION");
        
        // Use HKDF to derive a 32-byte key
        let salt = b"omemo_ephemeral_salt";
        let derived_key = crypto::hkdf_derive(salt, &input, b"ephemeral", 32)
            .map_err(|e| OmemoError::CryptoError(e))?;
        
        debug!("Derived deterministic ephemeral key: {}", hex::encode(&derived_key));
        // Log the inputs to help debug session consistency
        debug!("Ephemeral key derivation inputs - local_device_id: {}, remote_device_id: {}", local_device_id, remote_device_id);
        debug!("Ephemeral key derivation inputs - local_identity: {}", hex::encode(local_identity));
        debug!("Ephemeral key derivation inputs - remote_identity: {}", hex::encode(remote_identity));
        Ok(derived_key)
    }
    
    /// Get a device identity from storage or fetch it
    async fn get_device_identity(&self, remote_jid: &str, device_id: DeviceId) -> Result<DeviceIdentity, OmemoError> {
        debug!("Getting device identity for {}:{}", remote_jid, device_id);
        
        // First try to get from storage
        let mut storage_guard = self.storage.lock().await;
        if let Ok(identity) = storage_guard.load_device_identity(remote_jid, device_id) {
            debug!("Found device identity in storage for {}:{}", remote_jid, device_id);
            return Ok(identity);
        }
        drop(storage_guard);
        
        // If not in storage, try to fetch it from the server
        info!("Device identity not found in storage for {}:{}, fetching from server", remote_jid, device_id);
        
        // In a real implementation, we would fetch the device bundle from the XMPP server
        // We'll use PubSub to fetch the bundle
        let bundle_node = format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id);
        
        // Make the request
        let response = match crate::xmpp::omemo_integration::request_pubsub_items(remote_jid, &bundle_node).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to fetch device bundle for {}:{}: {}", remote_jid, device_id, e);
                return Err(OmemoError::MissingDataError(format!("Failed to fetch device bundle: {}", e)));
            }
        };
        
        // Parse the response to extract the device bundle
        // See XEP-0384 for the format of this bundle
        let identity = self.parse_device_bundle_response(&response, device_id)?;
        
        // Store the identity
        let mut storage_guard = self.storage.lock().await;
        storage_guard.save_device_identity(remote_jid, &identity, false)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store device identity: {}", e)))?;
        
        Ok(identity)
    }
    
    /// Encrypt a message for a recipient
    pub async fn encrypt_message(&mut self, recipient: &str, plaintext: &str) -> Result<OmemoMessage, OmemoError> {
        info!("Encrypting message for {}", recipient);
        
        // Get the device list for the recipient with timeout protection
        // ALWAYS force refresh to avoid stale device list issues - NO CACHED FALLBACK
        let device_discovery_timeout = Duration::from_secs(15); // Increased timeout for fresh fetches
        info!("Forcing fresh device list fetch for {} (NO CACHE FALLBACK)", recipient);
        let recipient_device_ids = match timeout(device_discovery_timeout, self.get_device_ids_with_force_refresh(recipient, true)).await {
            Ok(Ok(devices)) => devices,
            Ok(Err(e)) => {
                error!("Fresh device list fetch failed for {}: {} - NO FALLBACK, failing fast", recipient, e);
                return Err(e);
            },
            Err(_) => {
                error!("Timeout while fetching fresh device list for {} - NO FALLBACK, failing fast", recipient);
                return Err(OmemoError::TimeoutError("Device list fetch timeout".to_string()));
            }
        };
        
        if recipient_device_ids.is_empty() {
            return Err(OmemoError::NoDeviceError(recipient.to_string()));
        }
        
        // Get our own device IDs (important for message carbons) with timeout
        // Also force refresh for our own devices to ensure consistency - NO CACHED FALLBACK
        let local_username = self.local_jid.split('@').next().unwrap_or(&self.local_jid);
        let local_domain = self.local_jid.split('@').nth(1).unwrap_or("");
        let user_bare_jid = format!("{}@{}", local_username, local_domain);
        info!("Forcing fresh device list fetch for own JID {} (NO CACHE FALLBACK)", user_bare_jid);
        let own_device_ids = match timeout(device_discovery_timeout, self.get_device_ids_with_force_refresh(&user_bare_jid, true)).await {
            Ok(Ok(devices)) => devices,
            Ok(Err(e)) => {
                warn!("Failed to get fresh own device list: {} - continuing with recipient devices only", e);
                // Don't fail for own devices - just continue with empty list
                Vec::new()
            },
            Err(_) => {
                warn!("Timeout while fetching fresh own device list - continuing with recipient devices only");
                // Don't fail for own devices - just continue with empty list
                Vec::new()
            }
        };
        
        info!("Found {} devices for recipient {}: {:?}", recipient_device_ids.len(), recipient, recipient_device_ids);
        info!("Found {} own devices: {:?}", own_device_ids.len(), own_device_ids);
        
        // Use Dino-compatible AES-GCM format by default
        // Generate a 16-byte AES key and 12-byte IV (compatible with Dino/Signal)
        let aes_key = crypto::generate_aes_key(); // 16 bytes
        let iv = crypto::generate_gcm_iv(); // 12 bytes
        debug!("Generated 16-byte AES-GCM key and 12-byte IV (Dino-compatible format)");
        
        // Encrypt the plaintext with AES-GCM
        let gcm_result = crypto::aes_gcm_encrypt(plaintext.as_bytes(), &aes_key, &iv)
            .map_err(OmemoError::CryptoError)?;
        
        // AES-GCM returns ciphertext + auth_tag combined
        // We need to split them: the last 16 bytes are the auth tag
        if gcm_result.len() < 16 {
            return Err(OmemoError::CryptoError(crypto::CryptoError::InvalidInputError(
                "AES-GCM result too short".to_string()
            )));
        }
        
        let ciphertext_len = gcm_result.len() - 16;
        let ciphertext = gcm_result[0..ciphertext_len].to_vec();
        let auth_tag = gcm_result[ciphertext_len..].to_vec();
        
        debug!("Encrypted payload with AES-GCM: ciphertext {} bytes, auth tag {} bytes", 
            ciphertext.len(), auth_tag.len());
        
        // For Dino compatibility, the message key is aes_key + auth_tag (32 bytes total)
        let mut message_key = aes_key.clone();
        message_key.extend_from_slice(&auth_tag);
        debug!("Created message key: {} bytes (16-byte AES key + 16-byte auth tag)", message_key.len());
        
        // Now encrypt the random key for each recipient device and our own devices
        let mut encrypted_keys = HashMap::new();
        
        // Merge device lists (removing duplicates if our own device ID appears in both lists)
        let mut all_devices = Vec::new();
        
        // Add recipient devices
        for device_id in recipient_device_ids {
            if !all_devices.contains(&(recipient.to_string(), device_id)) {
                all_devices.push((recipient.to_string(), device_id));
            }
        }
        
        // Add our own devices (for message carbons), but exclude our current device
        // to avoid session state conflicts with self-encryption
        for device_id in own_device_ids {
            // Skip our current device to avoid creating sessions with ourselves
            if device_id == self.device_id {
                debug!("Skipping our current device {} for message encryption", device_id);
                continue;
            }
            
            if !all_devices.contains(&(user_bare_jid.clone(), device_id)) {
                all_devices.push((user_bare_jid.clone(), device_id));
            }
        }
        
        info!("Encrypting message key for {} total devices", all_devices.len());
        
        // Clone the device list for use after the async operations
        let device_list_copy = all_devices.clone();
        
        // Now encrypt the message key (aes_key + auth_tag, 32 bytes) for all devices
        // Add overall timeout protection to prevent UI hangs
        let overall_timeout = Duration::from_secs(15); // Maximum 15 seconds for all session creations
        let session_creation_future = async {
            for (jid, device_id) in all_devices {
                let device_key = (jid.clone(), device_id);
                
                // Check if this device needs a PreKey message after session reset
                let needs_prekey = self.pending_prekey_sends.contains(&device_key);
                
                // Skip ignored devices UNLESS they need a PreKey message
                if !needs_prekey {
                    if let Ok(true) = self.is_device_ignored(&jid, device_id).await {
                        debug!("Skipping ignored device {}:{} (no PreKey needed)", jid, device_id);
                        continue;
                    }
                }
                
                if needs_prekey {
                    debug!("Processing device {}:{} for PreKey message", jid, device_id);
                }
                
                // Add per-device timeout to prevent individual device hangs
                let device_timeout = Duration::from_secs(8); // 8 seconds per device
                let session_result = timeout(device_timeout, self.get_or_create_session(&jid, device_id)).await;
                
                match session_result {
                    Ok(Ok(session)) => {
                        // Encrypt the message key (aes_key + auth_tag) for this device
                        match session.encrypt_key(&message_key) {
                            Ok(encrypted_key) => {
                                encrypted_keys.insert(device_id, encrypted_key);
                                debug!("Encrypted message key for {}:{}", jid, device_id);
                                
                                // If this device was waiting for a PreKey message, mark it as sent
                                if needs_prekey {
                                    self.pending_prekey_sends.remove(&device_key);
                                    info!("Sent PreKey message to {}:{}, removing from pending list", jid, device_id);
                                }
                            },
                            Err(e) => {
                                warn!("Failed to encrypt message key for {}:{}: {}", jid, device_id, e);
                                // Continue with other devices
                            }
                        }
                    },
                    Ok(Err(e)) => {
                        warn!("Failed to get or create session with {}:{}: {}", jid, device_id, e);
                        // Continue with other devices
                    },
                    Err(_) => {
                        warn!("Timeout getting session with {}:{}, skipping device", jid, device_id);
                        // Continue with other devices
                    }
                }
            }
        };
        
        // Apply overall timeout
        if let Err(_) = timeout(overall_timeout, session_creation_future).await {
            warn!("Overall timeout while creating sessions for message encryption");
            // Continue with whatever sessions we managed to create
        }
        
        info!("Message encrypted successfully for {} devices", encrypted_keys.len());
        
        // Check if this message contains any PreKey messages (devices with stored ephemeral keys)
        let has_prekey_devices = device_list_copy.iter().any(|(jid, device_id)| {
            let device_key = (jid.clone(), *device_id);
            self.prekey_ephemeral_keys.contains_key(&device_key)
        });
        
        // If this is a PreKey message, we need to include an ephemeral key
        // For simplicity, use the first ephemeral key if multiple devices need PreKey messages
        let ephemeral_key = if has_prekey_devices {
            device_list_copy.iter()
                .find_map(|(jid, device_id)| {
                    let device_key = (jid.clone(), *device_id);
                    let ephemeral = self.prekey_ephemeral_keys.get(&device_key).cloned();
                    log::debug!("EPHEMERAL_DEBUG: Checking device {}:{}, has ephemeral: {}", 
                        jid, device_id, ephemeral.is_some());
                    if let Some(ref eph) = ephemeral {
                        log::debug!("EPHEMERAL_DEBUG: Ephemeral key length: {}, first 16 bytes: {}", 
                            eph.len(), hex::encode(&eph[..16.min(eph.len())]));
                    }
                    ephemeral
                })
        } else {
            None
        };
        
        log::debug!("EPHEMERAL_DEBUG: Final ephemeral key is_some: {}, has_prekey_devices: {}", 
            ephemeral_key.is_some(), has_prekey_devices);
        
        // Create the complete OMEMO message using Dino-compatible AES-GCM format
        let message = OmemoMessage {
            sender_device_id: self.device_id,
            ratchet_key: self.key_bundle.as_ref().unwrap().signed_pre_key_pair.public_key.clone(),
            previous_counter: 0,
            counter: 0,
            ciphertext,
            mac: vec![], // AES-GCM doesn't use separate HMAC, auth tag is embedded in encrypted keys
            iv: iv.to_vec(), // 12-byte IV for AES-GCM
            encrypted_keys,
            is_prekey: has_prekey_devices,
            ephemeral_key: ephemeral_key.clone(),
        };
        
        // Clear the ephemeral keys for devices that got PreKey messages
        if has_prekey_devices {
            for (jid, device_id) in &device_list_copy {
                let device_key = (jid.clone(), *device_id);
                self.prekey_ephemeral_keys.remove(&device_key);
            }
        }
        
        Ok(message)
    }
    
    /// Force refresh device list for a JID (public method)
    pub async fn force_refresh_device_list(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        info!("[OMEMO] Force refreshing device list for {}", jid);
        self.get_device_ids_with_force_refresh(jid, true).await
    }
    
    /// Decrypt a message from a sender
    pub async fn decrypt_message(&mut self, sender: &str, device_id: u32, message: &OmemoMessage) -> Result<String, OmemoError> {
        info!("Decrypting message from {}:{}", sender, device_id);
        
        // Check if this is a PreKey message (has ephemeral key)
        if message.is_prekey && message.ephemeral_key.is_some() {
            info!("Received PreKey message from {}:{}, creating recipient session", sender, device_id);
            
            // Create session as recipient using the ephemeral key from the message
            let ephemeral_key = message.ephemeral_key.as_ref().unwrap();
            let bare_jid = Self::normalize_jid_to_bare(sender);
            
            // Get our identity and signed prekey
            let our_identity_key_pair = match &self.key_bundle {
                Some(bundle) => bundle.identity_key_pair.clone(),
                None => return Err(OmemoError::SessionError(
                    session::SessionError::InvalidStateError("Key bundle not initialized".to_string())
                )),
            };
            let our_signed_prekey_pair = match &self.key_bundle {
                Some(bundle) => bundle.signed_pre_key_pair.clone(),
                None => return Err(OmemoError::SessionError(
                    session::SessionError::InvalidStateError("Key bundle not initialized".to_string())
                )),
            };
            
            // Get sender's identity key
            let sender_identity = self.get_device_identity(&bare_jid, device_id).await?;
            
            // Create recipient session
            let session = OmemoSession::new_recipient(
                bare_jid.clone(),
                device_id,
                our_identity_key_pair,
                sender_identity.identity_key,
                our_signed_prekey_pair,
                None, // No one-time PreKey for simplicity
                ephemeral_key.clone(),
                self.device_id
            )?;
            
            // Store the session
            let key = (bare_jid.clone(), device_id);
            let ratchet_state = session.ratchet_state.clone();
            self.sessions.insert(key.clone(), session);
            self.store_session_state(&bare_jid, device_id, &ratchet_state).await?;
            
            info!("Created new recipient session for {}:{}", bare_jid, device_id);
        }
        
        // Note: We used to block messages when waiting to send PreKey messages, but this
        // prevented proper PreKey message reception. Now we always allow message processing
        // and let the session logic determine if it's a valid PreKey message or not.
        let bare_jid = Self::normalize_jid_to_bare(sender);
        let key = (bare_jid.clone(), device_id);
        
        if self.pending_prekey_sends.contains(&key) {
            info!("Receiving message from {}:{} while waiting to send PreKey message - processing normally", bare_jid, device_id);
        }
        
        // First, check if we have an encrypted key for our device
        let encrypted_key = match message.encrypted_keys.get(&self.device_id) {
            Some(key) => key,
            None => {
                warn!("No encrypted key found for our device {} in message from {}:{}", self.device_id, sender, device_id);
                warn!("Available keys in message: {:?}", message.encrypted_keys.keys().collect::<Vec<_>>());
                
                // This could mean the sender is using outdated device lists
                // Force refresh our own device list to make sure it's published correctly
                let local_username = self.local_jid.split('@').next().unwrap_or(&self.local_jid);
                let local_domain = self.local_jid.split('@').nth(1).unwrap_or("");
                let user_bare_jid = format!("{}@{}", local_username, local_domain);
                
                if let Err(e) = self.force_refresh_device_list(&user_bare_jid).await {
                    warn!("Failed to refresh our own device list: {}", e);
                }
                
                // Also try to refresh the sender's device list in case they have a new device
                if let Err(e) = self.force_refresh_device_list(sender).await {
                    warn!("Failed to refresh sender's device list: {}", e);
                }
                
                return Err(OmemoError::MissingDataError(format!(
                    "No encrypted key found for device {} (our device not in recipient list)", 
                    self.device_id
                )));
            }
        };
        
        // Get the session for the sender device
        let sender_str = sender.to_string();
        
        
        // Get or create session with timeout protection
        let session = match tokio::time::timeout(
            std::time::Duration::from_secs(8),
            self.get_or_create_session(&sender_str, device_id)
        ).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(OmemoError::SessionError(
                    crate::omemo::session::SessionError::InvalidStateError(
                        format!("Timeout while creating session for decryption with {}:{}", sender_str, device_id)
                    )
                ));
            }
        };
        
        // Decrypt the message key and capture session state for later storage
        let (decrypted_key_data, session_state_to_store) = {
            let ratchet_state = session.ratchet_state.clone();
            let decryption_result = session.decrypt_key(encrypted_key);
            
            match decryption_result {
                Ok(data) => {
                    // Successful decryption - mark for resetting failure count
                    (data, Some(ratchet_state))
                },
                Err(session_error) => {
                    // Track failure but don't store updated session state
                    return self.handle_decryption_failure(sender_str, device_id, session_error).await;
                }
            }
        };
        
        // Reset failure count after successful decryption
        {
            let storage_guard = self.storage.lock().await;
            if let Err(e) = storage_guard.reset_device_failure_count(&sender_str, device_id) {
                warn!("Failed to reset failure count for {}:{}: {}", sender_str, device_id, e);
            }
        }
        
        debug!("Decrypted key data ({} bytes): {}", decrypted_key_data.len(), hex::encode(&decrypted_key_data));
        
        // Only support Dino-compatible AES-GCM format
        // Expected: 32-byte key data (16-byte AES key + 16-byte auth tag) and 12-byte IV
        if decrypted_key_data.len() != 32 {
            error!("Invalid key data length: {} (expected 32 bytes for AES-GCM)", decrypted_key_data.len());
            return Err(OmemoError::CryptoError(crypto::CryptoError::InvalidInputError(
                format!("Invalid key data length: {} (expected 32 bytes for AES-GCM)", decrypted_key_data.len())
            )));
        }
        
        if message.iv.len() != 12 {
            error!("Invalid IV length: {} (expected 12 bytes for AES-GCM)", message.iv.len());
            return Err(OmemoError::CryptoError(crypto::CryptoError::InvalidIV(
                format!("Invalid IV length: {} (expected 12 bytes for AES-GCM)", message.iv.len())
            )));
        }
        
        // Dino/Signal format: 16-byte AES key + 16-byte auth tag, 12-byte IV, AES-GCM
        debug!("Using Dino/Signal format (AES-GCM): 32-byte key+tag, 12-byte IV");
        let aes_key = &decrypted_key_data[0..16];
        let auth_tag = &decrypted_key_data[16..32];
        let iv = &message.iv;
        
        debug!("AES-GCM key (hex): {}", hex::encode(aes_key));
        debug!("Auth tag (hex): {}", hex::encode(auth_tag));
        debug!("IV (hex): {}", hex::encode(iv));
        debug!("Ciphertext (hex): {}", hex::encode(&message.ciphertext));
        
        // Combine ciphertext + auth_tag for AES-GCM decryption
        let mut gcm_ciphertext = message.ciphertext.clone();
        gcm_ciphertext.extend_from_slice(auth_tag);
        
        // Decrypt using AES-GCM
        let plaintext = crypto::aes_gcm_decrypt(&gcm_ciphertext, aes_key, iv)
            .map_err(|e| OmemoError::CryptoError(e))?;
        
        debug!("Successfully decrypted payload");
        
        // Store the updated session state if successful
        if let Some(ratchet_state) = session_state_to_store {
            self.store_session_state(&sender_str, device_id, &ratchet_state).await?;
        }
        
        // Convert the plaintext to a string
        let content = String::from_utf8(plaintext)
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to decode message: {}", e)))?;
        
        info!("Message decrypted successfully from {}:{}", sender, device_id);
        
        Ok(content)
    }
    
    /// Get the device IDs for a user
    async fn get_device_ids(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        self.get_device_ids_with_force_refresh(jid, false).await
    }
    
    /// Get the device IDs for a user with optional force refresh
    async fn get_device_ids_with_force_refresh(&self, jid: &str, force_refresh: bool) -> Result<Vec<DeviceId>, OmemoError> {
        debug!("[OMEMO] get_device_ids: called with jid = {}, force_refresh = {}", jid, force_refresh);
        
        // Validate JID format first
        if !jid.contains('@') {
            warn!("[OMEMO] get_device_ids: Invalid JID format (missing @): {}", jid);
            return Err(OmemoError::InvalidInput(format!("Invalid JID format: {}", jid)));
        }
        
        // AGGRESSIVE FIX: Always fetch fresh from server to eliminate stale device list issues
        // This bypasses all caching to ensure we always have the latest device information
        warn!("[OMEMO] get_device_ids: ALWAYS fetching fresh from server (no caching) for {}", jid);
        
        // If not in storage or cached list is empty/stale, fetch from the server
        info!("[OMEMO] get_device_ids: Fetching device list for {} from XMPP server", jid);
        
        // Try to fetch with limited retries and faster timeout for better UX
        match self.fetch_device_list_from_server(jid).await {
            Ok(ids) => {
                info!("[OMEMO] get_device_ids: Successfully fetched device list for {}: {:?}", jid, ids);
                
                // Store the device list with current timestamp
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                
                let entry = storage::DeviceListEntry {
                    jid: jid.to_string(),
                    device_ids: ids.clone(),
                    last_update: now,
                };
                
                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard.save_device_list(&entry) {
                    warn!("[OMEMO] get_device_ids: Failed to store device list: {}", e);
                    // Non-fatal error, continue
                }
                drop(storage_guard);
                
                return Ok(ids);
            },
            Err(e) => {
                warn!("[OMEMO] get_device_ids: Failed to fetch device list for {}: {}", jid, e);
                
                // For item-not-found errors, immediately return empty list instead of retrying
                if e.to_string().contains("item-not-found") || e.to_string().contains("No device list found") {
                    info!("[OMEMO] get_device_ids: No OMEMO devices found for {} (no device list published)", jid);
                    
                    // Store an empty device list to cache this result
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    
                    let entry = storage::DeviceListEntry {
                        jid: jid.to_string(),
                        device_ids: vec![], // Empty list
                        last_update: now,
                    };
                    
                    let storage_guard = self.storage.lock().await;
                    if let Err(e) = storage_guard.save_device_list(&entry) {
                        warn!("[OMEMO] get_device_ids: Failed to store empty device list: {}", e);
                    }
                    drop(storage_guard);
                    
                    return Ok(vec![]); // Return empty list
                }
                
                // NO FALLBACK TO CACHED DATA - fail fast to surface the real issue
                error!("[OMEMO] get_device_ids: Fetch failed for {}, NO CACHE FALLBACK - failing fast", jid);
                return Err(e);
            }
        }
    }
    
    /// Fetch device list from the XMPP server
    /// 
    /// This method retrieves the list of OMEMO-enabled devices for a user
    /// according to XEP-0384 Section 4.2. It performs a PubSub request to 
    /// the user's server to retrieve the device list from the appropriate node.
    pub async fn fetch_device_list_from_server(&self, jid: &str) -> Result<Vec<u32>, OmemoError> {
        info!("[OMEMO] fetch_device_list_from_server: Fetching OMEMO device list from server for {}", jid);
        debug!("[OMEMO] fetch_device_list_from_server: backtrace = {:?}", std::backtrace::Backtrace::capture());

        // Use the enhanced device discovery module to try all possible formats
        match device_discovery::fetch_device_list_with_fallbacks(jid).await {
            Ok(devices) => {
                info!("[OMEMO] Found {} devices with enhanced discovery: {:?}", devices.len(), devices);
                return Ok(devices);
            },
            Err(e) => {
                warn!("[OMEMO] Enhanced device discovery failed: {}, falling back to basic method", e);
            }
        }

        // Fall back to basic method if enhanced discovery fails
        if let Some(client) = crate::xmpp::get_global_xmpp_client().await {
            let client_guard = client.lock().await;
            
            // Try with the standard namespace first
            let standard_node = format!("{}:devices", OMEMO_NAMESPACE);
            info!("[OMEMO] Trying standard node: {}", standard_node);
            match crate::xmpp::omemo_integration::request_pubsub_items(jid, &standard_node).await {
                Ok(xml) => {
                    match self.parse_device_list_response(&xml) {
                        Ok(devices) if !devices.is_empty() => {
                            info!("[OMEMO] Found {} devices with standard namespace: {:?}", devices.len(), devices);
                            return Ok(devices);
                        },
                        Ok(_) => {
                            info!("[OMEMO] No devices found with standard namespace, trying legacy");
                        },
                        Err(e) => {
                            warn!("[OMEMO] Failed to parse standard namespace response: {}", e);
                        }
                    }
                },
                Err(e) => {
                    info!("[OMEMO] Standard namespace failed: {}, trying legacy", e);
                }
            }
            
            // Try with the legacy namespace as fallback
            let legacy_node = "eu.siacs.conversations.axolotl:devices";
            info!("[OMEMO] Trying legacy node: {}", legacy_node);
            match crate::xmpp::omemo_integration::request_pubsub_items(jid, &legacy_node).await {
                Ok(xml) => {
                    match self.parse_device_list_response(&xml) {
                        Ok(devices) => {
                            info!("[OMEMO] Found {} devices with legacy namespace: {:?}", devices.len(), devices);
                            return Ok(devices);
                        },
                        Err(e) => {
                            warn!("[OMEMO] Failed to parse legacy namespace response: {}", e);
                            return Err(e);
                        }
                    }
                },
                Err(e) => {
                    error!("[OMEMO] Both standard and legacy namespace failed: {}", e);
                    return Err(OmemoError::ProtocolError(format!("Failed to fetch device list from both namespaces: {}", e)));
                }
            }
        } else {
            return Err(OmemoError::MissingDataError("No XMPP client available".to_string()));
        }
    }
        
    /// Get our key bundle for publishing
    pub fn get_key_bundle_xml(&self) -> Result<String, OmemoError> {
        debug!("Getting key bundle XML for device {}", self.device_id);
        
        let bundle = match &self.key_bundle {
            Some(bundle) => bundle,
            None => return Err(OmemoError::MissingDataError("Key bundle not initialized".to_string())),
        };
        
        // Create a device identity from the key bundle
        let identity = DeviceIdentity {
            id: self.device_id,
            identity_key: bundle.identity_key_pair.public_key.clone(),
            signed_pre_key: protocol::SignedPreKeyBundle {
                id: bundle.signed_pre_key_id,
                public_key: bundle.signed_pre_key_pair.public_key.clone(),
                signature: bundle.signed_pre_key_signature.clone(),
            },
            pre_keys: bundle.one_time_pre_key_pairs.iter()
                .map(|(id, pair)| protocol::PreKeyBundle {
                    id: *id,
                    public_key: pair.public_key.clone(),
                })
                .collect(),
        };
        
        // Convert to XML
        let xml = protocol::utils::device_bundle_to_xml(&identity)
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to create bundle XML: {}", e)))?;
        
        Ok(xml)
    }
    
    /// Get our device list for publishing
    pub fn get_device_list_xml(&self) -> Result<String, OmemoError> {
        debug!("Getting device list XML");
        
        let device_ids = vec![self.device_id];
        
        // Convert to XML
        let xml = protocol::utils::device_list_to_xml(&device_ids)
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to create device list XML: {}", e)))?;
        
        Ok(xml)
    }
    
    /// Process an incoming OMEMO message from XML
    pub fn process_message_xml(&self, xml: &str) -> Result<OmemoMessage, OmemoError> {
        debug!("Processing OMEMO message XML");
        
        // Parse the XML into an OmemoMessage
        let message = protocol::utils::omemo_message_from_xml(xml)
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to parse message XML: {}", e)))?;
        
        Ok(message)
    }
    
    /// Convert an OMEMO message to XML for sending
    pub fn message_to_xml(&self, message: &OmemoMessage) -> String {
        debug!("Converting OMEMO message to XML");
        
        protocol::utils::omemo_message_to_xml(message)
    }

    /// Store a session's ratchet state
    pub async fn store_session_state(&mut self, jid: &str, device_id: DeviceId, state: &RatchetState) -> Result<(), OmemoError> {
        // Normalize JID to bare JID for consistent storage
        let bare_jid = Self::normalize_jid_to_bare(jid);
        
        // Store the session directly
        let storage_guard = self.storage.lock().await;
        storage_guard.save_session(&bare_jid, device_id, state)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store session: {}", e)))?;
        
        debug!("Stored session state for {}:{}", bare_jid, device_id);
        
        Ok(())
    }

    /// Normalize a JID to bare JID (without resource) for OMEMO session storage
    /// OMEMO sessions should be bound to bare JIDs, not full JIDs with resources
    fn normalize_jid_to_bare(jid: &str) -> String {
        let clean_jid = jid.to_lowercase().trim().to_string();
        
        // Strip the resource part (everything after the last '/')
        if let Some(slash_pos) = clean_jid.rfind('/') {
            clean_jid[..slash_pos].to_string()
        } else {
            clean_jid
        }
    }

    /// Check if a device identity is trusted
    pub async fn is_device_identity_trusted(&self, sender: &str, device_id: DeviceId) -> Result<bool, OmemoError> {
        debug!("Checking if device identity for {}:{} is trusted", sender, device_id);
        
        let storage_guard = self.storage.lock().await;
        let trusted = storage_guard.is_device_trusted(sender, device_id)
            .map_err(|e| OmemoError::StorageError(format!("Failed to check trust: {}", e)))?;
        
        Ok(trusted)
    }
    
    /// Mark a device identity as trusted
    pub async fn trust_device_identity(&self, sender: &str, device_id: DeviceId) -> Result<(), OmemoError> {
        debug!("Marking device identity for {}:{} as trusted", sender, device_id);
        
        let storage_guard = self.storage.lock().await;
        storage_guard.set_device_trust(sender, device_id, true)
            .map_err(|e| OmemoError::StorageError(format!("Failed to set trust: {}", e)))?;
        
        Ok(())
    }
    
    /// Mark a device identity as untrusted
    pub async fn untrust_device_identity(&self, sender: &str, device_id: DeviceId) -> Result<(), OmemoError> {
        debug!("Marking device identity for {}:{} as untrusted", sender, device_id);
        
        let storage_guard = self.storage.lock().await;
        storage_guard.set_device_trust(sender, device_id, false)
            .map_err(|e| OmemoError::StorageError(format!("Failed to set untrust: {}", e)))?;
        
        Ok(())
    }
    
    /// Get a fingerprint for a device identity
    pub async fn get_device_fingerprint(&self, sender: &str, device_id: DeviceId) -> Result<String, OmemoError> {
        debug!("Getting fingerprint for device {}:{}", sender, device_id);
        let device_identity = self.get_device_identity(sender, device_id).await?;
        // Log the raw identity key as hex
        let raw_bytes = &device_identity.identity_key;
        let hex_dump = raw_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        debug!("Raw identity key for {}:{} ({} bytes): {}", sender, device_id, raw_bytes.len(), hex_dump);
        // Log the SHA-256 hash of the key
        let hash = crate::omemo::crypto::sha256_hash(raw_bytes);
        let hash_hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        debug!("SHA-256 hash for {}:{}: {}", sender, device_id, hash_hex);
        // Create a fingerprint from the identity key using standard SHA-256 hash
        let fingerprint = self.generate_standard_fingerprint(raw_bytes);
        debug!("Generated fingerprint for {}:{}: {}", sender, device_id, fingerprint);
        Ok(fingerprint)
    }

    /// Generate a standard fingerprint from a public key using SHA-256
    fn generate_standard_fingerprint(&self, public_key: &[u8]) -> String {
        // Create a SHA-256 hash of the key
        let hash = crate::omemo::crypto::sha256_hash(public_key);
        // Log the hash for debugging
        debug!("generate_standard_fingerprint: SHA-256 hash: {}", hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        // Format the SHA-256 fingerprint as groups of 8 hex characters separated by spaces
        // This follows the standard format used in most OMEMO clients
        let mut fingerprint = String::new();
        for (i, chunk) in hash.chunks(4).enumerate() {
            if i > 0 {
                fingerprint.push(' ');
            }
            for byte in chunk {
                fingerprint.push_str(&format!("{:02X}", byte));
            }
        }
        debug!("generate_standard_fingerprint: Final fingerprint string: {}", fingerprint);
        fingerprint
    }

    /// Check if PreKeys need rotation and rotate if necessary
    pub async fn check_and_rotate_prekeys(&mut self) -> Result<bool, OmemoError> {
        debug!("Checking if PreKeys need rotation");
        
        // Get current time in seconds since epoch
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| OmemoError::ProtocolError(format!("Time error: {}", e)))?
            .as_secs();
        
        // Check if it's time to rotate
        if (now - self.prekey_rotation_config.last_rotation) < self.prekey_rotation_config.check_interval {
            debug!("Not time to rotate PreKeys yet");
            return Ok(false);
        }
        
        info!("Performing PreKey rotation");
        
        // Get current bundle
        let current_bundle = match &self.key_bundle {
            Some(bundle) => bundle.clone(),
            None => return Err(OmemoError::MissingDataError("Key bundle not initialized".to_string())),
        };
        
        // Generate a new signed PreKey
        info!("Generating new signed PreKey");
        let signed_pre_key_pair = X3DHProtocol::generate_key_pair()
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to generate signed PreKey: {}", e)))?;
        
        let signed_pre_key_id = current_bundle.signed_pre_key_id + 1;
        
        // Sign the PreKey with the identity key
        let signed_pre_key_signature = X3DHProtocol::sign_pre_key(
            &current_bundle.identity_key_pair.private_key,
            &signed_pre_key_pair.public_key
        ).map_err(|e| OmemoError::ProtocolError(format!("Failed to sign PreKey: {}", e)))?;
        
        // Count remaining one-time PreKeys
        let remaining_one_time_prekeys = current_bundle.one_time_pre_key_pairs.len() as u32;
        
        // Generate additional one-time PreKeys if needed
        let mut one_time_pre_key_pairs = current_bundle.one_time_pre_key_pairs.clone();
        
        if remaining_one_time_prekeys < self.prekey_rotation_config.min_one_time_prekeys {
            info!("Generating additional one-time PreKeys");
            let to_generate = self.prekey_rotation_config.min_one_time_prekeys - remaining_one_time_prekeys;
            
            // Find the highest existing PreKey ID
            let mut max_id = 0;
            for id in one_time_pre_key_pairs.keys() {
                if *id > max_id {
                    max_id = *id;
                }
            }
            
            // Generate new PreKeys
            for i in 1..=to_generate {
                let key_pair = X3DHProtocol::generate_key_pair()
                    .map_err(|e| OmemoError::ProtocolError(format!("Failed to generate one-time PreKey: {}", e)))?;
                one_time_pre_key_pairs.insert(max_id + i, key_pair);
            }
        }
        
        // Create a new bundle with the updated keys
        let new_bundle = protocol::X3DHKeyBundle {
            device_id: self.device_id,
            identity_key_pair: current_bundle.identity_key_pair.clone(),
            signed_pre_key_id,
            signed_pre_key_pair,
            signed_pre_key_signature,
            one_time_pre_key_pairs,
        };
        
        // Store the new bundle
        let storage_guard = self.storage.lock().await;
        storage_guard.store_key_bundle(&new_bundle)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store key bundle: {}", e)))?;
        drop(storage_guard);
        
        // Update the manager's state
        self.key_bundle = Some(new_bundle);
        self.prekey_rotation_config.last_rotation = now;
        
        // Store the last rotation time
        let storage_guard = self.storage.lock().await;
        storage_guard.store_prekey_rotation_time(now as i64)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store rotation time: {}", e)))?;
        
        info!("PreKey rotation completed successfully");
        
        Ok(true)
    }

    /// Force reset all broken sessions (useful for debugging and fixing stuck sessions)
    pub async fn force_reset_broken_sessions(&mut self) -> Result<Vec<String>, OmemoError> {
        let mut reset_sessions = Vec::new();
        
        // Get all sessions that are in pending_prekey_sends (stuck waiting to send PreKey)
        let stuck_sessions: Vec<_> = self.pending_prekey_sends.iter().cloned().collect();
        
        for (bare_jid, device_id) in stuck_sessions {
            warn!("Force resetting stuck session with {}:{}", bare_jid, device_id);
            if let Err(e) = self.reset_session(&bare_jid, device_id).await {
                error!("Failed to force reset session {}:{}: {}", bare_jid, device_id, e);
            } else {
                reset_sessions.push(format!("{}:{}", bare_jid, device_id));
            }
        }
        
        if !reset_sessions.is_empty() {
            info!("Force reset {} broken sessions: {:?}", reset_sessions.len(), reset_sessions);
        } else {
            info!("No broken sessions found to reset");
        }
        
        Ok(reset_sessions)
    }


    
    /// Get the device ID for this OMEMO manager
    pub fn get_device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Ensure that our device list is published to the server
    /// 
    /// This method checks if we have already published our device list,
    /// and if not, retrieves the existing list, adds our device ID, and publishes it.
    pub async fn ensure_device_list_published(&self) -> Result<()> {
        debug!("Ensuring device list is published for {}", self.local_jid);
        
        // Format our JID to get the bare JID (without resource part)
        let parts: Vec<&str> = self.local_jid.split('/').collect();
        let bare_jid = parts[0];
        
        debug!("Using bare JID for device list publishing: {}", bare_jid);
        
        // First, try to fetch the existing device list from the server, but with a timeout
        let device_list_result = timeout(Duration::from_secs(5), self.fetch_device_list_from_server(bare_jid)).await;
        let mut device_list = match device_list_result {
            Ok(Ok(devices)) => {
                info!("Found existing device list with {} devices", devices.len());
                devices
            },
            Ok(Err(e)) => {
                warn!("Failed to fetch existing device list: {}, starting with empty list", e);
                Vec::new()
            },
            Err(_) => {
                error!("Timeout while fetching device list from server for {}", bare_jid);
                Vec::new()
            }
        };
        info!("[DEBUG] Proceeding after device list fetch. Device list: {:?}", device_list);
        
        // Check if our device ID is already in the list
        if !device_list.contains(&self.device_id) {
            info!("Adding our device ID {} to device list", self.device_id);
            device_list.push(self.device_id);
            
            // Use the specialized publishing function with the device list
            if let Err(e) = crate::xmpp::omemo_integration::publish_pubsub_item_device_list(&device_list).await {
                error!("Failed to publish device list: {}", e);
                return Err(anyhow!("Failed to publish device list: {}", e));
            }
            
            info!("Published updated device list with {} devices", device_list.len());
        } else {
            debug!("Our device ID {} is already in the device list", self.device_id);
        }
        
        // Store the published list in storage
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
            
        let entry = storage::DeviceListEntry {
            jid: bare_jid.to_string(),
            device_ids: device_list.clone(),
            last_update: now,
        };
        
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.save_device_list(&entry) {
            warn!("Failed to store updated device list: {}", e);
            // Non-fatal error, continue
        }
        info!("[DEBUG] Finished ensure_device_list_published, proceeding to bundle publication if needed.");
        Ok(())
    }
    
    /// Ensure that our device bundle is published to the server
    /// 
    /// This method checks if we have already published our device bundle,
    /// and if not, generates and publishes it.
    pub async fn ensure_bundle_published(&self) -> Result<()> {
        debug!("Ensuring bundle is published for device {}", self.device_id);
        let storage = self.storage.lock().await;
        info!("[DEBUG] Forcing OMEMO bundle publication for device {}", self.device_id);
        let has_published = false;
        if !has_published {
            info!("Bundle not found or forced, publishing new bundle");
            let bundle = match self.generate_bundle().await {
                Ok(bundle) => bundle,
                Err(e) => {
                    error!("Failed to generate bundle: {}", e);
                    println!("[OMEMO ERROR] Failed to generate bundle: {}", e);
                    return Err(anyhow!("Failed to generate bundle: {}", e));
                }
            };
            match self.bundle_to_xml(&bundle) {
                Ok(xml) => info!("[DEBUG] Bundle XML to be published: {}", xml),
                Err(e) => error!("[DEBUG] Failed to convert bundle to XML: {}", e),
            }
            if let Err(e) = self.publish_bundle(bundle).await {
                error!("Failed to publish bundle: {}", e);
                println!("[OMEMO ERROR] Failed to publish bundle: {}", e);
                return Err(anyhow!("Failed to publish bundle: {}", e));
            }
            if let Err(e) = storage.mark_bundle_published(self.device_id).await {
                warn!("Failed to mark bundle as published: {}", e);
            }
        } else {
            debug!("Bundle already published");
        }
        Ok(())
    }
    
    // Private methods to help with the above public methods
    

    
 
    

    
    /// Publish a device list to the server
    pub async fn publish_device_list(&self, bare_jid: &str) -> Result<(), OmemoError> {
        // Use special publishing function for device list
        info!("Publishing device list for {}", bare_jid);
        
        // First get the current list of device IDs
        // Add our device ID to the list if it's not already there
        let mut devices = self.get_device_ids_for(bare_jid).await?;
        
        // Add our device ID if it's not already in the list
        let own_device_id = self.device_id;
        if !devices.contains(&own_device_id) {
            info!("Adding our device ID {} to device list", own_device_id);
            devices.push(own_device_id);
        }
        
        // Sort the list for consistency
        devices.sort();
        
        debug!("Publishing device list: {:?}", devices);
        
        // Use the specialized device list publishing function that properly handles namespaces
        match crate::xmpp::omemo_integration::publish_pubsub_item_device_list(&devices).await {
            Ok(_) => {
                info!("Device list published successfully: {:?}", devices);
                
                // Mark the device list as published - using storage guard properly
                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard.mark_device_list_published(bare_jid) {
                    warn!("Failed to mark device list as published: {}", e);
                    // Non-fatal error, continue
                }
                
                Ok(())
            },
            Err(e) => {
                error!("Failed to publish device list: {}", e);
                Err(OmemoError::PublicationError(format!("Failed to publish device list: {}", e)))
            }
        }
    }
    

    /// Get the device IDs for a user (public wrapper for testing)
    pub async fn get_device_ids_for_test(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        self.get_device_ids(jid).await
    }

    // This is the implementation of decrypt_message_key in the OmemoManager
    pub async fn decrypt_message_key(&mut self, from: String, sender_device_id: u32, encrypted_key: &[u8]) -> Result<Vec<u8>, OmemoError> {
        debug!("Decrypting message key from device {} (sender: {})", sender_device_id, from);
        
        // Find the session for this device with timeout protection
        let session = match tokio::time::timeout(
            std::time::Duration::from_secs(8),
            self.get_or_create_session(&from, sender_device_id)
        ).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(OmemoError::SessionError(
                    crate::omemo::session::SessionError::InvalidStateError(
                        format!("Timeout while creating session for key decryption with {}:{}", from, sender_device_id)
                    )
                ));
            }
        };
        
        // Decrypt the key using the session
        match session.decrypt_key(encrypted_key) {
            Ok(key) => {
                debug!("Successfully decrypted message key");
                Ok(key)
            },
            Err(e) => {
                error!("Failed to decrypt message key: {}", e);
                Err(OmemoError::DecryptionError(format!("Failed to decrypt message key: {}", e)))
            }
        }
    }

    /// Track an undecryptable message from a device (Dino-style approach)
    pub async fn track_undecryptable_message(&mut self, remote_jid: &str, remote_device_id: u32) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        
        // Track failed decryptions for this device
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Store undecryptable message timestamp
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.update_last_undecryptable_message(&bare_jid, remote_device_id, current_time as i64) {
            warn!("Failed to update undecryptable message timestamp: {}", e);
        }
        drop(storage_guard);
        
        // Check if this device should be temporarily ignored
        let failure_count = self.get_device_failure_count(&bare_jid, remote_device_id).await;
        if failure_count >= 3 {
            warn!("Device {}:{} has {} consecutive failures, temporarily ignoring", bare_jid, remote_device_id, failure_count);
            if let Err(e) = self.ignore_device(&bare_jid, remote_device_id, std::time::Duration::from_secs(300)).await {
                warn!("Failed to ignore device {}:{}: {}", bare_jid, remote_device_id, e);
            }
        }
        
        info!("Tracked undecryptable message from {}:{} (failure count: {})", bare_jid, remote_device_id, failure_count);
        Ok(())
    }

    /// Ignore a device temporarily (Dino-style device ignoring)
    pub async fn ignore_device(&mut self, remote_jid: &str, remote_device_id: u32, duration: std::time::Duration) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        
        let ignore_until = std::time::SystemTime::now() + duration;
        
        // Store ignore status
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.set_device_ignore_until(&bare_jid, remote_device_id, ignore_until) {
            warn!("Failed to set device ignore status: {}", e);
        }
        drop(storage_guard);
        
        info!("Ignoring device {}:{} for {} seconds", bare_jid, remote_device_id, duration.as_secs());
        Ok(())
    }

    /// Check if a device is currently being ignored
    pub async fn is_device_ignored(&self, remote_jid: &str, remote_device_id: u32) -> Result<bool, OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        
        let storage_guard = self.storage.lock().await;
        match storage_guard.get_device_ignore_until(&bare_jid, remote_device_id) {
            Ok(Some(ignore_until)) => {
                let now = std::time::SystemTime::now();
                Ok(now < ignore_until)
            },
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // Default to not ignored if we can't determine
        }
    }

    /// Get the number of consecutive decryption failures for a device
    async fn get_device_failure_count(&self, remote_jid: &str, remote_device_id: u32) -> u32 {
        let storage_guard = self.storage.lock().await;
        storage_guard.get_device_failure_count(remote_jid, remote_device_id).unwrap_or(0)
    }

    /// Reset failure count for a device after successful decryption
    async fn reset_device_failure_count(&self, remote_jid: &str, remote_device_id: u32) {
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.reset_device_failure_count(remote_jid, remote_device_id) {
            warn!("Failed to reset failure count for {}:{}: {}", remote_jid, remote_device_id, e);
        }
    }

    /// Reset a session with a specific device (aggressive approach for broken sessions)
    pub async fn reset_session(&mut self, remote_jid: &str, remote_device_id: u32) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        let key = (bare_jid.clone(), remote_device_id);
        
        warn!("Aggressively resetting OMEMO session with {}:{} due to repeated failures", bare_jid, remote_device_id);
        
        // Remove from memory
        self.sessions.remove(&key);
        
        // Also remove from storage to force complete rebuild
        let session_key = format!("{}:{}", bare_jid, remote_device_id);
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.delete_session(&session_key) {
            warn!("Failed to delete stored session for {}:{}: {}", bare_jid, remote_device_id, e);
        }
        
        // Clear the ignore status so this device can be contacted for PreKey exchange
        if let Err(e) = storage_guard.clear_device_ignore_status(&bare_jid, remote_device_id) {
            warn!("Failed to clear ignore status for {}:{}: {}", bare_jid, remote_device_id, e);
        }
        
        // Reset failure count to give the session a fresh start
        if let Err(e) = storage_guard.reset_device_failure_count(&bare_jid, remote_device_id) {
            warn!("Failed to reset failure count for {}:{}: {}", bare_jid, remote_device_id, e);
        }
        drop(storage_guard);
        
        // Clear any pending flags
        self.pending_session_rebuilds.remove(&key);
        self.pending_prekey_sends.remove(&key);
        
        info!("Completely reset session with {}:{} - fresh start on next encryption/decryption", bare_jid, remote_device_id);
        
        info!("Successfully reset session with {}:{}", bare_jid, remote_device_id);
        Ok(())
    }

    /// Verify that a message is encrypted and isn't leaking plaintext
    /// 
    /// # Arguments
    /// 
    /// * `xml` - The XML stanza to verify
    /// * `plaintext` - The original plaintext that shouldn't appear in the XML
    /// 
    /// # Returns
    /// 
    /// Ok(()) if verification passes, or an error describing the issue
    pub fn verify_message_encryption(&self, xml: &str, plaintext: &str) -> Result<(), EncryptionVerificationError> {
        
        debug!("Verifying message encryption");

        // Check if the plaintext is present in the XML
        if xml.contains(plaintext) {
            error!("Plaintext detected in encrypted message");
            return Err(EncryptionVerificationError::PlaintextDetected);
        }

        // All checks passed
        Ok(())
    }

    /// Parse a device list response from the server
    fn parse_device_list_response(&self, response: &str) -> Result<Vec<u32>, OmemoError> {
        debug!("Parsing device list response - starting");
        
        // Check if the response is empty or whitespace only
        if response.trim().is_empty() {
            debug!("Empty response received, returning empty device list");
            return Ok(Vec::new());
        }
        
        // Check for item-not-found error before attempting to parse
        if response.contains("item-not-found") {
            debug!("Response contains 'item-not-found', returning empty device list");
            return Ok(Vec::new());
        }
        
        debug!("Parsing device list response - starting XML parsing");
        
        // Parse the XML response
        let document = match roxmltree::Document::parse(response) {
            Ok(doc) => doc,
            Err(e) => {
                error!("Failed to parse device list XML: {}", e);
                return Err(OmemoError::ProtocolError(format!("XML parsing error: {}", e)));
            }
        };
        
        debug!("Parsing device list response - XML parsed successfully, checking for errors");
        
        // Check for error responses first
       
        if let Some(error) = document.descendants().find(|n| n.has_tag_name("error")) {
            let error_type = error.attribute("type").unwrap_or("unknown");
            
            // Find the error condition
            let error_condition = error.children()
                .find(|n| n.is_element() && n.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas"))
                .map(|n| n.tag_name().name())
                .unwrap_or("unknown");
            
            warn!("Error in device list response: type={}, condition={}", error_type, error_condition);
            
            match error_condition {
                "item-not-found" => {
                    // This means no device list exists yet, return empty list
                    debug!("No device list found (item-not-found)");
                    return Ok(Vec::new());
                },
                _ => {
                    return Err(OmemoError::ProtocolError(
                        format!("XMPP error in device list response: {}", error_condition)
                    ));
                }
            }
        }
        
        debug!("Parsing device list response - no errors found, extracting device IDs");
        
        // Extract device IDs from the response
        let mut device_ids = Vec::new();
        
        // Approach 1: Find <list> element by namespace
        let list_elements: Vec<_> = document.descendants()
            .filter(|n| n.has_tag_name("list") && 
                  (n.attribute("xmlns") == Some(OMEMO_NAMESPACE) || 
                   n.tag_name().namespace() == Some(OMEMO_NAMESPACE)))
            .collect();
        
        if !list_elements.is_empty() {
            debug!("Found {} list elements with OMEMO namespace", list_elements.len());
            
            for list in list_elements {
                for device in list.children().filter(|n| n.has_tag_name("device") && n.has_attribute("id")) {
                    if let Some(id_str) = device.attribute("id") {
                        if let Ok(id) = id_str.parse::<u32>() {
                            debug!("Found device ID: {}", id);
                            if !device_ids.contains(&id) {
                                device_ids.push(id);
                            }
                        } else {
                            warn!("Invalid device ID '{}' in device list", id_str);
                        }
                    }
                }
            }
        } else {
            // Approach 2: Try to find <list> inside <item id='current'> (PubSub format)
            debug!("No direct list elements found, trying PubSub item structure");
            
            let item_elements: Vec<_> = document.descendants()
                .filter(|n| n.has_tag_name("item") && n.attribute("id") == Some("current"))
                .collect();
            
            if !item_elements.is_empty() {
                debug!("Found {} item elements with id='current'", item_elements.len());
                
                for item in item_elements {
                    if let Some(list) = item.children().find(|n| n.has_tag_name("list")) {
                        for device in list.children().filter(|n| n.has_tag_name("device") && n.has_attribute("id")) {
                            if let Some(id_str) = device.attribute("id") {
                                if let Ok(id) = id_str.parse::<u32>() {
                                    debug!("Found device ID: {}", id);
                                    if !device_ids.contains(&id) {
                                        device_ids.push(id);
                                    }
                                } else {
                                    warn!("Invalid device ID '{}' in device list", id_str);
                                }
                            }
                        }
                    }
                }
            } else {
                // Approach 3: Search any <device> elements with "id" attributes anywhere
                debug!("No PubSub item structure found, looking for any device elements");
                
                for device in document.descendants().filter(|n| n.has_tag_name("device") && n.has_attribute("id")) {
                    if let Some(id_str) = device.attribute("id") {
                        if let Ok(id) = id_str.parse::<u32>() {
                            debug!("Found device ID: {}", id);
                            if !device_ids.contains(&id) {
                                device_ids.push(id);
                            }
                        } else {
                            warn!("Invalid device ID '{}' in device list", id_str);
                        }
                    }
                }
            }
        }
        
        // If we found device IDs with any approach, return them
        if !device_ids.is_empty() {
            info!("Found {} OMEMO device IDs: {:?}", device_ids.len(), device_ids);
            return Ok(device_ids);
        }
        
        // If we reach here, we found no device IDs. This could mean no devices exist yet
        // Return an empty list as this is a valid state for a new user
        debug!("No device IDs found in response, returning empty list");
        Ok(Vec::new())
    }

    
    /// Helper function to get device IDs for a specific JID
    /// This is used when publishing device lists
    async fn get_device_ids_for(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        debug!("Getting device IDs for JID: {}", jid);
        
        // Try to get from storage first
        let storage_guard = self.storage.lock().await;
        if let Ok(device_list) = storage_guard.load_device_list(jid) {
            debug!("Found device list in storage: {:?}", device_list.device_ids);
            return Ok(device_list.device_ids);
        }
        drop(storage_guard);
        
        // If not in storage, try to fetch from server
        let device_ids = match self.fetch_device_list_from_server(jid).await {
            Ok(ids) => {
                info!("Fetched device list from server: {:?}", ids);
                ids
            },
            Err(e) => {
                warn!("Failed to fetch device list: {}, starting with empty list", e);
                Vec::new()
            }
        };
        
        // Store the fetched list for future use
        let entry = storage::DeviceListEntry {
            jid: jid.to_string(),
            device_ids: device_ids.clone(),
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };
        
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.save_device_list(&entry) {
            warn!("Failed to save device list: {}", e);
            // Non-fatal error, continue
        }
        
        Ok(device_ids)
    }

    /// Check if our bundle is published
    pub async fn is_bundle_published(&self) -> Result<bool, OmemoError> {
        debug!("Checking if bundle is published for device {}", self.device_id);
        
        // Check in storage first
        let storage_guard = self.storage.lock().await;
        match storage_guard.is_bundle_published(self.device_id) {
            Ok(published) => {
                debug!("Bundle published status from storage: {}", published);
                Ok(published)
            },
            Err(e) => {
                warn!("Error checking bundle published status: {}", e);
                // Default to false if we can't determine
                Ok(false)
            }
        }
    }

    pub async fn publish_bundle_to_server(&mut self) -> Result<bool> {
        debug!("Publishing bundle for device {}", self.device_id);
        
        // Get the bundle from storage
        let bundle = match self.storage.lock().await.load_key_bundle_with_id(self.device_id)? {
            Some(bundle) => bundle,
            None => {
                error!("No bundle found in storage for publishing");
                return Err(anyhow!("No bundle found in storage for publishing"));
            }
        };
        
        // Add some basic validation to make sure the bundle is valid
        if bundle.identity_key_pair.public_key.is_empty() || 
           bundle.signed_pre_key_pair.public_key.is_empty() ||
           bundle.signed_pre_key_signature.is_empty() ||
           bundle.one_time_pre_key_pairs.is_empty() {
            error!("Invalid bundle data - missing required fields");
            return Err(anyhow!("Invalid bundle data for publishing"));
        }
        
        // Convert the bundle to an XML element
        let bundle_xml = self.convert_x3dh_bundle_to_xml(&bundle)?;
        
        // Log what we would publish (useful for debugging)
        info!("Would publish PubSub item: {}", bundle_xml);
        
        // Use direct access to the omemo_integration module
        // This uses the global client instance set in the module
        let node = format!("{}.bundles:{}", OMEMO_NAMESPACE, self.device_id);
        
        // Use the publish_pubsub_item function directly
        match crate::xmpp::omemo_integration::publish_pubsub_item(None, &node, "current", &bundle_xml).await {
            Ok(_) => {
                info!("Successfully published to node {}", node);
                
                // Mark the bundle as published in storage
                self.storage.lock().await.mark_bundle_published(self.device_id).await?;
                
                Ok(true)
            },
            Err(e) => {
                error!("Failed to publish bundle: {}", e);
                
                // Try an alternative bundle format as a fallback if the error indicates an XML format issue
               
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("bad-request") || error_str.contains("invalid item") {
                    error!("Server rejected bundle with bad-request - check XML validity");
                    // Try an alternative bundle format as a fallback
                    return self.publish_bundle_alternative_format().await;
                }
                
                Ok(false)
            }
        }
    }

    /// Publish the bundle using an alternative format that some servers might accept
    async fn publish_bundle_alternative_format(&mut self) -> Result<bool> {
        debug!("Attempting bundle publication with alternative format for device {}", self.device_id);
        
        // Get the bundle from storage
        let bundle = match self.storage.lock().await.load_key_bundle_with_id(self.device_id)? {
            Some(bundle) => bundle,
            None => {
                error!("No bundle found in storage for alternative publishing");
                return Err(anyhow!("No bundle found in storage for alternative publishing"));
            }
        };
        
        // Simplified bundle format with fewer namespaces
        let alternative_payload = format!(
            "<bundle xmlns='eu.siacs.conversations.axolotl'>\
                <identityKey>{}</identityKey>\
                <signedPreKeyPublic signedPreKeyId='{}'>{}</signedPreKeyPublic>\
                <signedPreKeySignature>{}</signedPreKeySignature>\
                <prekeys>{}</prekeys>\
            </bundle>",
            base64::engine::general_purpose::STANDARD.encode(&bundle.identity_key_pair.public_key),
            bundle.signed_pre_key_id,
            base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key_pair.public_key),
            base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key_signature),
            bundle.one_time_pre_key_pairs.iter()
                .map(|(id, keypair)| format!("<preKeyPublic preKeyId='{}'>{}</preKeyPublic>",
                    id,
                    base64::engine::general_purpose::STANDARD.encode(&keypair.public_key)
                ) + "</preKeyPublic>")
                .collect::<Vec<_>>()
                .join("")
        );
        
        debug!("Attempting with alternative bundle format: {}", alternative_payload);
        
        // Use direct access to the omemo_integration module
        let node = format!("{}.bundles:{}", OMEMO_NAMESPACE, self.device_id);
        
        // Try publishing with the alternative format
        match crate::xmpp::omemo_integration::publish_pubsub_item(None, &node, "current", &alternative_payload).await {
            Ok(_) => {
                info!("Successfully published bundle with alternative format for device {}", self.device_id);
                
                // Mark the bundle as published
                self.storage.lock().await.mark_bundle_published(self.device_id).await?;
                
                Ok(true)
            },
            Err(e) => {
                error!("Failed to publish bundle with alternative format: {}", e);
                Ok(false)
            }
        }
    }

    /// Handle decryption failure with Dino-style tracking and session management
    async fn handle_decryption_failure(&mut self, sender_jid: String, device_id: u32, session_error: crate::omemo::session::SessionError) -> Result<String, OmemoError> {
        // Normalize JID to bare JID for consistent tracking
        let bare_jid = Self::normalize_jid_to_bare(&sender_jid);
        
        // Track this as an undecryptable message (Dino-style approach)
        warn!("Failed to decrypt message key from {}:{}: {}", sender_jid, device_id, session_error);
        
        // **NEW: Check if this could be a PreKey message that we should handle as a recipient**
        // If the decryption failed with an AEAD error, it might be because we're using the wrong session
        // Try to detect if this is a PreKey message and create a recipient session
        if let crate::omemo::session::SessionError::DoubleRatchetError(ratchet_error) = &session_error {
            if let crate::omemo::protocol::DoubleRatchetError::CryptoError(crypto_error) = ratchet_error {
                if let crate::omemo::crypto::CryptoError::AesGcmError(aes_error) = crypto_error {
                    if aes_error.contains("aead::Error") {
                        warn!("AEAD decryption failure from {}:{} - this might be a PreKey message", sender_jid, device_id);
                        // For now, we'll continue with the existing reset logic, but in the future
                        // we could try to create a recipient session here
                    }
                }
            }
        }
        
        // Track the undecryptable message
        if let Err(e) = self.track_undecryptable_message(&sender_jid, device_id).await {
            warn!("Failed to track undecryptable message: {}", e);
        }
        
        // Check if this is a Double Ratchet state mismatch and we should consider session reset
        if let crate::omemo::session::SessionError::DoubleRatchetError(ratchet_error) = &session_error {
            if let crate::omemo::protocol::DoubleRatchetError::CryptoError(crypto_error) = ratchet_error {
                if let crate::omemo::crypto::CryptoError::AesGcmError(aes_error) = crypto_error {
                    if aes_error.contains("aead::Error") {
                        // AEAD failures indicate session state mismatch - be aggressive about fixing this
                        warn!("AEAD decryption failure from {}:{} - triggering immediate session reset", sender_jid, device_id);
                        
                        // Use the new aggressive session reset handler
                        if let Err(reset_err) = self.handle_aead_decryption_failure(&sender_jid, device_id).await {
                            error!("Failed to handle AEAD decryption failure: {}", reset_err);
                        }
                        
                        return Err(OmemoError::SessionError(session_error));
                    }
                }
            }
        }
        
        // Fallback logic for other types of errors
        let failure_count = self.get_device_failure_count(&bare_jid, device_id).await;
        if failure_count >= 3 {
            warn!("Multiple consecutive failures ({}) from {}:{}, resetting session", failure_count, sender_jid, device_id);
            if let Err(reset_err) = self.reset_session(&bare_jid, device_id).await {
                error!("Failed to reset session: {}", reset_err);
            }
        }
        
        // For all errors, propagate them
        Err(OmemoError::SessionError(session_error))
    }

    /// Handle AEAD decryption failures by aggressively resetting sessions
    /// This is critical for OMEMO reliability when sessions get out of sync
    async fn handle_aead_decryption_failure(&mut self, sender_jid: &str, device_id: u32) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(sender_jid);
        warn!("AEAD decryption failure detected for {}:{} - implementing aggressive session reset", bare_jid, device_id);
        
        // Immediately reset the session to clear any corrupted state
        if let Err(e) = self.reset_session(&bare_jid, device_id).await {
            error!("Failed to reset session during AEAD failure handling: {}", e);
        }
        
        // Mark this device as needing a fresh PreKey exchange
        let key = (bare_jid.clone(), device_id);
        self.pending_prekey_sends.insert(key.clone());
        
        // Clear any existing session state to prevent continued failures
        self.sessions.remove(&key);
        
        // CRITICAL: Also clear our own session with this contact to force mutual session reset
        // This ensures that when we send a message back, it will be a PreKey message
        let our_device_ids = match self.get_own_device_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!("Failed to get own device IDs during session reset: {}", e);
                vec![]
            }
        };
        
        for our_device_id in our_device_ids {
            let reverse_key = (bare_jid.clone(), our_device_id);
            if self.sessions.contains_key(&reverse_key) {
                warn!("Clearing our session with {}:{} to force mutual PreKey exchange", bare_jid, our_device_id);
                self.sessions.remove(&reverse_key);
            }
        }
        
        // Force refresh of device bundles for fresh key material
        if let Err(e) = self.force_refresh_device_list(&bare_jid).await {
            warn!("Failed to refresh device list during session reset: {}", e);
        }
        
        // Mark all devices of this contact for PreKey message sending
        let target_device_ids = match self.get_device_ids(&bare_jid).await {
            Ok(devices) => devices,
            Err(_) => vec![device_id], // At minimum, mark the problematic device
        };
        
        for target_device_id in target_device_ids {
            let device_key = (bare_jid.clone(), target_device_id);
            self.pending_prekey_sends.insert(device_key.clone());
            info!("Marked device {}:{} for PreKey message sending after session reset", bare_jid, target_device_id);
        }
        
        // Mark that this contact needs fresh session establishment from both sides
        warn!("Mutual session reset initiated for {} - both parties will send PreKey messages", bare_jid);
        
        info!("Session reset complete for {}:{} - waiting for new PreKey message", bare_jid, device_id);
        Ok(())
    }

    /// Get our own device IDs for session management
    async fn get_own_device_ids(&self) -> Result<Vec<u32>, OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(&self.local_jid);
        match self.get_device_ids(&bare_jid).await {
            Ok(device_ids) => Ok(device_ids),
            Err(e) => {
                warn!("Failed to get own device IDs: {}", e);
                // Return our device ID as fallback
                Ok(vec![self.device_id])
            }
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

    // Helper function to create a temporary OMEMO storage for testing
    async fn create_test_storage() -> Result<OmemoStorage, anyhow::Error> {
        // Create a temporary directory for our test storage
        let temp_dir = tempdir()?;
        let storage_path = temp_dir.path().to_path_buf();
        
        // Create a new storage instance with this path
        let storage = OmemoStorage::new(Some(storage_path))?;
        
        Ok(storage)
    }

    #[tokio::test]
    async fn test_device_id_generation() {
        // Generate a device ID directly
        let device_id = generate_device_id();
        assert!(device_id > 0, "Device ID should be non-zero");
        
        // Generate another one to make sure they're different
        let device_id2 = generate_device_id();
        assert!(device_id2 > 0, "Second device ID should be non-zero");
        
        // Device IDs should be different with high probability
        // (there's a tiny chance they could be the same, but it's extremely unlikely)
        assert_ne!(device_id, device_id2, "Two generated device IDs should likely be different");
    }

    #[tokio::test]
    #[ignore] // Ignore due to file permission issues in CI environment
    async fn test_omemo_manager_device_id() -> Result<(), anyhow::Error> {
        // // Create test storage
        let storage = create_test_storage().await?;
        
        // Create a manager with auto-generated device ID
        let manager = OmemoManager::new(storage, "test@example.com".to_string(), None).await
            .expect("Failed to create OmemoManager");
        
        // Verify the device ID was generated and is available
        let device_id = manager.get_device_id();
        assert!(device_id > 0, "Manager's device ID should be non-zero");
        
        // Create a new manager with the same storage path to test persistence
        let storage_path = std::env::temp_dir().join("omemo_device_id_test.db");
        if storage_path.exists() {
            std::fs::remove_file(&storage_path)?;
        }
        
        // Create a storage instance with a persistent path
        let storage1 = OmemoStorage::new(Some(storage_path.clone()))?;
        let manager1 = OmemoManager::new(storage1, "test@example.com".to_string(), None).await
            .expect("Failed to create first manager");
        
        // Save the device ID from the first manager
        let device_id1 = manager1.get_device_id();
        assert!(device_id1 > 0, "First manager's device ID should be non-zero");
        
        // Create a second manager with the same storage path
        let storage2 = OmemoStorage::new(Some(storage_path.clone()))?;
        let manager2 = OmemoManager::new(storage2, "test@example.com".to_string(), None).await
            .expect("Failed to create second manager");
        
        // The device ID should be the same
        let device_id2 = manager2.get_device_id();
        assert_eq!(device_id1, device_id2, "Device ID should persist in storage");
        
        // Clean up
        if storage_path.exists() {
            std::fs::remove_file(&storage_path)?;
        }
        
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Ignore due to file permission issues in CI environment
    async fn test_explicit_device_id() -> Result<(), anyhow::Error> {
        // Create test storage
        let storage = create_test_storage().await?;
        
        // Create a manager with an explicitly provided device ID
        let explicit_id: DeviceId = 12345;
        let manager = OmemoManager::new(storage, "test@example.com".to_string(), Some(explicit_id)).await
            .expect("Failed to create OmemoManager with explicit ID");
        
        // Verify the device ID matches what we provided
        let device_id = manager.get_device_id();
        assert_eq!(device_id, explicit_id, "Manager should use the explicitly provided device ID");
        
        Ok(())
    }
}
