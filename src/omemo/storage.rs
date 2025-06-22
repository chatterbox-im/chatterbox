// src/omemo/storage.rs
//! Filesystem-based storage for OMEMO keys and sessions
//!
//! This module provides filesystem-based storage for OMEMO encryption,
//! using binary serialization for complex structures and plain text for simple values.

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::fs;
use crate::omemo::protocol::{DeviceIdentity, X3DHKeyBundle, RatchetState};
use crate::omemo::device_id::DeviceId;
use log::error;
use once_cell::sync::OnceCell;
use crate::omemo::device_id;
use bincode;

/// Entry for a device list
pub struct DeviceListEntry {
    /// The JID of the user
    pub jid: String,
    
    /// The device IDs for this user
    pub device_ids: Vec<DeviceId>,
    
    /// The timestamp of the last update (seconds since epoch)
    pub last_update: i64,
}

/// Filesystem-based storage for OMEMO data
pub struct OmemoStorage {
    /// Root directory for OMEMO storage
    base_path: PathBuf,
    
    /// Our device ID
    device_id: DeviceId,
}

static STORAGE_PATH_OVERRIDE: OnceCell<PathBuf> = OnceCell::new();

pub fn set_storage_path_override(path: PathBuf) {
    let _ = STORAGE_PATH_OVERRIDE.set(path);
}

impl OmemoStorage {
    /// Create a new OMEMO storage
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        // Determine the storage path
        let base_path = match path {
            Some(p) => p,
            None => {
                // If OMEMO_DIR_OVERRIDE is set, use it
                if let Some(dir) = device_id::get_omemo_dir_override() {
                    dir.clone()
                } else if let Some(jid) = device_id::get_omemo_jid() {
                    // Use user-specific directory for OMEMO storage
                    let mut storage_path = match dirs::data_dir() {
                        Some(path) => path,
                        None => return Err(anyhow!("Could not determine XDG_DATA_HOME directory")),
                    };
                    storage_path.push("chatterbox");
                    storage_path.push(&jid);
                    storage_path.push("omemo");
                    storage_path
                } else if let Some(override_path) = STORAGE_PATH_OVERRIDE.get() {
                    override_path.clone()
                } else {
                    // Use the default path in the user's home directory
                    let mut home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
                    home.push(".local");
                    home.push("share");
                    home.push("chatterbox");
                    home.push("omemo");
                    home
                }
            }
        };
        
        // Create the directory structure
        fs::create_dir_all(&base_path)?;
        fs::create_dir_all(base_path.join("device_lists"))?;
        fs::create_dir_all(base_path.join("identities"))?;
        fs::create_dir_all(base_path.join("sessions"))?;
        fs::create_dir_all(base_path.join("key_bundles"))?;
        fs::create_dir_all(base_path.join("metadata"))?;
        
        // Load or generate device ID
        let device_id = Self::load_or_generate_device_id(&base_path)?;
        
        Ok(Self {
            base_path,
            device_id,
        })
    }

    /// Create a new OMEMO storage with default settings
    pub fn new_default() -> Result<Self> {
        Self::new(None)
    }
    
    /// Load or generate device ID
    fn load_or_generate_device_id(base_path: &Path) -> Result<DeviceId> {
        let device_id_path = base_path.join("metadata").join("device_id");
        
        if device_id_path.exists() {
            let content = fs::read_to_string(&device_id_path)?;
            content.trim().parse::<DeviceId>()
                .map_err(|e| anyhow!("Failed to parse device ID: {}", e))
        } else {
            // Generate new device ID and save it
            let device_id = crate::omemo::device_id::generate_device_id();
            Self::write_text_file(&device_id_path, &device_id.to_string())?;
            Ok(device_id)
        }
    }
    
    /// Write text content to a file atomically
    fn write_text_file(path: &Path, content: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Write to temporary file first, then rename for atomicity
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content)?;
        fs::rename(&temp_path, path)?;
        Ok(())
    }
    
    /// Write binary content to a file atomically
    fn write_binary_file<T: serde::Serialize>(path: &Path, data: &T) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Serialize with bincode
        let encoded = bincode::serialize(data)?;
        
        // Write to temporary file first, then rename for atomicity
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, encoded)?;
        fs::rename(&temp_path, path)?;
        Ok(())
    }
    
    /// Read binary content from a file
    fn read_binary_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        let data = fs::read(path)?;
        bincode::deserialize(&data).map_err(|e| anyhow!("Failed to deserialize: {}", e))
    }
    
    /// Get path for JID-based data
    fn get_jid_path(&self, base_dir: &str, jid: &str) -> PathBuf {
        // Convert JID to alphanumeric filename
        let alphanumeric_jid = self.jid_to_alphanumeric(jid);
        self.base_path.join(base_dir).join(alphanumeric_jid)
    }
    
    /// Store a device ID
    pub fn store_device_id(&mut self, device_id: DeviceId) -> Result<()> {
        let device_id_path = self.base_path.join("metadata").join("device_id");
        Self::write_text_file(&device_id_path, &device_id.to_string())?;
        
        // Also update the instance variable for immediate use
        self.device_id = device_id;
        
        // Save to filesystem as well for persistence across installations
        crate::omemo::device_id::save_device_id(device_id)?;
        
        Ok(())
    }
    
    /// Get the stored device ID
    pub fn get_device_id(&self) -> DeviceId {
        self.device_id
    }
    
    /// Store a device list
    pub fn save_device_list(&self, entry: &DeviceListEntry) -> Result<()> {
        let jid_dir = self.get_jid_path("device_lists", &entry.jid);
        fs::create_dir_all(&jid_dir)?;
        
        // Write device IDs as newline-separated plain text
        let device_ids_content = entry.device_ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        Self::write_text_file(&jid_dir.join("device_ids"), &device_ids_content)?;
        
        // Write last update timestamp
        Self::write_text_file(&jid_dir.join("last_update"), &entry.last_update.to_string())?;
        
        Ok(())
    }
    
    /// Load a device list
    pub fn load_device_list(&self, jid: &str) -> Result<DeviceListEntry> {
        let jid_dir = self.get_jid_path("device_lists", jid);
        
        // Read device IDs
        let device_ids_path = jid_dir.join("device_ids");
        let device_ids = if device_ids_path.exists() {
            let content = fs::read_to_string(&device_ids_path)?;
            content.lines()
                .filter(|line| !line.is_empty())
                .map(|line| line.parse::<DeviceId>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("Failed to parse device ID: {}", e))?
        } else {
            return Err(anyhow!("Device list not found for JID: {}", jid));
        };
        
        // Read last update timestamp
        let last_update_path = jid_dir.join("last_update");
        let last_update = if last_update_path.exists() {
            let content = fs::read_to_string(&last_update_path)?;
            content.trim().parse::<i64>()
                .map_err(|e| anyhow!("Failed to parse last_update: {}", e))?
        } else {
            0 // Default value if not found
        };
        
        Ok(DeviceListEntry {
            jid: jid.to_string(),
            device_ids,
            last_update,
        })
    }
    
    /// Store a device identity
    pub fn save_device_identity(&mut self, jid: &str, identity: &DeviceIdentity, trusted: bool) -> Result<()> {
        let jid_dir = self.get_jid_path("identities", jid);
        let device_dir = jid_dir.join(identity.id.to_string());
        fs::create_dir_all(&device_dir)?;
        
        // Store the identity using binary serialization
        Self::write_binary_file(&device_dir.join("identity.bin"), &identity)?;
        
        // Store trust status as plain text
        Self::write_text_file(&device_dir.join("trusted"), &trusted.to_string())?;
        
        Ok(())
    }
    
    /// Load a device identity
    pub fn load_device_identity(&mut self, jid: &str, device_id: DeviceId) -> Result<DeviceIdentity> {
        let jid_dir = self.get_jid_path("identities", jid);
        let device_dir = jid_dir.join(device_id.to_string());
        let identity_path = device_dir.join("identity.bin");
        
        if !identity_path.exists() {
            return Err(anyhow!("Device identity not found for JID: {}, device_id: {}", jid, device_id));
        }
        
        Self::read_binary_file(&identity_path)
    }
    
    /// Check if a device identity is trusted
    pub fn is_device_trusted(&self, jid: &str, device_id: DeviceId) -> Result<bool> {
        let jid_dir = self.get_jid_path("identities", jid);
        let device_dir = jid_dir.join(device_id.to_string());
        let trusted_path = device_dir.join("trusted");
        
        if trusted_path.exists() {
            let content = fs::read_to_string(&trusted_path)?;
            content.trim().parse::<bool>()
                .map_err(|e| anyhow!("Failed to parse trusted status: {}", e))
        } else {
            // If no record exists, consider the device untrusted
            Ok(false)
        }
    }
    
    /// Set the trust status of a device identity
    pub fn set_device_trust(&self, jid: &str, device_id: DeviceId, trusted: bool) -> Result<()> {
        let jid_dir = self.get_jid_path("identities", jid);
        let device_dir = jid_dir.join(device_id.to_string());
        
        // Create directory if it doesn't exist
        fs::create_dir_all(&device_dir)?;
        
        // Store trust status
        Self::write_text_file(&device_dir.join("trusted"), &trusted.to_string())?;
        
        Ok(())
    }
    
    /// Store a key bundle
    pub fn store_key_bundle(&self, bundle: &X3DHKeyBundle) -> Result<()> {
        let bundle_dir = self.base_path.join("key_bundles").join(bundle.device_id.to_string());
        fs::create_dir_all(&bundle_dir)?;
        
        // Store the bundle using binary serialization
        Self::write_binary_file(&bundle_dir.join("bundle.bin"), bundle)?;
        
        // Store creation timestamp
        let timestamp = chrono::Utc::now().timestamp();
        Self::write_text_file(&bundle_dir.join("created_at"), &timestamp.to_string())?;
        
        Ok(())
    }
    
    /// Load a key bundle
    pub fn load_key_bundle_with_id(&self, device_id: DeviceId) -> Result<Option<X3DHKeyBundle>> {
        let bundle_path = self.base_path.join("key_bundles").join(device_id.to_string()).join("bundle.bin");
        
        if bundle_path.exists() {
            let bundle: X3DHKeyBundle = Self::read_binary_file(&bundle_path)?;
            Ok(Some(bundle))
        } else {
            Ok(None)
        }
    }
    
    /// Store a session
    pub fn save_session(&self, jid: &str, device_id: DeviceId, state: &RatchetState) -> Result<()> {
        let jid_dir = self.get_jid_path("sessions", jid);
        let session_dir = jid_dir.join(device_id.to_string());
        fs::create_dir_all(&session_dir)?;
        
        // Store the session state using binary serialization
        Self::write_binary_file(&session_dir.join("state.bin"), state)?;
        
        // Store last updated timestamp
        let timestamp = chrono::Utc::now().timestamp();
        Self::write_text_file(&session_dir.join("last_updated"), &timestamp.to_string())?;
        
        Ok(())
    }
    
    /// Load all sessions
    pub fn load_all_sessions(&self) -> Result<std::collections::HashMap<String, RatchetState>> {
        let mut sessions = std::collections::HashMap::new();
        let sessions_dir = self.base_path.join("sessions");
        
        if !sessions_dir.exists() {
            return Ok(sessions);
        }
        
        // Iterate through JID directories
        for jid_entry in fs::read_dir(&sessions_dir)? {
            let jid_entry = jid_entry?;
            if !jid_entry.file_type()?.is_dir() {
                continue;
            }
            
            let jid_name = jid_entry.file_name().to_string_lossy().to_string();
            // Convert back from safe filename to JID
            let jid = jid_name.replace('_', "@"); // Simple conversion - may need more sophisticated handling
            
            // Iterate through device directories
            for device_entry in fs::read_dir(jid_entry.path())? {
                let device_entry = device_entry?;
                if !device_entry.file_type()?.is_dir() {
                    continue;
                }
                
                if let Ok(device_id) = device_entry.file_name().to_string_lossy().parse::<DeviceId>() {
                    let state_path = device_entry.path().join("state.bin");
                    if state_path.exists() {
                        match Self::read_binary_file::<RatchetState>(&state_path) {
                            Ok(state) => {
                                let key = format!("{}:{}", jid, device_id);
                                sessions.insert(key, state);
                            },
                            Err(e) => {
                                error!("Failed to deserialize session for {}:{}: {}", jid, device_id, e);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(sessions)
    }
    
    /// Get the session state for a peer device
    pub fn get_session_ratchet_state(&self, jid: &str, device_id: DeviceId) -> Result<Option<RatchetState>> {
        let jid_dir = self.get_jid_path("sessions", jid);
        let session_path = jid_dir.join(device_id.to_string()).join("state.bin");
        
        if session_path.exists() {
            let state: RatchetState = Self::read_binary_file(&session_path)?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }
    
    /// Store the timestamp of the last PreKey rotation
    pub fn store_prekey_rotation_time(&self, timestamp: i64) -> Result<()> {
        let metadata_path = self.base_path.join("metadata").join("prekey_rotation_time");
        Self::write_text_file(&metadata_path, &timestamp.to_string())?;
        Ok(())
    }
    
    /// Load the timestamp of the last PreKey rotation
    pub fn load_prekey_rotation_time(&self) -> Result<i64> {
        let metadata_path = self.base_path.join("metadata").join("prekey_rotation_time");
        
        if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            content.trim().parse::<i64>()
                .map_err(|e| anyhow!("Failed to parse prekey rotation time: {}", e))
        } else {
            Err(anyhow!("PreKey rotation time not found"))
        }
    }

    /// Check if device list has been published
    pub async fn has_published_device_list(&self, jid: &str) -> Result<bool> {
        let metadata_path = self.base_path.join("metadata").join(format!("published_device_list_{}", self.sanitize_jid(jid)));
        
        if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            Ok(content.trim() == "true")
        } else {
            Ok(false)
        }
    }
    
    /// Mark device list as published (can be called from both sync and async contexts)
    pub fn mark_device_list_published(&self, jid: &str) -> Result<()> {
        let metadata_path = self.base_path.join("metadata").join(format!("published_device_list_{}", self.sanitize_jid(jid)));
        Self::write_text_file(&metadata_path, "true")?;
        Ok(())
    }
    
    /// Check if bundle has been published
    pub async fn has_published_bundle(&self, device_id: u32) -> Result<bool> {
        let metadata_path = self.base_path.join("metadata").join(format!("published_bundle_{}", device_id));
        
        if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            Ok(content.trim() == "true")
        } else {
            Ok(false)
        }
    }
    
    /// Mark bundle as published
    pub async fn mark_bundle_published(&self, device_id: u32) -> Result<()> {
        let metadata_path = self.base_path.join("metadata").join(format!("published_bundle_{}", device_id));
        Self::write_text_file(&metadata_path, "true")?;
        Ok(())
    }

    /// Store information about a pending device verification
    pub fn store_pending_device_verification(&self, jid: &str, device_id: DeviceId, fingerprint: &str) -> Result<()> {
        let metadata_path = self.base_path.join("metadata").join(format!("pending_verification_{}_{}",
            self.sanitize_jid(jid), device_id));
        Self::write_text_file(&metadata_path, fingerprint)?;
        Ok(())
    }
    
    /// Check if there's a pending verification for a device
    pub fn get_pending_device_verification(&self, jid: &str) -> Result<Option<(DeviceId, String)>> {
        let metadata_dir = self.base_path.join("metadata");
        if !metadata_dir.exists() {
            return Ok(None);
        }
        
        let prefix = format!("pending_verification_{}_", self.sanitize_jid(jid));
        
        for entry in fs::read_dir(&metadata_dir)? {
            let entry = entry?;
            let filename = entry.file_name().to_string_lossy().to_string();
            
            if filename.starts_with(&prefix) {
                // Extract device ID from filename
                if let Some(device_id_str) = filename.strip_prefix(&prefix) {
                    if let Ok(device_id) = device_id_str.parse::<DeviceId>() {
                        let fingerprint = fs::read_to_string(entry.path())?;
                        return Ok(Some((device_id, fingerprint.trim().to_string())));
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    /// Remove a pending verification
    pub fn remove_pending_device_verification(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        let metadata_path = self.base_path.join("metadata").join(format!("pending_verification_{}_{}",
            self.sanitize_jid(jid), device_id));
        
        if metadata_path.exists() {
            fs::remove_file(&metadata_path)?;
        }
        
        Ok(())
    }

    /// Check if a bundle has been published for a given device ID
    pub fn is_bundle_published(&self, device_id: DeviceId) -> Result<bool> {
        let metadata_path = self.base_path.join("metadata").join(format!("published_bundle_{}", device_id));
        
        if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            Ok(content.trim() == "true")
        } else {
            Ok(false)
        }
    }

    /// Sanitize JID for use in filenames
    /// Convert JID to alphanumeric filename
    fn jid_to_alphanumeric(&self, jid: &str) -> String {
        jid.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("{:02x}", c as u8)
                }
            })
            .collect()
    }

    /// Legacy method for backward compatibility - now uses alphanumeric encoding
    fn sanitize_jid(&self, jid: &str) -> String {
        self.jid_to_alphanumeric(jid)
    }    
    /// Dump all device identities for debugging
    pub fn dump_all_device_identities(&self) -> Result<Vec<(String, DeviceId, DeviceIdentity)>> {
        let mut identities = Vec::new();
        let identities_dir = self.base_path.join("identities");
        
        if !identities_dir.exists() {
            return Ok(identities);
        }
        
        // Iterate through JID directories
        for jid_entry in fs::read_dir(&identities_dir)? {
            let jid_entry = jid_entry?;
            if !jid_entry.file_type()?.is_dir() {
                continue;
            }
            
            let jid_name = jid_entry.file_name().to_string_lossy().to_string();
            // Convert back from safe filename to JID (reverse sanitization)
            let jid = jid_name.replace('_', "@"); // Simple conversion - may need more sophisticated handling
            
            // Iterate through device directories
            for device_entry in fs::read_dir(jid_entry.path())? {
                let device_entry = device_entry?;
                if !device_entry.file_type()?.is_dir() {
                    continue;
                }
                
                if let Ok(device_id) = device_entry.file_name().to_string_lossy().parse::<DeviceId>() {
                    let identity_path = device_entry.path().join("identity.bin");
                    if identity_path.exists() {
                        match Self::read_binary_file::<DeviceIdentity>(&identity_path) {
                            Ok(identity) => {
                                identities.push((jid.clone(), device_id, identity));
                            },
                            Err(e) => {
                                error!("Failed to load identity for {}:{}: {}", jid, device_id, e);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(identities)
    }
}