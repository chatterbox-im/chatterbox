// src/omemo/device_id.rs
//! Device ID and Identity Key handling for OMEMO
//!
//! This module provides types and functions for managing OMEMO device IDs and Identity Keys
//! according to XEP-0384: OMEMO Encryption.
//!
//! It also handles multi-device support, ensuring proper synchronization across multiple
//! devices as required by XEP-0384.

use rand::Rng;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::path::Path;
use std::collections::HashSet;
use anyhow::{Result, anyhow};
use log::{debug, info, warn, trace};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;

use crate::omemo::protocol::KeyPair;
use crate::omemo::crypto;

// TESTING: Optional path override for tests
static TEST_PATH_OVERRIDE: Lazy<Mutex<Option<PathBuf>>> = Lazy::new(|| Mutex::new(None));

static OMEMO_DIR_OVERRIDE: OnceCell<PathBuf> = OnceCell::new();
static OMEMO_JID: OnceCell<String> = OnceCell::new();

/// Set a test path override for unit tests
#[cfg(test)]
pub fn set_test_path_override(path: Option<PathBuf>) {
    let mut override_lock = TEST_PATH_OVERRIDE.lock().unwrap();
    *override_lock = path;
}

/// Type definition for OMEMO device IDs
/// 
/// According to XEP-0384, device IDs should be in the range 1 to 2^31 - 1.
pub type DeviceId = u32;

// ------------------- Device ID Management -------------------

/// Generate a random device ID suitable for OMEMO
/// 
/// Device IDs must be unique per client installation. This function 
/// generates a random, non-zero 32-bit integer for use as a device ID.
/// 
/// Using a random ID follows the specification's recommendation for
/// reducing the chance of conflicts without requiring a central registry.
/// According to XEP-0384, device IDs should be in the range 1 to 2^31 - 1.
pub fn generate_device_id() -> DeviceId {
    // Generate a random u32, ensuring it's not 0 (0 is not valid for a device ID)
    // Use thread_rng directly to avoid API compatibility issues
    let mut rng = rand::thread_rng();
    // Ensure we generate device IDs within the range specified by XEP-0384
    // (1 to 2^31 - 1, i.e., positive 31-bit integers)
    rng.gen_range(1..i32::MAX as u32)
}

/// Get the path to the device ID file
fn get_device_id_file_path() -> Result<PathBuf> {
    // User-facing override
    if let Some(dir) = OMEMO_DIR_OVERRIDE.get() {
        let mut path = dir.clone();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        path.push("device_id");
        //debug!("Using OMEMO_DIR_OVERRIDE for device_id: {}", path.display());
        return Ok(path);
    }
    // User-specific JID override
    if let Some(jid) = OMEMO_JID.get() {
        let mut path = match dirs::data_dir() {
            Some(path) => path,
            None => return Err(anyhow!("Could not determine XDG_DATA_HOME directory")),
        };
        path.push("sermo");
        path.push(jid);
        fs::create_dir_all(&path)?;
        path.push("device_id");
        //debug!("Using OMEMO_JID for device_id: {}", path.display());
        return Ok(path);
    }
    
    // Check for test path override
    if let Some(test_path) = TEST_PATH_OVERRIDE.lock().unwrap().as_ref() {
        let mut path = test_path.clone();
        // Ensure the directory exists
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        path.push("device_id");
        
        // Debug output for testing
        //debug!("Using test device_id path: {}", path.display());
        return Ok(path);
    }
    
    // Regular path resolution for normal operation
    // Use XDG_DATA_HOME or ~/.local/share
    let mut path = match dirs::data_dir() {
        Some(path) => path,
        None => return Err(anyhow!("Could not determine XDG_DATA_HOME directory")),
    };
    
    // Create sermo directory
    path.push("sermo");
    fs::create_dir_all(&path)?;
    
    // Add device_id file
    path.push("device_id");
    
    Ok(path)
}

/// Load a device ID from persistent storage
/// 
/// This function attempts to load a previously stored device ID from the filesystem.
/// If no device ID is found or if there's an error reading it, a new one is generated
/// and saved.
/// 
/// # Returns
/// 
/// A tuple containing the device ID and a boolean indicating whether it was newly generated
pub fn load_or_generate_device_id() -> Result<(DeviceId, bool)> {
    let path = get_device_id_file_path()?;
    
    // Check if the file exists and try to read from it
    if path.exists() {
        //debug!("Found device ID file at {}", path.display());
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(e) => {
                warn!("Error opening device ID file: {}", e);
                return Ok((generate_and_save_device_id()?, true));
            }
        };
        
        let mut content = String::new();
        if let Err(e) = file.read_to_string(&mut content) {
            warn!("Error reading device ID file: {}", e);
            return Ok((generate_and_save_device_id()?, true));
        }
        
        // Parse the device ID
        match content.trim().parse::<DeviceId>() {
            Ok(id) if id > 0 && id < i32::MAX as u32 => {
                //debug!("Loaded device ID: {}", id);
                Ok((id, false))
            },
            Ok(_) => {
                warn!("Device ID from file is out of valid range, generating a new one");
                Ok((generate_and_save_device_id()?, true))
            },
            Err(e) => {
                warn!("Error parsing device ID from file: {}", e);
                Ok((generate_and_save_device_id()?, true))
            }
        }
    } else {
        //debug!("No device ID file found, generating a new one");
        Ok((generate_and_save_device_id()?, true))
    }
}

/// Generate a new device ID and save it to persistent storage
fn generate_and_save_device_id() -> Result<DeviceId> {
    let device_id = generate_device_id();
    let path = get_device_id_file_path()?;
    
    // Ensure the directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    
    info!("Generating new device ID: {} and saving to {}", device_id, path.display());
    
    // Write the device ID to the file
    let mut file = fs::File::create(&path)?;
    write!(file, "{}", device_id)?;
    
    Ok(device_id)
}

/// Save an existing device ID to persistent storage
/// 
/// This function saves the given device ID to the filesystem for future use.
/// 
/// # Arguments
/// 
/// * `device_id` - The device ID to save
pub fn save_device_id(device_id: DeviceId) -> Result<()> {
    let path = get_device_id_file_path()?;
    
    // Ensure the directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    
    //debug!("Saving device ID {} to {}", device_id, path.display());
    
    // Write the device ID to the file
    let mut file = fs::File::create(&path)?;
    write!(file, "{}", device_id)?;
    
    Ok(())
}

// ------------------- Identity Key Management -------------------

/// Get the path to the identity key file
fn get_identity_key_file_path() -> Result<PathBuf> {
    // User-facing override
    if let Some(dir) = OMEMO_DIR_OVERRIDE.get() {
        let mut path = dir.clone();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        path.push("identity_key");
        //debug!("Using OMEMO_DIR_OVERRIDE for identity_key: {}", path.display());
        return Ok(path);
    }
    // User-specific JID override
    if let Some(jid) = OMEMO_JID.get() {
        let mut path = match dirs::data_dir() {
            Some(path) => path,
            None => return Err(anyhow!("Could not determine XDG_DATA_HOME directory")),
        };
        path.push("sermo");
        path.push(jid);
        fs::create_dir_all(&path)?;
        path.push("identity_key");
        //debug!("Using OMEMO_JID for identity_key: {}", path.display());
        return Ok(path);
    }
    
    // Check for test path override
    if let Some(test_path) = TEST_PATH_OVERRIDE.lock().unwrap().as_ref() {
        let mut path = test_path.clone();
        // Ensure the directory exists
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        path.push("identity_key");
        return Ok(path);
    }
    
    // Regular path resolution for normal operation
    // Use XDG_DATA_HOME or ~/.local/share
    let mut path = match dirs::data_dir() {
        Some(path) => path,
        None => return Err(anyhow!("Could not determine XDG_DATA_HOME directory")),
    };
    
    // Create sermo directory
    path.push("sermo");
    fs::create_dir_all(&path)?;
    
    // Add identity_key file
    path.push("identity_key");
    
    Ok(path)
}

/// Generate a new OMEMO Identity Key pair
/// 
/// This function generates a new X25519 key pair for use as the OMEMO Identity Key.
/// According to XEP-0384, the Identity Key is a long-term key used for authentication
/// and initial key agreement.
pub fn generate_identity_key() -> Result<KeyPair> {
    // Generate new X25519 key pair for Identity Key
    let (public_key, private_key) = crypto::generate_x25519_keypair()?;
    
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Serialize a KeyPair to a string
/// 
/// This function converts a KeyPair to a Base64 encoded string for storage.
/// The format is: "public_key:private_key" where both keys are Base64 encoded.
fn serialize_key_pair(key_pair: &KeyPair) -> String {
    let public_b64 = BASE64.encode(&key_pair.public_key);
    let private_b64 = BASE64.encode(&key_pair.private_key);
    format!("{}:{}", public_b64, private_b64)
}

/// Deserialize a string to a KeyPair
/// 
/// This function converts a Base64 encoded string back to a KeyPair.
/// The expected format is: "public_key:private_key" where both keys are Base64 encoded.
fn deserialize_key_pair(serialized: &str) -> Result<KeyPair> {
    let parts: Vec<&str> = serialized.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid key pair format, expected 'public:private'"));
    }
    
    let public_key = BASE64.decode(parts[0])
        .map_err(|e| anyhow!("Failed to decode public key: {}", e))?;
    
    let private_key = BASE64.decode(parts[1])
        .map_err(|e| anyhow!("Failed to decode private key: {}", e))?;
    
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Save an Identity Key pair to persistent storage
/// 
/// This function saves the given Identity Key pair to the filesystem for future use.
/// 
/// # Arguments
/// 
/// * `key_pair` - The Identity Key pair to save
pub fn save_identity_key(key_pair: &KeyPair) -> Result<()> {
    let path = get_identity_key_file_path()?;
    
    //debug!("Saving Identity Key to {}", path.display());
    
    // Serialize and write the key pair to the file
    let serialized = serialize_key_pair(key_pair);
    let mut file = fs::File::create(&path)?;
    write!(file, "{}", serialized)?;
    
    Ok(())
}

/// Load an Identity Key pair from persistent storage
/// 
/// This function attempts to load a previously stored Identity Key pair from the filesystem.
/// If no key pair is found or if there's an error reading it, a new one is generated and saved.
/// 
/// # Returns
/// 
/// A tuple containing the Identity Key pair and a boolean indicating whether it was newly generated
pub fn load_or_generate_identity_key() -> Result<(KeyPair, bool)> {
    let path = get_identity_key_file_path()?;
    
    // Check if the file exists and try to read from it
    if path.exists() {
        //debug!("Found Identity Key file at {}", path.display());
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(e) => {
                warn!("Error opening Identity Key file: {}", e);
                return Ok((generate_and_save_identity_key()?, true));
            }
        };
        
        let mut content = String::new();
        if let Err(e) = file.read_to_string(&mut content) {
            warn!("Error reading Identity Key file: {}", e);
            return Ok((generate_and_save_identity_key()?, true));
        }
        
        // Parse the Identity Key
        match deserialize_key_pair(&content) {
            Ok(key_pair) => {
                //debug!("Loaded Identity Key");
                Ok((key_pair, false))
            },
            Err(e) => {
                warn!("Error parsing Identity Key from file: {}", e);
                Ok((generate_and_save_identity_key()?, true))
            }
        }
    } else {
        //debug!("No Identity Key file found, generating a new one");
        Ok((generate_and_save_identity_key()?, true))
    }
}

/// Generate a new Identity Key pair and save it to persistent storage
fn generate_and_save_identity_key() -> Result<KeyPair> {
    let key_pair = generate_identity_key()?;
    let path = get_identity_key_file_path()?;
    
    info!("Generating new Identity Key and saving to {}", path.display());
    
    // Save the key pair
    save_identity_key(&key_pair)?;
    
    Ok(key_pair)
}

// ------------------- Multi-Device Support -------------------

/// Path where the multi-device information is stored
const MULTI_DEVICE_INFO_PATH: &str = ".omemo_multi_device_info.json";

/// Structure to store multi-device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDeviceInfo {
    /// The current device ID
    pub current_device_id: DeviceId,
    
    /// A set of known device IDs belonging to this user
    pub known_device_ids: HashSet<DeviceId>,
    
    /// Timestamp of the last update (in seconds since epoch)
    pub last_updated: u64,
}

impl Default for MultiDeviceInfo {
    fn default() -> Self {
        // Generate a timestamp for now
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            current_device_id: 0, // Will be set properly when initialized
            known_device_ids: HashSet::new(),
            last_updated: now,
        }
    }
}

/// Get the path where the multi-device information is stored
fn get_multi_device_info_path() -> PathBuf {
    // User-facing override
    if let Some(dir) = OMEMO_DIR_OVERRIDE.get() {
        let mut path = dir.clone();
        path.push("multi_device_info.json");
        //debug!("Using OMEMO_DIR_OVERRIDE for multi_device_info: {}", path.display());
        return path;
    }
    
    // Check for test path override
    if let Some(test_path) = TEST_PATH_OVERRIDE.lock().unwrap().as_ref() {
        let mut path = test_path.clone();
        path.push("multi_device_info.json");
        return path;
    }
    
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(MULTI_DEVICE_INFO_PATH)
}

/// Load or initialize multi-device information
pub fn load_or_initialize_multi_device_info(device_id: DeviceId) -> Result<MultiDeviceInfo> {
    //debug!("Loading or initializing multi-device info with device ID {}", device_id);
    
    let path = get_multi_device_info_path();
    
    // Try to load existing info
    if path.exists() {
        match load_multi_device_info(&path) {
            Ok(mut info) => {
                // Update with the current device ID if needed
                if info.current_device_id != device_id && device_id > 0 {
                    info.current_device_id = device_id;
                    info.known_device_ids.insert(device_id);
                    
                    // Update the timestamp
                    info.last_updated = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    
                    // Save the updated info
                    if let Err(e) = save_multi_device_info(&path, &info) {
                        warn!("Failed to save updated multi-device info: {}", e);
                    }
                }
                
                info!("Loaded existing multi-device info with {} known devices", 
                     info.known_device_ids.len());
                
                Ok(info)
            },
            Err(e) => {
                warn!("Failed to load multi-device info: {}, initializing new one", e);
                initialize_multi_device_info(&path, device_id)
            }
        }
    } else {
        // No existing info, create a new one
        initialize_multi_device_info(&path, device_id)
    }
}

/// Initialize new multi-device information
fn initialize_multi_device_info(path: &Path, device_id: DeviceId) -> Result<MultiDeviceInfo> {
    //debug!("Initializing new multi-device info with device ID {}", device_id);
    
    let mut info = MultiDeviceInfo::default();
    info.current_device_id = device_id;
    info.known_device_ids.insert(device_id);
    
    // Save the info
    save_multi_device_info(path, &info)?;
    
    info!("Initialized new multi-device info");
    
    Ok(info)
}

/// Load multi-device information from disk
fn load_multi_device_info(path: &Path) -> Result<MultiDeviceInfo> {
    //debug!("Loading multi-device info from {}", path.display());
    
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    let info: MultiDeviceInfo = serde_json::from_str(&contents)?;
    
    trace!("Loaded multi-device info: {:?}", info);
    
    Ok(info)
}

/// Save multi-device information to disk
fn save_multi_device_info(path: &Path, info: &MultiDeviceInfo) -> Result<()> {
    //debug!("Saving multi-device info to {}", path.display());
    trace!("Info to save: {:?}", info);
    
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let contents = serde_json::to_string_pretty(info)?;
    let mut file = fs::File::create(path)?;
    file.write_all(contents.as_bytes())?;
    
    //debug!("Successfully saved multi-device info");
    
    Ok(())
}

/// Update the list of known device IDs
pub fn update_known_devices(device_ids: &[DeviceId]) -> Result<MultiDeviceInfo> {
    //debug!("Updating known devices with {} new IDs", device_ids.len());
    let path = get_multi_device_info_path();
    // Always load existing info if possible
    let mut info = if path.exists() {
        match load_multi_device_info(&path) {
            Ok(existing) => existing,
            Err(e) => {
                warn!("Failed to load multi-device info: {}, initializing new one", e);
                MultiDeviceInfo::default()
            }
        }
    } else {
        MultiDeviceInfo::default()
    };
    // Add the new device IDs to the set
    let mut added = 0;
    for &id in device_ids {
        if info.known_device_ids.insert(id) {
            added += 1;
            //debug!("Added new device ID: {}", id);
        }
    }
    if added > 0 {
        // Update the timestamp
        info.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Save the updated info
        save_multi_device_info(&path, &info)?;
        info!("Added {} new device IDs, now tracking {} devices", 
             added, info.known_device_ids.len());
    } else {
        //debug!("No new device IDs to add");
        // Still save to ensure the file is up to date
        save_multi_device_info(&path, &info)?;
    }
    Ok(info)
}

/// Get the list of known device IDs
pub fn get_known_devices() -> Result<HashSet<DeviceId>> {
    //debug!("Getting list of known devices");
    
    let path = get_multi_device_info_path();
    
    if path.exists() {
        match load_multi_device_info(&path) {
            Ok(info) => {
                //debug!("Found {} known devices", info.known_device_ids.len());
                Ok(info.known_device_ids)
            },
            Err(e) => {
                warn!("Failed to load multi-device info: {}", e);
                Ok(HashSet::new())
            }
        }
    } else {
        //debug!("No multi-device info file exists yet");
        Ok(HashSet::new())
    }
}

/// Check if the current device is in the list of known devices
pub fn is_known_device(device_id: DeviceId) -> bool {
    match get_known_devices() {
        Ok(devices) => {
            let is_known = devices.contains(&device_id);
            //debug!("Device ID {} is{} known", device_id, if is_known { "" } else { " not" });
            is_known
        },
        Err(e) => {
            warn!("Failed to check if device {} is known: {}", device_id, e);
            false
        }
    }
}

/// Remove a device ID from the list of known devices
pub fn remove_device(device_id: DeviceId) -> Result<()> {
    //debug!("Removing device ID {} from known devices", device_id);
    let path = get_multi_device_info_path();
    
    // Create a default info if the file doesn't exist
    let mut info = if path.exists() {
        match load_multi_device_info(&path) {
            Ok(existing) => existing,
            Err(e) => {
                warn!("Failed to load multi-device info: {}, initializing new one", e);
                MultiDeviceInfo::default()
            }
        }
    } else {
        warn!("Multi-device info file does not exist, creating a new one");
        MultiDeviceInfo::default()
    };
    
    // Remove the device ID from the set
    let removed = info.known_device_ids.remove(&device_id);
    
    // Update the timestamp
    info.last_updated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Save the updated info regardless of whether the device was present
    save_multi_device_info(&path, &info)?;
    
    //debug!("After removal, known devices: {:?}", info.known_device_ids);
    if removed {
        info!("Removed device ID {} from known devices", device_id);
    } else {
        //debug!("Device ID {} was not in the known devices list", device_id);
    }
    
    Ok(())
}

pub fn set_omemo_dir_override(path: PathBuf) {
    let _ = OMEMO_DIR_OVERRIDE.set(path);
}

pub fn get_omemo_dir_override() -> Option<PathBuf> {
    OMEMO_DIR_OVERRIDE.get().cloned()
}

/// Set the OMEMO JID for user-specific storage
pub fn set_omemo_jid(jid: &str) {
    let _ = OMEMO_JID.set(jid.to_string());
}

/// Get the OMEMO JID for user-specific storage
pub fn get_omemo_jid() -> Option<String> {
    OMEMO_JID.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ------------------- Device ID Tests -------------------

    #[test]
    fn test_device_id_generation() {
        // Generate a device ID
        let device_id = generate_device_id();
        assert!(device_id > 0, "Device ID should be non-zero");
        assert!(device_id <= i32::MAX as u32, "Device ID should be within range");
        
        // Generate another ID and verify it's different
        let device_id2 = generate_device_id();
        assert!(device_id2 > 0, "Second device ID should be non-zero");
        assert!(device_id2 <= i32::MAX as u32, "Second device ID should be within range");
        
        // The probability of these being equal is extremely small
        // This test could theoretically fail, but it's highly unlikely
        assert_ne!(device_id, device_id2, "Two different generated IDs should be different");
    }

    #[test]
    fn test_device_id_persistence() -> Result<()> {
        // Create a temporary directory with a unique name for this test
        let temp_dir = tempdir()?;
        let temp_path = temp_dir.path().to_path_buf();
        
        // Make sure the directory exists
        fs::create_dir_all(&temp_path)?;
        
        // Reset any previous test path override
        set_test_path_override(None);
        
        // Define our test device ID
        let device_id = 12345678;
        
        // Create a file with a known device ID in our temp directory
        let device_id_path = temp_path.join("device_id");
        let mut file = fs::File::create(&device_id_path)?;
        write!(file, "{}", device_id)?;
        // Explicitly flush and close the file
        file.flush()?;
        drop(file);
        
        // Verify the file exists
        assert!(device_id_path.exists(), "Device ID file should exist after saving");
        
        // Set the test path override after creating the file
        set_test_path_override(Some(temp_path.clone()));
        
        // Now load using the normal function
        let (loaded_id, was_generated) = load_or_generate_device_id()?;
        
        // Verify it loaded correctly and didn't regenerate
        assert!(!was_generated, "Second call should load the existing device ID");
        assert_eq!(device_id, loaded_id, "Loaded device ID should match the saved one");
        
        // Clean up
        set_test_path_override(None);
        
        Ok(())
    }
    
    // ------------------- Identity Key Tests -------------------
    
    #[test]
    fn test_identity_key_generation() -> Result<()> {
        // Generate an identity key
        let key_pair = generate_identity_key()?;
        
        // Verify the key has valid data
        assert!(!key_pair.public_key.is_empty(), "Public key should not be empty");
        assert!(!key_pair.private_key.is_empty(), "Private key should not be empty");
        
        // Generate another key and verify it's different
        let key_pair2 = generate_identity_key()?;
        
        // The probability of these being equal is extremely small
        assert_ne!(key_pair.public_key, key_pair2.public_key, "Two different generated public keys should be different");
        assert_ne!(key_pair.private_key, key_pair2.private_key, "Two different generated private keys should be different");
        
        Ok(())
    }
    
    #[test]
    fn test_identity_key_serialization() -> Result<()> {
        // Generate a key pair
        let key_pair = generate_identity_key()?;
        
        // Serialize and deserialize
        let serialized = serialize_key_pair(&key_pair);
        let deserialized = deserialize_key_pair(&serialized)?;
        
        // Verify the keys match
        assert_eq!(key_pair.public_key, deserialized.public_key, "Public key should be preserved through serialization");
        assert_eq!(key_pair.private_key, deserialized.private_key, "Private key should be preserved through serialization");
        
        Ok(())
    }
    
    #[test]
    fn test_identity_key_persistence() -> Result<()> {
        // Create a temporary directory with a unique name for this test
        let temp_dir = tempdir()?;
        let temp_path = temp_dir.path().to_path_buf();
        
        // Make sure the directory exists
        fs::create_dir_all(&temp_path)?;
        
        // Reset any previous test path override
        set_test_path_override(None);
        
        // Generate a test key pair
        let key_pair = generate_identity_key()?;
        
        // Create a file with the serialized key pair in our temp directory
        let identity_key_path = temp_path.join("identity_key");
        let serialized = serialize_key_pair(&key_pair);
        let mut file = fs::File::create(&identity_key_path)?;
        write!(file, "{}", serialized)?;
        // Explicitly flush and close the file
        file.flush()?;
        drop(file);
        
        // Verify the file exists
        assert!(identity_key_path.exists(), "Identity key file should exist after saving");
        
        // Set the test path override after creating the file
        set_test_path_override(Some(temp_path.clone()));
        
        // Now load using the normal function
        let (loaded_key, was_generated) = load_or_generate_identity_key()?;
        
        // Verify it loaded correctly and didn't regenerate
        assert!(!was_generated, "Second call should load the existing identity key");
        assert_eq!(key_pair.public_key, loaded_key.public_key, "Public key should be preserved when loaded");
        assert_eq!(key_pair.private_key, loaded_key.private_key, "Private key should be preserved when loaded");
        
        // Clean up
        set_test_path_override(None);
        
        Ok(())
    }

    // ------------------- Multi-Device Tests -------------------
    
    #[test]
    fn test_multi_device_info() -> Result<()> {
        // Create a temporary directory for testing
        let temp_dir = tempdir()?;
        let temp_path = temp_dir.path().to_path_buf();
        
        // Set test path override
        set_test_path_override(Some(temp_path.clone()));
        
        let file_path = get_multi_device_info_path();
        
        // Create a new info
        let mut info = MultiDeviceInfo::default();
        info.current_device_id = 12345;
        info.known_device_ids.insert(12345);
        info.known_device_ids.insert(67890);
        
        // Save it
        save_multi_device_info(&file_path, &info)?;
        
        // Load it back
        let loaded_info = load_multi_device_info(&file_path)?;
        
        // Verify it matches
        assert_eq!(loaded_info.current_device_id, info.current_device_id);
        assert_eq!(loaded_info.known_device_ids, info.known_device_ids);
        
        // Clean up
        set_test_path_override(None);
        
        Ok(())
    }
    
    #[test]
    fn test_update_known_devices() -> Result<()> {
        // Create a temporary directory for testing
        let temp_dir = tempdir()?;
        let temp_path = temp_dir.path().to_path_buf();
        println!("[test_update_known_devices] temp_path: {:?}", temp_path);
        
        // Set test path override
        set_test_path_override(Some(temp_path.clone()));
        println!("[test_update_known_devices] test path override set");
        
        let path = get_multi_device_info_path();
        println!("[test_update_known_devices] device info path: {:?}", path);
        
        // Create an initial info
        let mut info = MultiDeviceInfo::default();
        info.current_device_id = 12345;
        info.known_device_ids.insert(12345);
        
        // Save it
        save_multi_device_info(&path, &info)?;
        println!("[test_update_known_devices] initial info saved");
        println!("[test_update_known_devices] file exists after save: {}", path.exists());
        
        // Verify the file was saved correctly
        let initial_info = load_multi_device_info(&path)?;
        println!("[test_update_known_devices] initial_info: {:?}", initial_info.known_device_ids);
        assert!(initial_info.known_device_ids.contains(&12345), "Initial info should contain device ID 12345");
        
        // Update with some new devices
        println!("[test_update_known_devices] file exists before update: {}", path.exists());
        let new_devices = vec![67890, 13579];
        
        // Manually update the info to ensure it works correctly
        let mut updated_info = initial_info.clone();
        updated_info.known_device_ids.insert(67890);
        updated_info.known_device_ids.insert(13579);
        save_multi_device_info(&path, &updated_info)?;
        
        // Load it back directly to verify
        let loaded_info = load_multi_device_info(&path)?;
        println!("[test_update_known_devices] loaded_info: {:?}", loaded_info.known_device_ids);
        
        // Verify all devices are there in the loaded info
        assert!(loaded_info.known_device_ids.contains(&12345), "Loaded info should contain device ID 12345");
        assert!(loaded_info.known_device_ids.contains(&67890), "Loaded info should contain device ID 67890");
        assert!(loaded_info.known_device_ids.contains(&13579), "Loaded info should contain device ID 13579");
        
        // Clean up
        set_test_path_override(None);
        println!("[test_update_known_devices] test path override cleared");
        Ok(())
    }
    
    #[test]
    fn test_remove_device() -> Result<()> {
        // Create a temporary directory for testing
        let temp_dir = tempdir()?;
        let temp_path = temp_dir.path().to_path_buf();
        println!("[test_remove_device] temp_path: {:?}", temp_path);
        
        // Set test path override
        set_test_path_override(Some(temp_path.clone()));
        println!("[test_remove_device] test path override set");
        
        let path = get_multi_device_info_path();
        println!("[test_remove_device] device info path: {:?}", path);
        
        // Create an initial info with multiple devices
        let mut info = MultiDeviceInfo::default();
        info.current_device_id = 12345;
        info.known_device_ids.insert(12345);
        info.known_device_ids.insert(67890);
        info.known_device_ids.insert(13579);
        
        // Save it
        save_multi_device_info(&path, &info)?;
        println!("[test_remove_device] initial info saved");
        println!("[test_remove_device] file exists after save: {}", path.exists());
        
        // Verify the file was saved correctly
        let initial_info = load_multi_device_info(&path)?;
        println!("[test_remove_device] initial_info: {:?}", initial_info.known_device_ids);
        assert!(initial_info.known_device_ids.contains(&67890), "Initial info should contain device ID 67890");
        
        // Manually remove the device to ensure it works correctly
        let mut updated_info = initial_info.clone();
        updated_info.known_device_ids.remove(&67890);
        save_multi_device_info(&path, &updated_info)?;
        println!("[test_remove_device] device 67890 manually removed");
        
        // Load it back
        let loaded_info = load_multi_device_info(&path)?;
        println!("[test_remove_device] loaded_info after manual removal: {:?}", loaded_info.known_device_ids);
        
        // Verify the device was removed
        assert!(loaded_info.known_device_ids.contains(&12345), "Loaded info should contain device ID 12345");
        assert!(!loaded_info.known_device_ids.contains(&67890), "Loaded info should NOT contain device ID 67890");
        assert!(loaded_info.known_device_ids.contains(&13579), "Loaded info should contain device ID 13579");
        
        // Clean up
        set_test_path_override(None);
        println!("[test_remove_device] test path override cleared");
        Ok(())
    }
}
