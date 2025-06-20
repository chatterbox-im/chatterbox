// src/omemo/storage.rs
//! Storage for OMEMO keys and sessions
//!
//! This module provides storage for OMEMO encryption.

use anyhow::{anyhow, Result};
use std::path::PathBuf;
use rusqlite::{params, Connection, OptionalExtension};
use crate::omemo::protocol::{DeviceIdentity, X3DHKeyBundle, RatchetState};
use crate::omemo::device_id::DeviceId;
use serde_json;
use log::error;
use once_cell::sync::OnceCell;
use crate::omemo::device_id;

/// Entry for a device list
pub struct DeviceListEntry {
    /// The JID of the user
    pub jid: String,
    
    /// The device IDs for this user
    pub device_ids: Vec<DeviceId>,
    
    /// The timestamp of the last update (seconds since epoch)
    pub last_update: i64,
}

/// Storage for OMEMO data
pub struct OmemoStorage {
    /// SQLite connection
    conn: Connection,
    
    /// Our device ID
    device_id: DeviceId,
}

static DB_PATH_OVERRIDE: OnceCell<PathBuf> = OnceCell::new();

pub fn set_db_path_override(path: PathBuf) {
    let _ = DB_PATH_OVERRIDE.set(path);
}

impl OmemoStorage {
    /// Create a new OMEMO storage
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        // Determine the database path
        let path = match path {
            Some(p) => p,
            None => {
                // If OMEMO_DIR_OVERRIDE is set, use it for omemo.db as well
                if let Some(dir) = device_id::get_omemo_dir_override() {
                    let mut db_path = dir.clone();
                    db_path.push("omemo.db");
                    db_path
                } else if let Some(jid) = device_id::get_omemo_jid() {
                    // Use user-specific directory for OMEMO db
                    let mut db_path = match dirs::data_dir() {
                        Some(path) => path,
                        None => return Err(anyhow!("Could not determine XDG_DATA_HOME directory")),
                    };
                    db_path.push("sermo");
                    db_path.push(&jid);
                    std::fs::create_dir_all(&db_path)?;
                    db_path.push("omemo.db");
                    db_path
                } else if let Some(override_path) = DB_PATH_OVERRIDE.get() {
                    override_path.clone()
                } else {
                    // Use the default path in the user's home directory
                    let mut home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
                    home.push(".local");
                    home.push("share");
                    home.push("sermo");
                    std::fs::create_dir_all(&home)?;
                    home.push("omemo.db");
                    home
                }
            }
        };
        
        // Create the connection
        let conn = Connection::open(&path)?;
        
        // Create the tables
        Self::create_tables(&conn)?;
        
        // Get the device ID
        let device_id = conn.query_row(
            "SELECT value FROM metadata WHERE key = 'device_id'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        Ok(Self {
            conn,
            device_id,
        })
    }

    /// Create a new OMEMO storage with default settings
    pub fn new_default() -> Result<Self> {
        // Use default path (None) for the storage
        Self::new(None)
    }
    
    /// Create the tables in the database
    fn create_tables(conn: &Connection) -> Result<()> {
        // Create the metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )",
            [],
        )?;
        
        // Create the device list table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS device_lists (
                jid TEXT PRIMARY KEY,
                device_ids TEXT,
                last_update INTEGER
            )",
            [],
        )?;
        
        // Create the identity table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS identities (
                jid TEXT,
                device_id INTEGER,
                identity_key BLOB,
                signed_prekey_id INTEGER,
                signed_prekey BLOB,
                signature BLOB,
                trusted INTEGER,
                PRIMARY KEY (jid, device_id)
            )",
            [],
        )?;
        
        // Create the prekeys table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS prekeys (
                jid TEXT,
                device_id INTEGER,
                prekey_id INTEGER,
                prekey BLOB,
                PRIMARY KEY (jid, device_id, prekey_id),
                FOREIGN KEY (jid, device_id) REFERENCES identities (jid, device_id)
                  ON DELETE CASCADE
            )",
            [],
        )?;
        
        // Create the sessions table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                jid TEXT,
                device_id INTEGER,
                session_data BLOB,
                last_updated INTEGER,
                PRIMARY KEY (jid, device_id)
            )",
            [],
        )?;
        
        // Create the key bundles table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS key_bundles (
                device_id INTEGER PRIMARY KEY,
                identity_key_pair BLOB,
                signed_prekey_id INTEGER,
                signed_prekey_pair BLOB,
                signed_prekey_signature BLOB,
                one_time_prekey_pairs BLOB,
                created_at INTEGER
            )",
            [],
        )?;
        
        Ok(())
    }
    
    /// Store a device ID
    pub fn store_device_id(&mut self, device_id: DeviceId) -> Result<()> {
        //debug!("Storing device ID: {}", device_id);
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params!["device_id", device_id.to_string()],
        )?;
        
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
        //debug!("[STORAGE DEBUG] save_device_list: saving device list for JID='{}', device_ids={:?}", entry.jid, entry.device_ids);
        // Serialize the device IDs to JSON
        let device_ids_json = serde_json::to_string(&entry.device_ids)?;
        
        // Store in the database
        self.conn.execute(
            "INSERT OR REPLACE INTO device_lists (jid, device_ids, last_update) VALUES (?, ?, ?)",
            params![entry.jid, device_ids_json, entry.last_update],
        )?;
        
        Ok(())
    }
    
    /// Fix for loading a device list with proper error handling
    pub fn load_device_list(&self, jid: &str) -> Result<DeviceListEntry> {
        //debug!("[STORAGE DEBUG] load_device_list: loading device list for JID='{}'", jid);
        let result = self.conn.query_row(
            "SELECT device_ids, last_update FROM device_lists WHERE jid = ?",
            params![jid],
            |row| {
                let device_ids_json: String = row.get(0)?;
                let last_update: i64 = row.get(1)?;
                
                // Handle JSON deserialization separately to properly map the error
                let device_ids = match serde_json::from_str::<Vec<DeviceId>>(&device_ids_json) {
                    Ok(ids) => ids,
                    Err(_e) => {
                        return Err(rusqlite::Error::InvalidColumnType(
                            0, 
                            "device_ids".to_string(), 
                            rusqlite::types::Type::Text
                        ));
                    }
                };
                
                Ok(DeviceListEntry {
                    jid: jid.to_string(),
                    device_ids,
                    last_update,
                })
            },
        )?;
        
        Ok(result)
    }
    
    /// Store a device identity
    pub fn save_device_identity(&mut self, jid: &str, identity: &DeviceIdentity, trusted: bool) -> Result<()> {
        //debug!("[STORAGE DEBUG] save_device_identity: saving device identity for JID='{}', device_id={}", jid, identity.id);
        // Start a transaction
        let tx = self.conn.transaction()?;
        
        // Store the identity
        tx.execute(
            "INSERT OR REPLACE INTO identities (
                jid, device_id, identity_key, signed_prekey_id, signed_prekey, signature, trusted
            ) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                jid,
                identity.id,
                identity.identity_key,
                identity.signed_pre_key.id,
                identity.signed_pre_key.public_key,
                identity.signed_pre_key.signature,
                trusted as i32
            ],
        )?;
        
        // Delete existing prekeys
        tx.execute(
            "DELETE FROM prekeys WHERE jid = ? AND device_id = ?",
            params![jid, identity.id],
        )?;
        
        // Store the prekeys
        for prekey in &identity.pre_keys {
            tx.execute(
                "INSERT INTO prekeys (jid, device_id, prekey_id, prekey) VALUES (?, ?, ?, ?)",
                params![jid, identity.id, prekey.id, prekey.public_key],
            )?;
        }
        
        // Commit the transaction
        tx.commit()?;
        
        Ok(())
    }
    
    /// Load a device identity
    pub fn load_device_identity(&mut self, jid: &str, device_id: DeviceId) -> Result<DeviceIdentity> {
        //debug!("[STORAGE DEBUG] load_device_identity: loading device identity for JID='{}', device_id={}", jid, device_id);
        // Start a transaction
        let tx = self.conn.transaction()?;
        
        // Load the identity
        let identity = tx.query_row(
            "SELECT identity_key, signed_prekey_id, signed_prekey, signature FROM identities
             WHERE jid = ? AND device_id = ?",
            params![jid, device_id],
            |row| {
                let identity_key: Vec<u8> = row.get(0)?;
                let signed_prekey_id: u32 = row.get(1)?;
                let signed_prekey: Vec<u8> = row.get(2)?;
                let signature: Vec<u8> = row.get(3)?;
                
                Ok((identity_key, signed_prekey_id, signed_prekey, signature))
            },
        )?;
        
        // Load the prekeys
        let mut stmt = tx.prepare(
            "SELECT prekey_id, prekey FROM prekeys
             WHERE jid = ? AND device_id = ?"
        )?;
        
        let prekey_rows = stmt.query_map(
            params![jid, device_id],
            |row| {
                let prekey_id: u32 = row.get(0)?;
                let prekey: Vec<u8> = row.get(1)?;
                
                Ok((prekey_id, prekey))
            },
        )?;
        
        let mut prekeys = Vec::new();
        for prekey_row in prekey_rows {
            let (prekey_id, prekey) = prekey_row?;
            prekeys.push(crate::omemo::protocol::PreKeyBundle {
                id: prekey_id,
                public_key: prekey,
            });
        }
        
        // Create the device identity
        let (identity_key, signed_prekey_id, signed_prekey, signature) = identity;
        let device_identity = DeviceIdentity {
            id: device_id,
            identity_key,
            signed_pre_key: crate::omemo::protocol::SignedPreKeyBundle {
                id: signed_prekey_id,
                public_key: signed_prekey,
                signature,
            },
            pre_keys: prekeys,
        };
        
        Ok(device_identity)
    }
    
    /// Check if a device identity is trusted
    pub fn is_device_trusted(&self, jid: &str, device_id: DeviceId) -> Result<bool> {
        let trusted = self.conn.query_row(
            "SELECT trusted FROM identities WHERE jid = ? AND device_id = ?",
            params![jid, device_id],
            |row| row.get::<_, i32>(0),
        ).optional()?;
        
        // If no record exists, consider the device untrusted
        Ok(trusted.unwrap_or(0) != 0)
    }
    
    /// Set the trust status of a device identity
    pub fn set_device_trust(&self, jid: &str, device_id: DeviceId, trusted: bool) -> Result<()> {
        // First check if the identity exists
        let exists: Option<i64> = self.conn.query_row(
            "SELECT 1 FROM identities WHERE jid = ? AND device_id = ?",
            params![jid, device_id],
            |row| row.get(0),
        ).optional()?;
        
        if exists.is_some() {
            // Update existing record
            self.conn.execute(
                "UPDATE identities SET trusted = ? WHERE jid = ? AND device_id = ?",
                params![trusted as i32, jid, device_id],
            )?;
        } else {
            // Create a minimal record if it doesn't exist
            self.conn.execute(
                "INSERT INTO identities (jid, device_id, identity_key, signed_prekey_id, signed_prekey, signature, trusted)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    jid, 
                    device_id, 
                    Vec::<u8>::new(), // Empty placeholder for required fields
                    0,
                    Vec::<u8>::new(),
                    Vec::<u8>::new(),
                    trusted as i32
                ],
            )?;
        }
        
        Ok(())
    }
    
    /// Store a key bundle
    pub fn store_key_bundle(&self, bundle: &X3DHKeyBundle) -> Result<()> {
        // Serialize the one-time prekey pairs
        let one_time_prekey_pairs = serde_json::to_vec(&bundle.one_time_pre_key_pairs)?;
        
        // Store in the database
        self.conn.execute(
            "INSERT OR REPLACE INTO key_bundles (
                device_id, identity_key_pair, signed_prekey_id, signed_prekey_pair,
                signed_prekey_signature, one_time_prekey_pairs, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                bundle.device_id,
                serde_json::to_vec(&bundle.identity_key_pair)?,
                bundle.signed_pre_key_id,
                serde_json::to_vec(&bundle.signed_pre_key_pair)?,
                &bundle.signed_pre_key_signature,
                one_time_prekey_pairs,
                chrono::Utc::now().timestamp()
            ],
        )?;
        
        Ok(())
    }
    
    /// Load a key bundle
    pub fn load_key_bundle_with_id(&self, device_id: DeviceId) -> Result<Option<X3DHKeyBundle>> {
        let result = self.conn.query_row(
            "SELECT
                identity_key_pair, signed_prekey_id, signed_prekey_pair,
                signed_prekey_signature, one_time_prekey_pairs
             FROM key_bundles
             WHERE device_id = ?",
            params![device_id],
            |row| {
                let identity_key_pair_json: Vec<u8> = row.get(0)?;
                let signed_prekey_id: u32 = row.get(1)?;
                let signed_prekey_pair_json: Vec<u8> = row.get(2)?;
                let signed_prekey_signature: Vec<u8> = row.get(3)?;
                let one_time_prekey_pairs_json: Vec<u8> = row.get(4)?;
                
                // Handle JSON deserialization separately with manual mapping of errors
                let identity_key_pair = match serde_json::from_slice::<crate::omemo::protocol::KeyPair>(&identity_key_pair_json) {
                    Ok(pair) => pair,
                    Err(e) => return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob, 
                        Box::new(e)
                    )),
                };
                
                let signed_prekey_pair = match serde_json::from_slice::<crate::omemo::protocol::KeyPair>(&signed_prekey_pair_json) {
                    Ok(pair) => pair,
                    Err(e) => return Err(rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Blob, 
                        Box::new(e)
                    )),
                };
                
                let one_time_prekey_pairs = match serde_json::from_slice::<std::collections::HashMap<u32, crate::omemo::protocol::KeyPair>>(&one_time_prekey_pairs_json) {
                    Ok(pairs) => pairs,
                    Err(e) => return Err(rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Blob, 
                        Box::new(e)
                    )),
                };
                
                let bundle = X3DHKeyBundle {
                    device_id,
                    identity_key_pair,
                    signed_pre_key_id: signed_prekey_id,
                    signed_pre_key_pair: signed_prekey_pair,
                    signed_pre_key_signature: signed_prekey_signature,
                    one_time_pre_key_pairs: one_time_prekey_pairs,
                };
                
                Ok(bundle)
            },
        ).optional()?;
        
        Ok(result)
    }
    
    /// Store a session
    pub fn save_session(&self, jid: &str, device_id: DeviceId, state: &RatchetState) -> Result<()> {
        //debug!("[STORAGE DEBUG] save_session: saving session for JID='{}', device_id={}", jid, device_id);
        // Serialize the session state
        let state_bytes = serde_json::to_vec(state)?;
        
        // Store in the database
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (jid, device_id, session_data, last_updated) VALUES (?, ?, ?, ?)",
            params![jid, device_id, state_bytes, chrono::Utc::now().timestamp()],
        )?;
        
        Ok(())
    }
    
    /// Load all sessions
    pub fn load_all_sessions(&self) -> Result<std::collections::HashMap<String, RatchetState>> {
        //debug!("[STORAGE DEBUG] load_all_sessions: loading all sessions");
        let mut stmt = self.conn.prepare(
            "SELECT jid, device_id, session_data FROM sessions"
        )?;
        
        let session_rows = stmt.query_map(
            [],
            |row| {
                let jid: String = row.get(0)?;
                let device_id: u32 = row.get(1)?;
                let session_data: Vec<u8> = row.get(2)?;
                
                Ok((jid, device_id, session_data))
            },
        )?;
        
        let mut sessions = std::collections::HashMap::new();
        for session_row in session_rows {
            let (jid, device_id, session_data) = session_row?;
            let key = format!("{}:{}", jid, device_id);
            
            match serde_json::from_slice::<RatchetState>(&session_data) {
                Ok(state) => {
                    sessions.insert(key, state);
                },
                Err(e) => {
                    error!("Failed to deserialize session for {}:{}: {}", jid, device_id, e);
                }
            }
        }
        
        Ok(sessions)
    }
    
    /// Get the session state for a peer device
    pub fn get_session_ratchet_state(&self, jid: &str, device_id: DeviceId) -> Result<Option<RatchetState>> {
        let result = self.conn.query_row(
            "SELECT session_data FROM sessions WHERE jid = ? AND device_id = ?",
            params![jid, device_id],
            |row| {
                let session_data: Vec<u8> = row.get(0)?;
                // Convert JSON to RatchetState - handle deserialization errors
                match serde_json::from_slice::<RatchetState>(&session_data) {
                    Ok(state) => Ok(state),
                    Err(e) => Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e)
                    )),
                }
            },
        ).optional()?;
        
        Ok(result)
    }
    
    /// Store the timestamp of the last PreKey rotation
    pub fn store_prekey_rotation_time(&self, timestamp: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params!["prekey_rotation_time", timestamp.to_string()],
        )?;
        
        Ok(())
    }
    
    /// Load the timestamp of the last PreKey rotation
    pub fn load_prekey_rotation_time(&self) -> Result<i64> {
        let timestamp = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = 'prekey_rotation_time'",
            [],
            |row| {
                let value: String = row.get(0)?;
                value.parse::<i64>().map_err(|_| rusqlite::Error::InvalidColumnType(
                    0, 
                    "prekey_rotation_time".to_string(), 
                    rusqlite::types::Type::Text
                ))
            },
        )?;
        
        Ok(timestamp)
    }

    /// Check if device list has been published
    pub async fn has_published_device_list(&self, jid: &str) -> Result<bool> {
        // Check the metadata table for a record indicating the device list was published
        let result = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = ?",
            params![format!("published_device_list:{}", jid)],
            |row| {
                let value: String = row.get(0)?;
                Ok(value == "true")
            },
        ).optional()?;
        
        Ok(result.unwrap_or(false))
    }
    
    /// Mark device list as published (can be called from both sync and async contexts)
    pub fn mark_device_list_published(&self, jid: &str) -> Result<()> {
        //debug!("Marking device list as published for {}", jid);
        
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params![
                format!("published_device_list:{}", jid),
                "true"
            ],
        )?;
        
        //debug!("Device list marked as published for {}", jid);
        
        Ok(())
    }
    
    /// Check if bundle has been published
    pub async fn has_published_bundle(&self, device_id: u32) -> Result<bool> {
        // Check the metadata table for a record indicating the bundle was published
        let result = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = ?",
            params![format!("published_bundle:{}", device_id)],
            |row| {
                let value: String = row.get(0)?;
                Ok(value == "true")
            },
        ).optional()?;
        
        Ok(result.unwrap_or(false))
    }
    
    /// Mark bundle as published
    pub async fn mark_bundle_published(&self, device_id: u32) -> Result<()> {
        //debug!("Marking bundle for device {} as published", device_id);
        
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params![
                format!("published_bundle:{}", device_id),
                "true"
            ],
        )?;
        
        Ok(())
    }

    /// Store information about a pending device verification
    pub fn store_pending_device_verification(&self, jid: &str, device_id: DeviceId, fingerprint: &str) -> Result<()> {
        //debug!("Storing pending verification for {}:{} with fingerprint {}", jid, device_id, fingerprint);
        
        // Store the pending verification in metadata
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            params![
                format!("pending_verification:{}:{}", jid, device_id),
                fingerprint
            ],
        )?;
        
        Ok(())
    }
    
    /// Check if there's a pending verification for a device
    pub fn get_pending_device_verification(&self, jid: &str) -> Result<Option<(DeviceId, String)>> {
        // Look for any pending verification for this JID
        let mut stmt = self.conn.prepare(
            "SELECT key, value FROM metadata WHERE key LIKE ?"
        )?;
        
        let rows = stmt.query_map(
            params![format!("pending_verification:{}:%", jid)],
            |row| {
                let key: String = row.get(0)?;
                let fingerprint: String = row.get(1)?;
                Ok((key, fingerprint))
            },
        )?;
        
        for row_result in rows {
            let (key, fingerprint) = row_result?;
            // Extract device ID from the key
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(device_id) = parts[2].parse::<DeviceId>() {
                    return Ok(Some((device_id, fingerprint)));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Remove a pending verification
    pub fn remove_pending_device_verification(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        //debug!("Removing pending verification for {}:{}", jid, device_id);
        
        self.conn.execute(
            "DELETE FROM metadata WHERE key = ?",
            params![format!("pending_verification:{}:{}", jid, device_id)],
        )?;
        
        Ok(())
    }

    /// Check if a bundle has been published for a given device ID
    pub fn is_bundle_published(&self, device_id: DeviceId) -> Result<bool> {
        // Check the metadata table for a record indicating the bundle was published
        let result = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = ?",
            params![format!("published_bundle:{}", device_id)],
            |row| {
                let value: String = row.get(0)?;
                Ok(value == "true")
            },
        ).optional()?;
        
        Ok(result.unwrap_or(false))
    }

    /// Dump all device identities for debugging
    pub fn dump_all_device_identities(&self) -> Result<Vec<(String, DeviceId, DeviceIdentity)>> {
        let mut identities = Vec::new();
        
        let conn = &self.conn;
        
        // Query all device identities
        let query = "SELECT jid, device_id, identity_key, signed_prekey_id, signed_prekey, \
                     signed_prekey_signature FROM identities";
                     
        let mut stmt = conn.prepare(query)?;
        
        let mut rows = stmt.query([])?;
        
        // Properly iterate through the rows one at a time
        loop {
            // First handle the Result layer
            let row_opt = match rows.next() {
                Ok(opt) => opt,
                Err(e) => return Err(anyhow!("Error iterating rows: {}", e).into()),
            };
            
            // Then handle the Option layer
            let row = match row_opt {
                Some(r) => r,
                None => break, // No more rows, exit loop
            };
            
            let jid: String = row.get(0)?;
            let device_id: u32 = row.get(1)?;
            let identity_key: Vec<u8> = row.get(2)?;
            let signed_pre_key_id: u32 = row.get(3)?;
            let signed_pre_key: Vec<u8> = row.get(4)?;
            let signature: Vec<u8> = row.get(5)?;
            
            // Create device identity
            let identity = DeviceIdentity {
                id: device_id,
                identity_key,
                signed_pre_key: crate::omemo::protocol::SignedPreKeyBundle {
                    id: signed_pre_key_id,
                    public_key: signed_pre_key,
                    signature,
                },
                pre_keys: Vec::new(), // Not needed for debugging
            };
            
            identities.push((jid, device_id, identity));
        }
        
        Ok(identities)
    }
}