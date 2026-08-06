// src/omemo/storage.rs
//! Storage for OMEMO keys and sessions.
//!
//! This is a thin facade over [`crate::omemo::store_sqlite::SqliteStore`]. The
//! public API is unchanged from the previous filesystem implementation so that
//! call sites across the OMEMO and XMPP layers did not need to move; the
//! persistence mechanics underneath it did.
//!
//! Why the change: the old layout stored ratchet state as bare `bincode` blobs
//! in a directory tree whose names were derived from a lossy JID encoding, with
//! per-device flags kept as individual marker files. That combination produced
//! three separate failure modes — unversioned blobs breaking on any struct
//! change, JIDs containing digits failing to round-trip, and no way to update
//! two objects atomically. See the module docs in `store_sqlite.rs`.
//!
//! On first run with an existing filesystem store, `OmemoStorage::new` imports
//! it (see `store_migrate.rs`) and archives the old tree.

use crate::jid::BareJid;
use crate::omemo::device_id;
use crate::omemo::device_id::DeviceId;
use crate::omemo::protocol::{DeviceIdentity, RatchetState, X3DHKeyBundle};
use crate::omemo::store_migrate;
use crate::omemo::store_sqlite::SqliteStore;
use anyhow::{anyhow, Result};
use log::{debug, warn};
use once_cell::sync::OnceCell;
use std::fs;
use std::path::PathBuf;

/// Filename of the OMEMO database inside the data directory.
const DB_FILENAME: &str = "omemo.sqlite3";

/// Entry for a device list
pub struct DeviceListEntry {
    /// The JID of the user
    pub jid: String,

    /// The device IDs for this user
    pub device_ids: Vec<DeviceId>,

    /// The timestamp of the last update (seconds since epoch)
    pub last_update: i64,
}

/// BTBV (Blind Trust Before Verification) trust levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// First encounter — blindly trusted until user verifies any device for this contact
    Undecided,
    /// Explicitly trusted (user accepted but didn't verify fingerprint)
    Trusted,
    /// Manually verified (e.g. via QR code or fingerprint comparison)
    Verified,
    /// Explicitly untrusted / revoked
    Untrusted,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Undecided => "undecided",
            TrustLevel::Trusted => "trusted",
            TrustLevel::Verified => "verified",
            TrustLevel::Untrusted => "untrusted",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "undecided" => Ok(TrustLevel::Undecided),
            "trusted"   => Ok(TrustLevel::Trusted),
            "verified"  => Ok(TrustLevel::Verified),
            "untrusted" => Ok(TrustLevel::Untrusted),
            other       => Err(format!("unknown trust level: {:?}", other)),
        }
    }

    /// Whether this trust level allows encryption/decryption
    pub fn is_trusted(&self) -> bool {
        matches!(
            self,
            TrustLevel::Undecided | TrustLevel::Trusted | TrustLevel::Verified
        )
    }
}

/// SQLite-backed storage for OMEMO data
pub struct OmemoStorage {
    /// Root directory for OMEMO data (holds the database and any archived
    /// legacy tree). Retained because `identity_key_path` is part of the API.
    base_path: PathBuf,

    /// The backing store.
    store: SqliteStore,

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
        // Determine the storage path (unchanged resolution order).
        let base_path = match path {
            Some(p) => p,
            None => {
                if let Some(dir) = device_id::get_omemo_dir_override() {
                    dir.clone()
                } else if let Some(jid) = device_id::get_omemo_jid() {
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
                    let mut home = dirs::home_dir()
                        .ok_or_else(|| anyhow!("Could not determine home directory"))?;
                    home.push(".local");
                    home.push("share");
                    home.push("chatterbox");
                    home.push("omemo");
                    home
                }
            }
        };

        fs::create_dir_all(&base_path)?;

        let store = SqliteStore::open(&base_path.join(DB_FILENAME))?;

        // One-time import of the pre-SQLite filesystem tree.
        if store_migrate::legacy_store_present(&base_path) {
            if let Err(e) = store_migrate::import_legacy_store(&base_path, &store) {
                // Do not fail startup: the legacy tree is left in place so the
                // import can be retried, and the user can still send/receive
                // (sessions will simply be re-established).
                warn!("Legacy OMEMO import failed (continuing without it): {}", e);
            }
        }

        let device_id = Self::load_or_generate_device_id(&store)?;

        Ok(Self {
            base_path,
            store,
            device_id,
        })
    }

    /// Create a new OMEMO storage with default settings
    pub fn new_default() -> Result<Self> {
        Self::new(None)
    }

    /// Create an in-memory store. Tests only.
    #[cfg(test)]
    pub fn new_in_memory() -> Result<Self> {
        let store = SqliteStore::open_in_memory()?;
        let device_id = Self::load_or_generate_device_id(&store)?;
        Ok(Self {
            base_path: PathBuf::from("."),
            store,
            device_id,
        })
    }

    fn load_or_generate_device_id(store: &SqliteStore) -> Result<DeviceId> {
        if let Some(v) = store.get_meta("device_id")? {
            if let Ok(id) = v.trim().parse::<DeviceId>() {
                return Ok(id);
            }
            warn!("Stored OMEMO device_id '{}' is unparseable; regenerating", v);
        }
        let device_id = crate::omemo::device_id::generate_device_id();
        store.set_meta("device_id", &device_id.to_string())?;
        Ok(device_id)
    }

    /// Store a device ID
    pub fn store_device_id(&mut self, device_id: DeviceId) -> Result<()> {
        self.store.set_meta("device_id", &device_id.to_string())?;
        self.device_id = device_id;
        Ok(())
    }

    /// Get the device ID
    pub fn get_device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Path historically used for the identity key file.
    ///
    /// Retained for API compatibility; identity material now lives in the
    /// database, so this is only meaningful as a location hint.
    pub fn identity_key_path(&self) -> PathBuf {
        self.base_path.join("identity_key")
    }

    // ---------------------------------------------------------- device lists --

    /// Save a device list
    pub fn save_device_list(&self, entry: &DeviceListEntry) -> Result<()> {
        self.store
            .save_device_list(&entry.jid, &entry.device_ids, entry.last_update)
    }

    /// Load a device list
    pub fn load_device_list(&self, jid: &BareJid) -> Result<DeviceListEntry> {
        match self.store.load_device_list(jid.as_str())? {
            Some((device_ids, last_update)) => Ok(DeviceListEntry {
                jid: jid.to_string(),
                device_ids,
                last_update,
            }),
            None => Err(anyhow!("Device list not found for JID: {}", jid)),
        }
    }

    // ------------------------------------------------------------ identities --

    /// Store a device identity with BTBV trust model
    pub fn save_device_identity(
        &mut self,
        jid: &BareJid,
        identity: &DeviceIdentity,
    ) -> Result<()> {
        let trust_level = if self.has_verified_device(jid).unwrap_or(false) {
            TrustLevel::Untrusted
        } else {
            TrustLevel::Undecided
        };

        self.store
            .save_identity(jid.as_str(), identity, trust_level)?;
        // `save_identity` preserves an existing trust level on conflict, so set
        // it explicitly for the first-insert case and for an intentional change.
        self.store.set_trust(jid.as_str(), identity.id, trust_level)
    }

    /// Persist a freshly-fetched device identity with **identity-key pinning**.
    ///
    /// A device's OMEMO identity key is permanent; fingerprint verification pins
    /// it. If a *different* identity key was already stored for this device, the
    /// key has changed — a possible MITM (e.g. a malicious/compromised server
    /// republishing a bundle). In that case we do NOT carry over the previous
    /// trust: trust is reset to `Untrusted` and a pending verification is recorded
    /// so the existing UI flow prompts the user to re-verify. Otherwise the prior
    /// trust level is preserved (unchanged refetch behavior).
    ///
    /// `new_fingerprint` is the displayable fingerprint of `identity`'s identity
    /// key (computed by the caller via `generate_standard_fingerprint`). Returns
    /// `true` iff the identity key changed.
    pub fn save_fetched_identity(
        &mut self,
        jid: &BareJid,
        identity: &DeviceIdentity,
        new_fingerprint: &str,
    ) -> Result<bool> {
        let device_id = identity.id;

        // Read the previously-pinned key (if any) BEFORE overwriting it.
        let existing_key = self
            .load_device_identity(jid, device_id)
            .ok()
            .map(|e| e.identity_key);
        let existing_trust = self.get_trust_level(jid, device_id).ok();

        let key_changed = existing_key
            .as_ref()
            .map(|old| crate::omemo::crypto::identity_key_changed(old, &identity.identity_key))
            .unwrap_or(false);

        // Persist the new identity.
        self.save_device_identity(jid, identity)?;

        if key_changed {
            warn!(
                "OMEMO identity key for {}:{} CHANGED since last fetch — possible MITM. \
                 Resetting trust to Untrusted and flagging for re-verification.",
                jid, device_id
            );
            self.set_trust_level(jid, device_id, TrustLevel::Untrusted)?;
            if let Err(e) = self.store_pending_device_verification(jid, device_id, new_fingerprint)
            {
                warn!(
                    "Failed to record pending verification for changed key {}:{}: {}",
                    jid, device_id, e
                );
            }
        } else if let Some(trust) = existing_trust {
            if trust != TrustLevel::Undecided {
                self.set_trust_level(jid, device_id, trust)?;
            }
        }

        Ok(key_changed)
    }

    /// Load a device identity
    pub fn load_device_identity(
        &mut self,
        jid: &BareJid,
        device_id: DeviceId,
    ) -> Result<DeviceIdentity> {
        self.store.load_identity(jid.as_str(), device_id)?.ok_or_else(|| {
            anyhow!(
                "Device identity not found for JID: {}, device_id: {}",
                jid,
                device_id
            )
        })
    }

    /// Check if a device identity is trusted
    pub fn is_device_trusted(&self, jid: &BareJid, device_id: DeviceId) -> Result<bool> {
        Ok(self.get_trust_level(jid, device_id)? != TrustLevel::Untrusted)
    }

    /// Get the trust level for a device
    pub fn get_trust_level(&self, jid: &BareJid, device_id: DeviceId) -> Result<TrustLevel> {
        match self.store.get_trust(jid.as_str(), device_id)? {
            None => Ok(TrustLevel::Undecided),
            Some(s) => TrustLevel::from_str(&s)
                .map_err(|e| anyhow::anyhow!("corrupt trust value for {}:{}: {}", jid, device_id, e)),
        }
    }

    /// Set the trust level for a device
    pub fn set_trust_level(&self, jid: &BareJid, device_id: DeviceId, level: TrustLevel) -> Result<()> {
        self.store.set_trust(jid.as_str(), device_id, level)
    }

    /// Check if any device for a contact has been manually verified
    pub fn has_verified_device(&self, jid: &BareJid) -> Result<bool> {
        self.store
            .has_trust_level(jid.as_str(), TrustLevel::Verified)
    }

    /// Set the trust status of a device identity
    pub fn dump_all_device_identities(&self) -> Result<Vec<(String, DeviceId, DeviceIdentity)>> {
        // The filesystem version reconstructed the JID with
        // `jid_name.replace('_', "@")`, which never matched the hex encoding
        // actually used and so returned mangled JIDs. JIDs are now stored
        // verbatim.
        self.store.all_identities()
    }

    // --------------------------------------------------------------- bundles --

    /// Store a key bundle
    pub fn store_key_bundle(&self, bundle: &X3DHKeyBundle) -> Result<()> {
        self.store.store_key_bundle(bundle)
    }

    /// Load a key bundle
    pub fn load_key_bundle_with_id(&self, device_id: DeviceId) -> Result<Option<X3DHKeyBundle>> {
        self.store.load_key_bundle(device_id)
    }

    // -------------------------------------------------------------- sessions --

    /// Store a session
    pub fn save_session(&self, jid: &BareJid, device_id: DeviceId, state: &RatchetState) -> Result<()> {
        self.store.save_session(jid.as_str(), device_id, state)
    }

    /// Atomically persist a session together with the key bundle whose one-time
    /// prekey it consumed.
    ///
    /// Use this instead of `save_session` + `store_key_bundle` on the X3DH
    /// receive path: as two writes, a crash in between leaves either a burned
    /// OPK with no session or a session referencing an OPK we still advertise,
    /// both of which surface later as an unrecoverable session.
    pub fn commit_prekey_consumption(
        &self,
        jid: &BareJid,
        device_id: DeviceId,
        state: &RatchetState,
        bundle: &X3DHKeyBundle,
    ) -> Result<()> {
        self.store
            .commit_prekey_consumption(jid.as_str(), device_id, state, bundle)
    }

    /// Load all sessions, keyed as `"<jid>:<device_id>"`.
    pub fn load_all_sessions(&self) -> Result<std::collections::HashMap<String, RatchetState>> {
        let mut sessions = std::collections::HashMap::new();
        for (jid, device_id, state) in self.store.load_all_sessions()? {
            sessions.insert(format!("{}:{}", jid, device_id), state);
        }
        Ok(sessions)
    }

    /// Get the session state for a peer device
    pub fn get_session_ratchet_state(
        &self,
        jid: &BareJid,
        device_id: DeviceId,
    ) -> Result<Option<RatchetState>> {
        self.store.load_session(jid.as_str(), device_id)
    }

    /// Delete a session identified by `"<jid>:<device_id>"`.
    pub fn delete_session(&self, session_key: &str) -> Result<()> {
        // Split from the right: a full JID may itself contain ':' in the resource.
        let (jid, device_str) = session_key
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid session key format: {}", session_key))?;
        let device_id = device_str
            .parse::<DeviceId>()
            .map_err(|_| anyhow!("Invalid device ID in session key: {}", device_str))?;

        self.store.delete_session(jid, device_id)?;
        debug!("Deleted session {}:{}", jid, device_id);
        Ok(())
    }

    // -------------------------------------------------------------- metadata --

    /// Store the timestamp of the last PreKey rotation
    pub fn store_prekey_rotation_time(&self, timestamp: i64) -> Result<()> {
        self.store
            .set_meta("prekey_rotation_time", &timestamp.to_string())
    }

    /// Load the timestamp of the last PreKey rotation
    pub fn load_prekey_rotation_time(&self) -> Result<i64> {
        self.store
            .get_meta("prekey_rotation_time")?
            .and_then(|v| v.trim().parse::<i64>().ok())
            .ok_or_else(|| anyhow!("PreKey rotation time not found"))
    }

    /// Check if device list has been published
    pub async fn has_published_device_list(&self, jid: &BareJid) -> Result<bool> {
        self.store.is_device_list_published(jid.as_str())
    }

    /// Mark device list as published (can be called from both sync and async contexts)
    pub fn mark_device_list_published(&self, jid: &BareJid) -> Result<()> {
        self.store.mark_device_list_published(jid.as_str())
    }

    /// Check if bundle has been published
    pub async fn has_published_bundle(&self, device_id: DeviceId) -> Result<bool> {
        self.store.is_bundle_published(device_id)
    }

    /// Mark bundle as published
    pub async fn mark_bundle_published(&self, device_id: DeviceId) -> Result<()> {
        self.store.mark_bundle_published(device_id)
    }

    /// Check if a bundle has been published for a given device ID
    pub fn is_bundle_published(&self, device_id: DeviceId) -> Result<bool> {
        self.store.is_bundle_published(device_id)
    }

    /// Store information about a pending device verification
    pub fn store_pending_device_verification(
        &self,
        jid: &BareJid,
        device_id: DeviceId,
        fingerprint: &str,
    ) -> Result<()> {
        self.store
            .set_pending_verification(jid.as_str(), device_id, fingerprint)
    }

    /// Check if there's a pending verification for a device
    pub fn get_pending_device_verification(&self, jid: &BareJid) -> Result<Option<(DeviceId, String)>> {
        self.store.get_pending_verification(jid.as_str())
    }

    /// Remove a pending verification
    pub fn remove_pending_device_verification(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        self.store.remove_pending_verification(jid.as_str(), device_id)
    }

    // ------------------------------------------------------ per-device state --

    /// Update the last undecryptable message timestamp for a device
    pub fn update_last_undecryptable_message(
        &self,
        jid: &BareJid,
        device_id: DeviceId,
        timestamp: i64,
    ) -> Result<()> {
        // Timestamp and failure-count increment are now a single statement;
        // previously two file writes, so a crash between them lost the bump.
        self.store.record_undecryptable(jid.as_str(), device_id, timestamp)?;
        debug!(
            "Updated undecryptable message timestamp for {}:{} to {}",
            jid, device_id, timestamp
        );
        Ok(())
    }

    /// Set the ignore-until timestamp for a device
    pub fn set_device_ignore_until(
        &self,
        jid: &BareJid,
        device_id: DeviceId,
        ignore_until: std::time::SystemTime,
    ) -> Result<()> {
        let timestamp = ignore_until
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.store.set_ignore_until(jid.as_str(), device_id, timestamp)?;
        debug!(
            "Set device ignore until timestamp for {}:{} to {}",
            jid, device_id, timestamp
        );
        Ok(())
    }

    /// Get the ignore-until timestamp for a device
    pub fn get_device_ignore_until(
        &self,
        jid: &BareJid,
        device_id: DeviceId,
    ) -> Result<Option<std::time::SystemTime>> {
        Ok(self.store.get_ignore_until(jid.as_str(), device_id)?.map(|ts| {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts.max(0) as u64)
        }))
    }

    /// Clear the ignore status for a device
    pub fn clear_device_ignore_status(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        self.store.clear_ignore_until(jid.as_str(), device_id)?;
        debug!("Cleared ignore status for {}:{}", jid, device_id);
        Ok(())
    }

    /// Get the failure count for a device
    pub fn get_device_failure_count(&self, jid: &BareJid, device_id: DeviceId) -> Result<u32> {
        self.store.get_failure_count(jid.as_str(), device_id)
    }

    /// Reset the failure count for a device
    pub fn reset_device_failure_count(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        self.store.reset_failure_count(jid.as_str(), device_id)?;
        debug!("Reset failure count for {}:{}", jid, device_id);
        Ok(())
    }

    // --- Session rebuild / prekey-pending persistence -----------------------

    /// Mark that the session with `(jid, device_id)` needs to be rebuilt the
    /// next time we encrypt for that device.  Survives process restarts.
    pub fn set_session_rebuild_needed(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        self.store.set_rebuild_needed(jid.as_str(), device_id, true)
    }

    /// Clear the rebuild-needed flag once the rebuild has been performed.
    pub fn clear_session_rebuild_needed(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        self.store.set_rebuild_needed(jid.as_str(), device_id, false)
    }

    /// Mark that a PreKey message is pending for `(jid, device_id)`.
    pub fn set_prekey_pending(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.store.set_prekey_pending(jid.as_str(), device_id, Some(ts))
    }

    /// Clear the prekey-pending flag once the PreKey message has been sent.
    pub fn clear_prekey_pending(&self, jid: &BareJid, device_id: DeviceId) -> Result<()> {
        self.store.set_prekey_pending(jid.as_str(), device_id, None)
    }

    /// Return the unix timestamp (seconds) at which the prekey-pending flag was
    /// set, or `None` if the flag is not set.
    pub fn get_prekey_pending_since(&self, jid: &BareJid, device_id: DeviceId) -> Option<u64> {
        self.store
            .get_prekey_pending_since(jid.as_str(), device_id)
            .ok()
            .flatten()
            .map(|ts| ts.max(0) as u64)
    }

    /// Return all (jid, device_id) pairs that have the rebuild-needed flag set,
    /// so they can be loaded back into `pending_session_rebuilds` on startup.
    pub fn load_all_rebuild_pending(&self) -> Vec<(String, DeviceId)> {
        self.store.all_rebuild_pending().unwrap_or_else(|e| {
            warn!("Failed to load rebuild-pending set: {}", e);
            vec![]
        })
    }

    /// Return all (jid, device_id) pairs that have the prekey-pending flag set.
    pub fn load_all_prekey_pending(&self) -> Vec<(String, DeviceId)> {
        self.store.all_prekey_pending().unwrap_or_else(|e| {
            warn!("Failed to load prekey-pending set: {}", e);
            vec![]
        })
    }

    // --- Failed-message-ID persistence (TTL: 24 h) --------------------------

    /// Persist a message ID as "decryption failed".  Used on startup to seed the
    /// in-memory `recently_failed_ids` deque so that MAM replays of
    /// previously-failed messages do not double-count as new failures.
    pub fn persist_failed_message_id(&self, msg_id: &str) -> Result<()> {
        if msg_id.is_empty() || msg_id == "unknown" {
            return Ok(());
        }
        self.store.persist_failed_message_id(msg_id)
    }

    /// Load message IDs whose failure was recorded within `ttl_secs`.
    /// Entries older than the TTL are pruned during this call.
    pub fn load_recent_failed_message_ids(&self, ttl_secs: u64) -> Vec<String> {
        self.store
            .recent_failed_message_ids(ttl_secs)
            .unwrap_or_else(|e| {
                warn!("Failed to load recent failed message ids: {}", e);
                vec![]
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::omemo::protocol::{DeviceIdentity, PreKeyBundle, SignedPreKeyBundle};

    fn make_identity(device_id: DeviceId, key_byte: u8) -> DeviceIdentity {
        DeviceIdentity {
            id: device_id,
            identity_key: vec![key_byte; 32],
            signed_pre_key: SignedPreKeyBundle {
                id: 1,
                public_key: vec![0xAA; 32],
                signature: vec![0xBB; 64],
            },
            pre_keys: vec![PreKeyBundle {
                id: 1,
                public_key: vec![0xCC; 32],
            }],
        }
    }

    #[test]
    fn test_identity_key_pinning_resets_trust_on_change() {
        let mut storage = OmemoStorage::new_in_memory().unwrap();

        let jid = BareJid::parse("alice@example.org").unwrap();
        let dev = DeviceId::from(1234u32);

        // First contact: store identity A. No prior key → not a change.
        let id_a = make_identity(dev, 0x11);
        let changed = storage.save_fetched_identity(&jid, &id_a, "FP_A").unwrap();
        assert!(!changed, "first save must not be flagged as a key change");

        // User verifies the device.
        storage
            .set_trust_level(&jid, dev, TrustLevel::Verified)
            .unwrap();
        assert_eq!(
            storage.get_trust_level(&jid, dev).unwrap(),
            TrustLevel::Verified
        );

        // Same key refetched → trust preserved, no pending verification raised.
        let changed = storage.save_fetched_identity(&jid, &id_a, "FP_A").unwrap();
        assert!(!changed, "same key must not be flagged as changed");
        assert_eq!(
            storage.get_trust_level(&jid, dev).unwrap(),
            TrustLevel::Verified,
            "verified trust must survive a same-key refetch"
        );

        // Attacker swaps the identity key for the SAME device id.
        let id_b = make_identity(dev, 0x22);
        let changed = storage.save_fetched_identity(&jid, &id_b, "FP_B").unwrap();

        assert!(changed, "key swap MUST be detected");
        assert_eq!(
            storage.get_trust_level(&jid, dev).unwrap(),
            TrustLevel::Untrusted,
            "trust MUST be reset to Untrusted on key change (no MITM trust transfer)"
        );
        // New key is persisted.
        assert_eq!(
            storage.load_device_identity(&jid, dev).unwrap().identity_key,
            id_b.identity_key
        );
        // UI re-verification is flagged with the new fingerprint.
        assert_eq!(
            storage.get_pending_device_verification(&jid).unwrap(),
            Some((dev, "FP_B".to_string()))
        );
    }

    /// The previous implementation keyed storage on a lossy filename encoding,
    /// so a JID containing a digit was written under one name and read back
    /// under another. There is no encoding step any more; this pins that.
    #[test]
    fn jids_with_digits_survive_a_save_load_cycle() {
        let storage = OmemoStorage::new_in_memory().unwrap();
        for jid_str in ["user1@example.com", "b0b@example.com", "user@10.0.0.5"] {
            let jid = BareJid::parse(jid_str).unwrap();
            storage
                .save_device_list(&DeviceListEntry {
                    jid: jid_str.to_string(),
                    device_ids: vec![DeviceId::from(1), DeviceId::from(2), DeviceId::from(3)],
                    last_update: 42,
                })
                .unwrap();
            let back = storage.load_device_list(&jid).unwrap();
            assert_eq!(back.jid, jid_str);
            assert_eq!(back.device_ids, vec![DeviceId::from(1), DeviceId::from(2), DeviceId::from(3)]);
        }
    }

    #[test]
    fn delete_session_parses_key_from_the_right() {
        let storage = OmemoStorage::new_in_memory().unwrap();
        // Should not error even though the JID itself contains no colon.
        storage
            .delete_session("user1@example.com:440198320")
            .unwrap();
        assert!(storage.delete_session("malformed-key").is_err());
    }
}
