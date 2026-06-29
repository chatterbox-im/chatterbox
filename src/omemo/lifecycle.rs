// src/omemo/lifecycle.rs
//! OMEMO lifecycle management: initialization, device discovery, trust, sessions, publishing

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use tokio::time::{timeout, Duration};

use crate::omemo::device_discovery;
use crate::omemo::device_id::DeviceId;
use crate::omemo::protocol::{self, RatchetState, X3DHProtocol};
use crate::omemo::session::{OmemoSession, OmemoSessionState};
use crate::omemo::storage::{self, TrustLevel};
use crate::omemo::{OmemoError, OmemoManager, OMEMO_NAMESPACE};
use base64::Engine;

impl OmemoManager {
    /// Initialize or load the key bundle with a persistent identity key
    pub(crate) async fn initialize_key_bundle_with_persistent_identity(
        &mut self,
    ) -> Result<(), OmemoError> {
        debug!(
            "Initializing key bundle with persistent identity key for device {}",
            self.device_id
        );

        // First, try to load an existing key bundle from storage
        let storage_guard = self.storage.lock().await;
        let bundle_result = storage_guard.load_key_bundle_with_id(self.device_id);
        drop(storage_guard);

        if let Ok(Some(bundle)) = bundle_result {
            info!("Loaded existing key bundle for device {}", self.device_id);
            self.key_bundle = Some(bundle);
            return Ok(());
        }

        // No bundle in storage, need to generate a new one
        let identity_key_path = {
            let storage_guard = self.storage.lock().await;
            storage_guard.identity_key_path()
        };
        let identity_key_pair = match crate::omemo::device_id::load_or_generate_identity_key_at(
            &identity_key_path,
        ) {
            Ok((key_pair, was_generated)) => {
                if was_generated {
                    info!(
                        "Generated new persistent identity key for device {}",
                        self.device_id
                    );
                } else {
                    info!(
                        "Loaded existing persistent identity key for device {}",
                        self.device_id
                    );
                }
                key_pair
            }
            Err(e) => {
                warn!("Failed to load/generate persistent identity key: {}, generating a temporary one", e);
                protocol::X3DHProtocol::generate_key_pair().map_err(|e| {
                    OmemoError::ProtocolError(format!("Failed to generate identity key: {}", e))
                })?
            }
        };

        info!(
            "Generating new key bundle for device {} using persistent identity key",
            self.device_id
        );

        let signed_pre_key_pair = protocol::X3DHProtocol::generate_key_pair().map_err(|e| {
            OmemoError::ProtocolError(format!("Failed to generate signed prekey: {}", e))
        })?;

        let signed_pre_key_signature = protocol::X3DHProtocol::sign_pre_key(
            &identity_key_pair.private_key,
            &signed_pre_key_pair.public_key,
        )
        .map_err(|e| OmemoError::ProtocolError(format!("Failed to sign prekey: {}", e)))?;

        let mut one_time_pre_key_pairs = std::collections::HashMap::new();
        let num_prekeys = 20;

        for i in 1..=num_prekeys {
            let pair = protocol::X3DHProtocol::generate_key_pair().map_err(|e| {
                OmemoError::ProtocolError(format!("Failed to generate one-time prekey: {}", e))
            })?;
            one_time_pre_key_pairs.insert(i, pair);
        }

        let bundle = protocol::X3DHKeyBundle {
            device_id: self.device_id,
            identity_key_pair,
            signed_pre_key_id: 1,
            signed_pre_key_pair,
            signed_pre_key_signature,
            one_time_pre_key_pairs,
            signed_pre_key_history: std::collections::HashMap::new(),
        };

        let storage_guard = self.storage.lock().await;
        storage_guard
            .store_key_bundle(&bundle)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store key bundle: {}", e)))?;
        drop(storage_guard);

        self.key_bundle = Some(bundle);
        info!(
            "Generated and stored new key bundle with persistent identity key for device {}",
            self.device_id
        );

        Ok(())
    }

    /// Load existing sessions from storage
    pub(crate) async fn load_sessions(&mut self) -> Result<(), OmemoError> {
        debug!("Loading existing OMEMO sessions from storage");

        let storage_guard = self.storage.lock().await;
        let sessions = storage_guard
            .load_all_sessions()
            .map_err(|e| OmemoError::StorageError(format!("Failed to load sessions: {}", e)))?;
        drop(storage_guard);

        for (key, state) in sessions {
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

            let bare_jid = Self::normalize_jid_to_bare(&jid);
            // Use `from_state` rather than `new()` + `restore_from_state()` so the
            // session is fully initialized in a single step — no uninitialized window.
            let session = OmemoSession::from_state(self.device_id, state);
            self.sessions
                .insert((bare_jid, device_id), OmemoSessionState::Active(session));
        }

        info!("Loaded {} existing sessions", self.sessions.len());

        Ok(())
    }

    /// Store a session's ratchet state
    pub async fn store_session_state(
        &mut self,
        jid: &str,
        device_id: DeviceId,
        state: &RatchetState,
    ) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(jid);

        let storage_guard = self.storage.lock().await;
        storage_guard
            .save_session(&bare_jid, device_id, state)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store session: {}", e)))?;

        debug!("Stored session state for {}:{}", bare_jid, device_id);
        Ok(())
    }

    /// Force refresh device list for a JID (public method)
    pub async fn force_refresh_device_list(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        info!("[OMEMO] Force refreshing device list for {}", jid);
        self.get_device_ids_with_force_refresh(jid, true).await
    }

    /// Get the device IDs for a user
    pub(crate) async fn get_device_ids(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        self.get_device_ids_with_force_refresh(jid, false).await
    }

    /// Get the device IDs for a user with optional force refresh
    pub(crate) async fn get_device_ids_with_force_refresh(
        &self,
        jid: &str,
        force_refresh: bool,
    ) -> Result<Vec<DeviceId>, OmemoError> {
        debug!(
            "[OMEMO] get_device_ids: called with jid = {}, force_refresh = {}",
            jid, force_refresh
        );

        if !jid.contains('@') {
            warn!(
                "[OMEMO] get_device_ids: Invalid JID format (missing @): {}",
                jid
            );
            return Err(OmemoError::InvalidInput(format!(
                "Invalid JID format: {}",
                jid
            )));
        }

        let bare_jid = if jid.contains('/') {
            jid.split('/').next().unwrap_or(jid)
        } else {
            jid
        };

        // If not force refresh, try cached data first
        if !force_refresh {
            let storage_guard = self.storage.lock().await;
            if let Ok(entry) = storage_guard.load_device_list(bare_jid) {
                if !entry.device_ids.is_empty() {
                    info!(
                        "[OMEMO] get_device_ids: Using cached device list for {}: {:?}",
                        bare_jid, entry.device_ids
                    );
                    drop(storage_guard);
                    return Ok(entry.device_ids);
                }
            }
            drop(storage_guard);
            debug!(
                "[OMEMO] get_device_ids: No cached data for {}, fetching from server",
                bare_jid
            );
        } else {
            debug!(
                "[OMEMO] get_device_ids: Force refresh requested for {}",
                bare_jid
            );
        }

        info!(
            "[OMEMO] get_device_ids: Fetching device list for {} from XMPP server",
            bare_jid
        );

        match self.fetch_device_list_from_server(bare_jid).await {
            Ok(ids) => {
                info!(
                    "[OMEMO] get_device_ids: Successfully fetched device list for {}: {:?}",
                    bare_jid, ids
                );

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let entry = storage::DeviceListEntry {
                    jid: bare_jid.to_string(),
                    device_ids: ids.clone(),
                    last_update: now,
                };

                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard.save_device_list(&entry) {
                    warn!("[OMEMO] get_device_ids: Failed to store device list: {}", e);
                }
                drop(storage_guard);

                return Ok(ids);
            }
            Err(e) => {
                warn!(
                    "[OMEMO] get_device_ids: Failed to fetch device list for {}: {}",
                    bare_jid, e
                );

                if e.to_string().contains("item-not-found")
                    || e.to_string().contains("No device list found")
                {
                    info!("[OMEMO] get_device_ids: No OMEMO devices found for {} (no device list published)", bare_jid);

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    let entry = storage::DeviceListEntry {
                        jid: bare_jid.to_string(),
                        device_ids: vec![],
                        last_update: now,
                    };

                    let storage_guard = self.storage.lock().await;
                    if let Err(e) = storage_guard.save_device_list(&entry) {
                        warn!(
                            "[OMEMO] get_device_ids: Failed to store empty device list: {}",
                            e
                        );
                    }
                    drop(storage_guard);

                    return Ok(vec![]);
                }

                // Fall back to cached data
                let storage_guard = self.storage.lock().await;
                if let Ok(entry) = storage_guard.load_device_list(bare_jid) {
                    if !entry.device_ids.is_empty() {
                        warn!("[OMEMO] get_device_ids: Using cached device list as fallback for {}: {:?}", bare_jid, entry.device_ids);
                        drop(storage_guard);
                        return Ok(entry.device_ids);
                    }
                }
                drop(storage_guard);

                error!(
                    "[OMEMO] get_device_ids: Fetch failed for {} with no cache fallback",
                    bare_jid
                );
                return Err(e);
            }
        }
    }

    /// Fetch device list from the XMPP server
    pub async fn fetch_device_list_from_server(&self, jid: &str) -> Result<Vec<u32>, OmemoError> {
        let bare_jid = if jid.contains('/') {
            jid.split('/').next().unwrap_or(jid)
        } else {
            jid
        };
        info!(
            "[OMEMO] fetch_device_list_from_server: Fetching OMEMO device list from server for {}",
            bare_jid
        );
        debug!(
            "[OMEMO] fetch_device_list_from_server: backtrace = {:?}",
            std::backtrace::Backtrace::capture()
        );

        // Use the enhanced device discovery module
        match device_discovery::fetch_device_list_with_fallbacks(bare_jid, self.pubsub()).await {
            Ok(devices) => {
                info!(
                    "[OMEMO] Found {} devices with enhanced discovery: {:?}",
                    devices.len(),
                    devices
                );
                return Ok(devices);
            }
            Err(e) => {
                warn!(
                    "[OMEMO] Enhanced device discovery failed: {}, falling back to basic method",
                    e
                );
            }
        }

        // Fall back to basic method
        {
            let standard_node = format!("{}:devices", OMEMO_NAMESPACE);
            info!("[OMEMO] Trying standard node: {}", standard_node);
            match self.pubsub.request_items(bare_jid, &standard_node).await {
                Ok(xml) => match self.parse_device_list_response(&xml) {
                    Ok(devices) if !devices.is_empty() => {
                        info!(
                            "[OMEMO] Found {} devices with standard namespace: {:?}",
                            devices.len(),
                            devices
                        );
                        return Ok(devices);
                    }
                    Ok(_) => {
                        info!("[OMEMO] No devices found with standard namespace, trying legacy");
                    }
                    Err(e) => {
                        warn!("[OMEMO] Failed to parse standard namespace response: {}", e);
                    }
                },
                Err(e) => {
                    info!("[OMEMO] Standard namespace failed: {}, trying legacy", e);
                }
            }

            let legacy_node = "eu.siacs.conversations.axolotl:devices";
            info!("[OMEMO] Trying legacy node: {}", legacy_node);
            match self.pubsub.request_items(bare_jid, &legacy_node).await {
                Ok(xml) => match self.parse_device_list_response(&xml) {
                    Ok(devices) => {
                        info!(
                            "[OMEMO] Found {} devices with legacy namespace: {:?}",
                            devices.len(),
                            devices
                        );
                        return Ok(devices);
                    }
                    Err(e) => {
                        warn!("[OMEMO] Failed to parse legacy namespace response: {}", e);
                        return Err(e);
                    }
                },
                Err(e) => {
                    error!("[OMEMO] Both standard and legacy namespace failed: {}", e);
                    return Err(OmemoError::ProtocolError(format!(
                        "Failed to fetch device list from both namespaces: {}",
                        e
                    )));
                }
            }
        }
    }

    /// Get our key bundle for publishing
    pub fn get_key_bundle_xml(&self) -> Result<String, OmemoError> {
        debug!("Getting key bundle XML for device {}", self.device_id);

        let bundle = match &self.key_bundle {
            Some(bundle) => bundle,
            None => {
                return Err(OmemoError::MissingDataError(
                    "Key bundle not initialized".to_string(),
                ))
            }
        };

        let identity = protocol::DeviceIdentity {
            id: self.device_id,
            identity_key: bundle.identity_key_pair.public_key.clone(),
            signed_pre_key: protocol::SignedPreKeyBundle {
                id: bundle.signed_pre_key_id,
                public_key: bundle.signed_pre_key_pair.public_key.clone(),
                signature: bundle.signed_pre_key_signature.clone(),
            },
            pre_keys: bundle
                .one_time_pre_key_pairs
                .iter()
                .map(|(id, pair)| protocol::PreKeyBundle {
                    id: *id,
                    public_key: pair.public_key.clone(),
                })
                .collect(),
        };

        let xml = protocol::utils::device_bundle_to_xml(&identity).map_err(|e| {
            OmemoError::ProtocolError(format!("Failed to create bundle XML: {}", e))
        })?;

        Ok(xml)
    }

    /// Get our device list for publishing
    pub fn get_device_list_xml(&self) -> Result<String, OmemoError> {
        debug!("Getting device list XML");

        let device_ids = vec![self.device_id];
        let xml = protocol::utils::device_list_to_xml(&device_ids).map_err(|e| {
            OmemoError::ProtocolError(format!("Failed to create device list XML: {}", e))
        })?;

        Ok(xml)
    }

    /// Check if PreKeys need rotation and rotate if necessary
    pub async fn check_and_rotate_prekeys(&mut self) -> Result<bool, OmemoError> {
        debug!("Checking if PreKeys need rotation");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| OmemoError::ProtocolError(format!("Time error: {}", e)))?
            .as_secs();

        if (now - self.prekey_rotation_config.last_rotation)
            < self.prekey_rotation_config.check_interval
        {
            debug!("Not time to rotate PreKeys yet");
            return Ok(false);
        }

        info!("Performing PreKey rotation");

        let current_bundle = match &self.key_bundle {
            Some(bundle) => bundle.clone(),
            None => {
                return Err(OmemoError::MissingDataError(
                    "Key bundle not initialized".to_string(),
                ))
            }
        };

        info!("Generating new signed PreKey");
        let signed_pre_key_pair = X3DHProtocol::generate_key_pair().map_err(|e| {
            OmemoError::ProtocolError(format!("Failed to generate signed PreKey: {}", e))
        })?;

        let signed_pre_key_id = current_bundle.signed_pre_key_id + 1;

        let signed_pre_key_signature = X3DHProtocol::sign_pre_key(
            &current_bundle.identity_key_pair.private_key,
            &signed_pre_key_pair.public_key,
        )
        .map_err(|e| OmemoError::ProtocolError(format!("Failed to sign PreKey: {}", e)))?;

        let remaining_one_time_prekeys = current_bundle.one_time_pre_key_pairs.len() as u32;
        let mut one_time_pre_key_pairs = current_bundle.one_time_pre_key_pairs.clone();

        if remaining_one_time_prekeys < self.prekey_rotation_config.min_one_time_prekeys {
            info!("Generating additional one-time PreKeys");
            let to_generate =
                self.prekey_rotation_config.min_one_time_prekeys - remaining_one_time_prekeys;

            let mut max_id = 0;
            for id in one_time_pre_key_pairs.keys() {
                if *id > max_id {
                    max_id = *id;
                }
            }

            for i in 1..=to_generate {
                let key_pair = X3DHProtocol::generate_key_pair().map_err(|e| {
                    OmemoError::ProtocolError(format!("Failed to generate one-time PreKey: {}", e))
                })?;
                one_time_pre_key_pairs.insert(max_id + i, key_pair);
            }
        }

        let new_bundle = protocol::X3DHKeyBundle {
            device_id: self.device_id,
            identity_key_pair: current_bundle.identity_key_pair.clone(),
            signed_pre_key_id,
            signed_pre_key_pair,
            signed_pre_key_signature,
            one_time_pre_key_pairs,
        signed_pre_key_history: {
            // Move the outgoing SPK into history so peers that built a
            // PreKeySignalMessage against it before the rotation can still
            // establish a session.  Trim to the last SPK_HISTORY_DEPTH entries.
            const SPK_HISTORY_DEPTH: usize = 5;
            let mut history = current_bundle.signed_pre_key_history.clone();
            history.insert(
                current_bundle.signed_pre_key_id,
                current_bundle.signed_pre_key_pair.clone(),
            );
            if history.len() > SPK_HISTORY_DEPTH {
                let mut ids: Vec<u32> = history.keys().copied().collect();
                ids.sort_unstable();
                for old_id in ids.iter().take(ids.len() - SPK_HISTORY_DEPTH) {
                    history.remove(old_id);
                }
            }
            history
        },
        };

        let storage_guard = self.storage.lock().await;
        storage_guard
            .store_key_bundle(&new_bundle)
            .map_err(|e| OmemoError::StorageError(format!("Failed to store key bundle: {}", e)))?;
        drop(storage_guard);

        self.key_bundle = Some(new_bundle);
        self.prekey_rotation_config.last_rotation = now;

        let storage_guard = self.storage.lock().await;
        storage_guard
            .store_prekey_rotation_time(now as i64)
            .map_err(|e| {
                OmemoError::StorageError(format!("Failed to store rotation time: {}", e))
            })?;

        info!("PreKey rotation completed successfully");
        Ok(true)
    }

    /// Force reset all broken sessions
    pub async fn force_reset_broken_sessions(&mut self) -> Result<Vec<String>, OmemoError> {
        let mut reset_sessions = Vec::new();

        // Find all devices currently in recovery state (RecoveryPreKeySent) — these
        // are the "stuck" sessions that replaced the old pending_prekey_sends map.
        let stuck_sessions: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(key, state)| {
                if matches!(state, crate::omemo::session::OmemoSessionState::RecoveryPreKeySent { .. }) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for (bare_jid, device_id) in stuck_sessions {
            warn!(
                "Force resetting stuck session with {}:{}",
                bare_jid, device_id
            );
            if let Err(e) = self.reset_session(&bare_jid, device_id).await {
                error!(
                    "Failed to force reset session {}:{}: {}",
                    bare_jid, device_id, e
                );
            } else {
                reset_sessions.push(format!("{}:{}", bare_jid, device_id));
            }
        }

        if !reset_sessions.is_empty() {
            info!(
                "Force reset {} broken sessions: {:?}",
                reset_sessions.len(),
                reset_sessions
            );
        } else {
            info!("No broken sessions found to reset");
        }

        Ok(reset_sessions)
    }

    /// Ensure that our device list is published to the server
    pub async fn ensure_device_list_published(&self) -> Result<()> {
        debug!("Ensuring device list is published for {}", self.local_jid);

        let parts: Vec<&str> = self.local_jid.split('/').collect();
        let bare_jid = parts[0];

        debug!("Using bare JID for device list publishing: {}", bare_jid);

        let device_list_result = timeout(
            Duration::from_secs(5),
            self.fetch_device_list_from_server(bare_jid),
        )
        .await;
        let mut device_list = match device_list_result {
            Ok(Ok(devices)) => {
                info!("Found existing device list with {} devices", devices.len());
                devices
            }
            Ok(Err(e)) => {
                warn!(
                    "Failed to fetch existing device list: {}, starting with empty list",
                    e
                );
                Vec::new()
            }
            Err(_) => {
                error!(
                    "Timeout while fetching device list from server for {}",
                    bare_jid
                );
                Vec::new()
            }
        };
        info!(
            "[DEBUG] Proceeding after device list fetch. Device list: {:?}",
            device_list
        );

        // When CHATTERBOX_RESET_OMEMO_DEVICES is set (e.g. in CI), replace the
        // entire device list with only the current device and delete the bundle
        // nodes for every removed device.  This keeps the server-side list short
        // so that encryption loops don't time out after many accumulated runs.
        let reset_mode = std::env::var("CHATTERBOX_RESET_OMEMO_DEVICES")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        if reset_mode {
            let stale_ids: Vec<_> = device_list
                .iter()
                .copied()
                .filter(|&id| id != self.device_id)
                .collect();
            if !stale_ids.is_empty() {
                info!(
                    "RESET: Removing {} stale device(s) from list: {:?}",
                    stale_ids.len(),
                    stale_ids
                );
                // Publish a list containing only the current device
                if let Err(e) = self.pubsub.publish_device_list(&[self.device_id]).await {
                    error!("RESET: Failed to publish clean device list: {}", e);
                    return Err(anyhow!("Failed to publish clean device list: {}", e));
                }
                info!("RESET: Published clean device list with only device {}", self.device_id);
                // Best-effort: delete the bundle node for each removed device
                for stale_id in &stale_ids {
                    if let Err(e) = self.pubsub.delete_bundle(*stale_id).await {
                        warn!("RESET: Failed to delete bundle for device {}: {}", stale_id, e);
                    }
                }
            } else if !device_list.contains(&self.device_id) {
                // List was empty or already only had us; just publish current device
                if let Err(e) = self.pubsub.publish_device_list(&[self.device_id]).await {
                    error!("RESET: Failed to publish device list: {}", e);
                    return Err(anyhow!("Failed to publish device list: {}", e));
                }
            }
            device_list = vec![self.device_id];
        } else if !device_list.contains(&self.device_id) {
            info!("Adding our device ID {} to device list", self.device_id);
            device_list.push(self.device_id);

            if let Err(e) = self.pubsub.publish_device_list(&device_list).await {
                error!("Failed to publish device list: {}", e);
                return Err(anyhow!("Failed to publish device list: {}", e));
            }

            info!(
                "Published updated device list with {} devices",
                device_list.len()
            );
        } else {
            debug!(
                "Our device ID {} is already in the device list",
                self.device_id
            );
        }

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
        }
        info!("[DEBUG] Finished ensure_device_list_published, proceeding to bundle publication if needed.");
        Ok(())
    }

    /// Ensure that our device bundle is published to the server
    pub async fn ensure_bundle_published(&self) -> Result<()> {
        debug!("Ensuring bundle is published for device {}", self.device_id);
        let storage = self.storage.lock().await;
        info!(
            "[DEBUG] Forcing OMEMO bundle publication for device {}",
            self.device_id
        );
        let has_published = false;
        if !has_published {
            info!("Bundle not found or forced, publishing new bundle");
            let bundle = match self.generate_bundle().await {
                Ok(bundle) => bundle,
                Err(e) => {
                    error!("Failed to generate bundle: {}", e);
                    return Err(anyhow!("Failed to generate bundle: {}", e));
                }
            };
            match self.bundle_to_xml(&bundle) {
                Ok(xml) => info!("[DEBUG] Bundle XML to be published: {}", xml),
                Err(e) => error!("[DEBUG] Failed to convert bundle to XML: {}", e),
            }
            if let Err(e) = self.publish_bundle(bundle).await {
                error!("Failed to publish bundle: {}", e);
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

    /// Publish a device list to the server
    pub async fn publish_device_list(&self, bare_jid: &str) -> Result<(), OmemoError> {
        info!("Publishing device list for {}", bare_jid);

        let mut devices = self.get_device_ids_for(bare_jid).await?;

        let own_device_id = self.device_id;
        if !devices.contains(&own_device_id) {
            info!("Adding our device ID {} to device list", own_device_id);
            devices.push(own_device_id);
        }

        devices.sort();
        debug!("Publishing device list: {:?}", devices);

        match self.pubsub.publish_device_list(&devices).await {
            Ok(_) => {
                info!("Device list published successfully: {:?}", devices);

                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard.mark_device_list_published(bare_jid) {
                    warn!("Failed to mark device list as published: {}", e);
                }

                Ok(())
            }
            Err(e) => {
                error!("Failed to publish device list: {}", e);
                Err(OmemoError::PublicationError(format!(
                    "Failed to publish device list: {}",
                    e
                )))
            }
        }
    }

    /// Get the device IDs for a user (public wrapper for testing)
    pub async fn get_device_ids_for_test(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        self.get_device_ids(jid).await
    }

    /// Track an undecryptable message from a device
    pub async fn track_undecryptable_message(
        &mut self,
        remote_jid: &str,
        remote_device_id: u32,
    ) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.update_last_undecryptable_message(
            &bare_jid,
            remote_device_id,
            current_time as i64,
        ) {
            warn!("Failed to update undecryptable message timestamp: {}", e);
        }
        drop(storage_guard);

        let failure_count = self
            .get_device_failure_count(&bare_jid, remote_device_id)
            .await;
        if failure_count >= 3 {
            warn!(
                "Device {}:{} has {} consecutive failures, temporarily ignoring",
                bare_jid, remote_device_id, failure_count
            );
            if let Err(e) = self
                .ignore_device(
                    &bare_jid,
                    remote_device_id,
                    std::time::Duration::from_secs(300),
                )
                .await
            {
                warn!(
                    "Failed to ignore device {}:{}: {}",
                    bare_jid, remote_device_id, e
                );
            }
        }

        info!(
            "Tracked undecryptable message from {}:{} (failure count: {})",
            bare_jid, remote_device_id, failure_count
        );
        Ok(())
    }

    /// Ignore a device temporarily
    pub async fn ignore_device(
        &mut self,
        remote_jid: &str,
        remote_device_id: u32,
        duration: std::time::Duration,
    ) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);

        let ignore_until = std::time::SystemTime::now() + duration;

        let storage_guard = self.storage.lock().await;
        if let Err(e) =
            storage_guard.set_device_ignore_until(&bare_jid, remote_device_id, ignore_until)
        {
            warn!("Failed to set device ignore status: {}", e);
        }
        drop(storage_guard);

        info!(
            "Ignoring device {}:{} for {} seconds",
            bare_jid,
            remote_device_id,
            duration.as_secs()
        );
        Ok(())
    }

    /// Check if a device is currently being ignored
    pub async fn is_device_ignored(
        &self,
        remote_jid: &str,
        remote_device_id: u32,
    ) -> Result<bool, OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);

        let storage_guard = self.storage.lock().await;
        match storage_guard.get_device_ignore_until(&bare_jid, remote_device_id) {
            Ok(Some(ignore_until)) => {
                let now = std::time::SystemTime::now();
                Ok(now < ignore_until)
            }
            Ok(None) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// Get the number of consecutive decryption failures for a device
    pub(crate) async fn get_device_failure_count(
        &self,
        remote_jid: &str,
        remote_device_id: u32,
    ) -> u32 {
        let storage_guard = self.storage.lock().await;
        storage_guard
            .get_device_failure_count(remote_jid, remote_device_id)
            .unwrap_or(0)
    }

    /// Reset a session with a specific device
    pub async fn reset_session(
        &mut self,
        remote_jid: &str,
        remote_device_id: u32,
    ) -> Result<(), OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(remote_jid);
        let key = (bare_jid.clone(), remote_device_id);

        warn!(
            "Aggressively resetting OMEMO session with {}:{} due to repeated failures",
            bare_jid, remote_device_id
        );

        // Remove from memory
        self.sessions.remove(&key);

        // Remove from storage
        let session_key = format!("{}:{}", bare_jid, remote_device_id);
        let storage_guard = self.storage.lock().await;
        if let Err(e) = storage_guard.delete_session(&session_key) {
            warn!(
                "Failed to delete stored session for {}:{}: {}",
                bare_jid, remote_device_id, e
            );
        }

        if let Err(e) = storage_guard.clear_device_ignore_status(&bare_jid, remote_device_id) {
            warn!(
                "Failed to clear ignore status for {}:{}: {}",
                bare_jid, remote_device_id, e
            );
        }

        if let Err(e) = storage_guard.reset_device_failure_count(&bare_jid, remote_device_id) {
            warn!(
                "Failed to reset failure count for {}:{}: {}",
                bare_jid, remote_device_id, e
            );
        }

        // Clear persistent rebuild / prekey-pending flags so they are not
        // mistakenly re-loaded on the next restart.
        if let Err(e) = storage_guard.clear_session_rebuild_needed(&bare_jid, remote_device_id) {
            warn!(
                "Failed to clear rebuild flag for {}:{}: {}",
                bare_jid, remote_device_id, e
            );
        }
        if let Err(e) = storage_guard.clear_prekey_pending(&bare_jid, remote_device_id) {
            warn!(
                "Failed to clear prekey-pending flag for {}:{}: {}",
                bare_jid, remote_device_id, e
            );
        }
        drop(storage_guard);

        // Clear pending flags (the sessions map entry was already removed above).
        // pending_trust_restorations is cleared separately.

        info!(
            "Completely reset session with {}:{} - fresh start on next encryption/decryption",
            bare_jid, remote_device_id
        );
        info!(
            "Successfully reset session with {}:{}",
            bare_jid, remote_device_id
        );
        Ok(())
    }

    // --- Trust management ---

    /// Check if a device identity is trusted
    pub async fn is_device_identity_trusted(
        &self,
        sender: &str,
        device_id: DeviceId,
    ) -> Result<bool, OmemoError> {
        debug!(
            "Checking if device identity for {}:{} is trusted",
            sender, device_id
        );

        let storage_guard = self.storage.lock().await;
        let trusted = storage_guard
            .is_device_trusted(sender, device_id)
            .map_err(|e| OmemoError::StorageError(format!("Failed to check trust: {}", e)))?;

        Ok(trusted)
    }

    /// Mark a device identity as trusted
    pub async fn trust_device_identity(
        &mut self,
        sender: &str,
        device_id: DeviceId,
    ) -> Result<(), OmemoError> {
        debug!(
            "Marking device identity for {}:{} as trusted",
            sender, device_id
        );

        let bare_jid = Self::normalize_jid_to_bare(sender);

        // Only force a session rebuild when the device was **explicitly** Untrusted.
        // An Undecided device still has a valid session (it was never deliberately
        // rejected), so a rebuild is unnecessary and would disrupt the ratchet
        // state — causing carbon-decode failures when the remote sends self-messages.
        // Untrusted → Trusted means the user previously rejected the device and is
        // now re-trusting it; the old session may be stale/de-synchronised and must
        // be rebuilt with a fresh X3DH exchange.
        let was_not_trusted = {
            let storage_guard = self.storage.lock().await;
            storage_guard
                .get_trust_level(&bare_jid, device_id)
                .ok()
                .map(|t| t == TrustLevel::Untrusted)
                .unwrap_or(false)
        };

        {
            let storage_guard = self.storage.lock().await;
            storage_guard
                .set_trust_level(&bare_jid, device_id, TrustLevel::Trusted)
                .map_err(|e| OmemoError::StorageError(format!("Failed to set trust: {}", e)))?;
        }

        if was_not_trusted {
            info!(
                "Device {}:{} was not yet trusted — forcing session rebuild on next encrypt",
                bare_jid, device_id
            );
            let key = (bare_jid.clone(), device_id);
            // Delete the stale on-disk session state.
            {
                let session_key = format!("{}:{}", bare_jid, device_id);
                let storage_guard = self.storage.lock().await;
                let _ = storage_guard.delete_session(&session_key);
            }
            // Mark for full session rebuild by writing `PeerResetPending` directly
            // into the sessions map (replaces the old `pending_session_rebuilds` HashSet).
            self.sessions
                .insert(key.clone(), OmemoSessionState::PeerResetPending);
            {
                let storage_guard = self.storage.lock().await;
                if let Err(e) = storage_guard
                    .set_session_rebuild_needed(&bare_jid, device_id)
                {
                    warn!("Failed to persist rebuild flag for {}:{}: {}", bare_jid, device_id, e);
                }
            }
            // Remember to restore Trusted after the rebuild
            self.pending_trust_restorations.insert(key);
        }

        Ok(())
    }

    /// Mark a device identity as manually verified (BTBV)
    pub async fn verify_device_identity(
        &self,
        sender: &str,
        device_id: DeviceId,
    ) -> Result<(), OmemoError> {
        debug!(
            "Marking device identity for {}:{} as VERIFIED",
            sender, device_id
        );

        let storage_guard = self.storage.lock().await;
        storage_guard
            .set_trust_level(sender, device_id, TrustLevel::Verified)
            .map_err(|e| OmemoError::StorageError(format!("Failed to set verified: {}", e)))?;

        Ok(())
    }

    /// Mark a device identity as untrusted
    pub async fn untrust_device_identity(
        &self,
        sender: &str,
        device_id: DeviceId,
    ) -> Result<(), OmemoError> {
        debug!(
            "Marking device identity for {}:{} as untrusted",
            sender, device_id
        );

        let storage_guard = self.storage.lock().await;
        storage_guard
            .set_trust_level(sender, device_id, TrustLevel::Untrusted)
            .map_err(|e| OmemoError::StorageError(format!("Failed to set untrust: {}", e)))?;

        Ok(())
    }

    /// Get the BTBV trust level for a device
    pub async fn get_device_trust_level(
        &self,
        sender: &str,
        device_id: DeviceId,
    ) -> Result<TrustLevel, OmemoError> {
        let storage_guard = self.storage.lock().await;
        storage_guard
            .get_trust_level(sender, device_id)
            .map_err(|e| OmemoError::StorageError(format!("Failed to get trust level: {}", e)))
    }

    /// Get a fingerprint for a device identity
    pub async fn get_device_fingerprint(
        &self,
        sender: &str,
        device_id: DeviceId,
    ) -> Result<String, OmemoError> {
        debug!("Getting fingerprint for device {}:{}", sender, device_id);
        let device_identity = self.get_device_identity(sender, device_id).await?;
        let raw_bytes = &device_identity.identity_key;
        let hex_dump = raw_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        debug!(
            "Raw identity key for {}:{} ({} bytes): {}",
            sender,
            device_id,
            raw_bytes.len(),
            hex_dump
        );
        let hash = crate::omemo::crypto::sha256_hash(raw_bytes);
        let hash_hex = hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        debug!("SHA-256 hash for {}:{}: {}", sender, device_id, hash_hex);
        let fingerprint = self.generate_standard_fingerprint(raw_bytes);
        debug!(
            "Generated fingerprint for {}:{}: {}",
            sender, device_id, fingerprint
        );
        Ok(fingerprint)
    }

    /// Generate a standard fingerprint from a public key using SHA-256
    pub(crate) fn generate_standard_fingerprint(&self, public_key: &[u8]) -> String {
        let hash = crate::omemo::crypto::sha256_hash(public_key);
        debug!(
            "generate_standard_fingerprint: SHA-256 hash: {}",
            hash.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        let mut fingerprint = String::new();
        for (i, chunk) in hash.chunks(4).enumerate() {
            if i > 0 {
                fingerprint.push(' ');
            }
            for byte in chunk {
                fingerprint.push_str(&format!("{:02X}", byte));
            }
        }
        debug!(
            "generate_standard_fingerprint: Final fingerprint string: {}",
            fingerprint
        );
        fingerprint
    }

    // --- Publishing ---

    /// Check if our bundle is published
    pub async fn is_bundle_published(&self) -> Result<bool, OmemoError> {
        debug!(
            "Checking if bundle is published for device {}",
            self.device_id
        );

        let storage_guard = self.storage.lock().await;
        match storage_guard.is_bundle_published(self.device_id) {
            Ok(published) => {
                debug!("Bundle published status from storage: {}", published);
                Ok(published)
            }
            Err(e) => {
                warn!("Error checking bundle published status: {}", e);
                Ok(false)
            }
        }
    }

    pub async fn publish_bundle_to_server(&mut self) -> Result<bool> {
        debug!("Publishing bundle for device {}", self.device_id);

        let bundle = match self
            .storage
            .lock()
            .await
            .load_key_bundle_with_id(self.device_id)?
        {
            Some(bundle) => bundle,
            None => {
                error!("No bundle found in storage for publishing");
                return Err(anyhow!("No bundle found in storage for publishing"));
            }
        };

        if bundle.identity_key_pair.public_key.is_empty()
            || bundle.signed_pre_key_pair.public_key.is_empty()
            || bundle.signed_pre_key_signature.is_empty()
            || bundle.one_time_pre_key_pairs.is_empty()
        {
            error!("Invalid bundle data - missing required fields");
            return Err(anyhow!("Invalid bundle data for publishing"));
        }

        let bundle_xml = self.convert_x3dh_bundle_to_xml(&bundle)?;

        info!("Would publish PubSub item: {}", bundle_xml);

        let node = format!("{}.bundles:{}", OMEMO_NAMESPACE, self.device_id);

        match self
            .pubsub
            .publish_item(None, &node, "current", &bundle_xml)
            .await
        {
            Ok(_) => {
                info!("Successfully published to node {}", node);
                self.storage
                    .lock()
                    .await
                    .mark_bundle_published(self.device_id)
                    .await?;
                Ok(true)
            }
            Err(e) => {
                error!("Failed to publish bundle: {}", e);

                let error_str = e.to_string().to_lowercase();
                if error_str.contains("bad-request") || error_str.contains("invalid item") {
                    error!("Server rejected bundle with bad-request - check XML validity");
                    return self.publish_bundle_alternative_format().await;
                }

                Ok(false)
            }
        }
    }

    /// Publish the bundle using an alternative format
    async fn publish_bundle_alternative_format(&mut self) -> Result<bool> {
        debug!(
            "Attempting bundle publication with alternative format for device {}",
            self.device_id
        );

        let bundle = match self
            .storage
            .lock()
            .await
            .load_key_bundle_with_id(self.device_id)?
        {
            Some(bundle) => bundle,
            None => {
                error!("No bundle found in storage for alternative publishing");
                return Err(anyhow!(
                    "No bundle found in storage for alternative publishing"
                ));
            }
        };

        let alternative_payload = format!(
            "<bundle xmlns='eu.siacs.conversations.axolotl'>\
                <identityKey>{}</identityKey>\
                <signedPreKeyPublic signedPreKeyId='{}'>{}</signedPreKeyPublic>\
                <signedPreKeySignature>{}</signedPreKeySignature>\
                <prekeys>{}</prekeys>\
            </bundle>",
            base64::engine::general_purpose::STANDARD.encode(&bundle.identity_key_pair.public_key),
            bundle.signed_pre_key_id,
            base64::engine::general_purpose::STANDARD
                .encode(&bundle.signed_pre_key_pair.public_key),
            base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key_signature),
            bundle
                .one_time_pre_key_pairs
                .iter()
                .map(|(id, keypair)| format!(
                    "<preKeyPublic preKeyId='{}'>{}</preKeyPublic>",
                    id,
                    base64::engine::general_purpose::STANDARD.encode(&keypair.public_key)
                ))
                .collect::<Vec<_>>()
                .join("")
        );

        debug!(
            "Attempting with alternative bundle format: {}",
            alternative_payload
        );

        let node = format!("{}.bundles:{}", OMEMO_NAMESPACE, self.device_id);

        match self
            .pubsub
            .publish_item(None, &node, "current", &alternative_payload)
            .await
        {
            Ok(_) => {
                info!(
                    "Successfully published bundle with alternative format for device {}",
                    self.device_id
                );
                self.storage
                    .lock()
                    .await
                    .mark_bundle_published(self.device_id)
                    .await?;
                Ok(true)
            }
            Err(e) => {
                error!("Failed to publish bundle with alternative format: {}", e);
                Ok(false)
            }
        }
    }

    /// Parse a device list response from the server
    pub(crate) fn parse_device_list_response(
        &self,
        response: &str,
    ) -> Result<Vec<u32>, OmemoError> {
        debug!("Parsing device list response - starting");

        if response.trim().is_empty() {
            debug!("Empty response received, returning empty device list");
            return Ok(Vec::new());
        }

        if response.contains("item-not-found") {
            debug!("Response contains 'item-not-found', returning empty device list");
            return Ok(Vec::new());
        }

        debug!("Parsing device list response - starting XML parsing");

        let document = match roxmltree::Document::parse(response) {
            Ok(doc) => doc,
            Err(e) => {
                error!("Failed to parse device list XML: {}", e);
                return Err(OmemoError::ProtocolError(format!(
                    "XML parsing error: {}",
                    e
                )));
            }
        };

        debug!("Parsing device list response - XML parsed successfully, checking for errors");

        if let Some(error) = document.descendants().find(|n| n.has_tag_name("error")) {
            let error_type = error.attribute("type").unwrap_or("unknown");

            let error_condition = error
                .children()
                .find(|n| {
                    n.is_element()
                        && n.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
                })
                .map(|n| n.tag_name().name())
                .unwrap_or("unknown");

            warn!(
                "Error in device list response: type={}, condition={}",
                error_type, error_condition
            );

            match error_condition {
                "item-not-found" => {
                    debug!("No device list found (item-not-found)");
                    return Ok(Vec::new());
                }
                _ => {
                    return Err(OmemoError::ProtocolError(format!(
                        "XMPP error in device list response: {}",
                        error_condition
                    )));
                }
            }
        }

        debug!("Parsing device list response - no errors found, extracting device IDs");

        let mut device_ids = Vec::new();

        // Approach 1: Find <list> element by namespace
        let list_elements: Vec<_> = document
            .descendants()
            .filter(|n| {
                n.has_tag_name("list")
                    && (n.attribute("xmlns") == Some(OMEMO_NAMESPACE)
                        || n.tag_name().namespace() == Some(OMEMO_NAMESPACE))
            })
            .collect();

        if !list_elements.is_empty() {
            debug!(
                "Found {} list elements with OMEMO namespace",
                list_elements.len()
            );

            for list in list_elements {
                for device in list
                    .children()
                    .filter(|n| n.has_tag_name("device") && n.has_attribute("id"))
                {
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
            // Approach 2: PubSub item structure
            debug!("No direct list elements found, trying PubSub item structure");

            let item_elements: Vec<_> = document
                .descendants()
                .filter(|n| n.has_tag_name("item") && n.attribute("id") == Some("current"))
                .collect();

            if !item_elements.is_empty() {
                debug!(
                    "Found {} item elements with id='current'",
                    item_elements.len()
                );

                for item in item_elements {
                    if let Some(list) = item.children().find(|n| n.has_tag_name("list")) {
                        for device in list
                            .children()
                            .filter(|n| n.has_tag_name("device") && n.has_attribute("id"))
                        {
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
                // Approach 3: Any <device> elements
                debug!("No PubSub item structure found, looking for any device elements");

                for device in document
                    .descendants()
                    .filter(|n| n.has_tag_name("device") && n.has_attribute("id"))
                {
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

        if !device_ids.is_empty() {
            info!(
                "Found {} OMEMO device IDs: {:?}",
                device_ids.len(),
                device_ids
            );
            return Ok(device_ids);
        }

        debug!("No device IDs found in response, returning empty list");
        Ok(Vec::new())
    }

    /// Helper function to get device IDs for a specific JID
    pub(crate) async fn get_device_ids_for(&self, jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
        debug!("Getting device IDs for JID: {}", jid);

        let storage_guard = self.storage.lock().await;
        if let Ok(device_list) = storage_guard.load_device_list(jid) {
            debug!("Found device list in storage: {:?}", device_list.device_ids);
            return Ok(device_list.device_ids);
        }
        drop(storage_guard);

        let device_ids = match self.fetch_device_list_from_server(jid).await {
            Ok(ids) => {
                info!("Fetched device list from server: {:?}", ids);
                ids
            }
            Err(e) => {
                warn!(
                    "Failed to fetch device list: {}, starting with empty list",
                    e
                );
                Vec::new()
            }
        };

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
        }

        Ok(device_ids)
    }

    /// Get our own device IDs for session management
    pub(crate) async fn get_own_device_ids(&self) -> Result<Vec<u32>, OmemoError> {
        let bare_jid = Self::normalize_jid_to_bare(&self.local_jid);
        match self.get_device_ids(&bare_jid).await {
            Ok(device_ids) => Ok(device_ids),
            Err(e) => {
                warn!("Failed to get own device IDs: {}", e);
                Ok(vec![self.device_id])
            }
        }
    }
}
