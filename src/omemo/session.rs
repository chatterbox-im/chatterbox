// src/omemo/session.rs
//! Session management for OMEMO encryption
//!
//! This module handles OMEMO Double Ratchet sessions.

use std::collections::HashMap;
use thiserror::Error;
use log::error;
use anyhow::Result;

use crate::omemo::protocol::{RatchetState, DoubleRatchet, DoubleRatchetError, KeyPair};
use crate::omemo::device_id::DeviceId;

/// Session manager errors
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session not found
    #[error("Session not found for {jid}:{device_id}")]
    SessionNotFound { jid: String, device_id: DeviceId },
    
    /// Double ratchet error
    #[error("Double ratchet error: {0}")]
    DoubleRatchetError(#[from] DoubleRatchetError),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// Invalid session state
    #[error("Invalid session state: {0}")]
    InvalidStateError(String),
}

/// Configuration for PreKey rotation
#[derive(Debug, Clone)]
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

/// A session for an OMEMO Double Ratchet
pub struct OmemoSession {
    /// Remote JID
    pub remote_jid: String,
    
    /// Remote device ID
    pub remote_device_id: DeviceId,
    
    /// Local device ID 
    pub local_device_id: DeviceId,
    
    /// Ratchet state
    pub ratchet_state: RatchetState,
}

impl OmemoSession {
    /// Create a new OMEMO session
    pub fn new(remote_jid: String, remote_device_id: DeviceId, local_device_id: DeviceId) -> Self {
        Self {
            remote_jid: remote_jid.clone(),
            remote_device_id,
            local_device_id,
            ratchet_state: RatchetState {
                initialized: false,
                is_initiator: false,
                remote_identity_key: vec![],
                local_identity_key_pair: KeyPair {
                    public_key: vec![],
                    private_key: vec![],
                },
                root_key: vec![],
                send_chain_key: vec![],
                receive_chain_key: vec![],
                ratchet_key_pair: KeyPair {
                    public_key: vec![],
                    private_key: vec![],
                },
                remote_ratchet_key: vec![],
                prev_remote_ratchet_key: vec![],
                send_message_number: 0,
                receive_message_number: 0,
                prev_receive_message_number: 0,
                skipped_message_keys: HashMap::new(),
                local_device_id,
                remote_device_id,
                remote_jid: remote_jid,
            },
        }
    }
    
    /// Create a new initiator session
    pub fn new_initiator(
        remote_jid: String,
        remote_device_id: DeviceId,
        local_identity_key_pair: KeyPair,
        remote_identity_key: Vec<u8>,
        remote_signed_prekey: Vec<u8>,
        remote_one_time_prekey: Option<Vec<u8>>,
        local_device_id: DeviceId,
    ) -> Result<Self, SessionError> {
        let ratchet_state = DoubleRatchet::new_session_initiator(
            local_identity_key_pair,
            remote_identity_key,
            remote_signed_prekey,
            remote_one_time_prekey,
            local_device_id,
            remote_device_id,
            remote_jid.clone(),
        )?;
        
        Ok(Self {
            remote_jid,
            remote_device_id,
            local_device_id,
            ratchet_state,
        })
    }
    
    /// Create a new recipient session
    pub fn new_recipient(
        remote_jid: String,
        remote_device_id: DeviceId,
        local_identity_key_pair: KeyPair,
        remote_identity_key: Vec<u8>,
        local_signed_prekey_pair: KeyPair,
        local_one_time_prekey_pair: Option<KeyPair>,
        remote_ephemeral_key: Vec<u8>,
        local_device_id: DeviceId,
    ) -> Result<Self, SessionError> {
        let ratchet_state = DoubleRatchet::new_session_recipient(
            local_identity_key_pair,
            remote_identity_key,
            local_signed_prekey_pair,
            local_one_time_prekey_pair,
            remote_ephemeral_key,
            local_device_id,
            remote_device_id,
            remote_jid.clone(),
        )?;
        
        Ok(Self {
            remote_jid,
            remote_device_id,
            local_device_id,
            ratchet_state,
        })
    }
    
    /// Restore a session from a ratchet state
    pub fn restore_from_state(&mut self, state: RatchetState) -> Result<(), SessionError> {
        if state.remote_device_id != self.remote_device_id {
            return Err(SessionError::InvalidStateError(format!(
                "Device ID mismatch: expected {}, got {}",
                self.remote_device_id,
                state.remote_device_id
            )));
        }
        
        // Normalize JIDs for comparison to handle different encoding formats
        let normalized_session_jid = Self::normalize_jid(&self.remote_jid);
        let normalized_state_jid = Self::normalize_jid(&state.remote_jid);
        
        if normalized_state_jid != normalized_session_jid {
            return Err(SessionError::InvalidStateError(format!(
                "JID mismatch: expected {}, got {}",
                self.remote_jid,
                state.remote_jid
            )));
        }
        
        self.ratchet_state = state;
        
        Ok(())
    }
    
    /// Normalize a JID for comparison purposes
    /// This ensures consistent comparison regardless of encoding differences
    fn normalize_jid(jid: &str) -> String {
        // Convert to lowercase and trim whitespace for consistent comparison
        jid.to_lowercase().trim().to_string()
    }
    
    /// Get the ratchet state
    pub fn get_state(&self) -> &RatchetState {
        &self.ratchet_state
    }
    
    /// Get the remote JID
    pub fn get_remote_jid(&self) -> &str {
        &self.remote_jid
    }
    
    /// Get the remote device ID
    pub fn get_remote_device_id(&self) -> DeviceId {
        self.remote_device_id
    }
    
    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if !self.ratchet_state.initialized {
            return Err(SessionError::InvalidStateError(
                "Session not initialized".to_string()
            ));
        }
        
        let message = DoubleRatchet::encrypt(&mut self.ratchet_state, plaintext)?;
        
        // For this example, we'll use JSON serialization
        let encoded = serde_json::to_vec(&message)
            .map_err(|e| SessionError::SerializationError(e.to_string()))?;
        
        Ok(encoded)
    }
    
    /// Decrypt a message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if !self.ratchet_state.initialized {
            return Err(SessionError::InvalidStateError(
                "Session not initialized".to_string()
            ));
        }
        
        // Deserialize the message
        let message = serde_json::from_slice(ciphertext)
            .map_err(|e| SessionError::SerializationError(e.to_string()))?;
        
        // Decrypt it
        let plaintext = DoubleRatchet::decrypt(&mut self.ratchet_state, &message)?;
        
        Ok(plaintext)
    }
    
    /// Encrypt a message key for transport
    pub fn encrypt_key(&mut self, key: &[u8]) -> Result<Vec<u8>, SessionError> {
        if !self.ratchet_state.initialized {
            return Err(SessionError::InvalidStateError(
                "Session not initialized".to_string()
            ));
        }
        
        let encrypted_key = DoubleRatchet::encrypt_key(&mut self.ratchet_state, key)?;
        
        Ok(encrypted_key)
    }
    
    /// Decrypt a message key
    pub fn decrypt_key(&mut self, encrypted_key: &[u8]) -> Result<Vec<u8>, SessionError> {
        if !self.ratchet_state.initialized {
            return Err(SessionError::InvalidStateError(
                "Session not initialized".to_string()
            ));
        }
        
        let key = DoubleRatchet::decrypt_key(&mut self.ratchet_state, encrypted_key)?;
        
        Ok(key)
    }

    /// Check if the session is initialized
    pub fn is_initialized(&self) -> bool {
        self.ratchet_state.initialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_jid_normalization() {
        // Test that JID normalization handles different cases consistently
        assert_eq!(
            OmemoSession::normalize_jid("hatt@mysterymen.duckdns.org"),
            OmemoSession::normalize_jid("HATT@mysterymen.duckdns.org")
        );
        
        assert_eq!(
            OmemoSession::normalize_jid("  user@domain.com  "),
            "user@domain.com"
        );
        
        // Test that different JIDs still produce different normalized results
        assert_ne!(
            OmemoSession::normalize_jid("user1@domain.com"),
            OmemoSession::normalize_jid("user2@domain.com")
        );
    }
    
    #[test]
    fn test_restore_from_state_with_case_mismatch() {
        use crate::omemo::protocol::RatchetState;
        use std::collections::HashMap;
        
        let remote_jid = "User@Domain.Com".to_string();
        let remote_device_id = 123;
        let local_device_id = 456;
        
        let mut session = OmemoSession::new(remote_jid.clone(), remote_device_id, local_device_id);
        
        // Create a ratchet state with different case
        let state = RatchetState {
            initialized: true,
            is_initiator: false,
            remote_identity_key: vec![],
            local_identity_key_pair: crate::omemo::protocol::KeyPair {
                private_key: vec![],
                public_key: vec![],
            },
            root_key: vec![],
            send_chain_key: vec![],
            receive_chain_key: vec![],
            ratchet_key_pair: crate::omemo::protocol::KeyPair {
                private_key: vec![],
                public_key: vec![],
            },
            remote_ratchet_key: vec![],
            prev_remote_ratchet_key: vec![],
            send_message_number: 0,
            receive_message_number: 0,
            prev_receive_message_number: 0,
            skipped_message_keys: HashMap::new(),
            local_device_id,
            remote_device_id,
            remote_jid: "user@domain.com".to_string(), // Different case
        };
        
        // Should succeed despite case difference
        assert!(session.restore_from_state(state).is_ok());
    }

    // ...existing tests...
}