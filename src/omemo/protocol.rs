// src/omemo/protocol.rs
//! Implementation of the OMEMO protocol according to XEP-0384
//!
//! This module handles the cryptographic protocol for OMEMO, including X3DH and Double Ratchet.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use log::debug;

use crate::omemo::crypto;
use crate::omemo::device_id::DeviceId;

/// Errors that can occur in double ratchet operations
#[derive(Debug, Error)]
pub enum DoubleRatchetError {
    /// Error during cryptographic operations
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crate::omemo::crypto::CryptoError),
    
    /// Key generation error
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
    
    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignatureError(String),
    
    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessageFormatError(String),
    
    /// Unknown message key
    #[error("Unknown message key: {0}")]
    UnknownMessageKeyError(String),
}

/// A key pair for OMEMO operations
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The public key
    pub public_key: Vec<u8>,
    
    /// The private key
    pub private_key: Vec<u8>,
}

/// Implements X3DH protocol for OMEMO
pub struct X3DHProtocol;

/// A bundle containing keys for X3DH key agreement
#[derive(Clone, Serialize, Deserialize)]
pub struct X3DHKeyBundle {
    /// Device ID
    pub device_id: DeviceId,
    
    /// Identity key pair
    pub identity_key_pair: KeyPair,
    
    /// Signed pre-key ID
    pub signed_pre_key_id: u32,
    
    /// Signed pre-key pair
    pub signed_pre_key_pair: KeyPair,
    
    /// Signature of the signed pre-key
    pub signed_pre_key_signature: Vec<u8>,
    
    /// One-time pre-key pairs
    pub one_time_pre_key_pairs: std::collections::HashMap<u32, KeyPair>,
}

/// A pre-key bundle format for OMEMO
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Pre-key ID
    pub id: u32,
    
    /// Pre-key public key
    pub public_key: Vec<u8>,
}

/// A signed pre-key bundle format for OMEMO
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKeyBundle {
    /// Signed pre-key ID
    pub id: u32,
    
    /// Signed pre-key public key
    pub public_key: Vec<u8>,
    
    /// Signature of the signed pre-key
    pub signature: Vec<u8>,
}

/// A device identity for OMEMO
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Device ID
    pub id: DeviceId,
    
    /// Identity key
    pub identity_key: Vec<u8>,
    
    /// Signed pre-key
    pub signed_pre_key: SignedPreKeyBundle,
    
    /// Pre-keys
    pub pre_keys: Vec<PreKeyBundle>,
}

/// State for the Double Ratchet
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    /// Flag indicating if the state is initialized
    pub initialized: bool,
    
    /// Flag indicating if this is the initiator
    pub is_initiator: bool,
    
    /// Remote identity key
    pub remote_identity_key: Vec<u8>,
    
    /// Local identity key pair
    pub local_identity_key_pair: KeyPair,
    
    /// Root key
    pub root_key: Vec<u8>,
    
    /// Send chain key
    pub send_chain_key: Vec<u8>,
    
    /// Receive chain key
    pub receive_chain_key: Vec<u8>,
    
    /// Ratchet key pair
    pub ratchet_key_pair: KeyPair,
    
    /// Remote ratchet key
    pub remote_ratchet_key: Vec<u8>,
    
    /// Previous remote ratchet key
    pub prev_remote_ratchet_key: Vec<u8>,
    
    /// Send message number
    pub send_message_number: u32,
    
    /// Receive message number
    pub receive_message_number: u32,
    
    /// Previous receive message number
    pub prev_receive_message_number: u32,
    
    /// Skipped message keys
    pub skipped_message_keys: std::collections::HashMap<(Vec<u8>, u32), Vec<u8>>,
    
    /// Local device ID
    pub local_device_id: DeviceId,
    
    /// Remote device ID
    pub remote_device_id: DeviceId,
    
    /// Remote JID
    pub remote_jid: String,
}

/// An OMEMO message for double ratchet encryption
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OmemoMessage {
    /// Sender device ID
    pub sender_device_id: DeviceId,
    
    /// Current ratchet key
    pub ratchet_key: Vec<u8>,
    
    /// Previous counter value
    pub previous_counter: u32,
    
    /// Counter value
    pub counter: u32,
    
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    
    /// Message authentication code
    pub mac: Vec<u8>,
    
    /// Initialization vector
    pub iv: Vec<u8>,
    
    /// Encrypted keys for each recipient device
    pub encrypted_keys: HashMap<DeviceId, Vec<u8>>,
    
    /// Whether this message is a PreKey message (forces new session creation)
    pub is_prekey: bool,
    
    /// Ephemeral public key used for X3DH (only present in PreKey messages)
    pub ephemeral_key: Option<Vec<u8>>,

    /// Set of device IDs that received a PreKeySignalMessage (for prekey="true" attribute)
    pub prekey_devices: HashSet<DeviceId>,
}

/// Double Ratchet implementation for OMEMO
pub struct DoubleRatchet;

impl X3DHProtocol {
    /// Generate a key pair for OMEMO operations
    pub fn generate_key_pair() -> Result<KeyPair, DoubleRatchetError> {
        // generate_x25519_keypair returns (private_key, public_key)
        let (private_key, public_key) = crypto::generate_x25519_keypair()
            .map_err(DoubleRatchetError::CryptoError)?;
        
        Ok(KeyPair {
            public_key,
            private_key,
        })
    }
    
    /// Generate a key bundle for a device
    pub fn generate_key_bundle(device_id: DeviceId, num_prekeys: u32) -> Result<X3DHKeyBundle, DoubleRatchetError> {
        // Generate identity key pair
        let identity_key_pair = Self::generate_key_pair()?;
        
        // Generate signed pre-key pair
        let signed_pre_key_pair = Self::generate_key_pair()?;
        
        // Sign the pre-key with the identity key
        let signed_pre_key_signature = Self::sign_pre_key(
            &identity_key_pair.private_key,
            &signed_pre_key_pair.public_key,
        )?;
        
        // Generate one-time pre-key pairs
        let mut one_time_pre_key_pairs = std::collections::HashMap::new();
        for i in 0..num_prekeys {
            let pre_key_id = i + 1; // Start from 1
            let pre_key_pair = Self::generate_key_pair()?;
            one_time_pre_key_pairs.insert(pre_key_id, pre_key_pair);
        }
        
        // Create the bundle
        Ok(X3DHKeyBundle {
            device_id,
            identity_key_pair,
            signed_pre_key_id: 1, // Start with 1
            signed_pre_key_pair,
            signed_pre_key_signature,
            one_time_pre_key_pairs,
        })
    }
    
    /// Sign a pre-key with the identity key using XEdDSA.
    /// This allows signing with an X25519 identity key (as OMEMO/Signal requires).
    pub fn sign_pre_key(identity_private_key: &[u8], pre_key_public: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        crypto::xeddsa_sign(identity_private_key, pre_key_public)
            .map_err(|e| DoubleRatchetError::InvalidSignatureError(
                format!("XEdDSA signing failed: {}", e)
            ))
    }
    
    /// Verify a pre-key signature using XEdDSA.
    /// Verifies that the signed prekey was signed by the holder of the X25519 identity key.
    pub fn verify_pre_key(identity_public_key: &[u8], pre_key_public: &[u8], signature: &[u8]) -> Result<bool, DoubleRatchetError> {
        crypto::xeddsa_verify(identity_public_key, pre_key_public, signature)
            .map_err(|e| DoubleRatchetError::InvalidSignatureError(
                format!("XEdDSA verification failed: {}", e)
            ))
    }
    
    /// Perform X3DH key agreement as the initiator with a provided ephemeral key
    pub fn key_agreement_initiator_with_ephemeral(
        identity_key_pair: &KeyPair,
        their_identity_key: &[u8],
        their_signed_pre_key: &[u8],
        their_one_time_pre_key: Option<&[u8]>,
        ephemeral_key: &[u8], // Use provided ephemeral key instead of generating
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        debug!("X3DH initiator key agreement starting");
        
        // DH1 = DH(IKa, SPKb)
        let dh1 = crypto::x25519_diffie_hellman(
            &identity_key_pair.private_key,
            their_signed_pre_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // DH2 = DH(EKa, IKb)
        let dh2 = crypto::x25519_diffie_hellman(
            ephemeral_key,
            their_identity_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // DH3 = DH(EKa, SPKb)
        let dh3 = crypto::x25519_diffie_hellman(
            ephemeral_key,
            their_signed_pre_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // DH4 = DH(EKa, OPKb) (if OPKb exists)
        let dh4 = if let Some(their_one_time_pre_key) = their_one_time_pre_key {
            Some(crypto::x25519_diffie_hellman(
                ephemeral_key,
                their_one_time_pre_key,
            ).map_err(DoubleRatchetError::CryptoError)?)
        } else {
            None
        };
        
        // Per Signal spec: IKM = F || DH1 || DH2 || DH3 [|| DH4]
        // where F = 0xFF repeated 32 times
        let mut ikm = vec![0xFFu8; 32];
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);
        if let Some(ref dh4) = dh4 {
            ikm.extend_from_slice(dh4);
        }
        
        // HKDF(salt=0x00*32, IKM, info="", L=32)
        let salt = vec![0u8; 32];
        let shared_secret = crypto::hkdf_derive(&salt, &ikm, b"", 32)
            .map_err(DoubleRatchetError::CryptoError)?;
        
        debug!("X3DH initiator key agreement complete");
        Ok(shared_secret)
    }

    /// Perform X3DH key agreement as the initiator
    pub fn key_agreement_initiator(
        identity_key_pair: &KeyPair,
        their_identity_key: &[u8],
        their_signed_pre_key: &[u8],
        their_one_time_pre_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        // Generate an ephemeral key pair
        let ephemeral_key_pair = Self::generate_key_pair()?;
        
        // Use the new function with the generated ephemeral key
        Self::key_agreement_initiator_with_ephemeral(
            identity_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key,
            &ephemeral_key_pair.private_key,
        )
    }
    
    /// Perform X3DH key agreement as the recipient
    pub fn key_agreement_recipient(
        identity_key_pair: &KeyPair,
        their_identity_key: &[u8],
        signed_pre_key_pair: &KeyPair,
        one_time_pre_key_pair: Option<&KeyPair>,
        their_ephemeral_key: &[u8],
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        debug!("X3DH recipient key agreement starting");
        
        // DH1 = DH(SPKb, IKa)
        let dh1 = crypto::x25519_diffie_hellman(
            &signed_pre_key_pair.private_key,
            their_identity_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // DH2 = DH(IKb, EKa)
        let dh2 = crypto::x25519_diffie_hellman(
            &identity_key_pair.private_key,
            their_ephemeral_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // DH3 = DH(SPKb, EKa)
        let dh3 = crypto::x25519_diffie_hellman(
            &signed_pre_key_pair.private_key,
            their_ephemeral_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // DH4 = DH(OPKb, EKa) (if OPKb exists)
        let dh4 = if let Some(one_time_pre_key_pair) = one_time_pre_key_pair {
            Some(crypto::x25519_diffie_hellman(
                &one_time_pre_key_pair.private_key,
                their_ephemeral_key,
            ).map_err(DoubleRatchetError::CryptoError)?)
        } else {
            None
        };
        
        // Per Signal spec: IKM = F || DH1 || DH2 || DH3 [|| DH4]
        // where F = 0xFF repeated 32 times
        let mut ikm = vec![0xFFu8; 32];
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);
        if let Some(ref dh4) = dh4 {
            ikm.extend_from_slice(dh4);
        }
        
        // HKDF(salt=0x00*32, IKM, info="", L=32)
        let salt = vec![0u8; 32];
        let shared_key = crypto::hkdf_derive(&salt, &ikm, b"", 32)
            .map_err(DoubleRatchetError::CryptoError)?;
        
        debug!("X3DH recipient key agreement complete");
        Ok(shared_key)
    }
}

impl DoubleRatchet {
    /// Create a new Double Ratchet session as the initiator with deterministic ephemeral key
    pub fn new_session_initiator_with_ephemeral(
        local_identity_key_pair: KeyPair,
        remote_identity_key: Vec<u8>,
        remote_signed_prekey: Vec<u8>,
        remote_one_time_prekey: Option<Vec<u8>>,
        ephemeral_key: Vec<u8>, // Use provided ephemeral key
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        remote_jid: String,
    ) -> Result<RatchetState, DoubleRatchetError> {
        // Perform X3DH key agreement with the provided ephemeral key
        let shared_secret = X3DHProtocol::key_agreement_initiator_with_ephemeral(
            &local_identity_key_pair,
            &remote_identity_key,
            &remote_signed_prekey,
            remote_one_time_prekey.as_deref(),
            &ephemeral_key,
        )?;
        
        // Create symmetric session state for both initiator and recipient
        Self::create_symmetric_session_state(
            shared_secret,
            local_identity_key_pair,
            remote_identity_key,
            remote_signed_prekey,
            ephemeral_key,
            true, // is_initiator
            local_device_id,
            remote_device_id,
            remote_jid,
        )
    }

    /// Maximum number of message keys to skip (DoS protection)
    const MAX_SKIP: u32 = 1000;

    /// Create a symmetric session state that both initiator and recipient can use
    /// Per Signal spec:
    /// - Initiator: sets remote_ratchet_key = Bob's signed prekey, does a sending DH ratchet step
    /// - Recipient: sets ratchet_key_pair = signed prekey, waits for first message to trigger DH ratchet
    fn create_symmetric_session_state(
        shared_secret: Vec<u8>,
        local_identity_key_pair: KeyPair,
        remote_identity_key: Vec<u8>,
        remote_signed_prekey: Vec<u8>,
        ephemeral_key: Vec<u8>,
        is_initiator: bool,
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        remote_jid: String,
    ) -> Result<RatchetState, DoubleRatchetError> {
        if is_initiator {
            // Alice (initiator):
            // - root_key = SK (shared secret from X3DH)
            // - remote_ratchet_key = Bob's signed prekey (SPKb)
            // - Perform an initial sending DH ratchet step:
            //   Generate new ratchet keypair, DH(new_ratchet, SPKb) -> KDF_RK -> (new_root, send_chain)
            let ratchet_key_pair = X3DHProtocol::generate_key_pair()?;
            
            // DH between our new ratchet key and their signed prekey
            let dh_output = crypto::x25519_diffie_hellman(
                &ratchet_key_pair.private_key,
                &remote_signed_prekey,
            ).map_err(DoubleRatchetError::CryptoError)?;
            
            // KDF_RK(SK, DH) -> (root_key, send_chain_key)
            let kdf_output = crypto::hkdf_derive(&shared_secret, &dh_output, b"WhisperRatchet", 64)
                .map_err(DoubleRatchetError::CryptoError)?;
            let root_key = kdf_output[..32].to_vec();
            let send_chain_key = kdf_output[32..64].to_vec();
            
            let state = RatchetState {
                initialized: true,
                is_initiator: true,
                remote_identity_key,
                local_identity_key_pair,
                root_key,
                send_chain_key,
                receive_chain_key: vec![0u8; 32], // Not yet established; set on first DH ratchet from Bob
                ratchet_key_pair,
                remote_ratchet_key: remote_signed_prekey,
                prev_remote_ratchet_key: vec![],
                send_message_number: 0,
                receive_message_number: 0,
                prev_receive_message_number: 0,
                skipped_message_keys: std::collections::HashMap::new(),
                local_device_id,
                remote_device_id,
                remote_jid: normalize_jid_to_bare(&remote_jid),
            };
            
            Ok(state)
        } else {
            // Bob (recipient):
            // - root_key = SK (shared secret from X3DH)
            // - ratchet_key_pair = signed prekey (SPKb) — this is what Alice will DH against
            // - Receive chain not yet set; will be established when we receive Alice's first message
            //   which triggers a DH ratchet using her ratchet key
            
            // Bob's ratchet key IS the signed prekey (Alice will send her ratchet key in first message)
            // We need to find the signed prekey private key - it's passed via ephemeral_key param
            // Actually for recipient, the ratchet key pair is the signed prekey pair
            // The caller (new_session_recipient) passes the signed prekey pair info
            // We'll use a placeholder - the DH ratchet on first received message will replace this
            let state = RatchetState {
                initialized: true,
                is_initiator: false,
                remote_identity_key,
                local_identity_key_pair,
                root_key: shared_secret,
                send_chain_key: vec![0u8; 32], // Not yet established
                receive_chain_key: vec![0u8; 32], // Not yet established
                ratchet_key_pair: KeyPair {
                    public_key: vec![], // Will be set properly by new_session_recipient
                    private_key: vec![],
                },
                remote_ratchet_key: ephemeral_key, // Alice's ephemeral key (or her first ratchet key)
                prev_remote_ratchet_key: vec![],
                send_message_number: 0,
                receive_message_number: 0,
                prev_receive_message_number: 0,
                skipped_message_keys: std::collections::HashMap::new(),
                local_device_id,
                remote_device_id,
                remote_jid: normalize_jid_to_bare(&remote_jid),
            };
            
            Ok(state)
        }
    }

    /// Create a new Double Ratchet session as the initiator
    pub fn new_session_initiator(
        local_identity_key_pair: KeyPair,
        remote_identity_key: Vec<u8>,
        remote_signed_prekey: Vec<u8>,
        remote_one_time_prekey: Option<Vec<u8>>,
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        remote_jid: String,
    ) -> Result<RatchetState, DoubleRatchetError> {
        // Generate a random ephemeral key pair for this session
        let ephemeral_key_pair = X3DHProtocol::generate_key_pair()?;
        
        // Use the with_ephemeral version with the generated ephemeral key
        Self::new_session_initiator_with_ephemeral(
            local_identity_key_pair,
            remote_identity_key,
            remote_signed_prekey,
            remote_one_time_prekey,
            ephemeral_key_pair.private_key,
            local_device_id,
            remote_device_id,
            remote_jid,
        )
    }
    
    /// Create a new Double Ratchet session as the recipient
    pub fn new_session_recipient(
        local_identity_key_pair: KeyPair,
        remote_identity_key: Vec<u8>,
        local_signed_prekey_pair: KeyPair,
        local_one_time_prekey_pair: Option<KeyPair>,
        remote_ephemeral_key: Vec<u8>,
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        remote_jid: String,
    ) -> Result<RatchetState, DoubleRatchetError> {
        // Perform X3DH key agreement
        let shared_secret = X3DHProtocol::key_agreement_recipient(
            &local_identity_key_pair,
            &remote_identity_key,
            &local_signed_prekey_pair,
            local_one_time_prekey_pair.as_ref(),
            &remote_ephemeral_key,
        )?;
        
        // For recipient: ratchet_key_pair = signed prekey (Bob's SPK)
        // Alice's ephemeral key is the remote_ratchet_key (she DH'd against our SPK)
        let spk_pair = local_signed_prekey_pair.clone();
        
        let mut state = Self::create_symmetric_session_state(
            shared_secret,
            local_identity_key_pair,
            remote_identity_key,
            local_signed_prekey_pair.public_key,
            remote_ephemeral_key,
            false, // is_initiator
            local_device_id,
            remote_device_id,
            remote_jid,
        )?;
        
        // Set ratchet key pair to signed prekey pair (Bob uses SPK as initial ratchet key)
        state.ratchet_key_pair = spk_pair;
        
        Ok(state)
    }
    
    /// Encrypt a message
    pub fn encrypt(state: &mut RatchetState, plaintext: &[u8]) -> Result<OmemoMessage, DoubleRatchetError> {
        // Get the message key
        let message_key = Self::derive_next_sending_key(state);
        
        // Generate a random IV
        let iv = crypto::generate_iv();
        
        // Encrypt the message
        let ciphertext = crypto::encrypt(plaintext, &message_key, &iv, &[])
            .map_err(DoubleRatchetError::CryptoError)?;
        
        // MAC: HMAC-SHA256(message_key, ciphertext), truncated to 16 bytes
        let mac = crypto::hmac_sha256(&message_key, &ciphertext)
            .expect("HMAC-SHA256 cannot fail")[..16].to_vec();
        
        // Create the message
        let message = OmemoMessage {
            sender_device_id: state.local_device_id,
            ratchet_key: state.ratchet_key_pair.public_key.clone(),
            previous_counter: state.prev_receive_message_number, // Messages in previous sending chain
            counter: state.send_message_number,
            ciphertext,
            mac,
            iv,
            encrypted_keys: std::collections::HashMap::new(),
            is_prekey: false,
            ephemeral_key: None,
            prekey_devices: HashSet::new(),
        };
        
        // Increment message counter
        state.send_message_number += 1;
        
        Ok(message)
    }
    
    /// Decrypt a message
    pub fn decrypt(state: &mut RatchetState, message: &OmemoMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        // Check if we need to perform a DH ratchet step
        if !state.remote_ratchet_key.eq(&message.ratchet_key) {
            // Ratchet key has changed, perform a DH ratchet step
            Self::dh_ratchet(state, &message.ratchet_key)?;
        }
        
        // Try to find a skipped message key
        let key = (message.ratchet_key.clone(), message.counter);
        if let Some(message_key) = state.skipped_message_keys.remove(&key) {
            // We have a skipped message key, use it to decrypt
            return Self::decrypt_message(message, &message_key);
        }
        
        // Check if we have already received this message
        if message.counter < state.receive_message_number {
            return Err(DoubleRatchetError::InvalidMessageFormatError(
                "Message counter is too old".to_string()
            ));
        }
        
        // Skip forward if needed
        if message.counter > state.receive_message_number {
            Self::skip_message_keys(state, message.counter)?;
        }
        
        // Get the message key
        let message_key = Self::derive_next_receiving_key(state);
        
        // Decrypt the message
        Self::decrypt_message(message, &message_key)
    }
    
    /// Decrypt a message with a key
    fn decrypt_message(message: &OmemoMessage, key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        // Verify the MAC: HMAC-SHA256(message_key, ciphertext), truncated to 16 bytes
        let calculated_mac = crypto::hmac_sha256(key, &message.ciphertext)
            .expect("HMAC-SHA256 cannot fail")[..16].to_vec();
        if !crypto::secure_compare(&calculated_mac, &message.mac) {
            return Err(DoubleRatchetError::InvalidMessageFormatError(
                "MAC verification failed".to_string()
            ));
        }
        
        // Decrypt the message
        let plaintext = crypto::decrypt(&message.ciphertext, key, &message.iv, &[])
            .map_err(DoubleRatchetError::CryptoError)?;
        
        Ok(plaintext)
    }
    
    /// Skip message keys up to a specific counter
    fn skip_message_keys(state: &mut RatchetState, target: u32) -> Result<(), DoubleRatchetError> {
        if target > state.receive_message_number + Self::MAX_SKIP {
            return Err(DoubleRatchetError::InvalidMessageFormatError(
                format!("Too many skipped messages: {} (max {})", target - state.receive_message_number, Self::MAX_SKIP)
            ));
        }
        
        while state.receive_message_number < target {
            let current_counter = state.receive_message_number;
            // derive_next_receiving_key increments receive_message_number
            let message_key = Self::derive_next_receiving_key(state);
            
            // Store with the counter value this key corresponds to
            let key = (state.remote_ratchet_key.clone(), current_counter);
            state.skipped_message_keys.insert(key, message_key);
        }
        
        Ok(())
    }
    
    /// Derive the next sending key using HMAC-based chain ratchet (Signal spec)
    /// message_key = HMAC-SHA256(chain_key, 0x01)
    /// next_chain_key = HMAC-SHA256(chain_key, 0x02)
    fn derive_next_sending_key(state: &mut RatchetState) -> Vec<u8> {
        let message_key = crypto::hmac_sha256(&state.send_chain_key, &[0x01]).expect("HMAC-SHA256 cannot fail");
        state.send_chain_key = crypto::hmac_sha256(&state.send_chain_key, &[0x02]).expect("HMAC-SHA256 cannot fail");
        message_key
    }
    
    /// Derive the next receiving key using HMAC-based chain ratchet (Signal spec)
    fn derive_next_receiving_key(state: &mut RatchetState) -> Vec<u8> {
        let message_key = crypto::hmac_sha256(&state.receive_chain_key, &[0x01]).expect("HMAC-SHA256 cannot fail");
        state.receive_chain_key = crypto::hmac_sha256(&state.receive_chain_key, &[0x02]).expect("HMAC-SHA256 cannot fail");
        state.receive_message_number += 1;
        message_key
    }
    
    /// Perform a DH ratchet step
    fn dh_ratchet(state: &mut RatchetState, their_ratchet_key: &[u8]) -> Result<(), DoubleRatchetError> {
        // Save previous state
        state.prev_remote_ratchet_key = state.remote_ratchet_key.clone();
        state.remote_ratchet_key = their_ratchet_key.to_vec();
        state.prev_receive_message_number = state.receive_message_number;
        state.receive_message_number = 0;
        
        // DH for receiving chain: DH(our_ratchet_private, their_new_ratchet_public)
        let dh_recv = crypto::x25519_diffie_hellman(
            &state.ratchet_key_pair.private_key,
            their_ratchet_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // KDF_RK(root_key, dh_recv) -> (new_root_key, receive_chain_key)
        let kdf_recv = crypto::hkdf_derive(&state.root_key, &dh_recv, b"WhisperRatchet", 64)
            .map_err(DoubleRatchetError::CryptoError)?;
        state.root_key = kdf_recv[..32].to_vec();
        state.receive_chain_key = kdf_recv[32..64].to_vec();
        
        // Generate a new ratchet key pair for sending
        state.ratchet_key_pair = X3DHProtocol::generate_key_pair()?;
        state.send_message_number = 0;
        
        // DH for sending chain: DH(new_ratchet_private, their_ratchet_public)
        let dh_send = crypto::x25519_diffie_hellman(
            &state.ratchet_key_pair.private_key,
            their_ratchet_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // KDF_RK(root_key, dh_send) -> (new_root_key, send_chain_key)
        let kdf_send = crypto::hkdf_derive(&state.root_key, &dh_send, b"WhisperRatchet", 64)
            .map_err(DoubleRatchetError::CryptoError)?;
        state.root_key = kdf_send[..32].to_vec();
        state.send_chain_key = kdf_send[32..64].to_vec();
        
        Ok(())
    }

    /// Encrypt a message key for transport using Signal wire format.
    /// Produces a serialized SignalMessage (version || protobuf || mac).
    pub fn encrypt_key(state: &mut RatchetState, key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        debug!("Double Ratchet encrypt_key: key length: {}", key.len());

        // Derive a message key from the sending chain
        let message_key = Self::derive_next_sending_key(state);

        // Expand message_key via HKDF to get (cipher_key, mac_key, iv)
        // Per Signal spec: HKDF(message_key, salt="", info="WhisperMessageKeys", L=80)
        let expanded = crypto::hkdf_derive(&[], &message_key, b"WhisperMessageKeys", 80)
            .map_err(DoubleRatchetError::CryptoError)?;
        let cipher_key = &expanded[..32];   // AES-256 key
        let mac_key = &expanded[32..64];    // HMAC-SHA256 key
        let iv = &expanded[64..80];         // CBC IV (16 bytes)

        // Encrypt the OMEMO message key using AES-256-CBC with PKCS7 padding
        let ciphertext = crypto::aes_256_cbc_encrypt(cipher_key, iv, key)
            .map_err(DoubleRatchetError::CryptoError)?;

        // Build a SignalMessage in wire format
        let signal_msg = crate::omemo::wire::SignalMessage {
            ratchet_key: state.ratchet_key_pair.public_key.clone(),
            counter: state.send_message_number,
            previous_counter: state.prev_receive_message_number,
            ciphertext,
            mac: Vec::new(), // computed during serialization
        };

        // Increment the message number after using it
        state.send_message_number += 1;

        // Serialize with MAC including identity keys
        let result = signal_msg.serialize_with_identity(
            mac_key,
            &state.local_identity_key_pair.public_key,
            &state.remote_identity_key,
        );

        debug!("Double Ratchet encrypt_key: result length: {} (Signal wire format)", result.len());
        Ok(result)
    }

    /// Decrypt a message key from Signal wire format (SignalMessage or PreKeySignalMessage).
    pub fn decrypt_key(state: &mut RatchetState, encrypted_key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        debug!("Double Ratchet decrypt_key: encrypted_key length: {}", encrypted_key.len());
        debug!("Double Ratchet decrypt_key: encrypted_key hex: {}", hex::encode(encrypted_key));

        // Try parsing as PreKeySignalMessage first, then SignalMessage
        let (signal_msg, raw_msg_bytes) = if let Some(prekey_msg) = crate::omemo::wire::PreKeySignalMessage::deserialize(encrypted_key) {
            debug!("Double Ratchet decrypt_key: parsed as PreKeySignalMessage (reg_id={}, spk_id={})",
                prekey_msg.registration_id, prekey_msg.signed_pre_key_id);
            // For PreKey messages, extract the inner SignalMessage raw bytes for MAC verification
            let inner_bytes = prekey_msg.raw_message_bytes.clone();
            (prekey_msg.message, inner_bytes)
        } else if let Some(msg) = crate::omemo::wire::SignalMessage::deserialize(encrypted_key) {
            debug!("Double Ratchet decrypt_key: parsed as SignalMessage (counter={})", msg.counter);
            // The raw bytes for MAC verification are the full encrypted_key
            (msg, encrypted_key.to_vec())
        } else {
            return Err(DoubleRatchetError::InvalidMessageFormatError(
                "Failed to parse encrypted key as SignalMessage or PreKeySignalMessage".to_string()
            ));
        };

        // Check if we need a DH ratchet step
        if !signal_msg.ratchet_key.is_empty() && signal_msg.ratchet_key != state.remote_ratchet_key {
            debug!("Double Ratchet decrypt_key: performing DH ratchet step (new ratchet key)");
            Self::dh_ratchet(state, &signal_msg.ratchet_key)?;
        }

        // Skip keys if needed (with MAX_SKIP protection)
        if signal_msg.counter > state.receive_message_number {
            if signal_msg.counter - state.receive_message_number > Self::MAX_SKIP {
                return Err(DoubleRatchetError::InvalidMessageFormatError(
                    "Too many skipped messages in decrypt_key".to_string()
                ));
            }
            while state.receive_message_number < signal_msg.counter {
                let current_counter = state.receive_message_number;
                let skipped_key = Self::derive_next_receiving_key(state);
                let skip_index = (signal_msg.ratchet_key.clone(), current_counter);
                state.skipped_message_keys.insert(skip_index, skipped_key);
            }
        }

        let message_key = Self::derive_next_receiving_key(state);

        // Expand message_key via HKDF to get (cipher_key, mac_key, iv)
        let expanded = crypto::hkdf_derive(&[], &message_key, b"WhisperMessageKeys", 80)
            .map_err(DoubleRatchetError::CryptoError)?;
        let cipher_key = &expanded[..32];   // AES-256 key
        let mac_key = &expanded[32..64];    // HMAC-SHA256 key
        let iv = &expanded[64..80];         // CBC IV (16 bytes)

        // Verify MAC before decryption
        // MAC covers: sender_identity || receiver_identity || version || protobuf
        // The raw_msg_bytes contain version || proto || mac[8]
        if raw_msg_bytes.len() > 8 {
            let msg_without_mac = &raw_msg_bytes[..raw_msg_bytes.len() - 8];
            let received_mac = &raw_msg_bytes[raw_msg_bytes.len() - 8..];

            let mut mac_input = Vec::with_capacity(
                state.remote_identity_key.len() +
                state.local_identity_key_pair.public_key.len() +
                msg_without_mac.len()
            );
            mac_input.extend_from_slice(&state.remote_identity_key);
            mac_input.extend_from_slice(&state.local_identity_key_pair.public_key);
            mac_input.extend_from_slice(msg_without_mac);

            if !crate::omemo::wire::verify_mac(mac_key, &mac_input, received_mac) {
                return Err(DoubleRatchetError::CryptoError(
                    crypto::CryptoError::AesGcmError("MAC verification failed".to_string())
                ));
            }
            debug!("Double Ratchet decrypt_key: MAC verified successfully");
        }

        // Decrypt using AES-256-CBC with PKCS7 padding
        let key = crypto::aes_256_cbc_decrypt(cipher_key, iv, &signal_msg.ciphertext)
            .map_err(DoubleRatchetError::CryptoError)?;

        debug!("Double Ratchet decrypt_key: decrypted key length: {}", key.len());
        Ok(key)
    }
}

/// Utility functions for OMEMO protocol
pub mod utils {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use roxmltree::Document;
    use std::collections::HashSet;
    use thiserror::Error;

    use super::{DeviceIdentity, OmemoMessage};
    // Use the legacy OMEMO namespace that actually works
    const OMEMO_NAMESPACE: &str = "eu.siacs.conversations.axolotl";
    
    /// Errors that can occur in XML processing
    #[derive(Debug, Error)]
    pub enum XmlError {
        /// Error parsing XML
        #[error("XML parsing error: {0}")]
        ParseError(String),
        
        /// Error encoding/decoding data
        #[error("Encoding error: {0}")]
        EncodingError(String),
        
        /// Missing required element or attribute
        #[error("Missing element or attribute: {0}")]
        MissingElementError(String),
    }
    
    /// Convert a device bundle to XML for publishing
    pub fn device_bundle_to_xml(bundle: &DeviceIdentity) -> Result<String, XmlError> {
        let mut xml = String::new();
        
        xml.push_str(&format!("<bundle xmlns='{}'>", OMEMO_NAMESPACE));
        
        // Identity key
        xml.push_str("<identityKey>");
        xml.push_str(&BASE64.encode(&bundle.identity_key));
        xml.push_str("</identityKey>");
        
        // Signed pre-key
        xml.push_str(&format!(
            "<signedPreKeyPublic signedPreKeyId='{}'>{}</signedPreKeyPublic>",
            bundle.signed_pre_key.id,
            BASE64.encode(&bundle.signed_pre_key.public_key)
        ));
        
        // Signature
        xml.push_str("<signedPreKeySignature>");
        xml.push_str(&BASE64.encode(&bundle.signed_pre_key.signature));
        xml.push_str("</signedPreKeySignature>");
        
        // Pre-keys
        xml.push_str("<prekeys>");
        for prekey in &bundle.pre_keys {
            xml.push_str(&format!(
                "<preKeyPublic preKeyId='{}'>{}</preKeyPublic>",
                prekey.id,
                BASE64.encode(&prekey.public_key)
            ));
        }
        xml.push_str("</prekeys>");
        
        xml.push_str("</bundle>");
        
        Ok(xml)
    }
    
    /// Convert a device list to XML for publishing
    pub fn device_list_to_xml(device_ids: &[u32]) -> Result<String, XmlError> {
        let mut xml = String::new();
        
        xml.push_str(&format!("<list xmlns='{}'>", OMEMO_NAMESPACE));
        
        for device_id in device_ids {
            xml.push_str(&format!("<device id='{}' />", device_id));
        }
        
        xml.push_str("</list>");
        
        Ok(xml)
    }
    
    /// Parse an OMEMO message from XML
    pub fn omemo_message_from_xml(xml: &str) -> Result<OmemoMessage, XmlError> {
        log::debug!("XML_PARSE_DEBUG: Parsing OMEMO message from XML: {}", xml);
        
        // Parse the XML
        let doc = Document::parse(xml)
            .map_err(|e| XmlError::ParseError(e.to_string()))?;
        
        // Find the encrypted element
        let encrypted = doc.descendants()
            .find(|n| n.has_tag_name("encrypted") && 
                  n.has_attribute("xmlns") && 
                  n.attribute("xmlns").unwrap() == OMEMO_NAMESPACE)
            .ok_or(XmlError::MissingElementError("encrypted element not found".to_string()))?;
        
        // Find the header element
        let header = encrypted.children()
            .find(|n| n.has_tag_name("header"))
            .ok_or(XmlError::MissingElementError("header element not found".to_string()))?;
        
        // Get the sender device id
        let sid = header.attribute("sid")
            .ok_or(XmlError::MissingElementError("sid attribute not found".to_string()))?;
        
        let sender_device_id = sid.parse::<u32>()
            .map_err(|e| XmlError::ParseError(format!("Invalid sid: {}", e)))?;
        
        log::debug!("XML_PARSE_DEBUG: sender_device_id: {}", sender_device_id);
        
        // Get the IV
        let iv_elem = header.children()
            .find(|n| n.has_tag_name("iv"))
            .ok_or(XmlError::MissingElementError("iv element not found".to_string()))?;
        
        let iv_text = iv_elem.text()
            .ok_or(XmlError::MissingElementError("iv text not found".to_string()))?;
        
        let iv = BASE64.decode(iv_text)
            .map_err(|e| XmlError::EncodingError(format!("Failed to decode iv: {}", e)))?;
        
        // Parse the keys
        let mut encrypted_keys = std::collections::HashMap::new();
        
        log::debug!("XML_PARSE_DEBUG: Starting to parse keys");
        for key_elem in header.children().filter(|n| n.has_tag_name("key")) {
            let rid = key_elem.attribute("rid")
                .ok_or(XmlError::MissingElementError("rid attribute not found".to_string()))?;
            
            let device_id = rid.parse::<u32>()
                .map_err(|e| XmlError::ParseError(format!("Invalid rid: {}", e)))?;
            
            let key_text = key_elem.text()
                .ok_or(XmlError::MissingElementError("key text not found".to_string()))?;
            
            let key = BASE64.decode(key_text)
                .map_err(|e| XmlError::EncodingError(format!("Failed to decode key: {}", e)))?;
            
            log::debug!("XML_PARSE_DEBUG: Parsed key for device {}: {} bytes", device_id, key.len());
            encrypted_keys.insert(device_id, key);
        }
        
        log::debug!("XML_PARSE_DEBUG: Total keys parsed: {}", encrypted_keys.len());
        for device_id in encrypted_keys.keys() {
            log::debug!("XML_PARSE_DEBUG: Key available for device: {}", device_id);
        }
        
        // Try to get the ephemeral key (for PreKey messages)
        let ephemeral_key = if let Some(eph_elem) = header.children().find(|n| n.has_tag_name("ephemeral")) {
            if let Some(eph_text) = eph_elem.text() {
                Some(BASE64.decode(eph_text)
                    .map_err(|e| XmlError::EncodingError(format!("Failed to decode ephemeral key: {}", e)))?)
            } else {
                None
            }
        } else {
            None
        };
        
        log::debug!("XML_PARSE_DEBUG: ephemeral_key is_some: {}", ephemeral_key.is_some());
        
        // Get the payload
        let payload = encrypted.children()
            .find(|n| n.has_tag_name("payload"))
            .ok_or(XmlError::MissingElementError("payload element not found".to_string()))?;
        
        let payload_text = payload.text()
            .ok_or(XmlError::MissingElementError("payload text not found".to_string()))?;
        
        let ciphertext = BASE64.decode(payload_text)
            .map_err(|e| XmlError::EncodingError(format!("Failed to decode payload: {}", e)))?;
        
        // Try to get the MAC from the header (optional)
        let mac = if let Some(mac_elem) = header.children().find(|n| n.has_tag_name("mac")) {
            if let Some(mac_text) = mac_elem.text() {
                BASE64.decode(mac_text)
                    .map_err(|e| XmlError::EncodingError(format!("Failed to decode mac: {}", e)))?
            } else {
                vec![] // Empty MAC if no text
            }
        } else {
            vec![] // Empty MAC if no element
        };
        
        // For this simplified implementation, we'll use placeholder values for ratchet_key,
        // previous_counter, counter which would normally be part of the Double Ratchet message
        
        // Create the OMEMO message
        let message = OmemoMessage {
            sender_device_id,
            ratchet_key: vec![0; 32], // Placeholder
            previous_counter: 0,      // Placeholder
            counter: 0,               // Placeholder
            ciphertext,
            mac,                      // Now using the actual MAC from XML
            iv,
            encrypted_keys,
            is_prekey: ephemeral_key.is_some(), // This is a PreKey message if ephemeral key is present
            ephemeral_key,            // Extracted from XML
            prekey_devices: HashSet::new(),
        };
        
        Ok(message)
    }
    
    /// Convert an OMEMO message to XML for sending
    pub fn omemo_message_to_xml(message: &OmemoMessage) -> String {
        let mut xml = String::new();
        
        log::debug!("XML_DEBUG: Converting OMEMO message to XML");
        log::debug!("XML_DEBUG: is_prekey: {}", message.is_prekey);
        log::debug!("XML_DEBUG: ephemeral_key is_some: {}", message.ephemeral_key.is_some());
        log::debug!("XML_DEBUG: encrypted_keys.len(): {}", message.encrypted_keys.len());
        for (device_id, key) in &message.encrypted_keys {
            log::debug!("XML_DEBUG: Key for device {}: {} bytes", device_id, key.len());
        }
        if let Some(ref eph) = message.ephemeral_key {
            log::debug!("XML_DEBUG: ephemeral_key length: {}, first 16 bytes: {}", 
                eph.len(), hex::encode(&eph[..16.min(eph.len())]));
        }
        
        xml.push_str(&format!("<encrypted xmlns='{}'>", OMEMO_NAMESPACE));
        
        // Header
        xml.push_str(&format!("<header sid='{}'>", message.sender_device_id));
        
        // IV
        xml.push_str("<iv>");
        xml.push_str(&BASE64.encode(&message.iv));
        xml.push_str("</iv>");
        
        // Ephemeral key (only for PreKey messages)
        if let Some(ephemeral_key) = &message.ephemeral_key {
            log::debug!("XML_DEBUG: Adding ephemeral key to XML");
            xml.push_str("<ephemeral>");
            xml.push_str(&BASE64.encode(ephemeral_key));
            xml.push_str("</ephemeral>");
        } else {
            log::debug!("XML_DEBUG: No ephemeral key to add to XML");
        }
        
        // Keys
        for (device_id, key) in &message.encrypted_keys {
            log::debug!("XML_DEBUG: Adding key for device {} to XML", device_id);
            xml.push_str(&format!("<key rid='{}'>{}</key>", device_id, BASE64.encode(key)));
        }
        
        xml.push_str("</header>");
        
        // Payload
        xml.push_str("<payload>");
        xml.push_str(&BASE64.encode(&message.ciphertext));
        xml.push_str("</payload>");
        
        xml.push_str("</encrypted>");
        
        log::debug!("XML_DEBUG: Generated XML: {}", xml);
        xml
    }
}

/// Normalize a JID to bare JID for OMEMO session consistency
/// This ensures OMEMO sessions are bound to accounts, not specific resources
fn normalize_jid_to_bare(jid: &str) -> String {
    let clean_jid = jid.to_lowercase().trim().to_string();
    
    // Strip the resource part (everything after the last '/')
    if let Some(slash_pos) = clean_jid.rfind('/') {
        clean_jid[..slash_pos].to_string()
    } else {
        clean_jid
    }
}