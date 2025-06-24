// src/omemo/protocol.rs
//! Implementation of the OMEMO protocol according to XEP-0384
//!
//! This module handles the cryptographic protocol for OMEMO, including X3DH and Double Ratchet.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

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
}

/// Double Ratchet implementation for OMEMO
pub struct DoubleRatchet;

impl X3DHProtocol {
    /// Generate a key pair for OMEMO operations
    pub fn generate_key_pair() -> Result<KeyPair, DoubleRatchetError> {
        // Generate an X25519 key pair using our crypto module's function
        // which avoids the API compatibility issues
        let (public_key, private_key) = crypto::generate_x25519_keypair()
            .map_err(DoubleRatchetError::CryptoError)?;
        
        // Return the key pair
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
    
    /// Sign a pre-key with the identity key - updated to use ed25519_dalek v2
    pub fn sign_pre_key(identity_private_key: &[u8], pre_key_public: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        // We'll use ed25519 for signing, which uses a different key format than x25519
        // Note: The identity_private_key provided MUST be a valid 32-byte Ed25519 private key (seed).
        // A more robust implementation would handle key generation and storage consistently.

        // Create the signing key
        let key_bytes: &[u8; 32] = identity_private_key.try_into().map_err(|_| {
            DoubleRatchetError::InvalidSignatureError("Invalid private key length for Ed25519".to_string())
        })?;
        let signing_key = SigningKey::from_bytes(key_bytes);
        
        // Sign the pre-key
        let signature = signing_key.sign(pre_key_public);

        Ok(signature.to_bytes().to_vec())
    }
    
    /// Verify a pre-key signature - updated to use ed25519_dalek v2
    pub fn verify_pre_key(identity_public_key: &[u8], pre_key_public: &[u8], signature: &[u8]) -> Result<bool, DoubleRatchetError> {
        // We'll use ed25519 for verifying, which uses a different key format than x25519
        if signature.len() != 64 {
            return Err(DoubleRatchetError::InvalidSignatureError(
                format!("Invalid signature length: {}", signature.len())
            ));
        }

        // Convert the signature to the expected format
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature::from_bytes(&sig_bytes);

        // Note: The identity_public_key provided MUST be a valid 32-byte Ed25519 public key.

        // Create the verifying key
        let verifying_key = match VerifyingKey::from_bytes(identity_public_key.try_into().map_err(|_| {
            DoubleRatchetError::InvalidSignatureError("Invalid public key length for Ed25519".to_string())
        })?) {
            Ok(k) => k,
            Err(e) => {
                return Err(DoubleRatchetError::InvalidSignatureError(
                    format!("Invalid verifying key: {}", e)
                ));
            }
        };

        // Verify the signature
        match verifying_key.verify(pre_key_public, &sig) {
            Ok(()) => Ok(true),
            Err(e) => {
                Err(DoubleRatchetError::InvalidSignatureError(
                    format!("Signature verification failed: {}", e)
                ))
            }
        }
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
        
        // Perform the key agreement
        let mut dh_values = Vec::new();
        
        // DH1 = DH(IKa, SPKb)
        let dh1 = crypto::x25519_diffie_hellman(
            &identity_key_pair.private_key,
            their_signed_pre_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        dh_values.push(dh1);
        
        // DH2 = DH(EKa, IKb)
        let dh2 = crypto::x25519_diffie_hellman(
            &ephemeral_key_pair.private_key,
            their_identity_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        dh_values.push(dh2);
        
        // DH3 = DH(EKa, SPKb)
        let dh3 = crypto::x25519_diffie_hellman(
            &ephemeral_key_pair.private_key,
            their_signed_pre_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        dh_values.push(dh3);
        
        // DH4 = DH(EKa, OPKb) (if OPKb exists)
        if let Some(their_one_time_pre_key) = their_one_time_pre_key {
            let dh4 = crypto::x25519_diffie_hellman(
                &ephemeral_key_pair.private_key,
                their_one_time_pre_key,
            ).map_err(DoubleRatchetError::CryptoError)?;
            dh_values.push(dh4);
        }
        
        // Concatenate all DH values
        let mut concat_dh = Vec::new();
        for dh in dh_values {
            concat_dh.extend_from_slice(&dh);
        }
        
        // Use HKDF to derive the shared key
        let salt = vec![0u8; 32]; // Zero salt
        let info = b"OMEMO X3DH";
        let shared_key = crypto::kdf(&concat_dh, &salt, info);
        
        Ok(shared_key)
    }
    
    /// Perform X3DH key agreement as the recipient
    pub fn key_agreement_recipient(
        identity_key_pair: &KeyPair,
        their_identity_key: &[u8],
        signed_pre_key_pair: &KeyPair,
        one_time_pre_key_pair: Option<&KeyPair>,
        their_ephemeral_key: &[u8],
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        // Perform the key agreement
        let mut dh_values = Vec::new();
        
        // DH1 = DH(SPKb, IKa)
        let dh1 = crypto::x25519_diffie_hellman(
            &signed_pre_key_pair.private_key,
            their_identity_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        dh_values.push(dh1);
        
        // DH2 = DH(IKb, EKa)
        let dh2 = crypto::x25519_diffie_hellman(
            &identity_key_pair.private_key,
            their_ephemeral_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        dh_values.push(dh2);
        
        // DH3 = DH(SPKb, EKa)
        let dh3 = crypto::x25519_diffie_hellman(
            &signed_pre_key_pair.private_key,
            their_ephemeral_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        dh_values.push(dh3);
        
        // DH4 = DH(OPKb, EKa) (if OPKb exists)
        if let Some(one_time_pre_key_pair) = one_time_pre_key_pair {
            let dh4 = crypto::x25519_diffie_hellman(
                &one_time_pre_key_pair.private_key,
                their_ephemeral_key,
            ).map_err(DoubleRatchetError::CryptoError)?;
            dh_values.push(dh4);
        }
        
        // Concatenate all DH values
        let mut concat_dh = Vec::new();
        for dh in dh_values {
            concat_dh.extend_from_slice(&dh);
        }
        
        // Use HKDF to derive the shared key
        let salt = vec![0u8; 32]; // Zero salt
        let info = b"OMEMO X3DH";
        let shared_key = crypto::kdf(&concat_dh, &salt, info);
        
        Ok(shared_key)
    }
}

impl DoubleRatchet {
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
        // Perform X3DH key agreement
        let shared_secret = X3DHProtocol::key_agreement_initiator(
            &local_identity_key_pair,
            &remote_identity_key,
            &remote_signed_prekey,
            remote_one_time_prekey.as_deref(),
        )?;
        
        // Generate an initial ratchet key pair
        let ratchet_key_pair = X3DHProtocol::generate_key_pair()?;
        
        // Initialize the sending and root chains
        let root_key = shared_secret;
        let send_chain_key = crypto::kdf(&root_key, &remote_signed_prekey, b"send_chain");
        
        // Create the state
        let state = RatchetState {
            initialized: true,
            is_initiator: true,
            remote_identity_key,
            local_identity_key_pair,
            root_key,
            send_chain_key,
            receive_chain_key: vec![],
            ratchet_key_pair,
            remote_ratchet_key: remote_signed_prekey.clone(),
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
        
        // Initialize the receiving and root chains
        let root_key = shared_secret;
        let receive_chain_key = crypto::kdf(&root_key, &remote_ephemeral_key, b"receive_chain");
        
        // Create the state
        let state = RatchetState {
            initialized: true,
            is_initiator: false,
            remote_identity_key,
            local_identity_key_pair,
            root_key,
            send_chain_key: vec![],
            receive_chain_key,
            ratchet_key_pair: local_signed_prekey_pair,
            remote_ratchet_key: remote_ephemeral_key,
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
    
    /// Encrypt a message
    pub fn encrypt(state: &mut RatchetState, plaintext: &[u8]) -> Result<OmemoMessage, DoubleRatchetError> {
        // Get the message key
        let message_key = Self::derive_next_sending_key(state);
        
        // Generate a random IV
        let iv = crypto::generate_iv();
        
        // Encrypt the message
        let ciphertext = crypto::encrypt(plaintext, &message_key, &iv, &[])
            .map_err(DoubleRatchetError::CryptoError)?;
        
        // Create a MAC
        let mac = crypto::sha256_hash(&message_key)[..16].to_vec();
        
        // Create the message
        let message = OmemoMessage {
            sender_device_id: state.local_device_id,
            ratchet_key: state.ratchet_key_pair.public_key.clone(),
            previous_counter: state.send_message_number,
            counter: state.send_message_number,
            ciphertext,
            mac,
            iv,
            encrypted_keys: std::collections::HashMap::new(),
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
        // Verify the MAC
        let calculated_mac = crypto::sha256_hash(key)[..16].to_vec();
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
        while state.receive_message_number < target {
            // Generate the key for this message
            let message_key = Self::derive_next_receiving_key(state);
            
            // Store it as a skipped message key
            let key = (state.remote_ratchet_key.clone(), state.receive_message_number);
            state.skipped_message_keys.insert(key, message_key);
        }
        
        Ok(())
    }
    
    /// Derive the next sending key
    fn derive_next_sending_key(state: &mut RatchetState) -> Vec<u8> {
        // Use the KDF to derive the next key
        let message_key = crypto::kdf(
            &state.send_chain_key,
            &[1u8], // Key derivation constant
            b"msg",
        );
        
        // Update the chain key
        state.send_chain_key = crypto::kdf(
            &state.send_chain_key,
            &[2u8], // Chain key derivation constant
            b"chain",
        );
        
        message_key
    }
    
    /// Derive the next receiving key
    fn derive_next_receiving_key(state: &mut RatchetState) -> Vec<u8> {
        // Use the KDF to derive the next key
        let message_key = crypto::kdf(
            &state.receive_chain_key,
            &[1u8], // Key derivation constant
            b"msg",
        );
        
        // Update the chain key
        state.receive_chain_key = crypto::kdf(
            &state.receive_chain_key,
            &[2u8], // Chain key derivation constant
            b"chain",
        );
        
        // Update the receive counter
        state.receive_message_number += 1;
        
        message_key
    }
    
    /// Perform a DH ratchet step
    fn dh_ratchet(state: &mut RatchetState, their_ratchet_key: &[u8]) -> Result<(), DoubleRatchetError> {
        // Update state
        state.prev_remote_ratchet_key = state.remote_ratchet_key.clone();
        state.remote_ratchet_key = their_ratchet_key.to_vec();
        state.prev_receive_message_number = state.receive_message_number;
        state.receive_message_number = 0;
        
        // Compute a new shared secret
        let dh_output = crypto::x25519_diffie_hellman(
            &state.ratchet_key_pair.private_key,
            their_ratchet_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // Update the root key and receive chain
        let kdf_out = crypto::kdf(&state.root_key, &dh_output, b"root_chain");
        state.root_key = kdf_out.clone();
        state.receive_chain_key = crypto::kdf(&state.root_key, &dh_output, b"receive_chain");
        
        // Generate a new ratchet key pair
        state.ratchet_key_pair = X3DHProtocol::generate_key_pair()?;
        
        // Compute a new shared secret
        let dh_output = crypto::x25519_diffie_hellman(
            &state.ratchet_key_pair.private_key,
            their_ratchet_key,
        ).map_err(DoubleRatchetError::CryptoError)?;
        
        // Update the root key and send chain
        let kdf_out = crypto::kdf(&state.root_key, &dh_output, b"root_chain");
        state.root_key = kdf_out.clone();
        state.send_chain_key = crypto::kdf(&state.root_key, &dh_output, b"send_chain");
        state.send_message_number = 0;
        
        Ok(())
    }

    /// Encrypt a message key for transport
    pub fn encrypt_key(state: &mut RatchetState, key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        // Generate a random IV for CBC mode (16 bytes)
        let iv = crypto::generate_cbc_iv();
        
        // Derive a transport key from the root key
        let transport_key = crypto::kdf(&state.root_key, &iv, b"transport");
        
        // Encrypt the key
        let encrypted_key = crypto::encrypt_data(key, &transport_key, &iv)
            .map_err(DoubleRatchetError::CryptoError)?;
        
        // Concatenate IV and encrypted key for storage/transport
        let mut result = Vec::new();
        result.extend_from_slice(&iv);
        result.extend_from_slice(&encrypted_key);
        
        Ok(result)
    }
    
    /// Decrypt a message key from transport
    pub fn decrypt_key(state: &mut RatchetState, encrypted_key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        // Split IV and encrypted key (first 16 bytes are the IV for CBC mode)
        if encrypted_key.len() < 16 {
            return Err(DoubleRatchetError::InvalidMessageFormatError(
                "Encrypted key too short".to_string()
            ));
        }
        
        let iv = &encrypted_key[0..16];
        let cipher = &encrypted_key[16..];
        
        // Derive the transport key
        let transport_key = crypto::kdf(&state.root_key, iv, b"transport");
        
        // Decrypt the key
        let key = crypto::decrypt_data(cipher, &transport_key, iv)
            .map_err(DoubleRatchetError::CryptoError)?;
        
        Ok(key)
    }
}

/// Utility functions for OMEMO protocol
pub mod utils {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use roxmltree::Document;
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
        
        for key_elem in header.children().filter(|n| n.has_tag_name("key")) {
            let rid = key_elem.attribute("rid")
                .ok_or(XmlError::MissingElementError("rid attribute not found".to_string()))?;
            
            let device_id = rid.parse::<u32>()
                .map_err(|e| XmlError::ParseError(format!("Invalid rid: {}", e)))?;
            
            let key_text = key_elem.text()
                .ok_or(XmlError::MissingElementError("key text not found".to_string()))?;
            
            let key = BASE64.decode(key_text)
                .map_err(|e| XmlError::EncodingError(format!("Failed to decode key: {}", e)))?;
            
            encrypted_keys.insert(device_id, key);
        }
        
        // Get the payload
        let payload = encrypted.children()
            .find(|n| n.has_tag_name("payload"))
            .ok_or(XmlError::MissingElementError("payload element not found".to_string()))?;
        
        let payload_text = payload.text()
            .ok_or(XmlError::MissingElementError("payload text not found".to_string()))?;
        
        let ciphertext = BASE64.decode(payload_text)
            .map_err(|e| XmlError::EncodingError(format!("Failed to decode payload: {}", e)))?;
        
        // For this simplified implementation, we'll use placeholder values for ratchet_key,
        // previous_counter, counter, and mac, which would normally be part of the Double Ratchet message
        
        // Create the OMEMO message
        let message = OmemoMessage {
            sender_device_id,
            ratchet_key: vec![0; 32], // Placeholder
            previous_counter: 0,      // Placeholder
            counter: 0,               // Placeholder
            ciphertext,
            mac: vec![0; 16],         // Placeholder
            iv,
            encrypted_keys,
        };
        
        Ok(message)
    }
    
    /// Convert an OMEMO message to XML for sending
    pub fn omemo_message_to_xml(message: &OmemoMessage) -> String {
        let mut xml = String::new();
        
        xml.push_str(&format!("<encrypted xmlns='{}'>", OMEMO_NAMESPACE));
        
        // Header
        xml.push_str(&format!("<header sid='{}'>", message.sender_device_id));
        
        // IV
        xml.push_str("<iv>");
        xml.push_str(&BASE64.encode(&message.iv));
        xml.push_str("</iv>");
        
        // Keys
        for (device_id, key) in &message.encrypted_keys {
            xml.push_str(&format!("<key rid='{}'>{}</key>", device_id, BASE64.encode(key)));
        }
        
        xml.push_str("</header>");
        
        // Payload
        xml.push_str("<payload>");
        xml.push_str(&BASE64.encode(&message.ciphertext));
        xml.push_str("</payload>");
        
        xml.push_str("</encrypted>");
        
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