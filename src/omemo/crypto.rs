// src/omemo/crypto.rs
//! Cryptographic primitives for OMEMO
//!
//! This module provides the cryptographic operations needed for OMEMO encryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use log::{debug, trace, error};
use std::time::Instant;
// Add imports for AES-CBC with PKCS#7 padding
use aes::Aes256;
// The KeyIvInit trait is needed for new() method on Encryptor and Decryptor
use aes::cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut};
use cbc::{Encryptor, Decryptor};
use block_padding::Pkcs7;

/// Errors related to cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Error during AES-GCM encryption or decryption
    #[error("AES-GCM error: {0}")]
    AesGcmError(String),
    
    /// Error during HMAC operation
    #[error("HMAC error: {0}")]
    HmacError(String),
    
    /// Error during KDF derivation
    #[error("KDF error: {0}")]
    KdfError(String),
    
    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInputError(String),
    
    /// Key generation error
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Invalid IV
    #[error("Invalid IV: {0}")]
    InvalidIV(String),
}

/// The size of the AES key in bytes (256 bits)
pub const AES_KEY_SIZE: usize = 32;

/// The size of the IV in bytes for AES-GCM (96 bits)
pub const AES_IV_SIZE: usize = 12;

/// The size of the IV in bytes for AES-CBC (128 bits)
pub const AES_CBC_IV_SIZE: usize = 16;

/// Generate a random initialization vector for AES-GCM
pub fn generate_iv() -> Vec<u8> {
    trace!("Generating random {}-bit IV for AES-GCM", AES_IV_SIZE * 8);
    let mut iv = vec![0u8; AES_IV_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    trace!("Generated IV: {}", hex::encode(&iv));
    iv
}

/// Generate a random initialization vector for AES-CBC
pub fn generate_cbc_iv() -> Vec<u8> {
    trace!("Generating random {}-bit IV for AES-CBC", AES_CBC_IV_SIZE * 8);
    let mut iv = vec![0u8; AES_CBC_IV_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    trace!("Generated CBC IV: {}", hex::encode(&iv));
    iv
}

/// Generate a random key for message encryption
pub fn generate_message_key() -> Vec<u8> {
    trace!("Generating random 256-bit message key");
    let mut bytes = vec![0u8; 32]; // 256 bits for AES-256
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    trace!("Generated message key: {}", hex::encode(&bytes));
    bytes
}

/// Validate an OMEMO initialization vector (IV)
pub fn validate_iv(iv: &[u8]) -> Result<(), CryptoError> {
    if iv.is_empty() {
        error!("IV is empty");
        return Err(CryptoError::InvalidIV("IV is empty".to_string()));
    }
    
    if iv.len() != AES_IV_SIZE {
        error!("Invalid IV length: {} (expected {} bytes)", iv.len(), AES_IV_SIZE);
        return Err(CryptoError::InvalidIV(format!(
            "Invalid IV length: {} (expected {} bytes)",
            iv.len(), AES_IV_SIZE
        )));
    }
    
    //debug!("IV validation successful: {} bytes", iv.len());
    trace!("IV: {}", hex::encode(iv));
    Ok(())
}

/// Encrypt a message using AES-256-GCM
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Encrypting {} bytes of data with AES-256-GCM", plaintext.len());
    trace!("Encryption key: {}", hex::encode(key));
    trace!("IV: {}", hex::encode(iv));
    if !associated_data.is_empty() {
        trace!("Associated data: {}", hex::encode(associated_data));
    }
    
    // Validate key and IV sizes
    if key.len() != AES_KEY_SIZE {
        error!("Invalid key size: {} (expected {} bytes)", key.len(), AES_KEY_SIZE);
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(), AES_KEY_SIZE
        )));
    }
    
    // Validate the IV
    validate_iv(iv)?;
    
    // Create the cipher
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create AES-GCM cipher: {}", e);
            return Err(CryptoError::AesGcmError(format!("Failed to create cipher: {}", e)));
        }
    };
    
    // Create the nonce
    let nonce = Nonce::from_slice(iv);
    
    // Encrypt the plaintext
    let ciphertext = match cipher.encrypt(nonce, plaintext) {
        Ok(c) => c,
        Err(e) => {
            error!("AES-GCM encryption failed: {}", e);
            return Err(CryptoError::AesGcmError(format!("Encryption failed: {}", e)));
        }
    };
    
    let duration = start.elapsed();
    //debug!("Encryption successful: {} bytes encrypted in {:?}", ciphertext.len(), duration);
    trace!("Ciphertext: {}", hex::encode(&ciphertext));
    
    Ok(ciphertext)
}

/// Decrypt a message using AES-256-GCM
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Decrypting {} bytes of data with AES-256-GCM", ciphertext.len());
    trace!("Decryption key: {}", hex::encode(key));
    trace!("IV: {}", hex::encode(iv));
    if !associated_data.is_empty() {
        trace!("Associated data: {}", hex::encode(associated_data));
    }
    trace!("Ciphertext: {}", hex::encode(ciphertext));
    
    // Validate key and IV sizes
    if key.len() != AES_KEY_SIZE {
        error!("Invalid key size: {} (expected {} bytes)", key.len(), AES_KEY_SIZE);
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(), AES_KEY_SIZE
        )));
    }
    
    // Validate the IV
    validate_iv(iv)?;
    
    // Create the cipher
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create AES-GCM cipher: {}", e);
            return Err(CryptoError::AesGcmError(format!("Failed to create cipher: {}", e)));
        }
    };
    
    // Create the nonce
    let nonce = Nonce::from_slice(iv);
    
    // Decrypt the ciphertext
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(e) => {
            error!("AES-GCM decryption failed: {}", e);
            return Err(CryptoError::AesGcmError(format!("Decryption failed: {}", e)));
        }
    };
    
    let duration = start.elapsed();
    //debug!("Decryption successful: {} bytes decrypted in {:?}", plaintext.len(), duration);
    
    Ok(plaintext)
}

/// Encrypt data using AES-256-CBC with PKCS#7 padding
/// This function is used for key wrapping in OMEMO
pub fn encrypt_data(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Encrypting {} bytes of data with AES-256-CBC", data.len());
    trace!("Encryption key: {}", hex::encode(key));
    trace!("IV: {}", hex::encode(iv));
    
    // Validate key and IV sizes
    if key.len() != AES_KEY_SIZE {
        error!("Invalid key size: {} (expected {} bytes)", key.len(), AES_KEY_SIZE);
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(), AES_KEY_SIZE
        )));
    }
    
    if iv.len() != 16 {  // AES-CBC requires a 16-byte IV (128 bits)
        error!("Invalid IV size for CBC: {} (expected 16 bytes)", iv.len());
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid IV size for CBC: {} (expected 16 bytes)",
            iv.len()
        )));
    }
    
    // Create a CBC mode encryptor with PKCS#7 padding
    // Note: This uses the KeyIvInit trait's new method
    let mut buffer = vec![0u8; data.len() + 16]; // Add space for padding
    
    // Create a new scope to ensure the mutable borrow is dropped
    let pos_len = {
        let pos = Encryptor::<Aes256>::new(key.into(), iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buffer)
            .map_err(|e| {
                error!("AES-CBC encryption failed: {}", e);
                CryptoError::AesGcmError(format!("AES-CBC encryption failed: {}", e))
            })?;
        
        pos.len() // Return the length to use after the borrow is released
    };
    
    // Now we can safely truncate the buffer
    buffer.truncate(pos_len);
    
    let duration = start.elapsed();
    //debug!("AES-CBC encryption successful: {} bytes encrypted in {:?}", buffer.len(), duration);
    trace!("Ciphertext: {}", hex::encode(&buffer));
    
    Ok(buffer)
}

/// Decrypt data using AES-256-CBC with PKCS#7 padding
/// This function is used for key unwrapping in OMEMO
pub fn decrypt_data(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Decrypting {} bytes of data with AES-256-CBC", data.len());
    trace!("Decryption key: {}", hex::encode(key));
    trace!("IV: {}", hex::encode(iv));
    trace!("Ciphertext: {}", hex::encode(data));
    
    // Validate key and IV sizes
    if key.len() != AES_KEY_SIZE {
        error!("Invalid key size: {} (expected {} bytes)", key.len(), AES_KEY_SIZE);
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(), AES_KEY_SIZE
        )));
    }
    
    if iv.len() != 16 {  // AES-CBC requires a 16-byte IV (128 bits)
        error!("Invalid IV size for CBC: {} (expected 16 bytes)", iv.len());
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid IV size for CBC: {} (expected 16 bytes)",
            iv.len()
        )));
    }
    
    // Create a CBC mode decryptor with PKCS#7 padding
    // Note: This uses the KeyIvInit trait's new method
    let mut buffer = vec![0u8; data.len()];
    
    // Create a new scope to ensure the mutable borrow is dropped
    let pos_len = {
        let pos = Decryptor::<Aes256>::new(key.into(), iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buffer)
            .map_err(|e| {
                error!("AES-CBC decryption failed: {}", e);
                CryptoError::AesGcmError(format!("AES-CBC decryption failed: {}", e))
            })?;
        
        pos.len() // Return the length to use after the borrow is released
    };
    
    // Now we can safely truncate the buffer
    buffer.truncate(pos_len);
    
    let duration = start.elapsed();
    //debug!("AES-CBC decryption successful: {} bytes decrypted in {:?}", buffer.len(), duration);
    
    Ok(buffer)
}

/// Calculate an HMAC using SHA-256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Calculating HMAC-SHA256 for {} bytes of data", data.len());
    trace!("HMAC key: {}", hex::encode(key));
    
    // Create the HMAC instance - using hmac::Mac trait's new_from_slice method
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|e| {
            error!("Failed to create HMAC: {}", e);
            CryptoError::HmacError(format!("Failed to create HMAC: {}", e))
        })?;
    
    // Update with the data
    mac.update(data);
    
    // Finalize and get the result
    let result = mac.finalize().into_bytes().to_vec();
    
    let duration = start.elapsed();
    //debug!("HMAC-SHA256 computation successful in {:?}", duration);
    trace!("HMAC result: {}", hex::encode(&result));
    
    Ok(result)
}

/// Derive a key using HKDF with SHA-256
pub fn kdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Vec<u8> {
    //debug!("Deriving key using HKDF-SHA256");
    trace!("Input key material: {}", hex::encode(ikm));
    trace!("Salt: {}", hex::encode(salt));
    trace!("Info: {}", String::from_utf8_lossy(info));
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; 32]; // 256 bits output
    
    // Extract and expand the key
    hkdf.expand(info, &mut output)
        .expect("HKDF expansion failed");
    
    trace!("Derived key: {}", hex::encode(&output));
    output
}

/// Calculate a SHA-256 hash
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let start = Instant::now();
    trace!("Calculating SHA-256 hash of {} bytes of data", data.len());
    
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize().to_vec();
    
    let duration = start.elapsed();
    //debug!("SHA-256 hash computation successful in {:?}", duration);
    trace!("Hash result: {}", hex::encode(&hash));
    hash
}

/// Securely compare two byte arrays in constant time
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    trace!("Performing constant-time comparison of {} bytes", a.len());
    
    if a.len() != b.len() {
        trace!("Length mismatch: {} != {}", a.len(), b.len());
        return false;
    }
    
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    let equal = result == 0;
    trace!("Secure comparison result: {}", equal);
    equal
}

/// Generate an ephemeral X25519 key pair for the X3DH key agreement
pub fn generate_x25519_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let start = Instant::now();
    //debug!("Generating X25519 key pair");
    
    // Generate a secure random static secret key using OsRng for cryptographic randomness
    let static_secret = StaticSecret::random_from_rng(OsRng);
    
    // Derive the public key from the secret key
    let public_key = PublicKey::from(&static_secret);
    
    // Get the bytes
    let public_key_bytes = public_key.as_bytes().to_vec();
    let private_key_bytes = static_secret.to_bytes().to_vec();
    
    let duration = start.elapsed();
    //debug!("X25519 key pair generation successful in {:?}", duration);
    trace!("Public key: {}", hex::encode(&public_key_bytes));
    trace!("Private key: {}", hex::encode(&private_key_bytes));
    
    Ok((private_key_bytes, public_key_bytes))
}

/// Perform a Diffie-Hellman key exchange with X25519
pub fn x25519_diffie_hellman(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Performing X25519 Diffie-Hellman key exchange");
    trace!("Using private key: {}", hex::encode(private_key));
    trace!("Using public key: {}", hex::encode(public_key));
    
    // Validate key lengths
    if private_key.len() != 32 || public_key.len() != 32 {
        error!("Invalid X25519 key length: private={}, public={}", private_key.len(), public_key.len());
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key length: private={}, public={}",
            private_key.len(), public_key.len()
        )));
    }
    
    // Convert to the appropriate types for x25519-dalek
    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(private_key);
    
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(public_key);
    
    // Create the StaticSecret from bytes
    let static_secret = StaticSecret::from(private_bytes);
    let public = PublicKey::from(public_bytes);
    
    // Compute the DH shared secret
    let shared_secret = static_secret.diffie_hellman(&public);
    let shared_bytes = shared_secret.as_bytes().to_vec();
    
    let duration = start.elapsed();
    //debug!("X25519 key exchange completed successfully in {:?}", duration);
    trace!("Shared secret: {}", hex::encode(&shared_bytes));
    
    Ok(shared_bytes)
}

/// Derive a key using HKDF
pub fn hkdf_derive(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let start = Instant::now();
    //debug!("Deriving key with HKDF: output_len={}", output_len);
    trace!("Salt: {}", hex::encode(salt));
    trace!("Input key material: {}", hex::encode(ikm));
    trace!("Info: {}", hex::encode(info));
    
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    
    if let Err(e) = hk.expand(info, &mut okm) {
        error!("HKDF expansion failed: {}", e);
        return Err(CryptoError::KdfError(format!("HKDF expansion failed: {}", e)));
    }
    
    let duration = start.elapsed();
    //debug!("HKDF key derivation successful in {:?}", duration);
    trace!("Derived key: {}", hex::encode(&okm));
    
    Ok(okm)
}

/// Create a Diffie-Hellman shared secret
pub fn calculate_dh(
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Just use our x25519_diffie_hellman function
    x25519_diffie_hellman(private_key, public_key)
}

/// Generate a key pair for X25519
pub fn generate_dh_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Just use our generate_x25519_keypair function
    generate_x25519_keypair()
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    sha256_hash(data)
}

/// Format a key fingerprint for human readability
pub fn format_fingerprint(fingerprint: &[u8]) -> String {
    let fp_hex = hex::encode(fingerprint);
    let chunks: Vec<String> = fp_hex.as_bytes()
        .chunks(2)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect();
    chunks.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_message_key();
        let iv = generate_iv();
        let plaintext = b"Hello, world!";
        let aad = b"additional data";
        
        let ciphertext = encrypt(plaintext, &key, &iv, aad).unwrap();
        assert_ne!(ciphertext, plaintext);
        
        let decrypted = decrypt(&ciphertext, &key, &iv, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_hkdf() {
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";
        
        let key = hkdf_derive(salt, ikm, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_dh() {
        let (priv_a, pub_a) = generate_dh_keypair().unwrap();
        let (priv_b, pub_b) = generate_dh_keypair().unwrap();
        
        let secret_a = calculate_dh(&priv_a, &pub_b).unwrap();
        let secret_b = calculate_dh(&priv_b, &pub_a).unwrap();
        
        assert_eq!(secret_a, secret_b);
    }
    
    #[test]
    fn test_hmac() {
        let key = b"key";
        let message = b"message";
        
        let hmac = hmac_sha256(key, message).unwrap();
        assert!(!hmac.is_empty());
    }
    
    #[test]
    fn test_sha256() {
        let data = b"data";
        
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);  // SHA-256 produces a 32-byte hash
    }
    
    #[test]
    fn test_validate_iv() {
        let valid_iv = generate_iv();
        assert!(validate_iv(&valid_iv).is_ok());
        
        let empty_iv: Vec<u8> = Vec::new();
        assert!(validate_iv(&empty_iv).is_err());
        
        let invalid_length_iv = vec![0; 16];
        assert!(validate_iv(&invalid_length_iv).is_err());
    }
    
    #[test]
    fn test_format_fingerprint() {
        let fingerprint = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        
        let formatted = format_fingerprint(&fingerprint);
        assert_eq!(formatted, "01:23:45:67:89:ab:cd:ef:fe:dc:ba:98:76:54:32:10");
    }
}