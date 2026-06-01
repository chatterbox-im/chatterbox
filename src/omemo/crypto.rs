// src/omemo/crypto.rs
//! Cryptographic primitives for OMEMO
//!
//! This module provides the cryptographic operations needed for OMEMO encryption.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint, scalar::Scalar};
use hex;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use log::{debug, error, trace};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

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
pub const AES_KEY_SIZE: usize = 16;

/// The size of the IV in bytes for AES-GCM (96 bits)
pub const AES_IV_SIZE: usize = 12;

/// Generate a random initialization vector for AES-GCM
pub fn generate_iv() -> Vec<u8> {
    trace!("Generating random {}-bit IV for AES-GCM", AES_IV_SIZE * 8);
    let mut iv = vec![0u8; AES_IV_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    trace!("Generated IV: {}", hex::encode(&iv));
    iv
}

/// Generate a random key for message encryption
pub fn generate_message_key() -> Vec<u8> {
    trace!("Generating random 128-bit message key");
    let mut bytes = vec![0u8; 16]; // 128 bits for AES-128
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    trace!("Generated message key: {}", hex::encode(&bytes));
    bytes
}

// Constants for Dino-compatible AES-GCM
pub const AES_GCM_KEY_SIZE: usize = 16; // 128-bit key for Dino compatibility
pub const AES_GCM_IV_SIZE: usize = 12; // 96-bit IV for AES-GCM

/// Generate a 16-byte AES key for Dino-compatible encryption
pub fn generate_aes_key() -> Vec<u8> {
    let mut key = vec![0u8; AES_GCM_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    trace!("Generated {}-byte AES key for GCM", AES_GCM_KEY_SIZE);
    key
}

/// Generate a 12-byte IV for AES-GCM (Dino-compatible)
pub fn generate_gcm_iv() -> Vec<u8> {
    let mut iv = vec![0u8; AES_GCM_IV_SIZE];
    OsRng.fill_bytes(&mut iv);
    trace!("Generated {}-byte IV for AES-GCM", AES_GCM_IV_SIZE);
    iv
}

/// Encrypt data using AES-128-GCM (Dino-compatible format)
/// Returns ciphertext + auth_tag combined
pub fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes_gcm_encrypt_with_ad(plaintext, key, iv, &[])
}

/// Encrypt data using AES-128-GCM with Associated Data (AD)
/// AD is authenticated but not encrypted — binds ciphertext to session context.
pub fn aes_gcm_encrypt_with_ad(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::Aes128Gcm;

    if key.len() != AES_GCM_KEY_SIZE {
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size for AES-GCM: {} (expected {} bytes)",
            key.len(),
            AES_GCM_KEY_SIZE
        )));
    }

    if iv.len() != AES_GCM_IV_SIZE {
        return Err(CryptoError::InvalidIV(format!(
            "Invalid IV size for AES-GCM: {} (expected {} bytes)",
            iv.len(),
            AES_GCM_IV_SIZE
        )));
    }

    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| {
        CryptoError::AesGcmError(format!("Failed to create AES-128-GCM cipher: {}", e))
    })?;

    let nonce = Nonce::from_slice(iv);

    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::AesGcmError(format!("AES-128-GCM encryption failed: {}", e)))?;

    trace!(
        "AES-128-GCM encryption successful: {} bytes plaintext -> {} bytes ciphertext+tag",
        plaintext.len(),
        ciphertext.len()
    );

    Ok(ciphertext)
}

/// Decrypt data using AES-128-GCM (Dino-compatible format)
/// Expects ciphertext + auth_tag combined
pub fn aes_gcm_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes_gcm_decrypt_with_ad(ciphertext, key, iv, &[])
}

/// Decrypt data using AES-128-GCM with Associated Data (AD)
pub fn aes_gcm_decrypt_with_ad(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::Aes128Gcm;

    if key.len() != AES_GCM_KEY_SIZE {
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size for AES-GCM: {} (expected {} bytes)",
            key.len(),
            AES_GCM_KEY_SIZE
        )));
    }

    if iv.len() != AES_GCM_IV_SIZE {
        return Err(CryptoError::InvalidIV(format!(
            "Invalid IV size for AES-GCM: {} (expected {} bytes)",
            iv.len(),
            AES_GCM_IV_SIZE
        )));
    }

    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| {
        CryptoError::AesGcmError(format!("Failed to create AES-128-GCM cipher: {}", e))
    })?;

    let nonce = Nonce::from_slice(iv);

    let payload = Payload {
        msg: ciphertext,
        aad: ad,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::AesGcmError(format!("AES-128-GCM decryption failed: {}", e)))?;

    trace!(
        "AES-128-GCM decryption successful: {} bytes ciphertext+tag -> {} bytes plaintext",
        ciphertext.len(),
        plaintext.len()
    );

    Ok(plaintext)
}

/// Encrypt using AES-256-CBC with PKCS7 padding (Signal protocol inner cipher)
pub fn aes_256_cbc_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    if key.len() != 32 {
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size for AES-256-CBC: {} (expected 32)",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(CryptoError::InvalidIV(format!(
            "Invalid IV size for AES-256-CBC: {} (expected 16)",
            iv.len()
        )));
    }

    let cipher = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| CryptoError::AesGcmError(format!("AES-256-CBC init failed: {}", e)))?;

    // Allocate buffer with space for padding (up to one extra block of 16 bytes)
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| CryptoError::AesGcmError("AES-256-CBC padding failed".to_string()))?;
    Ok(ct.to_vec())
}

/// Decrypt using AES-256-CBC with PKCS7 padding (Signal protocol inner cipher)
pub fn aes_256_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    if key.len() != 32 {
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size for AES-256-CBC: {} (expected 32)",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(CryptoError::InvalidIV(format!(
            "Invalid IV size for AES-256-CBC: {} (expected 16)",
            iv.len()
        )));
    }

    let cipher = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::AesGcmError(format!("AES-256-CBC init failed: {}", e)))?;

    let mut buf = ciphertext.to_vec();
    let pt = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| {
        CryptoError::AesGcmError("AES-256-CBC decryption/unpadding failed".to_string())
    })?;
    Ok(pt.to_vec())
}

/// Validate an OMEMO initialization vector (IV)
pub fn validate_iv(iv: &[u8]) -> Result<(), CryptoError> {
    if iv.is_empty() {
        error!("IV is empty");
        return Err(CryptoError::InvalidIV("IV is empty".to_string()));
    }

    if iv.len() != AES_IV_SIZE {
        error!(
            "Invalid IV length: {} (expected {} bytes)",
            iv.len(),
            AES_IV_SIZE
        );
        return Err(CryptoError::InvalidIV(format!(
            "Invalid IV length: {} (expected {} bytes)",
            iv.len(),
            AES_IV_SIZE
        )));
    }

    trace!("IV: {}", hex::encode(iv));
    Ok(())
}

/// Encrypt a message (currently uses GCM but I think it needs to be CBC for OMEMO)
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    _associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    trace!("Encryption key: {}", hex::encode(key));
    trace!("IV: {}", hex::encode(iv));

    // Validate key and IV sizes
    if key.len() != AES_KEY_SIZE {
        error!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(),
            AES_KEY_SIZE
        );
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(),
            AES_KEY_SIZE
        )));
    }

    // Validate the IV
    validate_iv(iv)?;

    // Create the cipher
    let cipher = match Aes128Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create AES-GCM cipher: {}", e);
            return Err(CryptoError::AesGcmError(format!(
                "Failed to create cipher: {}",
                e
            )));
        }
    };

    // Create the nonce
    let nonce = Nonce::from_slice(iv);

    // Encrypt the plaintext
    let ciphertext = match cipher.encrypt(nonce, plaintext) {
        Ok(c) => c,
        Err(e) => {
            error!("AES-GCM encryption failed: {}", e);
            return Err(CryptoError::AesGcmError(format!(
                "Encryption failed: {}",
                e
            )));
        }
    };

    trace!("Ciphertext: {}", hex::encode(&ciphertext));

    Ok(ciphertext)
}

/// Decrypt a message using AES-256-GCM
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    _associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    trace!("Decryption key: {}", hex::encode(key));
    trace!("IV: {}", hex::encode(iv));
    trace!("Ciphertext: {}", hex::encode(ciphertext));

    // Validate key and IV sizes
    if key.len() != AES_KEY_SIZE {
        error!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(),
            AES_KEY_SIZE
        );
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key size: {} (expected {} bytes)",
            key.len(),
            AES_KEY_SIZE
        )));
    }

    // Validate the IV
    validate_iv(iv)?;

    // Create the cipher
    let cipher = match Aes128Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create AES-GCM cipher: {}", e);
            return Err(CryptoError::AesGcmError(format!(
                "Failed to create cipher: {}",
                e
            )));
        }
    };

    // Create the nonce
    let nonce = Nonce::from_slice(iv);

    // Decrypt the ciphertext
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(e) => {
            error!("AES-GCM decryption failed: {}", e);
            return Err(CryptoError::AesGcmError(format!(
                "Decryption failed: {}",
                e
            )));
        }
    };

    Ok(plaintext)
}

/// HMAC-SHA256 for message authentication
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    //debug!("Calculating HMAC-SHA256 for {} bytes of data", data.len());
    trace!("HMAC key: {}", hex::encode(key));

    // Create the HMAC instance - using hmac::Mac trait's new_from_slice method
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|e| {
        error!("Failed to create HMAC: {}", e);
        CryptoError::HmacError(format!("Failed to create HMAC: {}", e))
    })?;

    // Update with the data
    mac.update(data);

    // Finalize and get the result
    let result = mac.finalize().into_bytes().to_vec();

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
    use sha2::Digest;
    trace!("Calculating SHA-256 hash of {} bytes of data", data.len());

    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize().to_vec();

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
    trace!("Generating X25519 key pair");

    // Generate a secure random static secret key using OsRng for cryptographic randomness
    let static_secret = StaticSecret::random_from_rng(OsRng);

    // Derive the public key from the secret key
    let public_key = PublicKey::from(&static_secret);

    // Get the bytes
    let public_key_bytes = public_key.as_bytes().to_vec();
    let private_key_bytes = static_secret.to_bytes().to_vec();

    //debug!("X25519 key pair generation successful in {:?}", duration);
    trace!("Public key: {}", hex::encode(&public_key_bytes));
    trace!("Private key: {}", hex::encode(&private_key_bytes));

    Ok((private_key_bytes, public_key_bytes))
}

/// Encode a Curve25519 public key to 33 bytes with 0x05 type prefix.
/// This is the format expected by libsignal (Conversations, Dino, etc.)
/// for bundle XML, PreKeySignalMessage, and SignalMessage wire formats.
pub fn encode_public_key_with_prefix(key: &[u8]) -> Vec<u8> {
    match key.len() {
        32 => {
            let mut prefixed = Vec::with_capacity(33);
            prefixed.push(0x05);
            prefixed.extend_from_slice(key);
            prefixed
        }
        33 if key[0] == 0x05 => {
            // Already has 0x05 prefix
            key.to_vec()
        }
        _ => {
            // Best effort: prepend 0x05 regardless
            let mut prefixed = Vec::with_capacity(key.len() + 1);
            prefixed.push(0x05);
            prefixed.extend_from_slice(key);
            prefixed
        }
    }
}

/// Ensure a public key is in Montgomery (X25519) form for DH operations.
/// If the key is already a valid Montgomery point (i.e., to_edwards succeeds), return as-is.
/// If it appears to be an Edwards (Ed25519) key, convert to Montgomery.
/// Handles the 0x05 prefix convention.
pub fn ensure_montgomery_form(key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Strip 0x05 prefix if present
    let raw = if key.len() == 33 && key[0] == 0x05 {
        &key[1..]
    } else if key.len() == 32 {
        key
    } else {
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid key length for Montgomery conversion: {}",
            key.len()
        )));
    };

    let key_array: [u8; 32] = raw.try_into().unwrap();

    // Try Montgomery→Edwards to verify it's a valid Montgomery point
    let montgomery = MontgomeryPoint(key_array);
    if montgomery.to_edwards(0).is_some() || montgomery.to_edwards(1).is_some() {
        // Already a valid Montgomery point
        return Ok(raw.to_vec());
    }

    // Not a valid Montgomery point — try interpreting as Edwards and converting
    let compressed = CompressedEdwardsY(key_array);
    match compressed.decompress() {
        Some(edwards_point) => {
            let montgomery_point = edwards_point.to_montgomery();
            debug!(
                "Converted Ed25519 identity key to X25519: {} -> {}",
                hex::encode(raw),
                hex::encode(montgomery_point.as_bytes())
            );
            Ok(montgomery_point.as_bytes().to_vec())
        }
        None => Err(CryptoError::InvalidInputError(
            "Key is neither a valid Montgomery nor Edwards point".to_string(),
        )),
    }
}

/// Normalize a Curve25519 public key to 32 bytes
/// OMEMO/Signal protocol sometimes encodes public keys with a 0x05 prefix byte
fn normalize_curve25519_public_key(key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match key.len() {
        32 => {
            trace!("Public key already 32 bytes, no normalization needed");
            Ok(key.to_vec())
        }
        33 => {
            // Check if it has the standard 0x05 prefix for Curve25519 public keys
            if key[0] == 0x05 {
                trace!("Normalizing 33-byte public key by removing 0x05 prefix");
                Ok(key[1..].to_vec())
            } else {
                error!(
                    "33-byte public key with unexpected prefix: 0x{:02X}",
                    key[0]
                );
                Err(CryptoError::InvalidInputError(format!(
                    "33-byte public key with unexpected prefix: 0x{:02X}",
                    key[0]
                )))
            }
        }
        _ => {
            error!("Invalid Curve25519 public key length: {}", key.len());
            Err(CryptoError::InvalidInputError(format!(
                "Invalid Curve25519 public key length: {}",
                key.len()
            )))
        }
    }
}

/// Perform a Diffie-Hellman key exchange with X25519
pub fn x25519_diffie_hellman(
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    trace!("Performing X25519 Diffie-Hellman key exchange");
    trace!("Using private key: {}", hex::encode(private_key));
    trace!("Using public key: {}", hex::encode(public_key));

    // Validate private key length
    if private_key.len() != 32 {
        error!("Invalid X25519 private key length: {}", private_key.len());
        return Err(CryptoError::InvalidInputError(format!(
            "Invalid private key length: {}",
            private_key.len()
        )));
    }

    // Normalize the public key (handle 33-byte keys with 0x05 prefix)
    let normalized_public_key = normalize_curve25519_public_key(public_key)?;

    // Convert to the appropriate types for x25519-dalek
    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(private_key);

    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(&normalized_public_key);

    // Create the StaticSecret from bytes
    let static_secret = StaticSecret::from(private_bytes);
    let public = PublicKey::from(public_bytes);

    // Compute the DH shared secret
    let shared_secret = static_secret.diffie_hellman(&public);
    let shared_bytes = shared_secret.as_bytes().to_vec();

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
    //debug!("Deriving key with HKDF: output_len={}", output_len);
    trace!("Salt: {}", hex::encode(salt));
    trace!("Input key material: {}", hex::encode(ikm));
    trace!("Info: {}", hex::encode(info));

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];

    if let Err(e) = hk.expand(info, &mut okm) {
        error!("HKDF expansion failed: {}", e);
        return Err(CryptoError::KdfError(format!(
            "HKDF expansion failed: {}",
            e
        )));
    }

    trace!("Derived key: {}", hex::encode(&okm));

    Ok(okm)
}

/// Create a Diffie-Hellman shared secret
pub fn calculate_dh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Just use our x25519_diffie_hellman function
    x25519_diffie_hellman(private_key, public_key)
}

/// Generate a key pair for X25519
pub fn generate_dh_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Just use our generate_x25519_keypair function
    generate_x25519_keypair()
}

/// Derive X25519 public key from private key
pub fn x25519_public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    trace!("Deriving X25519 public key from private key");

    // Validate private key length
    if private_key.len() != 32 {
        error!("Invalid X25519 private key length: {}", private_key.len());
        return Err(CryptoError::InvalidInputError(format!(
            "X25519 private key must be 32 bytes, got {}",
            private_key.len()
        )));
    }

    // Convert to the appropriate type for x25519-dalek
    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(private_key);

    // Create the StaticSecret from bytes
    let static_secret = StaticSecret::from(private_bytes);

    // Derive the public key
    let public_key = PublicKey::from(&static_secret);

    Ok(public_key.as_bytes().to_vec())
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    sha256_hash(data)
}

/// Format a key fingerprint for human readability
pub fn format_fingerprint(fingerprint: &[u8]) -> String {
    let fp_hex = hex::encode(fingerprint);
    let chunks: Vec<String> = fp_hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect();
    chunks.join(":")
}

/// XEdDSA: Sign a message using an X25519 private key.
///
/// This implements the XEdDSA signing algorithm used by Signal/OMEMO:
/// 1. Clamp the X25519 private key to get the scalar
/// 2. Compute the Edwards public key from the scalar
/// 3. If the Edwards Y coordinate's sign bit is set, negate the scalar
/// 4. Sign using Ed25519 with the adjusted scalar
///
/// This produces signatures compatible with libsignal's Curve25519.calculateSignature().
pub fn xeddsa_sign(x25519_private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if x25519_private_key.len() != 32 {
        return Err(CryptoError::InvalidInputError(format!(
            "X25519 private key must be 32 bytes, got {}",
            x25519_private_key.len()
        )));
    }

    // Step 1: Clamp the private key (X25519 clamping)
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(x25519_private_key);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    // Step 2: Convert to a Scalar
    let scalar = Scalar::from_bytes_mod_order(clamped);

    // Step 3: Compute the Edwards public key (with its natural sign)
    let edwards_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;
    let compressed = edwards_point.compress();
    let edwards_bytes = compressed.to_bytes();

    // Step 4: Record the sign bit (but do NOT negate the scalar)
    // libsignal-protocol-c's curve25519_verify reconstructs the Edwards point
    // from the Montgomery u-coordinate + this sign bit. The signer must use
    // the SAME Edwards point (with its natural sign) in the challenge hash.
    let sign_bit = edwards_bytes[31] & 0x80;

    // Step 5: Use the original public key (with its natural sign) for signing
    let public_bytes = edwards_bytes;

    // Step 6: Generate a random nonce (64 bytes)
    let mut random = [0u8; 64];
    OsRng.fill_bytes(&mut random);

    // Step 7: Compute nonce: SHA-512(random || message)
    let mut nonce_hash = Sha512::new();
    nonce_hash.update(&random);
    nonce_hash.update(message);
    let nonce_digest = nonce_hash.finalize();
    let nonce_scalar = Scalar::from_bytes_mod_order_wide(&nonce_digest.into());

    // Step 8: R = nonce_scalar * B
    let r_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &nonce_scalar;
    let r_bytes = r_point.compress().to_bytes();

    // Step 9: Compute challenge: SHA-512(R || public_key || message)
    let mut challenge_hash = Sha512::new();
    challenge_hash.update(&r_bytes);
    challenge_hash.update(&public_bytes);
    challenge_hash.update(message);
    let challenge_digest = challenge_hash.finalize();
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest.into());

    // Step 10: s = nonce_scalar + challenge * scalar (using original, unnegated scalar)
    let s = nonce_scalar + challenge * scalar;

    // Step 11: Signature = R || s, with sign bit encoded in s[31] high bit
    // The verifier extracts this sign bit to reconstruct the correct Edwards point
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(&s.to_bytes());
    signature[63] &= 0x7F; // Clear high bit of s (reserved for sign bit)
    signature[63] |= sign_bit; // Encode sign bit so verifier can reconstruct A

    Ok(signature.to_vec())
}

/// XEdDSA: Verify a signature using an X25519 public key (Montgomery point).
///
/// Supports two protocol variants:
/// 1. Standard XEdDSA (convert_mont with sign=0)
/// 2. libsignal-protocol-c variant (sign bit encoded in signature[63] high bit)
///
/// Also handles identity keys published in Edwards form by converting to Montgomery first.
pub fn xeddsa_verify(
    x25519_public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    if x25519_public_key.len() != 32 {
        return Err(CryptoError::InvalidInputError(format!(
            "X25519 public key must be 32 bytes, got {}",
            x25519_public_key.len()
        )));
    }
    if signature.len() != 64 {
        return Err(CryptoError::InvalidInputError(format!(
            "Signature must be 64 bytes, got {}",
            signature.len()
        )));
    }

    let key_array = <&[u8; 32]>::try_from(x25519_public_key).unwrap();

    // Determine the Montgomery u-coordinate for XEdDSA verification
    let montgomery = MontgomeryPoint(*key_array);
    let montgomery_key = if montgomery.to_edwards(0).is_some() || montgomery.to_edwards(1).is_some()
    {
        // Key is already in Montgomery form
        debug!(
            "xeddsa_verify: key is Montgomery form: {}",
            hex::encode(key_array)
        );
        montgomery
    } else {
        // Key might be in Edwards form — convert to Montgomery
        let compressed = CompressedEdwardsY(*key_array);
        match compressed.decompress() {
            Some(edwards_point) => {
                let mont = edwards_point.to_montgomery();
                debug!(
                    "xeddsa_verify: key is Edwards form: {} -> Montgomery: {}",
                    hex::encode(key_array),
                    hex::encode(mont.as_bytes())
                );
                mont
            }
            None => {
                return Err(CryptoError::InvalidInputError(
                    "Key is neither a valid Montgomery nor Edwards point".to_string(),
                ));
            }
        }
    };

    // Extract R from signature (first 32 bytes, unchanged in both protocols)
    let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();

    // Decompress R
    let r_compressed = CompressedEdwardsY(r_bytes);
    let r_point = match r_compressed.decompress() {
        Some(point) => point,
        None => return Ok(false),
    };

    // libsignal protocol: sign bit is encoded in signature[63] high bit
    // Extract sign bit and clean s
    let sign_bit = (signature[63] & 0x80) >> 7;
    let mut s_bytes: [u8; 32] = signature[32..].try_into().unwrap();
    s_bytes[31] &= 0x7F; // Clear sign bit from s

    debug!(
        "xeddsa_verify: sign_bit={}, R={}, s(cleaned)={}, msg_len={}",
        sign_bit,
        hex::encode(&r_bytes),
        hex::encode(&s_bytes),
        message.len()
    );

    // Convert s to scalar
    let s = match Scalar::from_canonical_bytes(s_bytes).into() {
        Some(s) => s,
        None => {
            debug!("xeddsa_verify: s is not canonical, returning false");
            return Ok(false);
        }
    };

    // s*B (common to all attempts)
    let sb = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &s;

    // Try verification with the sign from the signature (libsignal protocol)
    if let Some(point) = montgomery_key.to_edwards(sign_bit) {
        let public_bytes = point.compress().to_bytes();
        debug!(
            "xeddsa_verify: try sign={}, A={}",
            sign_bit,
            hex::encode(&public_bytes)
        );
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(&r_bytes);
        challenge_hash.update(&public_bytes);
        challenge_hash.update(message);
        let challenge_digest = challenge_hash.finalize();
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest.into());
        let ca = point * challenge;
        let expected = r_point + ca;
        if sb == expected {
            debug!("xeddsa_verify: SUCCESS with sign={}", sign_bit);
            return Ok(true);
        }
    } else {
        debug!("xeddsa_verify: to_edwards({}) returned None", sign_bit);
    }

    // Try with the opposite sign (in case sign bit wasn't set by signer)
    let other_sign = 1 - sign_bit;
    if let Some(point) = montgomery_key.to_edwards(other_sign) {
        let public_bytes = point.compress().to_bytes();
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(&r_bytes);
        challenge_hash.update(&public_bytes);
        challenge_hash.update(message);
        let challenge_digest = challenge_hash.finalize();
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest.into());
        let ca = point * challenge;
        let expected = r_point + ca;
        if sb == expected {
            return Ok(true);
        }
    }

    // Also try with the original s (without clearing sign bit) in case the
    // signer didn't use the libsignal sign-encoding convention
    let s_orig = match Scalar::from_canonical_bytes(signature[32..].try_into().unwrap()).into() {
        Some(s) => s,
        None => return Ok(false),
    };
    if s_orig != s {
        let sb_orig = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &s_orig;
        for sign in [0u8, 1u8] {
            if let Some(point) = montgomery_key.to_edwards(sign) {
                let public_bytes = point.compress().to_bytes();
                let mut challenge_hash = Sha512::new();
                challenge_hash.update(&r_bytes);
                challenge_hash.update(&public_bytes);
                challenge_hash.update(message);
                let challenge_digest = challenge_hash.finalize();
                let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest.into());
                let ca = point * challenge;
                let expected = r_point + ca;
                if sb_orig == expected {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dino_key_montgomery_to_edwards() {
        // This is device 1019198589's identity key from storage — it's an Ed25519 key,
        // not an X25519 key. Montgomery conversion fails, but Edwards decompression works.
        let key_bytes: [u8; 32] = [
            0x25, 0x09, 0x39, 0xf2, 0x0f, 0xb4, 0xa2, 0x6c, 0x23, 0x1b, 0xc2, 0x8e, 0xf2, 0x8f,
            0xdc, 0xdc, 0xe3, 0x0a, 0xed, 0x6e, 0xef, 0x16, 0x52, 0x42, 0x63, 0xd1, 0x1a, 0xfd,
            0x36, 0xb8, 0x1c, 0x55,
        ];
        let montgomery = MontgomeryPoint(key_bytes);
        // Montgomery conversion returns None for this key
        assert!(montgomery.to_edwards(0).is_none());
        assert!(montgomery.to_edwards(1).is_none());

        // But it IS a valid Edwards point
        let compressed = CompressedEdwardsY(key_bytes);
        assert!(
            compressed.decompress().is_some(),
            "Key should be valid as Edwards point"
        );

        // And we can convert Edwards -> Montgomery -> Edwards(sign=0) for XEdDSA
        let edwards_point = compressed.decompress().unwrap();
        let montgomery_point = edwards_point.to_montgomery();
        // The Montgomery form should be convertible back to Edwards
        assert!(
            montgomery_point.to_edwards(0).is_some() || montgomery_point.to_edwards(1).is_some()
        );
    }

    #[test]
    fn test_xeddsa_verify_with_montgomery_key() {
        // Test verification with proper Montgomery key (the format used in OMEMO bundles)
        let (private_key, _) = generate_x25519_keypair().unwrap();
        let message = b"test signed prekey data";

        let signature = xeddsa_sign(&private_key, message).unwrap();

        // Derive the Montgomery public key (as it appears in OMEMO bundles)
        let public_key = {
            let secret = x25519_dalek::StaticSecret::from(
                <[u8; 32]>::try_from(private_key.as_slice()).unwrap(),
            );
            x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec()
        };

        // Verify using Montgomery form of the key
        let result = xeddsa_verify(&public_key, message, &signature).unwrap();
        assert!(result, "XEdDSA verify should succeed with Montgomery key");
    }

    #[test]
    fn test_xeddsa_verify_prefixed_message() {
        // Test with the 0x05-prefixed message format used by libsignal
        let (private_key, _) = generate_x25519_keypair().unwrap();
        let (_, spk_pub) = generate_x25519_keypair().unwrap();

        // Sign the prefixed SPK (as libsignal does)
        let mut message = vec![0x05];
        message.extend_from_slice(&spk_pub);

        let signature = xeddsa_sign(&private_key, &message).unwrap();

        // Verify with Montgomery key
        let public_key = {
            let secret = x25519_dalek::StaticSecret::from(
                <[u8; 32]>::try_from(private_key.as_slice()).unwrap(),
            );
            x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec()
        };
        let result = xeddsa_verify(&public_key, &message, &signature).unwrap();
        assert!(
            result,
            "XEdDSA verify with 0x05-prefixed SPK should succeed"
        );
    }

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
        assert_eq!(hash.len(), 32); // SHA-256 produces a 32-byte hash
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
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];

        let formatted = format_fingerprint(&fingerprint);
        assert_eq!(formatted, "01:23:45:67:89:ab:cd:ef:fe:dc:ba:98:76:54:32:10");
    }

    #[test]
    fn test_normalize_curve25519_public_key() {
        // Test 32-byte key (should remain unchanged)
        let key_32 = vec![0x01; 32];
        let result = normalize_curve25519_public_key(&key_32).unwrap();
        assert_eq!(result, key_32);

        // Test 33-byte key with 0x05 prefix (should remove prefix)
        let mut key_33 = vec![0x05];
        key_33.extend_from_slice(&vec![0x02; 32]);
        let result = normalize_curve25519_public_key(&key_33).unwrap();
        assert_eq!(result, vec![0x02; 32]);

        // Test 33-byte key with wrong prefix (should fail)
        let mut key_33_wrong = vec![0x04];
        key_33_wrong.extend_from_slice(&vec![0x03; 32]);
        let result = normalize_curve25519_public_key(&key_33_wrong);
        assert!(result.is_err());

        // Test invalid length (should fail)
        let key_invalid = vec![0x01; 31];
        let result = normalize_curve25519_public_key(&key_invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_with_33_byte_public_key() {
        // Generate a test key pair
        let (private_key, public_key_32) = generate_x25519_keypair().unwrap();

        // Create a 33-byte version with 0x05 prefix
        let mut public_key_33 = vec![0x05];
        public_key_33.extend_from_slice(&public_key_32);

        // Both should produce the same result
        let result_32 = x25519_diffie_hellman(&private_key, &public_key_32).unwrap();
        let result_33 = x25519_diffie_hellman(&private_key, &public_key_33).unwrap();

        assert_eq!(result_32, result_33);
    }

    #[test]
    fn test_secure_compare() {
        let data1 = vec![0x01, 0x02, 0x03, 0x04];
        let data2 = vec![0x01, 0x02, 0x03, 0x04];
        let data3 = vec![0x01, 0x02, 0x03, 0x05];
        let data4 = vec![0x01, 0x02, 0x03]; // Different length

        assert!(
            secure_compare(&data1, &data2),
            "Identical data should compare as equal"
        );
        assert!(
            !secure_compare(&data1, &data3),
            "Different data should compare as not equal"
        );
        assert!(
            !secure_compare(&data1, &data4),
            "Different length data should compare as not equal"
        );
    }

    #[test]
    fn test_xeddsa_sign_verify_roundtrip() {
        // Generate an X25519 key pair
        let (private_key, public_key) = generate_x25519_keypair().unwrap();
        let message = b"test message for XEdDSA";

        // Sign with private key
        let signature = xeddsa_sign(&private_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify with public key
        let valid = xeddsa_verify(&public_key, message, &signature).unwrap();
        assert!(
            valid,
            "XEdDSA signature should verify with matching public key"
        );

        // Verify fails with wrong message
        let valid = xeddsa_verify(&public_key, b"wrong message", &signature).unwrap();
        assert!(
            !valid,
            "XEdDSA signature should not verify with wrong message"
        );

        // Verify fails with wrong key
        let (_, other_public) = generate_x25519_keypair().unwrap();
        let valid = xeddsa_verify(&other_public, message, &signature).unwrap();
        assert!(!valid, "XEdDSA signature should not verify with wrong key");
    }
}
