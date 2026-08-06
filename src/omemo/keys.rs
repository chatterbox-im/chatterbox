// src/omemo/keys.rs
//! Typed wrappers for cryptographic key material.
//!
//! Three problems `&[u8]` cannot prevent:
//!   1. Argument-order swaps (salt vs IKM, key vs IV) — compile error with distinct types.
//!   2. Wrong-size keys reaching a cipher — compile error via fixed-size newtypes.
//!   3. Accidental logging of secrets — `Secret<N>` has a redacting `Debug`; no `Display`,
//!      no `Deref`, no `AsRef`. Logging requires an explicit `expose_secret()` call.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroize;

// ── Secret<N> ───────────────────────────────────────────────────────────────

/// A fixed-size secret value with zeroize-on-drop and a redacting Debug.
///
/// Intentionally has no `Display`, `Deref<Target=[u8]>`, or `AsRef<[u8]>`.
/// Access bytes with `.expose_secret()` — the name shows up in code review
/// and `grep expose_secret` finds every exfiltration site.
///
/// Serializes/deserializes identically to `Vec<u8>` (length-prefixed) so
/// existing bincode blobs are fully compatible.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Construct from a slice. Returns `None` if the length is not exactly N.
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; N]>::try_from(b).ok().map(Secret)
    }

    /// The only way to get bytes out. Greppable and visible in code review.
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Clone for Secret<N> {
    fn clone(&self) -> Self {
        Secret(self.0)
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{}>(redacted)", N)
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<const N: usize> Eq for Secret<N> {}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Serialize as Vec<u8> so bincode layout is identical to the old Vec<u8> fields.
impl<const N: usize> Serialize for Secret<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.to_vec().serialize(s)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Secret<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        let array: [u8; N] = bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected {} bytes, got {}", N, v.len()))
        })?;
        Ok(Secret(array))
    }
}

// ── Cipher key newtypes ──────────────────────────────────────────────────────

/// 16-byte AES-128-GCM key. Zeroized on drop.
#[derive(Clone, Debug)]
pub struct AesGcmKey(Secret<16>);

impl AesGcmKey {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(Secret::new(bytes))
    }
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        Secret::<16>::from_slice(b).map(AesGcmKey)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

/// 32-byte AES-256-CBC key. Zeroized on drop.
#[derive(Clone, Debug)]
pub struct AesCbcKey(Secret<32>);

impl AesCbcKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        Secret::<32>::from_slice(b).map(AesCbcKey)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// 12-byte AES-GCM nonce (IV). Not secret — nonces are transmitted publicly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcmNonce([u8; 12]);

impl GcmNonce {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; 12]>::try_from(b).ok().map(GcmNonce)
    }
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// 16-byte AES-CBC IV. Not secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CbcIv([u8; 16]);

impl CbcIv {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; 16]>::try_from(b).ok().map(CbcIv)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// ── HKDF label types ─────────────────────────────────────────────────────────

/// Newtype for the `salt` parameter of `hkdf_derive`.
/// Prevents silently swapping salt and IKM (they have opposite roles in HKDF).
#[derive(Clone, Copy)]
pub struct Salt<'a>(pub &'a [u8]);

/// Newtype for the `ikm` (input key material) parameter of `hkdf_derive`.
#[derive(Clone, Copy)]
pub struct Ikm<'a>(pub &'a [u8]);

impl<'a> From<&'a [u8]> for Salt<'a> {
    fn from(b: &'a [u8]) -> Self {
        Salt(b)
    }
}
impl<'a> From<&'a [u8]> for Ikm<'a> {
    fn from(b: &'a [u8]) -> Self {
        Ikm(b)
    }
}
// Allow constructing Salt/Ikm directly from a Secret reference.
impl<'a, const N: usize> From<&'a Secret<N>> for Salt<'a> {
    fn from(s: &'a Secret<N>) -> Self {
        Salt(s.expose_secret())
    }
}
impl<'a, const N: usize> From<&'a Secret<N>> for Ikm<'a> {
    fn from(s: &'a Secret<N>) -> Self {
        Ikm(s.expose_secret())
    }
}

// ── PreKey ID newtypes ───────────────────────────────────────────────────────
// Each ID type is distinct so `encrypt_key_prekey(msg, registration_id,
// opk_id, spk_id, ...)` cannot have its u32 arguments silently transposed.

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RegistrationId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SignedPreKeyId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OneTimePreKeyId(pub u32);
