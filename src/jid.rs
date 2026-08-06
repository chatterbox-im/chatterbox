// src/jid.rs
//! JID (Jabber ID) types that enforce invariants at construction time.
//!
//! `BareJid` is the only entry point for raw strings.  All downstream code
//! receives typed values and can never have a resource-bearing or
//! non-lowercase JID slip through.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum JidError {
    Malformed(String),
}

impl fmt::Display for JidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JidError::Malformed(s) => write!(f, "malformed JID: {:?}", s),
        }
    }
}
impl std::error::Error for JidError {}

/// A bare XMPP JID: lowercase, exactly one `@`, no resource (`/`).
///
/// This is the only type accepted by storage, session maps, and trust APIs.
/// Construct with `BareJid::parse(s)` — that is the single normalization point.
/// There is no `From<String>` and no `Deref<Target=str>` to prevent silent
/// laundry back into untyped strings.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BareJid(String);

impl BareJid {
    /// Parse and normalize a bare or full JID.
    ///
    /// Strips the resource, lowercases, and validates that there is exactly
    /// one `@` not at the start or end.
    pub fn parse(s: &str) -> Result<Self, JidError> {
        let s = s.trim().to_lowercase();
        // Strip resource if present
        let s = s.split('/').next().unwrap_or(&s);
        let at_count = s.matches('@').count();
        if at_count != 1 || s.starts_with('@') || s.ends_with('@') {
            return Err(JidError::Malformed(s.to_string()));
        }
        Ok(BareJid(s.to_string()))
    }

    /// Returns the JID as a `&str` for SQLite queries and stanza serialization.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BareJid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BareJid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BareJid({:?})", self.0)
    }
}

// Serde support: round-trips through `parse` so deserialized values are
// always validated.
impl Serialize for BareJid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BareJid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        BareJid::parse(&s).map_err(serde::de::Error::custom)
    }
}

// TryFrom<&str> and TryFrom<String> as the explicit construction paths.
impl TryFrom<&str> for BareJid {
    type Error = JidError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        BareJid::parse(s)
    }
}

impl TryFrom<String> for BareJid {
    type Error = JidError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        BareJid::parse(&s)
    }
}

impl BareJid {
    /// Normalize `s` to a bare JID the same way the old `normalize_jid_to_bare`
    /// helper did: lowercase, trim, strip resource.  Accepts inputs that lack an
    /// `@` (unlike `parse`) so that existing call sites do not panic during the
    /// `BareJid` migration.  Prefer `parse` for all new code.
    pub fn from_raw_lossy(s: &str) -> BareJid {
        let s = s.trim().to_lowercase();
        let bare = s.split('/').next().unwrap_or(&s);
        BareJid(bare.to_string())
    }
}
