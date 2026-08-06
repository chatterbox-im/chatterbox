// src/units.rs
//! Typed time units that make timestamp-unit confusion a compile error.
//!
//! `Message.timestamp: Millis`, `FfiMessage.timestamp: Secs`, and
//! `DeviceListEntry.last_update: Secs` are now distinct types.
//! The conversion between them is explicit; `MAX_PLAUSIBLE_UNIX_SECS`
//! magnitude-sniffing is replaced by a single `.to_secs()` call.

use serde::{Deserialize, Serialize};

/// A Unix timestamp measured in milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Millis(pub i64);

/// A Unix timestamp measured in whole seconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secs(pub i64);

impl Millis {
    pub fn now() -> Self {
        use chrono::Utc;
        Millis(Utc::now().timestamp_millis())
    }
    pub fn get(self) -> i64 {
        self.0
    }
    /// Truncates to whole seconds (floor division).
    pub fn to_secs(self) -> Secs {
        Secs(self.0.div_euclid(1000))
    }
}

impl Secs {
    pub fn now() -> Self {
        use chrono::Utc;
        Secs(Utc::now().timestamp())
    }
    pub fn get(self) -> i64 {
        self.0
    }
    pub fn to_millis(self) -> Millis {
        Millis(self.0.saturating_mul(1000))
    }
}

impl From<i64> for Millis {
    fn from(v: i64) -> Self {
        Millis(v)
    }
}
impl From<i64> for Secs {
    fn from(v: i64) -> Self {
        Secs(v)
    }
}
impl From<Millis> for i64 {
    fn from(m: Millis) -> i64 {
        m.0
    }
}
impl From<Secs> for i64 {
    fn from(s: Secs) -> i64 {
        s.0
    }
}
