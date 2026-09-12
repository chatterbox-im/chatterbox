// Enforce zero hand-written unsafe. When the `ffi` feature is on, uniffi's
// proc macros expand `unsafe extern "C"` scaffolding into this crate, but
// rustc does not apply local lint levels inside external proc-macro
// expansions, so no allow is needed: forbid/deny governs all hand-written
// code in every configuration.
#![cfg_attr(not(feature = "ffi"), forbid(unsafe_code))]
#![cfg_attr(feature = "ffi", deny(unsafe_code))]

// Re-export needed modules for testing
pub mod jid;
pub mod models;
pub mod omemo; // OMEMO module
pub mod units;
pub mod storage; // Local message persistence
pub mod xmpp; // Our new modular XMPP implementation

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!("chatterbox");

#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export main types for convenience
pub use models::*;
pub use models::AppEvent;
pub use xmpp::XMPPClient; // Expose the XMPPClient directly

