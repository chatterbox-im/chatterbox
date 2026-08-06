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

