// src/commands.rs
//! Typed UI→App command channel.
//! Replaces the 17-sentinel `(String, String)` RPC that travelled over the chat channel.

use chatterbox::omemo::storage::TrustLevel;

/// Every action the UI can request of the application layer.
/// Produced by `ChatUI::handle_terminal_event`; consumed by `handle_user_command`.
/// An exhaustive `match` in the consumer means adding a new action requires
/// updating both producer and consumer — the compiler enforces it.
#[derive(Debug)]
pub enum UiCommand {
    /// User pressed Esc — exit the event loop.
    Quit,
    /// User pressed Enter with text in the input box (OMEMO-encrypted path).
    SendMessage { to: String, body: String },
    /// User typed `/plain <body>` — send without encryption.
    SendPlainMessage { to: String, body: String },
    /// User accepted a key-verification prompt.
    KeyAccepted { contact: String },
    /// User rejected a key-verification prompt.
    KeyRejected { contact: String },
    /// User toggled a per-device trust flag in the fingerprints dialog.
    SetDeviceTrust { jid: String, device_id: u32, level: TrustLevel },
    /// User pressed Ctrl-T — toggle trust for all devices of the active contact.
    ToggleOmemoTrust { contact: String },
    /// User pressed Ctrl-F — show the device-fingerprints dialog.
    ShowDeviceFingerprints,
    /// User pressed Ctrl-A — show the add-contact dialog.
    ShowAddContact,
    /// User confirmed adding a contact in the dialog.
    AddContact { jid: String },
    /// User pressed Ctrl-D — start contact removal (shows confirmation).
    RemoveContact { contact: String },
    /// User confirmed contact removal.
    RemoveContactConfirmed { contact: String },
    /// User navigated to a different contact in the sidebar.
    ContactChanged { contact: String },
    /// User reached the top of a conversation and requested older history.
    LoadOlderHistory { contact: String },
    /// User pressed Ctrl-P — toggle OS notifications.
    ToggleOsNotifications,
    /// User pressed Ctrl-M — enable XEP-0280 message carbons.
    EnableCarbons,
    /// Re-fetch OMEMO device list for the active contact.
    RefetchOmemo { contact: String },
}
