use anyhow::Result;
use crossterm::{
    event::{self, DisableFocusChange, EnableFocusChange, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::debug; // Add the debug import
use log::info; // Add the log import
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    },
    Frame,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use textwrap::{wrap, Options, WordSplitter};
use tui_input::{backend::crossterm::EventHandler, Input};
use uuid::Uuid;

// Use the new Message type from the models module and TypingStatus from xmpp
use chatterbox::models::{ContactStatus, DeliveryStatus, Message};
use chatterbox::omemo::TrustLevel;
use chatterbox::xmpp::chat_states::TypingStatus;

// Export types needed by main module
pub use ratatui::backend::CrosstermBackend;
pub use ratatui::Terminal;

const EVENT_READER_POLL_TIMEOUT: Duration = Duration::from_millis(250);

pub struct TerminalEventReader {
    rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TerminalEventReader {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);

        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match event::poll(EVENT_READER_POLL_TIMEOUT) {
                    Ok(true) => match event::read() {
                        Ok(event) => {
                            if tx.send(event).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Terminal event read failed: {}", e);
                            break;
                        }
                    },
                    Ok(false) => {}
                    Err(e) => {
                        debug!("Terminal event poll failed: {}", e);
                        break;
                    }
                }
            }
        });

        Self {
            rx,
            stop,
            thread: Some(thread),
        }
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

impl Drop for TerminalEventReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct ChatUI {
    pub messages: Vec<Message>, // Make messages public so it can be accessed from main.rs
    input: Input,
    contact: String,
    pub contacts: Vec<String>,
    active_tab: Tab,
    current_contact_index: usize,
    contact_status: HashMap<String, ContactStatus>,
    typing_states: HashMap<String, (TypingStatus, chrono::DateTime<chrono::Utc>)>, // Contact -> (Status, Timestamp)
    omemo_enabled: bool, // Track if OMEMO encryption is enabled
    os_notifications_enabled: bool,
    terminal_focused: bool,
    key_confirmation: Option<KeyConfirmation>, // Add this field for key confirmation popup
    contact_add_dialog: Option<ContactAddDialog>, // Add this field for adding new contacts
    contact_remove_dialog: Option<ContactRemoveDialog>, // Add this field for remove confirmation
    help_dialog: Option<HelpDialog>,           // Add this field for help popup
    device_fingerprints_dialog: Option<DeviceFingerprintsDialog>, // Add this field for device fingerprints popup
    friend_request_notification: Option<FriendRequestNotification>, // Add this field for friend request notifications
    resources: HashMap<String, Vec<String>>, // Map of base JID -> resource JIDs
    connection_status: bool,                 // Track XMPP server connection status
    sidebar_hidden: bool,                    // Whether the contacts sidebar is hidden
    message_scroll_offset: Option<usize>, // None = auto-scroll to bottom, Some(n) = n lines scrolled up from bottom
    unread_contacts: HashSet<String>,     // Contacts with unread messages
    pub history_loaded_contacts: HashSet<String>, // Contacts whose history has been loaded
}

// Add this new struct to represent key confirmation data
struct KeyConfirmation {
    contact: String,
    fingerprint: String,
    device_id: Option<String>,
}

// Add this new struct for the add contact dialog
struct ContactAddDialog {
    input: Input,
    server_domain: String, // Store the current server's domain for username-only JIDs
}

// Add this new struct for contact removal confirmation
struct ContactRemoveDialog {
    contact: String, // The contact to be removed
}

// Add this new struct for help dialog
struct HelpDialog {
    // No additional state needed for the help dialog
}

// Device fingerprints / trust table dialog (opened with Ctrl+F)
struct DeviceFingerprintsDialog {
    /// Contact devices: (device_id, fingerprint, trust).
    contact_rows: Vec<(String, String, TrustLevel)>,
    contact_jid: Option<String>,
    /// Own devices: (device_id, fingerprint, trust, is_current_device).
    own_rows: Vec<(String, String, TrustLevel, bool)>,
    /// Bare JID of the local account (used when toggling own-device trust).
    own_jid: String,
    /// Unified cursor: 0..contact_rows.len() = contact section,
    /// contact_rows.len()..total = own section.
    selected_row: usize,
}

// Add this new struct for friend request notification
struct FriendRequestNotification {
    contact: String, // The contact that was automatically accepted
    timestamp: chrono::DateTime<chrono::Utc>, // When the notification was created (for auto-dismiss)
}

enum Tab {
    Messages,
    Contacts,
}

impl ChatUI {
    pub fn new() -> Self {
        ChatUI {
            messages: Vec::new(),
            input: Input::default(),
            contact: String::new(),
            contacts: Vec::new(),
            active_tab: Tab::Messages,
            current_contact_index: 0,
            contact_status: HashMap::new(),
            typing_states: HashMap::new(),
            omemo_enabled: true, // Default to enabled
            os_notifications_enabled: false,
            terminal_focused: true,
            key_confirmation: None,                  // Initialize to None
            contact_add_dialog: None,                // Initialize to None
            contact_remove_dialog: None,             // Initialize to None
            help_dialog: None,                       // Initialize to None
            device_fingerprints_dialog: None,        // Initialize to None
            friend_request_notification: None,       // Initialize to None
            resources: HashMap::new(),               // Initialize resources map
            connection_status: false,                // Initialize connection status to disconnected
            sidebar_hidden: false,                   // Sidebar visible by default
            message_scroll_offset: None,             // Auto-scroll to bottom by default
            unread_contacts: HashSet::new(),         // No unread messages initially
            history_loaded_contacts: HashSet::new(), // No history loaded yet
        }
    }

    // Helper method to extract the base JID (without resource) from a full JID
    fn get_base_jid(jid: &str) -> String {
        jid.split('/').next().unwrap_or(jid).to_string()
    }

    // Helper method to get any resource part from a JID
    fn get_resource(jid: &str) -> Option<String> {
        let parts: Vec<&str> = jid.splitn(2, '/').collect();
        if parts.len() > 1 && !parts[1].is_empty() {
            Some(parts[1].to_string())
        } else {
            None
        }
    }

    pub fn add_message(&mut self, message: Message) {
        // Mark contact as unread if message is from someone other than the active contact
        let sender_base = Self::get_base_jid(&message.sender_id);
        if sender_base != "me" && sender_base != "system" && sender_base != self.contact {
            self.unread_contacts.insert(sender_base);
        }

        // First check if we already have this message by ID
        if let Some(idx) = self.messages.iter().position(|m| m.id == message.id) {
            // Update the existing message's status
            let existing = &mut self.messages[idx];
            existing.delivery_status = message.delivery_status;
            // Only update timestamp if the new timestamp is more recent
            if message.timestamp > existing.timestamp {
                existing.timestamp = message.timestamp;
            }
        } else {
            // Also check for matching content from the same sender within a recent timeframe
            // This helps deduplicate messages that might have different IDs but are the same message
            let recent_threshold = chrono::Utc::now().timestamp() as u64 - 10; // Within last 10 seconds
            if let Some(idx) = self.messages.iter().position(|m| {
                m.sender_id == message.sender_id
                    && m.recipient_id == message.recipient_id
                    && m.content == message.content
                    && m.timestamp > recent_threshold
            }) {
                // It's likely the same message with a different ID, update status
                let existing = &mut self.messages[idx];
                // Only update if the new status is "higher" in the delivery chain
                if message.delivery_status as u8 > existing.delivery_status as u8 {
                    existing.delivery_status = message.delivery_status;
                }
                if message.timestamp > existing.timestamp {
                    existing.timestamp = message.timestamp;
                }
            } else {
                // Insert in chronological order by timestamp
                let insert_pos = self
                    .messages
                    .partition_point(|m| m.timestamp <= message.timestamp);
                self.messages.insert(insert_pos, message);
            }
        }
    }

    pub fn add_contact(&mut self, contact: &str) {
        let base_jid = Self::get_base_jid(contact);
        let resource = Self::get_resource(contact);

        // Store the resource if present
        if let Some(res) = resource {
            let resources = self
                .resources
                .entry(base_jid.clone())
                .or_insert_with(Vec::new);
            if !resources.contains(&res) {
                resources.push(res);
            }
        }

        // Only add the base JID to contacts list if not already present
        if !self.contacts.contains(&base_jid) {
            self.contacts.push(base_jid);
        }
    }

    // Get all resources for a given base JID
    pub fn get_resources(&self, base_jid: &str) -> Vec<String> {
        self.resources.get(base_jid).cloned().unwrap_or_default()
    }

    pub fn set_active_contact(&mut self, contact: &str) {
        // Always store the base JID as the active contact
        self.contact = Self::get_base_jid(contact);
    }

    pub fn has_active_contact(&self) -> bool {
        !self.contact.is_empty()
    }

    // Add this method to show key confirmation popup
    /// Shows a popup dialog asking the user to confirm or reject an unrecognized OMEMO key
    ///
    /// # Arguments
    /// * `contact` - The contact whose key needs confirmation
    /// * `fingerprint` - The fingerprint of the key (should be formatted for display)
    /// * `device_id` - Optional device ID associated with the key
    pub fn show_key_confirmation(
        &mut self,
        contact: &str,
        fingerprint: &str,
        device_id: Option<&str>,
    ) {
        //debug!{"UI: Showing key confirmation for contact: {} with fingerprint {} for device {}", contact, fingerprint, device_id.unwrap_or("N/A")};
        self.key_confirmation = Some(KeyConfirmation {
            contact: contact.to_string(),
            fingerprint: fingerprint.to_string(),
            device_id: device_id.map(|id| id.to_string()),
        });
    }

    // Add this method to show add contact dialog
    /// Shows a popup dialog for adding a new contact
    ///
    /// # Arguments
    /// * `server_domain` - The current server's domain for username-only JIDs
    pub fn show_add_contact_dialog(&mut self, server_domain: &str) {
        self.contact_add_dialog = Some(ContactAddDialog {
            input: Input::default(),
            server_domain: server_domain.to_string(),
        });
    }

    /// Shows a popup dialog asking the user to confirm contact removal
    ///
    /// # Arguments
    /// * `contact` - The contact to be removed
    pub fn show_contact_remove_dialog(&mut self, contact: &str) {
        self.contact_remove_dialog = Some(ContactRemoveDialog {
            contact: contact.to_string(),
        });
    }

    /// Shows a help dialog with all available shortcuts
    pub fn show_help_dialog(&mut self) {
        self.help_dialog = Some(HelpDialog {});
    }

    /// Shows the OMEMO device-trust table dialog (Ctrl+F).
    pub fn show_device_fingerprints_dialog(
        &mut self,
        own_jid: String,
        own_rows: Vec<(String, String, TrustLevel, bool)>,
        contact_jid: Option<String>,
        contact_rows: Vec<(String, String, TrustLevel)>,
    ) {
        self.device_fingerprints_dialog = Some(DeviceFingerprintsDialog {
            own_jid,
            own_rows,
            contact_jid,
            contact_rows,
            selected_row: 0,
        });
    }

    /// Shows a non-blocking notification when a friend request is automatically accepted
    ///
    /// # Arguments
    /// * `contact` - The contact whose request was automatically accepted
    pub fn show_friend_request_notification(&mut self, contact: &str) {
        debug!(
            "UI: Showing friend request notification for contact: {}",
            contact
        );
        self.friend_request_notification = Some(FriendRequestNotification {
            contact: contact.to_string(),
            timestamp: chrono::Utc::now(),
        });

        // Add a system message about the friend request acceptance
        self.add_message(Message::system(
            "me",
            format!("Friend request from {} automatically accepted", contact),
        ));
    }

    // Add a helper method to process the entered JID
    fn process_jid_input(&self, input: &str) -> String {
        let input = input.trim();

        // If the input already contains @, assume it's a full JID
        if input.contains('@') {
            return input.to_string();
        }

        // Otherwise, append the server domain from the dialog
        if let Some(dialog) = &self.contact_add_dialog {
            // Add the server domain to create a proper JID
            format!("{}@{}", input, dialog.server_domain)
        } else {
            // This is a fallback but shouldn't happen as the dialog should always be present
            // when this method is called during contact addition
            log::warn!("Processing JID input without active dialog: {}", input);
            input.to_string()
        }
    }

    pub fn handle_terminal_event(
        &mut self,
        terminal_event: Event,
    ) -> Result<Option<(String, String)>> {
        if let Some(focused) = focus_state_from_event(&terminal_event) {
            self.terminal_focused = focused;
            return Ok(None);
        }

        let Event::Key(key) = terminal_event else {
            return Ok(None);
        };

        if key.kind != KeyEventKind::Press {
            return Ok(None);
        }

        // Handle key confirmation popup if active
        if self.key_confirmation.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    // Accept the key
                    let contact = self.key_confirmation.as_ref().unwrap().contact.clone();
                    self.key_confirmation = None;

                    // Add system message about key acceptance
                    self.add_message(Message::system(
                        "me",
                        format!("OMEMO key for {} has been accepted", contact),
                    ));

                    return Ok(Some((contact, String::from("__KEY_ACCEPTED__"))));
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    // Reject the key
                    let contact = self.key_confirmation.as_ref().unwrap().contact.clone();
                    self.key_confirmation = None;

                    // Add system message about key rejection
                    self.add_message(Message::system(
                        "me",
                        format!("OMEMO key for {} has been rejected", contact),
                    ));

                    return Ok(Some((contact, String::from("__KEY_REJECTED__"))));
                }
                _ => {} // Ignore other keys when popup is active
            }
            return Ok(None);
        }

        // Handle contact remove confirmation dialog if active
        if let Some(dialog) = &self.contact_remove_dialog {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    // Confirm contact removal
                    let contact = dialog.contact.clone();
                    self.contact_remove_dialog = None;

                    // Add system message about the removal
                    self.add_message(Message::system(
                        "me",
                        format!("Removing contact {}...", contact),
                    ));

                    return Ok(Some((
                        contact,
                        String::from("__REMOVE_CONTACT_CONFIRMED__"),
                    )));
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    // Cancel contact removal
                    self.contact_remove_dialog = None;

                    // Add system message about cancellation
                    self.add_message(Message::system("me", "Contact removal cancelled"));

                    return Ok(None);
                }
                _ => {} // Ignore other keys when dialog is active
            }
            return Ok(None);
        }

        // Handle contact add dialog if active
        if let Some(dialog) = &self.contact_add_dialog {
            match key.code {
                KeyCode::Esc => {
                    // Cancel the dialog
                    self.contact_add_dialog = None;
                    return Ok(None);
                }
                KeyCode::Enter => {
                    // Process and add contact
                    let input = dialog.input.value().trim();
                    if !input.is_empty() {
                        let contact_jid = self.process_jid_input(input);
                        self.contact_add_dialog = None;

                        // Return the new contact JID to be added
                        return Ok(Some((contact_jid, String::from("__ADD_CONTACT__"))));
                    }
                }
                _ => {
                    // Create a new dialog with the updated input
                    let mut new_input = dialog.input.clone();
                    new_input.handle_event(&Event::Key(key));

                    // Update the dialog with the modified input
                    self.contact_add_dialog = Some(ContactAddDialog {
                        input: new_input,
                        server_domain: dialog.server_domain.clone(),
                    });
                }
            }
            return Ok(None);
        }

        // Handle help dialog if active
        if self.help_dialog.is_some() {
            // Any key press will close the help dialog
            self.help_dialog = None;
            return Ok(None);
        }

        // Handle device fingerprints / trust dialog if active
        if let Some(ref mut dialog) = self.device_fingerprints_dialog {
            let n_contact = dialog.contact_rows.len();
            let n_own = dialog.own_rows.len();
            let total = n_contact + n_own;
            match key.code {
                KeyCode::Up => {
                    if total > 0 && dialog.selected_row > 0 {
                        dialog.selected_row -= 1;
                    }
                }
                KeyCode::Down => {
                    if total > 0 && dialog.selected_row + 1 < total {
                        dialog.selected_row += 1;
                    }
                }
                KeyCode::Char(' ') | KeyCode::Enter => {
                    let sel = dialog.selected_row;
                    if sel < n_contact {
                        // Contact device row
                        let row = &mut dialog.contact_rows[sel];
                        let jid = dialog.contact_jid.clone().unwrap_or_default();
                        let device_id = row.0.clone();
                        let new_trusted =
                            !matches!(row.2, TrustLevel::Trusted | TrustLevel::Verified);
                        row.2 = if new_trusted {
                            TrustLevel::Trusted
                        } else {
                            TrustLevel::Untrusted
                        };
                        let flag = if new_trusted { "1" } else { "0" };
                        let signal = format!("__SET_DEVICE_TRUST__:{}:{}:{}", jid, device_id, flag);
                        return Ok(Some((String::new(), signal)));
                    } else {
                        // Own device row — skip "this device"
                        let own_idx = sel - n_contact;
                        if let Some(row) = dialog.own_rows.get_mut(own_idx) {
                            let is_current = row.3;
                            if !is_current {
                                let jid = dialog.own_jid.clone();
                                let device_id = row.0.clone();
                                let new_trusted =
                                    !matches!(row.2, TrustLevel::Trusted | TrustLevel::Verified);
                                row.2 = if new_trusted {
                                    TrustLevel::Trusted
                                } else {
                                    TrustLevel::Untrusted
                                };
                                let flag = if new_trusted { "1" } else { "0" };
                                let signal =
                                    format!("__SET_DEVICE_TRUST__:{}:{}:{}", jid, device_id, flag);
                                return Ok(Some((String::new(), signal)));
                            }
                        }
                    }
                }
                KeyCode::Esc => {
                    self.device_fingerprints_dialog = None;
                }
                _ => {} // absorb other keys — don't close dialog accidentally
            }
            return Ok(None);
        }

        match key.code {
            KeyCode::Esc => return Ok(Some((String::new(), String::new()))), // Signal to quit
            KeyCode::Enter => {
                if !self.input.value().is_empty() {
                    let message_content = self.input.value().to_string();
                    let recipient_jid = self.contact.clone();

                    // Clear input field immediately
                    self.input = Input::default();

                    // When creating a new message:
                    let message = if self.omemo_enabled {
                        Message::outgoing_encrypted(
                            Uuid::new_v4().to_string(),
                            recipient_jid.clone(),
                            message_content.clone(),
                        )
                    } else {
                        Message::outgoing_plaintext(
                            Uuid::new_v4().to_string(),
                            recipient_jid.clone(),
                            message_content.clone(),
                        )
                    };

                    // Add the message to UI immediately
                    self.add_message(message);

                    // Check if we're about to send an encrypted message
                    if self.omemo_enabled {
                        info!("UI: Preparing encrypted message for {}", recipient_jid);
                        // Instead of appending to the message content, add it as a separate flag
                        info!("UI: Using __VERIFY_KEYS__ prefix in recipient field instead of content");
                        return Ok(Some((
                            format!("__VERIFY_KEYS__:{}", recipient_jid),
                            message_content,
                        )));
                    } else {
                        info!("UI: Sending unencrypted message to {}", recipient_jid);
                        return Ok(Some((recipient_jid, message_content)));
                    }
                }
            }
            KeyCode::Tab => {
                self.active_tab = match self.active_tab {
                    Tab::Messages => Tab::Contacts,
                    Tab::Contacts => Tab::Messages,
                };
            }
            KeyCode::Char('o') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                // Toggle OMEMO encryption
                self.omemo_enabled = !self.omemo_enabled;

                // Add a system message about the change
                let status_msg = if self.omemo_enabled {
                    "OMEMO encryption enabled for this conversation"
                } else {
                    "OMEMO encryption disabled for this conversation"
                };

                self.add_message(Message::system("me", status_msg));
            }
            KeyCode::Char('p') | KeyCode::Char('P')
                if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
            {
                self.os_notifications_enabled = !self.os_notifications_enabled;
                let status_msg = if self.os_notifications_enabled {
                    "OS notifications enabled"
                } else {
                    "OS notifications disabled"
                };

                self.add_message(Message::system("me", status_msg));
                return Ok(Some((
                    String::new(),
                    String::from("__TOGGLE_OS_NOTIFICATIONS__"),
                )));
            }
            KeyCode::Char('t') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                // Toggle trust for the current contact's OMEMO keys
                if self.has_active_contact() {
                    let current_contact = self.contact.clone();

                    // Request a trust toggle operation from the main app
                    // We'll use a special message format that will be handled in main.rs
                    return Ok(Some((
                        current_contact,
                        String::from("__TOGGLE_OMEMO_TRUST__"),
                    )));
                }
            }
            KeyCode::Char('a') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                // Show add contact dialog
                // We'll use the base domain from the current credentials
                // The server domain will be supplied by main.rs before showing the dialog
                return Ok(Some((String::new(), String::from("__SHOW_ADD_CONTACT__"))));
            }
            KeyCode::Char('d') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                // Delete/remove the current contact
                if self.has_active_contact() {
                    let current_contact = self.contact.clone();

                    // Request contact removal from the main app
                    return Ok(Some((current_contact, String::from("__REMOVE_CONTACT__"))));
                }
            }
            KeyCode::Char('h') | KeyCode::Char('H')
                if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
            {
                // Show help dialog
                self.show_help_dialog();
                return Ok(None);
            }
            KeyCode::Char('f') | KeyCode::Char('F')
                if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
            {
                return Ok(Some((
                    String::new(),
                    String::from("__SHOW_DEVICE_FINGERPRINTS__"),
                )));
            }
            KeyCode::Char('m') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                return Ok(Some((String::new(), String::from("__ENABLE_CARBONS__"))));
            }
            KeyCode::Char('r') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {}
            // Add test shortcut for friend request notifications (Ctrl+N)
            KeyCode::Char('n') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                return Ok(Some((
                    String::new(),
                    String::from("__TEST_FRIEND_REQUEST__"),
                )));
            }
            KeyCode::Char('s') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                self.sidebar_hidden = !self.sidebar_hidden;
            }
            KeyCode::Up => {
                if let Tab::Contacts = self.active_tab {
                    if !self.contacts.is_empty() {
                        self.current_contact_index =
                            (self.current_contact_index + self.contacts.len() - 1)
                                % self.contacts.len();
                        let new_contact = self.contacts[self.current_contact_index].clone();
                        let contact_changed = new_contact != self.contact;
                        self.contact = new_contact;

                        // Clear unread status for the newly selected contact
                        if contact_changed {
                            self.unread_contacts.remove(&self.contact);
                            return Ok(Some((
                                self.contact.clone(),
                                String::from("__CONTACT_CHANGED__"),
                            )));
                        }
                    }
                } else if let Tab::Messages = self.active_tab {
                    let current = self.message_scroll_offset.unwrap_or(0);
                    self.message_scroll_offset = Some(current + 3);
                }
            }
            KeyCode::Down => {
                if let Tab::Contacts = self.active_tab {
                    if !self.contacts.is_empty() {
                        self.current_contact_index =
                            (self.current_contact_index + 1) % self.contacts.len();
                        let new_contact = self.contacts[self.current_contact_index].clone();
                        let contact_changed = new_contact != self.contact;
                        self.contact = new_contact;

                        // Clear unread status for the newly selected contact
                        if contact_changed {
                            self.unread_contacts.remove(&self.contact);
                            return Ok(Some((
                                self.contact.clone(),
                                String::from("__CONTACT_CHANGED__"),
                            )));
                        }
                    }
                } else if let Tab::Messages = self.active_tab {
                    if let Some(offset) = self.message_scroll_offset {
                        if offset <= 3 {
                            self.message_scroll_offset = None;
                        } else {
                            self.message_scroll_offset = Some(offset - 3);
                        }
                    }
                }
            }
            KeyCode::PageUp => {
                // Scroll messages up (Fn+Up on Mac)
                let current = self.message_scroll_offset.unwrap_or(0);
                self.message_scroll_offset = Some(current + 10);
            }
            KeyCode::PageDown => {
                // Scroll messages down (Fn+Down on Mac)
                if let Some(offset) = self.message_scroll_offset {
                    if offset <= 10 {
                        // Back to auto-scroll mode
                        self.message_scroll_offset = None;
                    } else {
                        self.message_scroll_offset = Some(offset - 10);
                    }
                }
                // If already None (auto-scroll), do nothing
            }
            KeyCode::End => {
                // Jump back to latest messages
                self.message_scroll_offset = None;
            }
            _ => {
                if let Tab::Messages = self.active_tab {
                    // Option+Left/Right for word navigation (macOS style)
                    if key.modifiers.contains(event::KeyModifiers::ALT) {
                        match key.code {
                            KeyCode::Left => {
                                let val = self.input.value();
                                let cursor = self.input.cursor();
                                // Move left past whitespace, then past word chars
                                let bytes = val.as_bytes();
                                let mut pos = cursor;
                                while pos > 0 && bytes[pos - 1] == b' ' {
                                    pos -= 1;
                                }
                                while pos > 0 && bytes[pos - 1] != b' ' {
                                    pos -= 1;
                                }
                                // Move cursor to new position
                                let steps = cursor - pos;
                                for _ in 0..steps {
                                    self.input.handle_event(&Event::Key(
                                        crossterm::event::KeyEvent::new(
                                            KeyCode::Left,
                                            event::KeyModifiers::NONE,
                                        ),
                                    ));
                                }
                            }
                            KeyCode::Right => {
                                let val = self.input.value();
                                let cursor = self.input.cursor();
                                let len = val.len();
                                let bytes = val.as_bytes();
                                // Move right past word chars, then past whitespace
                                let mut pos = cursor;
                                while pos < len && bytes[pos] != b' ' {
                                    pos += 1;
                                }
                                while pos < len && bytes[pos] == b' ' {
                                    pos += 1;
                                }
                                let steps = pos - cursor;
                                for _ in 0..steps {
                                    self.input.handle_event(&Event::Key(
                                        crossterm::event::KeyEvent::new(
                                            KeyCode::Right,
                                            event::KeyModifiers::NONE,
                                        ),
                                    ));
                                }
                            }
                            _ => {
                                self.input.handle_event(&Event::Key(key));
                            }
                        }
                    } else {
                        self.input.handle_event(&Event::Key(key));
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn draw(&self, frame: &mut Frame) {
        let size = frame.area();

        // Create a layout with 3 horizontal sections
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(if self.sidebar_hidden {
                vec![Constraint::Length(0), Constraint::Percentage(100)]
            } else {
                vec![Constraint::Percentage(20), Constraint::Percentage(80)]
            })
            .split(size);

        // Split the right section for messages, input, and help
        let chat_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),    // Messages area
                Constraint::Length(3), // Input box
                Constraint::Length(1), // Help line
            ])
            .split(chunks[1]);

        // Draw contacts list
        let contacts: Vec<ListItem> = self
            .contacts
            .iter()
            .enumerate()
            .map(|(i, c)| {
                // Add online status indicator
                let status_indicator = match self.get_contact_status(c) {
                    ContactStatus::Online => "🟢 ",
                    ContactStatus::Away => "🟠 ",
                    ContactStatus::Offline => "⚪ ",
                };

                // Get the resources for this contact
                let resources = self.get_resources(c);
                let resources_text = if !resources.is_empty() {
                    format!(" ({})", resources.join(", "))
                } else {
                    String::new()
                };

                let content = if i == self.current_contact_index {
                    format!("> {}{}{}", status_indicator, c, resources_text)
                } else {
                    format!("  {}{}{}", status_indicator, c, resources_text)
                };
                let style = if self.unread_contacts.contains(c) {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(content).style(style)
            })
            .collect();

        let contacts_list = List::new(contacts).block(
            Block::default()
                .title("Contacts (Tab to focus)")
                .borders(Borders::ALL)
                .border_style(match self.active_tab {
                    Tab::Contacts => Style::default().fg(Color::Yellow),
                    _ => Style::default(),
                }),
        );
        frame.render_widget(contacts_list, chunks[0]);

        // Draw messages (filtered to active contact only)
        let active_contact = &self.contact;
        let filtered_messages: Vec<&Message> = self
            .messages
            .iter()
            .filter(|m| {
                if active_contact.is_empty() {
                    return true; // Show all if no contact selected
                }
                let sender_base = Self::get_base_jid(&m.sender_id);
                let recipient_base = Self::get_base_jid(&m.recipient_id);
                // Show messages from the active contact, or sent to the active contact, or system messages
                sender_base == *active_contact
                    || recipient_base == *active_contact
                    || m.sender_id == "system"
            })
            .collect();
        let filtered_owned: Vec<Message> = filtered_messages.into_iter().cloned().collect();
        draw_messages(frame, &filtered_owned, chat_chunks[0], self);

        // Draw input box
        let input_block = Block::default()
            .title("Message")
            .borders(Borders::ALL)
            .border_style(match self.active_tab {
                Tab::Messages => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            });

        let input_widget = Paragraph::new(self.input.value())
            .block(input_block)
            .style(Style::default());
        frame.render_widget(input_widget, chat_chunks[1]);

        // Draw help line
        let omemo_status_text = if self.omemo_enabled {
            "enabled"
        } else {
            "disabled"
        };
        let omemo_status_style = if self.omemo_enabled {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };
        let notification_status_text = if self.os_notifications_enabled {
            "on"
        } else {
            "off"
        };
        let notification_status_style = if self.os_notifications_enabled {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };

        let help_spans = vec![
            Span::styled(
                " ESC quit | TAB switch | Ctrl+H help | Ctrl+A add | Ctrl+O OMEMO [",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(omemo_status_text, omemo_status_style),
            Span::styled(
                "] | Ctrl+P notifications [",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(notification_status_text, notification_status_style),
            Span::styled(
                "] | Ctrl+T trust | Ctrl+S sidebar | Fn+↑/↓ scroll",
                Style::default().fg(Color::Gray),
            ),
        ];

        let help = Paragraph::new(Line::from(help_spans));
        frame.render_widget(help, chat_chunks[2]);

        // Set cursor position
        if let Tab::Messages = self.active_tab {
            frame.set_cursor_position((
                // Put cursor past the end of the input text
                chat_chunks[1].x + self.input.cursor() as u16 + 1,
                // Put cursor at the start of the input line
                chat_chunks[1].y + 1,
            ));
        }

        // Draw key confirmation popup if active
        if let Some(key_conf) = &self.key_confirmation {
            draw_key_confirmation(frame, key_conf, size);
        }

        // Draw add contact dialog if active
        if let Some(dialog) = &self.contact_add_dialog {
            draw_add_contact_dialog(frame, dialog, size);
        }

        // Draw contact remove dialog if active
        if let Some(dialog) = &self.contact_remove_dialog {
            draw_contact_remove_dialog(frame, dialog, size);
        }

        // Draw help dialog if active
        if let Some(_) = &self.help_dialog {
            draw_help_dialog(frame, size);
        }

        // Draw device fingerprints dialog if active
        if let Some(dialog) = &self.device_fingerprints_dialog {
            draw_device_fingerprints_dialog(frame, dialog, size);
        }

        // Draw friend request notification if active
        if let Some(notification) = &self.friend_request_notification {
            info!(
                "UI: Friend request notification is active for contact: {}",
                notification.contact
            );
            draw_friend_request_notification(frame, notification, size);
        } else {
            // This could spam the logs, so it's commented out, but useful for debugging
            // log::debug!("UI: No friend request notification active during this render");
        }
    }

    pub fn remove_last_message(&mut self) {
        self.messages.pop();
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
        self.message_scroll_offset = None;
    }

    pub fn update_contact_status(&mut self, contact_id: &str, status: ContactStatus) {
        // Store status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.contact_status.insert(base_jid, status);
    }

    pub fn get_contact_status(&self, contact_id: &str) -> ContactStatus {
        // Get status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.contact_status
            .get(&base_jid)
            .cloned()
            .unwrap_or(ContactStatus::Offline)
    }

    // New methods for typing indicators
    pub fn update_typing_status(&mut self, contact_id: &str, status: TypingStatus) {
        // Store typing status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.typing_states
            .insert(base_jid, (status, chrono::Utc::now()));
    }

    // Check and clear typing states older than the timeout duration
    pub fn clean_typing_states(&mut self, timeout_secs: i64) -> bool {
        let now = chrono::Utc::now();
        let mut to_remove = Vec::new();

        for (jid, (status, timestamp)) in &self.typing_states {
            // Only auto-expire Composing and Paused states
            if (*status == TypingStatus::Composing || *status == TypingStatus::Paused)
                && (now - *timestamp).num_seconds() > timeout_secs
            {
                to_remove.push(jid.clone());
            }
        }

        let changed = !to_remove.is_empty();
        for jid in to_remove {
            self.typing_states.remove(&jid);
        }

        changed
    }

    // Reset typing status when a message is received from contact
    pub fn message_received_from(&mut self, contact_id: &str) {
        // When we receive a message, clear any typing status
        let base_jid = Self::get_base_jid(contact_id);
        self.typing_states.remove(&base_jid);
    }

    pub fn get_active_contact(&self) -> String {
        self.contact.clone()
    }

    /// Returns whether OMEMO encryption is currently enabled for conversations
    ///
    /// This setting can be toggled by the user with Ctrl+O
    pub fn is_omemo_enabled(&self) -> bool {
        self.omemo_enabled
    }

    /// Returns whether OS notifications are currently enabled.
    pub fn os_notifications_enabled(&self) -> bool {
        self.os_notifications_enabled
    }

    pub fn set_os_notifications_enabled(&mut self, enabled: bool) {
        self.os_notifications_enabled = enabled;
    }

    /// Returns whether the terminal currently reports keyboard focus.
    pub fn is_terminal_focused(&self) -> bool {
        self.terminal_focused
    }

    /// Set the connection status to the XMPP server
    ///
    /// # Arguments
    /// * `connected` - true if connected to the XMPP server, false otherwise
    pub fn set_connection_status(&mut self, connected: bool) {
        self.connection_status = connected;
    }

    /// Returns whether the client is currently connected to the XMPP server
    pub fn is_connected(&self) -> bool {
        self.connection_status
    }

    /// Reset/clear the device fingerprints dialog if it's active
    pub fn reset_device_fingerprints_dialog(&mut self) {
        //debug!("UI: Resetting device fingerprints dialog");
        self.device_fingerprints_dialog = None;
    }

    // Check and clear friend request notification if it's been shown for enough time
    pub fn clean_friend_request_notifications(&mut self, timeout_secs: i64) -> bool {
        if let Some(notification) = &self.friend_request_notification {
            let now = chrono::Utc::now();
            if (now - notification.timestamp).num_seconds() > timeout_secs {
                debug!(
                    "UI: Auto-dismissing friend request notification for {}",
                    notification.contact
                );
                self.friend_request_notification = None;
                return true;
            }
        } else {
            // Auto-dismissal isn't happening because there's no active notification
            // This is expected most of the time, so we'll use a trace level log
            // debug!("UI: No friend request notification to clean");
        }
        false
    }

    /// Test the friend request notification UI by artificially triggering a notification
    ///
    /// This is a helper method for testing the UI notification system
    pub fn test_friend_request_notification(&mut self) {
        // Show a test notification
        info!("TEST: Artificially showing friend request notification for test@example.com");
        self.show_friend_request_notification("test@example.com");

        // Also add the test contact to the contacts list
        self.add_contact("test@example.com");

        // Add a system message to confirm test was triggered
        self.add_message(Message::system(
            "me",
            "TEST: Friend request notification triggered manually",
        ));
    }
}

/// Splits a text line into ratatui spans, styling any URLs with cyan + underline
/// so Ghostty (and other terminals) can identify them as clickable links.
fn spans_for_line(text: &str, base_style: Style) -> Line<'static> {
    let link_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::UNDERLINED);
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut rest = text;
    loop {
        let url_start = match (rest.find("http://"), rest.find("https://")) {
            (None, None) => {
                if !rest.is_empty() {
                    spans.push(Span::styled(rest.to_owned(), base_style));
                }
                break;
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (Some(a), Some(b)) => a.min(b),
        };
        if url_start > 0 {
            spans.push(Span::styled(rest[..url_start].to_owned(), base_style));
        }
        let after = &rest[url_start..];
        let url_len = after
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(after.len());
        spans.push(Span::styled(after[..url_len].to_owned(), link_style));
        rest = &rest[url_start + url_len..];
    }
    Line::from(spans)
}

fn draw_messages(f: &mut Frame, messages: &[Message], area: Rect, ui: &ChatUI) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // Messages
            Constraint::Length(1), // Typing indicator
        ])
        .split(area);

    let wrap_width = area.width.saturating_sub(2) as usize; // Account for borders

    let messages_with_status: Vec<ListItem> = messages
        .iter()
        .flat_map(|m| {
            let datetime = chrono::DateTime::from_timestamp(m.timestamp as i64, 0)
                .unwrap_or_else(|| chrono::Utc::now());

            let now = chrono::Utc::now();
            let _is_today = datetime.date_naive() == now.date_naive();

            let timestamp = datetime.format("%Y-%m-%d %H:%M").to_string();

            // Add encryption indicator based on whether this specific message was encrypted
            let encryption_indicator = if m.encrypted { " 🔒" } else { " ❌" };
            let prefix =
                if m.sender_id == "me" || m.sender_id.contains("@") && m.recipient_id != "me" {
                    format!("[{}] You{}: ", timestamp, encryption_indicator)
                } else if m.sender_id == "system" {
                    format!("[{}] System: ", timestamp)
                } else {
                    format!("[{}] {}{}: ", timestamp, m.sender_id, encryption_indicator)
                };

            // Simplified status indicator using ticks clearly
            let status_indicator =
                if m.sender_id == "me" || m.sender_id.contains("@") && m.recipient_id != "me" {
                    match m.delivery_status {
                        DeliveryStatus::Sending => "", // no tick yet
                        DeliveryStatus::Sent => " ✓",
                        DeliveryStatus::Delivered => " ✓✓",
                        DeliveryStatus::Read => " ✓✓✓",
                        DeliveryStatus::Stored => " 📥",
                        DeliveryStatus::Failed => " ❌",
                        DeliveryStatus::Unknown => "",
                    }
                } else {
                    ""
                };

            let full_content = format!("{}{}{}", prefix, m.content, status_indicator);

            // Use textwrap to wrap the content. NoHyphenation prevents URLs from
            // being broken at hyphens, which would defeat terminal URL detection.
            let wrapped_lines: Vec<String> = wrap(
                &full_content,
                Options::new(wrap_width).word_splitter(WordSplitter::NoHyphenation),
            )
            .into_iter()
            .map(|l| l.into_owned())
            .collect();

            let style = if m.sender_id == "system" {
                Style::default().fg(Color::Gray)
            } else if m.sender_id == "me" {
                match m.delivery_status {
                    DeliveryStatus::Failed => Style::default().fg(Color::Red),
                    DeliveryStatus::Delivered | DeliveryStatus::Read => {
                        Style::default().fg(Color::Green)
                    }
                    DeliveryStatus::Sent | DeliveryStatus::Sending => {
                        Style::default().fg(Color::Blue)
                    }
                    DeliveryStatus::Stored => Style::default().fg(Color::Yellow),
                    _ => Style::default(),
                }
            } else {
                Style::default()
            };

            wrapped_lines.into_iter().map(move |line| {
                if line.contains("http://") || line.contains("https://") {
                    ListItem::new(Text::from(spans_for_line(&line, style)))
                } else {
                    ListItem::new(Text::from(line)).style(style)
                }
            })
        })
        .collect();

    // Add connection status icon to the title
    let connection_icon = if ui.is_connected() { "🔌 " } else { "❌ " };
    let scroll_indicator = if ui.message_scroll_offset.is_some() {
        " [scrolled - Fn+End to jump to latest]"
    } else {
        ""
    };
    let title = format!("{}Messages{}", connection_icon, scroll_indicator);

    // Create a ListState to control the scroll position
    let mut list_state = ListState::default();

    // Set the selected item based on scroll offset
    if !messages_with_status.is_empty() {
        let last = messages_with_status.len() - 1;
        let selected = match ui.message_scroll_offset {
            None => last, // Auto-scroll to bottom
            Some(lines_from_bottom) => last.saturating_sub(lines_from_bottom),
        };
        list_state.select(Some(selected));
    }

    let messages_list = List::new(messages_with_status)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default()); // Use default style to make selection invisible

    // Render the widget with state to allow scrolling to the selected (last) message
    f.render_stateful_widget(messages_list, chunks[0], &mut list_state);
}

fn draw_key_confirmation(f: &mut Frame, key_conf: &KeyConfirmation, area: Rect) {
    let device_info = key_conf
        .device_id
        .as_ref()
        .map_or(String::new(), |id| format!(" (Device ID: {})", id));

    // Size the popup to fit the fingerprint line (border=2, h-margins=4 → 6 overhead cols).
    let fingerprint_line = format!("Key fingerprint: {}", key_conf.fingerprint);
    let desired_popup_width = (fingerprint_line.len() as u16 + 6).max(44);
    let max_popup_width = area.width.saturating_sub(4);
    let popup_width = desired_popup_width.min(max_popup_width);

    // When the terminal is too narrow to show the fingerprint on one line, split it in two.
    let inner_width = popup_width.saturating_sub(6) as usize;
    let fingerprint_lines: Vec<String> = if fingerprint_line.len() <= inner_width {
        vec![fingerprint_line]
    } else {
        // Split the hex-colon string at roughly the midpoint on a colon boundary.
        let fp = &key_conf.fingerprint;
        let mid = fp.len() / 2;
        let split = fp[..mid].rfind(':').map(|i| i + 1).unwrap_or(mid);
        vec![
            "Key fingerprint:".to_string(),
            format!("  {}", &fp[..split.saturating_sub(1)]),
            format!("  {}", &fp[split..]),
        ]
    };

    let mut content: Vec<String> = vec![
        format!("Contact: {}{}", key_conf.contact, device_info),
        "".to_string(),
    ];
    content.extend(fingerprint_lines);
    content.push("".to_string());
    content.push("Do you want to accept this key?".to_string());
    content.push("Press [Y] to accept or [N] to reject".to_string());

    let popup_height = (content.len() as u16 + 2).min(area.height.saturating_sub(4));
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    let popup_block = Block::default()
        .title("Unrecognized OMEMO Key")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    f.render_widget(Clear, popup_area);
    f.render_widget(popup_block, popup_area);

    let inner_area = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 2,
    });

    let content_list = List::new(
        content
            .iter()
            .map(|s| ListItem::new(s.as_str()))
            .collect::<Vec<_>>(),
    )
    .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(content_list, inner_area);
}

fn draw_add_contact_dialog(f: &mut Frame, dialog: &ContactAddDialog, area: Rect) {
    // Calculate popup size and position (centered)
    let popup_width = 50.min(area.width - 4);
    let popup_height = 7.min(area.height - 4);

    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Create popup with border
    let popup_block = Block::default()
        .title("Add New Contact")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);

    // Create inner area for content
    let inner_area = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 2,
    });

    // Split inner area for content and input field
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Instructions
            Constraint::Length(3), // Input field
        ])
        .split(inner_area);

    // Display instructions
    let instructions = vec![
        "Enter username or full JID (username@domain) of the contact:".to_string(),
        format!(
            "Server: {} (will be used if only username is entered)",
            dialog.server_domain
        ),
    ];

    let instructions_list = List::new(
        instructions
            .iter()
            .map(|s| ListItem::new(s.as_str()))
            .collect::<Vec<_>>(),
    );

    f.render_widget(instructions_list, chunks[0]);

    // Display input field
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let input_widget = Paragraph::new(dialog.input.value())
        .block(input_block)
        .style(Style::default());

    f.render_widget(input_widget, chunks[1]);

    // Set cursor position in the input field
    f.set_cursor_position((
        chunks[1].x + dialog.input.cursor() as u16 + 1,
        chunks[1].y + 1,
    ));
}

fn draw_contact_remove_dialog(f: &mut Frame, dialog: &ContactRemoveDialog, area: Rect) {
    // Calculate popup size and position (centered)
    let popup_width = 60.min(area.width - 4); // Increased from 50 to 60
    let popup_height = 8.min(area.height - 4); // Increased from 6 to 8

    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Create popup with border
    let popup_block = Block::default()
        .title("Confirm Contact Removal")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red)); // Use red for warning

    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);

    // Create inner area for content
    let inner_area = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 2,
    });

    // Prepare the content
    let content = vec![
        format!(
            "Are you sure you want to remove contact '{}'?",
            dialog.contact
        ),
        "".to_string(),
        "This will remove the contact from your roster.".to_string(),
        "This action cannot be undone.".to_string(), // Added extra explanation line
        "".to_string(),
        "Press [Y] to confirm or [N]/[ESC] to cancel".to_string(),
    ];

    // Display content as a list
    let content_list = List::new(
        content
            .iter()
            .map(|s| ListItem::new(s.as_str()))
            .collect::<Vec<_>>(),
    )
    .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(content_list, inner_area);
}

fn draw_help_dialog(f: &mut Frame, area: Rect) {
    // Calculate popup size and position (centered)
    let popup_width = 80.min(area.width - 4);
    let popup_height = 28.min(area.height - 4);

    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Create popup with border
    let popup_block = Block::default()
        .title("Keyboard Shortcuts")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);

    // Create inner area for content
    let inner_area = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 2,
    });

    // Create the shortcuts list
    let shortcuts = vec![
        ("General", ""),
        ("ESC", "Quit application"),
        ("Tab", "Switch between Messages and Contacts"),
        ("Ctrl+S", "Toggle sidebar (contacts panel) visibility"),
        ("Ctrl+H", "Show this help dialog"),
        ("", ""),
        ("Contacts Navigation", ""),
        (
            "↑/↓",
            "Navigate through contacts (when Contacts tab is active)",
        ),
        ("", ""),
        ("Contacts Management", ""),
        ("Ctrl+A", "Add a new contact"),
        ("Ctrl+D", "Delete/remove current contact"),
        ("", ""),
        ("Messages", ""),
        ("Enter", "Send message (when Messages tab is active)"),
        ("", ""),
        ("Security", ""),
        ("Ctrl+O", "Toggle OMEMO encryption for current conversation"),
        ("Ctrl+T", "Toggle trust for current contact's OMEMO keys"),
        (
            "Ctrl+M",
            "Enable Message Carbons protocol (sync messages between devices)",
        ),
        ("Ctrl+F", "Show device fingerprints dialog"),
        (
            "Ctrl+R",
            "Force OMEMO device list re-fetch for active contact",
        ),
        ("Ctrl+P", "Toggle OS notifications"),
        ("", ""),
        ("Press any key to close this dialog", ""),
    ];

    // Convert the shortcuts to ListItems
    let items: Vec<ListItem> = shortcuts
        .iter()
        .map(|(key, desc)| {
            if desc.is_empty() {
                // If this is a category header or blank line
                if key.is_empty() {
                    // Blank line
                    ListItem::new("")
                } else {
                    // Category header
                    ListItem::new(Text::styled(
                        key.to_string(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ))
                }
            } else {
                // This is a shortcut entry
                let formatted_key = format!("{:<10}", key);
                let line = Line::from(vec![
                    Span::styled(formatted_key, Style::default().fg(Color::Green)),
                    Span::raw(desc.to_string()),
                ]);
                ListItem::new(line)
            }
        })
        .collect();

    // Display the shortcuts list
    let shortcuts_list = List::new(items);
    f.render_widget(shortcuts_list, inner_area);
}

fn draw_device_fingerprints_dialog(f: &mut Frame, dialog: &DeviceFingerprintsDialog, area: Rect) {
    // ── popup geometry ────────────────────────────────────────────────────────
    let popup_width = 84u16.min(area.width.saturating_sub(4));
    let contact_rows = dialog.contact_rows.len() as u16;
    let own_rows = dialog.own_rows.len() as u16;
    // header + contact section header + table header + rows + gap + own section
    // header + table header + rows + footer
    let popup_height =
        (4 + contact_rows.max(1) + 4 + own_rows.max(1) + 4).min(area.height.saturating_sub(4));
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);
    let outer_block = Block::default()
        .title(" OMEMO Keys  ↑/↓ navigate · Space toggle trust · Esc close ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    f.render_widget(outer_block, popup_area);

    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    // ── helper: format a fingerprint to fit in `w` chars ─────────────────────
    fn fmt_fp(fp: &str, w: usize) -> String {
        // strip spaces → re-chunk into groups of 4 hex chars separated by spaces
        let hex: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let grouped: String = hex
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ");
        if grouped.len() > w {
            format!("{}…", &grouped[..w.saturating_sub(1)])
        } else {
            grouped
        }
    }

    // ── trust slider helper ───────────────────────────────────────────────────
    fn trust_cell(trust: &TrustLevel) -> (String, Color) {
        match trust {
            TrustLevel::Trusted | TrustLevel::Verified => {
                ("────● Trusted".to_string(), Color::Green)
            }
            TrustLevel::Untrusted => ("●──── Blocked".to_string(), Color::Red),
            TrustLevel::Undecided => ("──?── Unknown".to_string(), Color::Yellow),
        }
    }

    // ── column widths ─────────────────────────────────────────────────────────
    // | device_id (9) | fingerprint (fill) | trust (13) |
    let widths = [
        Constraint::Length(9),
        Constraint::Fill(1),
        Constraint::Length(13),
    ];
    let fp_width = (inner.width as usize).saturating_sub(9 + 13 + 4); // approx

    // ── layout: split inner vertically ───────────────────────────────────────
    let contact_table_height = 2 + contact_rows.max(1); // header row + data rows
    let gap = 1u16;
    let own_table_height = 2 + own_rows.max(1);
    let footer_height = 1u16;
    let sections = Layout::vertical([
        Constraint::Length(contact_table_height),
        Constraint::Length(gap),
        Constraint::Length(own_table_height),
        Constraint::Min(footer_height),
    ])
    .split(inner);

    // ── contact-device table ──────────────────────────────────────────────────
    let header_style = Style::default()
        .fg(Color::Magenta)
        .add_modifier(Modifier::BOLD);
    let contact_title = dialog.contact_jid.as_deref().unwrap_or("Contact devices");
    let contact_rows_rendered: Vec<Row> = if dialog.contact_rows.is_empty() {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from("No OMEMO devices found for this contact")
                .style(Style::default().fg(Color::DarkGray)),
            Cell::from(""),
        ])]
    } else {
        dialog
            .contact_rows
            .iter()
            .map(|(dev, fp, trust)| {
                let (trust_text, trust_color) = trust_cell(trust);
                Row::new(vec![
                    Cell::from(dev.as_str()),
                    Cell::from(fmt_fp(fp, fp_width)),
                    Cell::from(Span::styled(trust_text, Style::default().fg(trust_color))),
                ])
            })
            .collect()
    };

    let n_contact = dialog.contact_rows.len();
    let mut contact_state = TableState::default();
    if !dialog.contact_rows.is_empty() && dialog.selected_row < n_contact {
        contact_state.select(Some(dialog.selected_row));
    }

    let contact_table = Table::new(contact_rows_rendered, widths)
        .header(Row::new(vec!["Device", "Fingerprint", "Trust"]).style(header_style))
        .block(
            Block::default()
                .title(Span::styled(
                    contact_title,
                    Style::default().fg(Color::Magenta),
                ))
                .borders(Borders::NONE),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(contact_table, sections[0], &mut contact_state);

    // ── own-device table ──────────────────────────────────────────────────────
    let own_header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let own_rows_rendered: Vec<Row> = if dialog.own_rows.is_empty() {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from("No own devices found").style(Style::default().fg(Color::DarkGray)),
            Cell::from(""),
        ])]
    } else {
        dialog
            .own_rows
            .iter()
            .map(|(dev, fp, trust, is_current)| {
                let dev_text = if *is_current {
                    format!("{} *", dev) // asterisk marks current device
                } else {
                    dev.clone()
                };
                let dev_style = if *is_current {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let (trust_text, trust_color) = if *is_current {
                    ("(this device)".to_string(), Color::Yellow)
                } else {
                    trust_cell(trust)
                };
                Row::new(vec![
                    Cell::from(Span::styled(dev_text, dev_style)),
                    Cell::from(fmt_fp(fp, fp_width)),
                    Cell::from(Span::styled(trust_text, Style::default().fg(trust_color))),
                ])
            })
            .collect()
    };

    // Selection within own section
    let mut own_state = TableState::default();
    if dialog.selected_row >= n_contact {
        let own_idx = dialog.selected_row - n_contact;
        if own_idx < dialog.own_rows.len() {
            own_state.select(Some(own_idx));
        }
    }

    let own_table = Table::new(own_rows_rendered, widths)
        .header(Row::new(vec!["Device", "Fingerprint", "Trust"]).style(own_header_style))
        .block(
            Block::default()
                .title(Span::styled(
                    "Your devices  (* = this device, cannot change trust)",
                    Style::default().fg(Color::Cyan),
                ))
                .borders(Borders::NONE),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(own_table, sections[2], &mut own_state);

    // ── footer hint ───────────────────────────────────────────────────────────
    if !sections[3].is_empty() {
        let hint = Paragraph::new(
            "Space/Enter to toggle trust for selected contact device  ·  Esc to close",
        )
        .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, sections[3]);
    }
}

fn draw_friend_request_notification(
    f: &mut Frame,
    notification: &FriendRequestNotification,
    area: Rect,
) {
    // Calculate popup size and position (top-right corner)
    let popup_width = 40.min(area.width - 4);
    let popup_height = 5.min(area.height - 4);

    // Position in top-right corner with some margin
    let popup_x = area.width - popup_width - 2;
    let popup_y = 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Log when rendering (this will help debug if the popup is being drawn)
    log::info!(
        "UI: Drawing friend request notification popup for contact: {}",
        notification.contact
    );

    // Create popup with border
    let popup_block = Block::default()
        .title("Friend Request Accepted")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);

    // Create inner area for content
    let inner_area = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 2,
    });

    // Format the content
    let content = vec![
        format!("✅ Friend request from {} was", notification.contact),
        "automatically accepted".to_string(),
    ];

    // Display content as a list
    let content_list = List::new(
        content
            .iter()
            .map(|s| ListItem::new(s.as_str()))
            .collect::<Vec<_>>(),
    )
    .style(Style::default().fg(Color::Green));

    f.render_widget(content_list, inner_area);
}

pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableFocusChange)?;
    // Alternate scroll mode: the terminal converts scroll-wheel events into
    // Up/Down arrow key sequences without consuming mouse button events, so
    // normal text selection still works.
    io::Write::write_all(&mut stdout, b"\x1b[?1007h")?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn restore_terminal(mut terminal: Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    let _ = io::Write::write_all(terminal.backend_mut(), b"\x1b[?1007l");
    let _ = io::Write::flush(terminal.backend_mut());
    execute!(
        terminal.backend_mut(),
        DisableFocusChange,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn focus_state_from_event(event: &Event) -> Option<bool> {
    match event {
        Event::FocusGained => Some(true),
        Event::FocusLost => Some(false),
        _ => None,
    }
}
