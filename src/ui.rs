use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::info;  // Add the log import
use log::debug; // Add the debug import
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Clear, ListState},
    Frame,
};
use std::{io, time::Duration, collections::HashMap};
use tui_input::{backend::crossterm::EventHandler, Input};
use uuid::Uuid;
use textwrap::wrap;

// Use the new Message type from the models module and TypingStatus from xmpp
use chatterbox::models::{Message, DeliveryStatus, ContactStatus};
use chatterbox::xmpp::chat_states::TypingStatus;

// Export types needed by main module
pub use ratatui::Terminal;
pub use ratatui::backend::CrosstermBackend;

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
    key_confirmation: Option<KeyConfirmation>, // Add this field for key confirmation popup
    contact_add_dialog: Option<ContactAddDialog>, // Add this field for adding new contacts
    contact_remove_dialog: Option<ContactRemoveDialog>, // Add this field for remove confirmation
    help_dialog: Option<HelpDialog>, // Add this field for help popup
    device_fingerprints_dialog: Option<DeviceFingerprintsDialog>, // Add this field for device fingerprints popup
    friend_request_notification: Option<FriendRequestNotification>, // Add this field for friend request notifications
    resources: HashMap<String, Vec<String>>, // Map of base JID -> resource JIDs
    connection_status: bool, // Track XMPP server connection status
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
    server_domain: String,  // Store the current server's domain for username-only JIDs
}

// Add this new struct for contact removal confirmation
struct ContactRemoveDialog {
    contact: String,  // The contact to be removed
}

// Add this new struct for help dialog
struct HelpDialog {
    // No additional state needed for the help dialog
}

// Add this new struct for device fingerprints dialog
struct DeviceFingerprintsDialog {
    fingerprints: Vec<(String, String)>, // (Device ID, Fingerprint)
    current_device_id: Option<String>,
}

// Add this new struct for friend request notification
struct FriendRequestNotification {
    contact: String,  // The contact that was automatically accepted
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
            key_confirmation: None, // Initialize to None
            contact_add_dialog: None, // Initialize to None
            contact_remove_dialog: None, // Initialize to None
            help_dialog: None, // Initialize to None
            device_fingerprints_dialog: None, // Initialize to None
            friend_request_notification: None, // Initialize to None
            resources: HashMap::new(), // Initialize resources map
            connection_status: false, // Initialize connection status to disconnected
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
            if let Some(idx) = self.messages.iter().position(|m| 
                m.sender_id == message.sender_id && 
                m.recipient_id == message.recipient_id &&
                m.content == message.content &&
                m.timestamp > recent_threshold) 
            {
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
                // It's a new message, add it
                self.messages.push(message);
            }
        }
    }

    pub fn add_contact(&mut self, contact: &str) {
        let base_jid = Self::get_base_jid(contact);
        let resource = Self::get_resource(contact);
        
        // Store the resource if present
        if let Some(res) = resource {
            let resources = self.resources.entry(base_jid.clone()).or_insert_with(Vec::new);
            if (!resources.contains(&res)) {
                resources.push(res);
            }
        }

        // Only add the base JID to contacts list if not already present
        if (!self.contacts.contains(&base_jid)) {
            self.contacts.push(base_jid);
        }
    }

    // Get all resources for a given base JID
    pub fn get_resources(&self, base_jid: &str) -> Vec<String> {
        self.resources.get(base_jid)
            .cloned()
            .unwrap_or_default()
    }

    // Public method to get the full JID (with resource) if available
    pub fn get_full_jid(&self, base_jid: &str) -> String {
        // If resources are available, use the first one (most recently active)
        if let Some(resources) = self.resources.get(base_jid) {
            if !resources.is_empty() {
                return format!("{}/{}", base_jid, resources[0]);
            }
        }
        base_jid.to_string()
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
    pub fn show_key_confirmation(&mut self, contact: &str, fingerprint: &str, device_id: Option<&str>) {
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
    
    /// Shows a dialog displaying all device fingerprints for the current account
    /// 
    /// # Arguments
    /// * `fingerprints` - A vector of tuples containing device ID and fingerprint
    pub fn show_device_fingerprints_dialog(&mut self, fingerprints: Vec<(String, String)>, current_device_id: Option<String>) {
        //debug!("UI: Showing device fingerprints dialog with {} devices", fingerprints.len());
        self.device_fingerprints_dialog = Some(DeviceFingerprintsDialog {
            fingerprints,
            current_device_id,
        });
    }

    /// Shows a non-blocking notification when a friend request is automatically accepted
    /// 
    /// # Arguments
    /// * `contact` - The contact whose request was automatically accepted
    pub fn show_friend_request_notification(&mut self, contact: &str) {
        debug!("UI: Showing friend request notification for contact: {}", contact);
        self.friend_request_notification = Some(FriendRequestNotification {
            contact: contact.to_string(),
            timestamp: chrono::Utc::now(),
        });
        
        // Add a system message about the friend request acceptance
        self.add_message(Message {
            id: Uuid::new_v4().to_string(),
            content: format!("Friend request from {} automatically accepted", contact),
            sender_id: "system".to_string(),
            recipient_id: "me".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Unknown,
        });
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

    // Modify handle_input to process key confirmation responses
    pub fn handle_input(&mut self) -> Result<Option<(String, String)>> {
        // Handle key confirmation popup if active
        if self.key_confirmation.is_some() {
            if event::poll(Duration::from_millis(10))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
                                // Accept the key
                                let contact = self.key_confirmation.as_ref().unwrap().contact.clone();
                                self.key_confirmation = None;
                                
                                // Add system message about key acceptance
                                self.add_message(Message {
                                    id: "system_key_acceptance".to_string(),
                                    content: format!("OMEMO key for {} has been accepted", contact),
                                    sender_id: "system".to_string(),
                                    recipient_id: "me".to_string(),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    delivery_status: DeliveryStatus::Unknown,
                                });
                                
                                return Ok(Some((contact, String::from("__KEY_ACCEPTED__"))));
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') => {
                                // Reject the key
                                let contact = self.key_confirmation.as_ref().unwrap().contact.clone();
                                self.key_confirmation = None;
                                
                                // Add system message about key rejection
                                self.add_message(Message {
                                    id: "system_key_rejection".to_string(),
                                    content: format!("OMEMO key for {} has been rejected", contact),
                                    sender_id: "system".to_string(),
                                    recipient_id: "me".to_string(),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    delivery_status: DeliveryStatus::Unknown,
                                });
                                
                                return Ok(Some((contact, String::from("__KEY_REJECTED__"))));
                            }
                            _ => {} // Ignore other keys when popup is active
                        }
                    }
                }
            }
            return Ok(None);
        }
        
        // Handle contact remove confirmation dialog if active
        if let Some(dialog) = &self.contact_remove_dialog {
            if event::poll(Duration::from_millis(10))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
                                // Confirm contact removal
                                let contact = dialog.contact.clone();
                                self.contact_remove_dialog = None;
                                
                                // Add system message about the removal
                                self.add_message(Message {
                                    id: Uuid::new_v4().to_string(),
                                    content: format!("Removing contact {}...", contact),
                                    sender_id: "system".to_string(),
                                    recipient_id: "me".to_string(),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    delivery_status: DeliveryStatus::Unknown,
                                });
                                
                                return Ok(Some((contact, String::from("__REMOVE_CONTACT_CONFIRMED__"))));
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                // Cancel contact removal
                                self.contact_remove_dialog = None;
                                
                                // Add system message about cancellation
                                self.add_message(Message {
                                    id: Uuid::new_v4().to_string(),
                                    content: "Contact removal cancelled".to_string(),
                                    sender_id: "system".to_string(),
                                    recipient_id: "me".to_string(),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    delivery_status: DeliveryStatus::Unknown,
                                });
                                
                                return Ok(None);
                            }
                            _ => {} // Ignore other keys when dialog is active
                        }
                    }
                }
            }
            return Ok(None);
        }
        
        // Handle contact add dialog if active
        if let Some(dialog) = &self.contact_add_dialog {
            if event::poll(Duration::from_millis(10))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Esc => {
                                // Cancel the dialog
                                self.contact_add_dialog = None;
                                return Ok(None);
                            }
                            KeyCode::Enter => {
                                // Process and add contact
                                let input = dialog.input.value().trim();
                                if (!input.is_empty()) {
                                    // Get the input before closing the dialog
                                    let input_str = input.to_string();
                                    
                                    // Close the dialog
                                    self.contact_add_dialog = None;
                                    
                                    // Process the input (add domain if needed)
                                    let contact_jid = self.process_jid_input(&input_str);
                                    
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
                    }
                }
            }
            return Ok(None);
        }

        // Handle help dialog if active
        if self.help_dialog.is_some() {
            if event::poll(Duration::from_millis(10))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        // Any key press will close the help dialog
                        self.help_dialog = None;
                    }
                }
            }
            return Ok(None);
        }

        // Handle device fingerprints dialog if active
        if self.device_fingerprints_dialog.is_some() {
            if event::poll(Duration::from_millis(10))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        // Any key press will close the device fingerprints dialog
                        self.device_fingerprints_dialog = None;
                    }
                }
            }
            return Ok(None);
        }

        // Original input handling code
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Esc => return Ok(Some((String::new(), String::new()))), // Signal to quit
                        KeyCode::Enter => {
                            if !self.input.value().is_empty() {   
                                let message_content = self.input.value().to_string();
                                let recipient_jid = self.contact.clone();
                                
                                // Clear input field immediately
                                self.input = Input::default();
                                
                                // When creating a new message:
                                let message = Message {
                                    id: Uuid::new_v4().to_string(), // unique ID
                                    content: message_content.clone(),
                                    sender_id: "me".to_string(),
                                    recipient_id: recipient_jid.clone(),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    delivery_status: DeliveryStatus::Sending,
                                };
                                
                                // Add the message to UI immediately
                                self.add_message(message);
                                
                                // Check if we're about to send an encrypted message
                                if self.omemo_enabled {
                                    info!("UI: Preparing encrypted message for {}", recipient_jid);
                                    // Instead of appending to the message content, add it as a separate flag
                                    info!("UI: Using __VERIFY_KEYS__ prefix in recipient field instead of content");
                                    return Ok(Some((format!("__VERIFY_KEYS__:{}", recipient_jid), message_content)));
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
                            
                            self.add_message(Message {
                                id: "system_encryption".to_string(),
                                content: status_msg.to_string(),
                                sender_id: "system".to_string(),
                                recipient_id: "me".to_string(), // Add the missing field
                                timestamp: chrono::Utc::now().timestamp() as u64,
                                delivery_status: DeliveryStatus::Unknown,
                            });
                        },
                        KeyCode::Char('t') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            // Toggle trust for the current contact's OMEMO keys
                            if self.has_active_contact() {
                                let current_contact = self.contact.clone();
                                
                                // Request a trust toggle operation from the main app
                                // We'll use a special message format that will be handled in main.rs
                                return Ok(Some((current_contact, String::from("__TOGGLE_OMEMO_TRUST__"))));
                            }
                        },
                        KeyCode::Char('a') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            // Show add contact dialog
                            // We'll use the base domain from the current credentials
                            // The server domain will be supplied by main.rs before showing the dialog
                            return Ok(Some((String::new(), String::from("__SHOW_ADD_CONTACT__"))));
                        },
                        KeyCode::Char('d') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            // Delete/remove the current contact
                            if self.has_active_contact() {
                                let current_contact = self.contact.clone();
                                
                                // Request contact removal from the main app
                                return Ok(Some((current_contact, String::from("__REMOVE_CONTACT__"))));
                            }
                        },
                        KeyCode::Char('h') | KeyCode::Char('H') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            // Show help dialog
                            self.show_help_dialog();
                            return Ok(None);
                        },
                        KeyCode::Char('f') | KeyCode::Char('F') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            return Ok(Some((String::new(), String::from("__SHOW_DEVICE_FINGERPRINTS__"))));
                        },
                        KeyCode::Char('m') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            return Ok(Some((String::new(), String::from("__ENABLE_CARBONS__"))));
                        },
                        KeyCode::Char('r') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                        },
                        // Add test shortcut for friend request notifications (Ctrl+N)
                        KeyCode::Char('n') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                            return Ok(Some((String::new(), String::from("__TEST_FRIEND_REQUEST__"))));
                        },
                        KeyCode::Up => {
                            if let Tab::Contacts = self.active_tab {
                                if !self.contacts.is_empty() {
                                    self.current_contact_index = 
                                        (self.current_contact_index + self.contacts.len() - 1) % self.contacts.len();
                                    let new_contact = self.contacts[self.current_contact_index].clone();
                                    let contact_changed = new_contact != self.contact;
                                    self.contact = new_contact;
                                    
                                    // Signal contact change for message history loading
                                    if contact_changed {
                                        return Ok(Some((self.contact.clone(), String::from("__CONTACT_CHANGED__"))));
                                    }
                                }
                            }
                        }
                        KeyCode::Down => {
                            if let Tab::Contacts = self.active_tab {
                                if !self.contacts.is_empty() {
                                    self.current_contact_index = (self.current_contact_index + 1) % self.contacts.len();
                                    let new_contact = self.contacts[self.current_contact_index].clone();
                                    let contact_changed = new_contact != self.contact;
                                    self.contact = new_contact;
                                    
                                    // Signal contact change for message history loading
                                    if contact_changed {
                                        return Ok(Some((self.contact.clone(), String::from("__CONTACT_CHANGED__"))));
                                    }
                                }
                            }
                        }
                        _ => {
                            if let Tab::Messages = self.active_tab {
                                self.input.handle_event(&Event::Key(key));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn draw<B: Backend>(&self, frame: &mut Frame<B>) {
        let size = frame.size();

        // Create a layout with 3 horizontal sections
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(20),  // Contacts panel
                Constraint::Percentage(80),  // Chat panel
            ])
            .split(size);

        // Split the right section for messages, input, and help
        let chat_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),          // Messages area
                Constraint::Length(3),       // Input box
                Constraint::Length(1),       // Help line
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
                ListItem::new(content)
            })
            .collect();

        let contacts_list = List::new(contacts)
            .block(Block::default()
                .title("Contacts (Tab to focus)")
                .borders(Borders::ALL)
                .border_style(match self.active_tab {
                    Tab::Contacts => Style::default().fg(Color::Yellow),
                    _ => Style::default(),
                }));
        frame.render_widget(contacts_list, chunks[0]);

        // Draw messages
        draw_messages(frame, &self.messages, chat_chunks[0], self);

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
        let omemo_status_text = if self.omemo_enabled { "enabled" } else { "disabled" };
        let omemo_status_style = if self.omemo_enabled {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };

        let help_spans = vec![
            Span::styled("ESC quit | TAB switch | Ctrl+A add | Ctrl+D del | Ctrl+O toggle OMEMO [", Style::default().fg(Color::Gray)),
            Span::styled(omemo_status_text, omemo_status_style),
            Span::styled("] | Ctrl+T trust | Ctrl+H help", Style::default().fg(Color::Gray)),
        ];
        
        let help = Paragraph::new(Line::from(help_spans));
        frame.render_widget(help, chat_chunks[2]);

        // Set cursor position
        if let Tab::Messages = self.active_tab {
            frame.set_cursor(
                // Put cursor past the end of the input text
                chat_chunks[1].x + self.input.cursor() as u16 + 1,
                // Put cursor at the start of the input line
                chat_chunks[1].y + 1,
            );
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
            info!("UI: Friend request notification is active for contact: {}", notification.contact);
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
    }

    pub fn update_contact_status(&mut self, contact_id: &str, status: ContactStatus) {
        // Store status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.contact_status.insert(base_jid, status);
    }
    
    pub fn get_contact_status(&self, contact_id: &str) -> ContactStatus {
        // Get status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.contact_status.get(&base_jid)
            .cloned()
            .unwrap_or(ContactStatus::Offline)
    }
    
    // New methods for typing indicators
    pub fn update_typing_status(&mut self, contact_id: &str, status: TypingStatus) {
        // Store typing status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.typing_states.insert(
            base_jid, 
            (status, chrono::Utc::now())
        );
    }
    
    pub fn get_typing_status(&self, contact_id: &str) -> Option<TypingStatus> {
        // Get typing status using the base JID
        let base_jid = Self::get_base_jid(contact_id);
        self.typing_states.get(&base_jid).map(|(status, _)| status.clone())
    }
    
    // Check and clear typing states older than the timeout duration
    pub fn clean_typing_states(&mut self, timeout_secs: i64) {
        let now = chrono::Utc::now();
        let mut to_remove = Vec::new();
        
        for (jid, (status, timestamp)) in &self.typing_states {
            // Only auto-expire Composing and Paused states
            if (*status == TypingStatus::Composing || *status == TypingStatus::Paused) 
                && (now - *timestamp).num_seconds() > timeout_secs {
                to_remove.push(jid.clone());
            }
        }
        
        for jid in to_remove {
            self.typing_states.remove(&jid);
        }
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
    pub fn clean_friend_request_notifications(&mut self, timeout_secs: i64) {
        if let Some(notification) = &self.friend_request_notification {
            let now = chrono::Utc::now();
            if (now - notification.timestamp).num_seconds() > timeout_secs {
                debug!("UI: Auto-dismissing friend request notification for {}", notification.contact);
                self.friend_request_notification = None;
            }
        } else {
            // Auto-dismissal isn't happening because there's no active notification
            // This is expected most of the time, so we'll use a trace level log
            // debug!("UI: No friend request notification to clean");
        }
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
        self.add_message(Message {
            id: Uuid::new_v4().to_string(),
            content: "TEST: Friend request notification triggered manually".to_string(),
            sender_id: "system".to_string(),
            recipient_id: "me".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Unknown,
        });
    }
}

fn draw_messages<B: Backend>(f: &mut Frame<B>, messages: &[Message], area: Rect, ui: &ChatUI) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),       // Messages
            Constraint::Length(1),    // Typing indicator
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

            // Add the padlock symbol to outgoing messages when OMEMO is enabled
            let prefix = if m.sender_id == "me" || m.sender_id.contains("@") && m.recipient_id != "me" {
                // Add padlock 🔒 for encrypted messages
                let encryption_indicator = if ui.is_omemo_enabled() { " 🔒" } else { "" };
                format!("[{}] You{}: ", timestamp, encryption_indicator)
            } else if m.sender_id == "system" {
                format!("[{}] System: ", timestamp)
            } else {
                format!("[{}] {}: ", timestamp, m.sender_id)
            };

            // Simplified status indicator using ticks clearly
            let status_indicator = if m.sender_id == "me" || m.sender_id.contains("@") && m.recipient_id != "me" {
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

            // Use textwrap to wrap the content, collecting into owned Strings
            let wrapped_lines: Vec<String> = wrap(&full_content, wrap_width)
                .into_iter()
                .map(|l| l.into_owned())
                .collect();

            let style = if m.sender_id == "system" {
                Style::default().fg(Color::Gray)
            } else if m.sender_id == "me" {
                match m.delivery_status {
                    DeliveryStatus::Failed => Style::default().fg(Color::Red),
                    DeliveryStatus::Delivered | DeliveryStatus::Read => Style::default().fg(Color::Green),
                    DeliveryStatus::Sent | DeliveryStatus::Sending => Style::default().fg(Color::Blue),
                    DeliveryStatus::Stored => Style::default().fg(Color::Yellow),
                    _ => Style::default(),
                }
            } else {
                Style::default()
            };

            wrapped_lines.into_iter().map(move |line| {
                ListItem::new(Text::from(line)).style(style)
            })
        })
        .collect();

    // Add connection status icon to the title
    let connection_icon = if ui.is_connected() { "🔌 " } else { "❌ " }; 
    let title = format!("{}Messages", connection_icon);
    
    // Create a ListState to control the scroll position
    let mut list_state = ListState::default();
    
    // Set the selected item to the last message to ensure auto-scrolling
    // This doesn't highlight the item (we disable highlighting below)
    if !messages_with_status.is_empty() {
        list_state.select(Some(messages_with_status.len() - 1));
    }
    
    let messages_list = List::new(messages_with_status)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default()); // Use default style to make selection invisible
        
    // Render the widget with state to allow scrolling to the selected (last) message
    f.render_stateful_widget(messages_list, chunks[0], &mut list_state);
}

fn draw_key_confirmation<B: Backend>(f: &mut Frame<B>, key_conf: &KeyConfirmation, area: Rect) {
    // Calculate popup size and position (centered)
    let popup_width = 60.min(area.width - 4);
    let popup_height = 10.min(area.height - 4);
    
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);
    
    // Create popup with border
    let popup_block = Block::default()
        .title("Unrecognized OMEMO Key")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    
    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);
    
    // Create inner area for content
    let inner_area = popup_area.inner(&Margin {
        vertical: 1,
        horizontal: 2,
    });
    
    // Format the content
    let device_info = key_conf.device_id.as_ref()
        .map_or(String::new(), |id| format!(" (Device ID: {})", id));
    
    let content = vec![
        format!("Contact: {}{}", key_conf.contact, device_info),
        "".to_string(),
        format!("Key fingerprint: {}", key_conf.fingerprint),
        "".to_string(),
        "Do you want to accept this key?".to_string(),
        "Press [Y] to accept or [N] to reject".to_string(),
    ];
    
    // Display content as a list
    let content_list = List::new(
        content.iter().map(|s| ListItem::new(s.as_str())).collect::<Vec<_>>()
    )
    .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(content_list, inner_area);
}

fn draw_add_contact_dialog<B: Backend>(f: &mut Frame<B>, dialog: &ContactAddDialog, area: Rect) {
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
    let inner_area = popup_area.inner(&Margin {
        vertical: 1,
        horizontal: 2,
    });
    
    // Split inner area for content and input field
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // Instructions
            Constraint::Length(3),  // Input field
        ])
        .split(inner_area);
    
    // Display instructions
    let instructions = vec![
        "Enter username or full JID (username@domain) of the contact:".to_string(),
        format!("Server: {} (will be used if only username is entered)", dialog.server_domain),
    ];
    
    let instructions_list = List::new(
        instructions.iter().map(|s| ListItem::new(s.as_str())).collect::<Vec<_>>()
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
    f.set_cursor(
        chunks[1].x + dialog.input.cursor() as u16 + 1,
        chunks[1].y + 1,
    );
}

fn draw_contact_remove_dialog<B: Backend>(f: &mut Frame<B>, dialog: &ContactRemoveDialog, area: Rect) {
    // Calculate popup size and position (centered)
    let popup_width = 60.min(area.width - 4);  // Increased from 50 to 60
    let popup_height = 8.min(area.height - 4);  // Increased from 6 to 8
    
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
    let inner_area = popup_area.inner(&Margin {
        vertical: 1,
        horizontal: 2,
    });
    
    // Prepare the content
    let content = vec![
        format!("Are you sure you want to remove contact '{}'?", dialog.contact),
        "".to_string(),
        "This will remove the contact from your roster.".to_string(),
        "This action cannot be undone.".to_string(), // Added extra explanation line
        "".to_string(),
        "Press [Y] to confirm or [N]/[ESC] to cancel".to_string(),
    ];
    
    // Display content as a list
    let content_list = List::new(
        content.iter().map(|s| ListItem::new(s.as_str())).collect::<Vec<_>>()
    )
    .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(content_list, inner_area);
}

fn draw_help_dialog<B: Backend>(f: &mut Frame<B>, area: Rect) {
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
    let inner_area = popup_area.inner(&Margin {
        vertical: 1,
        horizontal: 2,
    });
    
    // Create the shortcuts list
    let shortcuts = vec![
        ("General", ""),
        ("ESC", "Quit application"),
        ("Tab", "Switch between Messages and Contacts"),
        ("", ""),
        ("Contacts Navigation", ""),
        ("↑/↓", "Navigate through contacts (when Contacts tab is active)"),
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
        ("Ctrl+M", "Enable Message Carbons protocol (sync messages between devices)"),
        ("Ctrl+F", "Show device fingerprints dialog"),
        ("Ctrl+R", "Force OMEMO device list re-fetch for active contact"),
        ("", ""),
        ("Debug", ""),
        ("Ctrl+N", "Test friend request notification popup (for debugging)"),
        ("", ""),
        ("Help", ""),
        ("Ctrl+H", "Show this help dialog"),
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
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
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

fn draw_device_fingerprints_dialog<B: Backend>(f: &mut Frame<B>, dialog: &DeviceFingerprintsDialog, area: Rect) {
    // Calculate popup size and position (centered)
    let popup_width = 70.min(area.width - 4);
    let popup_height = 20.min(area.height - 4);
    
    let popup_x = (area.width - popup_width) / 2;
    let popup_y = (area.height - popup_height) / 2;
    
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);
    
    // Create popup with border
    let popup_block = Block::default()
        .title("Device Fingerprints")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    
    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);
    
    // Create inner area for content
    let inner_area = popup_area.inner(&Margin {
        vertical: 1,
        horizontal: 2,
    });
    
    // Create the fingerprints list
    let mut fingerprints_content = Vec::new();
    
    // Add header
    fingerprints_content.push("Your OMEMO device fingerprints:".to_string());
    fingerprints_content.push("".to_string());
    
    if dialog.fingerprints.is_empty() {
        fingerprints_content.push("No devices found with OMEMO keys".to_string());
    } else {
        for (device_id, fingerprint) in &dialog.fingerprints {
            let is_current = dialog.current_device_id.as_ref().map_or(false, |id| id == device_id);
            let device_label = if is_current {
                format!("Device ID: {} (this device)", device_id)
            } else {
                format!("Device ID: {}", device_id)
            };
            fingerprints_content.push(device_label);
            fingerprints_content.push(format!("Fingerprint: {}", fingerprint));
            fingerprints_content.push("".to_string());
        }
    }
    
    fingerprints_content.push("".to_string());
    fingerprints_content.push("Press any key to close this dialog".to_string());
    
    // Convert content to ListItems
    let items: Vec<ListItem> = fingerprints_content
        .iter()
        .map(|s| {
            if s.contains("(this device)") {
                ListItem::new(Text::styled(
                    s.clone(),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
                ))
            } else if s.starts_with("Device ID:") {
                ListItem::new(Text::styled(
                    s.clone(),
                    Style::default().fg(Color::Yellow)
                ))
            } else if s.starts_with("Fingerprint:") {
                ListItem::new(Text::styled(
                    s.clone(),
                    Style::default().fg(Color::Green)
                ))
            } else if s.starts_with("Your OMEMO") {
                ListItem::new(Text::styled(
                    s.clone(), 
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                ))
            } else {
                ListItem::new(s.as_str())
            }
        })
        .collect();
    
    // Display the fingerprints list
    let fingerprints_list = List::new(items);
    f.render_widget(fingerprints_list, inner_area);
}

fn draw_friend_request_notification<B: Backend>(f: &mut Frame<B>, notification: &FriendRequestNotification, area: Rect) {
    // Calculate popup size and position (top-right corner)
    let popup_width = 40.min(area.width - 4);
    let popup_height = 5.min(area.height - 4);
    
    // Position in top-right corner with some margin
    let popup_x = area.width - popup_width - 2;
    let popup_y = 2;
    
    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);
    
    // Log when rendering (this will help debug if the popup is being drawn)
    log::info!("UI: Drawing friend request notification popup for contact: {}", notification.contact);
    
    // Create popup with border
    let popup_block = Block::default()
        .title("Friend Request Accepted")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));
    
    f.render_widget(Clear, popup_area); // Clear the area first
    f.render_widget(popup_block, popup_area);
    
    // Create inner area for content
    let inner_area = popup_area.inner(&Margin {
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
        content.iter().map(|s| ListItem::new(s.as_str())).collect::<Vec<_>>()
    )
    .style(Style::default().fg(Color::Green));
    
    f.render_widget(content_list, inner_area);
}

pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn restore_terminal(mut terminal: Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}