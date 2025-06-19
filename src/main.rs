#![deny(dead_code)] // DO NOT REMOVE THIS EVER
use anyhow::Result;
use log::{info, error, warn, debug, LevelFilter};
use std::{env, io};
use clap::Parser;
use std::path::PathBuf;

mod ui;
mod utils;
mod credentials;


use crate::{
    ui::ChatUI,
    credentials::{Credentials, load_credentials, save_credentials},
};
// Import the XMPP client and types from our new module structure
use chatterbox::{xmpp::{XMPPClient, chat_states::TypingStatus}, models::{Message, DeliveryStatus}};
use chatterbox::xmpp::message_archive::MAMQueryOptions;
// Import ServiceDiscovery for XEP-0030
use chatterbox::xmpp::discovery::ServiceDiscovery;

/// Command line arguments for Sermo
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Sermo: A CLI XMPP chat client with OMEMO encryption.",
    long_about = "Sermo is a command-line chat client for XMPP with OMEMO encryption support.\n\n\
    Optional parameters:\n\
    --omemo-dir <PATH>     Override the directory for OMEMO device_id, identity_key, and multi-device info files\n\
    Use -h or --help to see all options."
)]
struct Args {
    /// Directory for OMEMO device_id, identity_key, and multi-device info files
    #[arg(long, value_name = "PATH", help = "Override the directory for OMEMO device_id, identity_key, and multi-device info files")]
    omemo_dir: Option<PathBuf>,
}

/// Prompts the user for login credentials or uses environment variables
fn prompt_credentials() -> (String, String, String) {
    let server = env::var("XMPP_SERVER").unwrap_or_else(|_| {
        eprintln!("Enter XMPP server domain (e.g., example.com):");
        utils::read_line().unwrap_or_default().trim().to_string()
    });

    let username = env::var("XMPP_USERNAME").unwrap_or_else(|_| {
        eprintln!("Enter username (without domain part if using XMPP_SERVER):");
        utils::read_line().unwrap_or_default().trim().to_string()
    });

    let password = env::var("XMPP_PASSWORD").unwrap_or_else(|_| {
        eprintln!("Enter password (input will not be shown):");
        utils::read_line().unwrap_or_default()
    });
    
    (server, username, password)
}

/// Creates a system message for display in the UI
fn create_system_message(to: &str, content: &str) -> Message {
    Message {
        id: uuid::Uuid::new_v4().to_string(),
        sender_id: "system".to_string(),
        recipient_id: to.to_string(),
        content: content.to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        delivery_status: DeliveryStatus::Delivered,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments FIRST
    let args = Args::parse();

    // Determine the log file path based on --omemo-dir
    let log_file_path = match &args.omemo_dir {
        Some(dir) => {
            // Ensure the directory exists, create it if not
            if !dir.exists() {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    // Log an error but continue, logging might still work to stdout/stderr
                    eprintln!("Warning: Failed to create OMEMO directory {}: {}. Log file might not be created.", dir.display(), e);
                    // Fallback to default filename
                    PathBuf::from("chatterbox.log")
                } else {
                    dir.join("chatterbox.log")
                }
            } else {
                dir.join("chatterbox.log")
            }
        }
        None => PathBuf::from("chatterbox.log"), // Default path
    };

    // Setup logging with the determined path
    // Convert PathBuf to Option<&str> for setup_logging
    utils::setup_logging(log_file_path.to_str(), LevelFilter::Debug)?;
    
    info!("Sermo XMPP Chat client starting up");
    info!("System information: {} {}", std::env::consts::OS, std::env::consts::ARCH);
    // Add log message indicating where the log file is being written
    info!("Logging to file: {}", log_file_path.display());

    // Patch: Override OMEMO secrets directory if provided
    // This needs to happen AFTER logging setup but before client initialization
    if let Some(ref omemo_dir) = args.omemo_dir {
        // Ensure the override function can handle the directory possibly being created above
        chatterbox::omemo::device_id::set_omemo_dir_override(omemo_dir.clone());
        info!("OMEMO directory overridden to: {}", omemo_dir.display());
    }

    // Before connecting, print the username and server for debugging
    let username = std::env::var("XMPP_USERNAME").unwrap_or_else(|_| "".to_string());
    let server = std::env::var("XMPP_SERVER").unwrap_or_else(|_| "".to_string());
    //debug!("[DEBUG] About to connect with username: '{}' and server: '{}'", username, server);
    println!("Connecting to XMPP server at {}... please wait...\n", server);

    // Get credentials: prefer environment variables, then file, then prompt
    let (server, username, password, credentials_from_env) = if let (Ok(server), Ok(username), Ok(password)) = (
        env::var("XMPP_SERVER"),
        env::var("XMPP_USERNAME"),
        env::var("XMPP_PASSWORD")
    ) {
        (server, username, password, true)
    } else if let Some(creds) = load_credentials()? {
        info!("Using cached credentials for {}", creds.username);
        if let Some(password) = creds.get_password() {
            (creds.server, creds.username, password, false)
        } else {
            eprintln!("Enter password for {}@{}:", creds.username, creds.server);
            let password = utils::read_line().unwrap_or_default();
            (creds.server, creds.username, password, false)
        }
    } else {
        let (server, username, password) = prompt_credentials();
        (server, username, password, false)
    };

    // Set up the XMPP client
    let (mut xmpp_client, mut msg_rx) = XMPPClient::new();

    // Set OMEMO JID for user-specific storage before OMEMO initialization
    let bare_jid = username.split('/').next().unwrap_or(&username);
    chatterbox::omemo::device_id::set_omemo_jid(bare_jid);

    match xmpp_client.connect(&server, &username, &password).await {
        Ok(_) => {
            // Save credentials on successful connection, but only if not from env vars
            if (!credentials_from_env) {
                let credentials = Credentials::new(&server, &username, &password);
                if let Err(e) = save_credentials(&credentials) {
                    eprintln!("Warning: Failed to save credentials: {}", e);
                }
            }
            
            // Initialize OMEMO encryption right after connecting 
            // This ensures all components that need OMEMO will have it available
            info!("Initializing OMEMO encryption...");
            match xmpp_client.initialize_client().await {
                Ok(_) => info!("OMEMO encryption initialized successfully"),
                Err(e) => panic!("Failed to initialize OMEMO encryption: {}, some messages may not be decrypted", e)
            }
            
            // Register the client in the global registry for OMEMO integration
            chatterbox::xmpp::register_global_client(xmpp_client.clone());

            // Initialize Service Discovery (XEP-0030)
            if let Some(client_ref) = xmpp_client.get_client_arc() {
                let service_discovery = ServiceDiscovery::new(client_ref);
                if let Err(e) = service_discovery.advertise_features().await {
                    warn!("Failed to advertise service discovery features: {}", e);
                }
            }

        },
        Err(e) => {
            // Get detailed error information - break it into multiple lines for better readability
            let error_details = format!("Connection to XMPP server failed: {}", e);
            let error_display = format!(
                "Failed to connect to {}@{}\n\
                 Details: {}\n\
                 Please check:\n\
                 - Network connectivity\n\
                 - Server address is correct\n\
                 - Username and password are correct\n\
                 - Server is running and accepting connections",
                username, server, error_details
            );
            
            // Log the error
            error!("{}", error_details);
            
            // Display error to user
            eprintln!("{}", error_display);
            
            return Err(anyhow::anyhow!(error_details));
        }
    }

    // Setup terminal UI
    let mut terminal = ui::setup_terminal()?;
    let mut chat_ui = ChatUI::new();
    
    // Draw UI early
    terminal.draw(|f| chat_ui.draw(f))?;

    // IMPORTANT: Add a small delay here to allow OMEMO initialization to complete fully
    // This ensures that when we request contacts, the OMEMO device list publication has finished
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    info!("Waiting for OMEMO initialization to complete...");
    
    // Set up the contact list (but don't wait for message history)
    setup_contacts(&mut chat_ui, &mut xmpp_client).await;
    
    // --- Show OMEMO fingerprints for each contact as system messages ---
    if xmpp_client.is_omemo_enabled().await {
        let contacts = chat_ui.contacts.clone();
        for contact in contacts {
            // Skip system/placeholder contacts
            if contact.starts_with('[') && contact.ends_with(']') {
                continue;
            }
            let bare_jid = contact.split('/').next().unwrap_or(contact.as_str());
            // Always refresh the device list from the server before showing fingerprints
            match xmpp_client.force_refresh_device_list(bare_jid).await {
                Ok(device_ids) if !device_ids.is_empty() => {
                    for device_id in device_ids {
                        match xmpp_client.get_device_fingerprint(bare_jid, device_id).await {
                            Ok(fingerprint) => {
                                let msg = create_system_message(
                                    &contact,
                                    &format!(
                                        "OMEMO device {} of {} has fingerprint: {}",
                                        device_id, bare_jid, fingerprint
                                    ),
                                );
                                chat_ui.add_message(msg);
                            },
                            Err(e) => {
                                let msg = create_system_message(
                                    &contact,
                                    &format!(
                                        "Could not retrieve fingerprint for OMEMO device {}: {}",
                                        device_id, e
                                    ),
                                );
                                chat_ui.add_message(msg);
                            }
                        }
                    }
                },
                Ok(_) => {
                    let msg = create_system_message(
                        &contact,
                        "No OMEMO devices found for this contact."
                    );
                    chat_ui.add_message(msg);
                },
                Err(e) => {
                    let msg = create_system_message(
                        &contact,
                        &format!("Could not retrieve OMEMO device list: {}", e)
                    );
                    chat_ui.add_message(msg);
                }
            }
        }
    }
    // --- End OMEMO device fingerprint system messages ---

    // Draw UI again with contact list and fingerprints
    terminal.draw(|f| chat_ui.draw(f))?;
    
    // Start message history loading in background if we have an active contact
    if chat_ui.has_active_contact() {
        // We need to find the active contact name from the contacts list
        // since chat_ui.contact is private
        if !chat_ui.contacts.is_empty() {
            // Get the first contact for now (or the one at current_contact_index if we had access to it)
            let active_contact = chat_ui.contacts[0].clone();
            
            // Add a "loading" message to the UI
            chat_ui.add_message(create_system_message(
                &active_contact,
                "Loading message history in background..."
            ));
            
            // Redraw UI with loading message
            terminal.draw(|f| chat_ui.draw(f))?;
            
            // Create a separate client for background loading
            let xmpp_client_clone = xmpp_client.clone();
            
            // Create a channel for message history results
            let (history_tx, mut history_rx) = tokio::sync::mpsc::channel(100);
            
            // Create a message sender for system messages
            let msg_tx_clone = xmpp_client.get_message_sender();
            let active_contact_clone = active_contact.clone();
            
            // Spawn a background task to load message history
            tokio::spawn(async move {
                // Load the message history in background
                match xmpp_client_clone.get_message_history(
                    MAMQueryOptions::new()
                        .with_jid(&active_contact)
                        .with_limit(50)
                ).await {
                    Ok(messages) => {
                        info!("Loaded {} historical messages for {}", messages.len(), active_contact);
                        
                        // Send completion system message
                        let completion_message = if messages.is_empty() {
                            create_system_message(&active_contact_clone, "No message history found")
                        } else {
                            create_system_message(&active_contact_clone, &format!("Loaded {} historical messages", messages.len()))
                        };
                        
                        // Send the completion message to the main message channel
                        if let Err(e) = msg_tx_clone.send(completion_message).await {
                            error!("Failed to send history completion message: {}", e);
                        }
                        
                        // Send messages to the history channel
                        for message in messages {
                            if let Err(e) = history_tx.send(message).await {
                                error!("Failed to send history message to channel: {}", e);
                                break;
                            }
                        }
                    },
                    Err(e) => {
                        error!("Failed to retrieve message history for {}: {}", active_contact, e);
                        
                        // Send error system message
                        let error_message = create_system_message(
                            &active_contact_clone,
                            &format!("Failed to load message history: {}", e)
                        );
                        
                        // Send the error message to the main message channel
                        if let Err(send_err) = msg_tx_clone.send(error_message).await {
                            error!("Failed to send history error message: {}", send_err);
                        }
                    }
                }
            });
            
            // Get a clone of the main message channel
            let msg_tx = xmpp_client.get_message_sender();
            
            // Merge the history channel into the main message channel
            tokio::spawn(async move {
                while let Some(message) = history_rx.recv().await {
                    if let Err(e) = msg_tx.send(message).await {
                        error!("Failed to forward history message to main channel: {}", e);
                    }
                }
            });
        }
    }

    // Check for pending OMEMO key verifications
    check_pending_key_verifications(&mut chat_ui, &xmpp_client).await?;

    // Main event loop
    run_main_loop(&mut chat_ui, &mut terminal, &mut xmpp_client, &mut msg_rx).await?;

    // Restore terminal
    ui::restore_terminal(terminal)?;
    
    println!("Chat session ended.");
    Ok(())
}

/// Set up the contacts list from the XMPP server
async fn setup_contacts(chat_ui: &mut ChatUI, xmpp_client: &mut XMPPClient) {
    // Try to fetch the roster (contact list) from the XMPP server
    match xmpp_client.get_roster().await {
        Ok(Some(contacts)) if !contacts.is_empty() => {
            // Add all contacts to the UI
            for contact in contacts {
                chat_ui.add_contact(&contact);
            }
            
            // Set first contact as active
            if !chat_ui.contacts.is_empty() {
                let first_contact = chat_ui.contacts[0].clone();
                chat_ui.set_active_contact(&first_contact);
            }
        },
        Ok(_) => {
            // No roster found or empty roster
            chat_ui.add_contact("[No contacts found]");
            chat_ui.add_message(create_system_message(
                "me",
                "No contacts found in your roster. You can still chat by entering a complete JID (e.g. user@domain.com)"
            ));
        },
        Err(e) => {
            // Error fetching roster
            error!("Error fetching roster: {}", e);
            chat_ui.add_contact("[Error loading contacts]");
            
            // Add a system message explaining the issue
            chat_ui.add_message(create_system_message(
                "me", 
                &format!("Failed to load contacts: {}. You can still chat with contacts by entering their full JID.", e)
            ));
        }
    }
    
    // Ensure we have a selected contact
    if !chat_ui.has_active_contact() && !chat_ui.contacts.is_empty() {
        let first_contact = chat_ui.contacts[0].clone();
        chat_ui.set_active_contact(&first_contact);
    }
}


/// Loads message history for a contact in the background without blocking the UI
/// Returns immediately while history loads asynchronously
fn load_message_history_async(chat_ui: &mut ChatUI, xmpp_client: &XMPPClient, contact: &str) {
    // Skip loading history for system contacts
    if contact.starts_with("[") && contact.ends_with("]") {
        return;
    }
    
    // Add a system message to show that we're checking history
    chat_ui.add_message(create_system_message(
        contact,
        "Checking for message history in background..."
    ));
    
    // Clone what we need for the background task
    let client_clone = xmpp_client.clone();
    let contact_clone = contact.to_string();
    let msg_tx = xmpp_client.get_message_sender();
    
    // Spawn a background task to check and load history
    tokio::spawn(async move {
        // First do a quick check to see if any history exists at all
        let has_history = match client_clone.has_message_history(&contact_clone, 1).await {
            Ok(exists) => {
                if (!exists) {
                    // No history exists
                    if let Err(e) = msg_tx.send(create_system_message(
                        &contact_clone,
                        "No message history found"
                    )).await {
                        error!("Failed to send 'no history' message: {}", e);
                    }
                    return; // Exit early if no history
                }
                true
            },
            Err(e) => {
                // Error checking history, but we'll still try to fetch
                error!("Failed to check for message history: {}", e);
                if let Err(send_err) = msg_tx.send(create_system_message(
                    &contact_clone,
                    &format!("History check failed: {}. Attempting full retrieval...", e)
                )).await {
                    error!("Failed to send history check error message: {}", send_err);
                }
                false // Continue with full retrieval despite error
            }
        };
        
        // If we have history, send an update message
        if (has_history) {
            if let Err(e) = msg_tx.send(create_system_message(
                &contact_clone,
                "Fetching message history..."
            )).await {
                error!("Failed to send history fetching message: {}", e);
            }
        }
        
        // Create query options
        let options = MAMQueryOptions::new()
            .with_jid(&contact_clone)
            .with_limit(50); // Fetch last 50 messages
        
        // Fetch message history with pagination info
        match client_clone.get_message_history_with_pagination(options).await {
            Ok(result) => {
                if (result.messages.is_empty()) {
                    // No history found
                    if let Err(e) = msg_tx.send(create_system_message(
                        &contact_clone,
                        "No message history found"
                    )).await {
                        error!("Failed to send 'no history' message: {}", e);
                    }
                } else {
                    // Add a system message with the count
                    if let Err(e) = msg_tx.send(create_system_message(
                        &contact_clone,
                        &format!("Loaded {} historical messages", result.messages.len())
                    )).await {
                        error!("Failed to send history success message: {}", e);
                    }
                    
                    // Add the messages to the UI
                    for message in &result.messages {
                        if let Err(e) = msg_tx.send(message.clone()).await {
                            error!("Failed to send historical message to UI: {}", e);
                            break;
                        }
                    }
                    
                    // If the query was not complete and we have a pagination token,
                    // continue loading history in the background
                    if (!result.complete && result.rsm_last.is_some()) {
                        // Create a short delay before starting the background loading to give UI time to render
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        
                        // Start background loading
                        if let Err(e) = client_clone.load_complete_message_history_in_background(
                            &contact_clone,
                            result,
                            msg_tx.clone(),
                            10 // Maximum 10 pages to avoid excessive loading
                        ).await {
                            error!("Error in background history loading: {}", e);
                        }
                    }
                }
            },
            Err(e) => {
                error!("Failed to retrieve message history for {}: {}", contact_clone, e);
                if let Err(send_err) = msg_tx.send(create_system_message(
                    &contact_clone,
                    &format!("Failed to load message history: {}", e)
                )).await {
                    error!("Failed to send history error message: {}", send_err);
                }
            }
        }
    });
}

/// Run the main event loop
async fn run_main_loop(
    chat_ui: &mut ChatUI,
    terminal: &mut ui::Terminal<ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    msg_rx: &mut tokio::sync::mpsc::Receiver<Message>
) -> Result<()> {
    // Subscribe to presence notifications
    let mut presence_rx = xmpp_client.subscribe_to_presence();
    
    // Subscribe to friend request notifications
    let mut friend_req_rx = xmpp_client.subscribe_to_friend_requests();
    
    // Create a channel for receiving typing notifications
    let (typing_tx, mut typing_rx) = tokio::sync::mpsc::channel::<(String, TypingStatus)>(100);
    
    // Save the typing channel globally for the XMPP client message handler
    if let Some(typing_tx_storage) = chatterbox::xmpp::TYPING_TX.lock().unwrap().as_mut() {
        *typing_tx_storage = typing_tx;
    }
    
    // Initialize connection status in UI to the current state
    chat_ui.set_connection_status(xmpp_client.is_client_accessible());
    
    // Variables to track user typing state
    let mut last_key_press = std::time::Instant::now();
    let mut last_state_sent = None::<TypingStatus>;
    
    // Track which contacts we've already checked OMEMO keys for
    let mut verified_contacts = std::collections::HashSet::new();
    
    // Track time for connection status check
    let mut last_connection_check = std::time::Instant::now();
    
    // Add these variables for safe typing state tracking
    let mut typing_failures: u32 = 0;
    let mut last_typing_check: Option<std::time::Instant> = None;
    
    loop {
        // Draw the UI
        terminal.draw(|f| chat_ui.draw(f))?;
        
        // Clean old typing states
        chat_ui.clean_typing_states(30); // Clear typing states older than 30 seconds
        
        // Clean friend request notifications
        chat_ui.clean_friend_request_notifications(5); // Clear friend request notifications after 5 seconds

        // Handle user input
        let input_result = chat_ui.handle_input()?;
        
        // Check if we need to verify OMEMO keys for the active contact
        if chat_ui.has_active_contact() && chat_ui.is_omemo_enabled() {
            let active_contact = chat_ui.get_active_contact();
            
            // Only check if we haven't already verified this contact
            if !verified_contacts.contains(&active_contact) {
                // Add to verified set so we don't check again
                verified_contacts.insert(active_contact.clone());
                
                // Check OMEMO keys in the background to avoid blocking the UI
                let client_clone = xmpp_client.clone();
                let contact_clone = active_contact.clone();
                
                tokio::spawn(async move {
                    // Check OMEMO keys for this contact
                    if let Err(e) = client_clone.check_omemo_keys_for_contact(&contact_clone).await {
                        error!("Failed to check OMEMO keys for {}: {}", contact_clone, e);
                    }
                });
            }
        }
        
        // Check for new messages from the XMPP client
        if let Ok(message) = msg_rx.try_recv() {
            // Check for OMEMO key confirmation requests
            if message.sender_id == "system" && message.content.starts_with("__OMEMO_KEY_VERIFY__:") {
                // Format: __OMEMO_KEY_VERIFY__:contact:fingerprint:device_id
                let parts: Vec<&str> = message.content.splitn(4, ':').collect();
                if parts.len() >= 3 {
                    let contact = parts[1];
                    let fingerprint = parts[2];
                    let device_id = if parts.len() > 3 { Some(parts[3]) } else { None };
                    
                    // Show key confirmation dialog
                    handle_new_omemo_key(
                        chat_ui, 
                        contact, 
                        fingerprint, 
                        device_id.as_deref()
                    );
                }
            } else {
                // Regular message
                chat_ui.add_message(message.clone());
                
                // If this is a message from a contact, reset their typing status
                if message.sender_id != "me" && message.sender_id != "system" {
                    chat_ui.message_received_from(&message.sender_id);
                }
                
                // If this is a new contact, add them to the contacts list
                if !chat_ui.contacts.contains(&message.sender_id) && message.sender_id != "me" && message.sender_id != "system" {
                    chat_ui.add_contact(&message.sender_id);
                }
            }
        }
        
        // Check for presence updates
        if let Ok((contact_id, status)) = presence_rx.try_recv() {
            // Update contact status in the UI
            chat_ui.update_contact_status(&contact_id, status);
        }
        
        // Check for friend request notifications
        if let Ok(contact_id) = friend_req_rx.try_recv() {
            // Show notification in the UI
            info!("Received auto-accepted friend request notification for {}", contact_id);
            chat_ui.show_friend_request_notification(&contact_id);
            
            // Add the contact to the contacts list (in case roster push hasn't happened yet)
            if !chat_ui.contacts.contains(&contact_id) {
                chat_ui.add_contact(&contact_id);
                info!("Added new contact {} to contacts list", contact_id);
            } else {
                info!("Contact {} was already in contacts list", contact_id);
            }
        }

        // Check for typing notifications
        if let Ok((contact_id, typing_status)) = typing_rx.try_recv() {
            // Update typing status in the UI
            chat_ui.update_typing_status(&contact_id, typing_status);
        }

        // Periodically check connection status (every 5 seconds)
        let now = std::time::Instant::now();
        if now.duration_since(last_connection_check) >= std::time::Duration::from_secs(5) {
            // Update connection status in UI
            let is_connected = xmpp_client.is_client_accessible();
            chat_ui.set_connection_status(is_connected);
            last_connection_check = now;
        }

        // If user is typing, send appropriate chat state notifications
        if input_result.is_none() && chat_ui.has_active_contact() {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(last_key_press);
            let contact = chat_ui.get_active_contact();
            
            // Use local state for typing failures and last typing check
            // Move these outside the loop if needed for persistence
            // For this patch, assume they are fields in the outer scope (not static mut)
            // e.g., let mut typing_failures: u32 = 0; let mut last_typing_check: Option<std::time::Instant> = None;
            // Here, we use variables assumed to be available in the async context
            // (If not, user should move them to the appropriate struct)
            
            // Only check and send typing status periodically (every 1 second)
            let should_check_typing = if let Some(last_check) = last_typing_check {
                if now.duration_since(last_check) >= std::time::Duration::from_secs(1) {
                    last_typing_check = Some(now);
                    true
                } else {
                    false
                }
            } else {
                last_typing_check = Some(now);
                true
            };
            
            // Only attempt to send typing notifications if we haven't had too many failures
            let should_send_typing = typing_failures < 3;
            
            if should_check_typing && should_send_typing {
                // Check if the user is currently typing
                if elapsed < std::time::Duration::from_secs(5) {
                    // User has typed within the last 5 seconds
                    
                    // If we haven't sent a composing state or it's been a while
                    if last_state_sent != Some(TypingStatus::Composing) || 
                       elapsed > std::time::Duration::from_secs(10) {
                        // Send composing state
                        match xmpp_client.send_chat_state(&contact, &TypingStatus::Composing).await {
                            Ok(_) => {
                                last_state_sent = Some(TypingStatus::Composing);
                                // Reset failure counter on success
                                typing_failures = 0;
                            },
                            Err(e) => {
                                error!("Failed to send typing indicator: {}", e);
                                // Increment failure counter
                                typing_failures += 1;
                            }
                        }
                    }
                } else if elapsed >= std::time::Duration::from_secs(5) && 
                          elapsed < std::time::Duration::from_secs(30) &&
                          last_state_sent != Some(TypingStatus::Paused) {
                    // User hasn't typed for 5-30 seconds, send paused state
                    match xmpp_client.send_chat_state(&contact, &TypingStatus::Paused).await {
                        Ok(_) => {
                            last_state_sent = Some(TypingStatus::Paused);
                            // Reset failure counter on success
                            typing_failures = 0;
                        },
                        Err(e) => {
                            error!("Failed to send paused typing indicator: {}", e);
                            // Increment failure counter
                            typing_failures += 1;
                        }
                    }
                } else if elapsed >= std::time::Duration::from_secs(30) && 
                          last_state_sent != Some(TypingStatus::Active) {
                    // User hasn't typed for 30+ seconds, send active state
                    match xmpp_client.send_chat_state(&contact, &TypingStatus::Active).await {
                        Ok(_) => {
                            last_state_sent = Some(TypingStatus::Active);
                            // Reset failure counter on success
                            typing_failures = 0;
                        },
                        Err(e) => {
                            error!("Failed to send active state: {}", e);
                            // Increment failure counter
                            typing_failures += 1;
                        }
                    }
                }
            }
        } else if input_result.is_some() {
            // User has interacted with the UI, update the timestamp
            last_key_press = std::time::Instant::now();
            // Reset typing failures when user does something
            typing_failures = 0;
        }

        match input_result {
            Some((recipient, content)) => {
                if content == "__SHOW_DEVICE_FINGERPRINTS__" {
                    // Handle showing device fingerprints dialog for the user's own devices
                    info!("MAIN: Received request to show device fingerprints dialog (own devices)");
                    chat_ui.reset_device_fingerprints_dialog();

                    // Always use our own bare JID
                    let my_jid = xmpp_client.get_jid();
                    let bare_jid = my_jid.split('/').next().unwrap_or(my_jid);
                    chat_ui.add_message(create_system_message(
                        "me",
                        &format!("Retrieving device fingerprints for your account ({}).", bare_jid)
                    ));
                    info!("MAIN: Using JID {} to fetch own device fingerprints", bare_jid);
                    terminal.draw(|f| chat_ui.draw(f))?;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        xmpp_client.get_device_ids_for_user(bare_jid)
                    ).await {
                        Ok(Ok(device_ids)) if !device_ids.is_empty() => {
                            chat_ui.remove_last_message();
                            let mut fingerprints = Vec::new();
                            for device_id in &device_ids {
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(3),
                                    xmpp_client.get_device_fingerprint(bare_jid, *device_id)
                                ).await {
                                    Ok(Ok(fingerprint)) => {
                                        fingerprints.push((device_id.to_string(), fingerprint));
                                    },
                                    Ok(Err(e)) => {
                                        fingerprints.push((device_id.to_string(), format!("Error: {}", e)));
                                    },
                                    Err(_) => {
                                        fingerprints.push((device_id.to_string(), "Error: Timeout retrieving fingerprint".to_string()));
                                    }
                                }
                            }
                            if fingerprints.is_empty() {
                                chat_ui.add_message(create_system_message(
                                    "me",
                                    "No device fingerprints could be retrieved."
                                ));
                            } else {
                                // Get the current device ID
                                let current_device_id = match xmpp_client.get_own_device_id().await {
                                    Ok(id) => Some(id.to_string()),
                                    Err(_) => None,
                                };
                                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    chat_ui.show_device_fingerprints_dialog(fingerprints.clone(), current_device_id);
                                })) {
                                    Ok(_) => {},
                                    Err(_) => {
                                        chat_ui.reset_device_fingerprints_dialog();
                                        chat_ui.add_message(create_system_message(
                                            "me",
                                            "Failed to display fingerprints in dialog. Showing as messages instead:"
                                        ));
                                        for (device_id, fingerprint) in fingerprints {
                                            chat_ui.add_message(create_system_message(
                                                "me",
                                                &format!("Device {}: {}", device_id, fingerprint)
                                            ));
                                        }
                                    }
                                }
                            }
                            if let Err(e) = terminal.draw(|f| chat_ui.draw(f)) {
                                chat_ui.reset_device_fingerprints_dialog();
                                chat_ui.add_message(create_system_message(
                                    "me",
                                    "Error displaying device fingerprints dialog"
                                ));
                            }
                        },
                        Ok(Ok(_)) => {
                            chat_ui.remove_last_message();
                            chat_ui.add_message(create_system_message(
                                "me",
                                "No OMEMO devices found for your account."
                            ));
                        },
                        Ok(Err(e)) => {
                            chat_ui.remove_last_message();
                            chat_ui.add_message(create_system_message(
                                "me",
                                &format!("Failed to retrieve device IDs: {}", e)
                            ));
                        },
                        Err(_) => {
                            chat_ui.remove_last_message();
                            chat_ui.add_message(create_system_message(
                                "me",
                                "Timed out while retrieving device IDs"
                            ));
                        }
                    }
                } else if recipient.starts_with("__VERIFY_KEYS__:") {
                    // Extract the actual recipient from the special format
                    let actual_recipient = recipient.trim_start_matches("__VERIFY_KEYS__:");
                    
                    // ... rest of verify keys handling code
                    info!("MAIN: Processing message with __VERIFY_KEYS__ prefix. Actual recipient: {}", actual_recipient);
                    
                    // Show sending status in the UI
                    chat_ui.add_message(create_system_message(actual_recipient, "Preparing secure message..."));
                    
                    // Reset typing state when sending a message
                    last_state_sent = None;
                    
                    // Send 'active' chat state to indicate we're no longer composing
                    if let Err(e) = xmpp_client.send_chat_state(actual_recipient, &TypingStatus::Active).await {
                        error!("Failed to send active state after message: {}", e);
                    }
                    
                    // Render UI to show the sending status
                    terminal.draw(|f| chat_ui.draw(f))?;
                    
                    // Check if we need to verify recipient's key first
                    if xmpp_client.is_omemo_enabled().await {
                        info!("MAIN: OMEMO is enabled, checking keys for: {}", actual_recipient);
                        // Check OMEMO keys for this recipient
                        if let Err(e) = xmpp_client.check_omemo_keys_for_contact(actual_recipient).await {
                            error!("Error checking OMEMO keys: {}", e);
                            
                            // Show error in UI
                            chat_ui.remove_last_message(); // Remove "preparing" message
                            chat_ui.add_message(create_system_message(
                                actual_recipient,
                                &format!("Error checking encryption keys: {}", e)
                            ));
                            continue;
                        }
                        
                        // Log the message content being sent
                        info!("MAIN: Sending message to {}: content_starts_with='{}'", 
                             actual_recipient, content.chars().take(30).collect::<String>());
                        
                        // Send the message
                        match xmpp_client.send_message(actual_recipient, &content).await {
                            Ok(_) => {
                                info!("MAIN: Message sent successfully to {}", actual_recipient);
                                // Remove the "preparing message..." status
                                chat_ui.remove_last_message();
                                
                                // Message sent successfully, the UI already has this message displayed
                                // as it was added when the user pressed Enter
                            },
                            Err(e) => {
                                error!("MAIN: Error sending message to {}: {}", actual_recipient, e);
                                // Remove the "preparing message..." status
                                chat_ui.remove_last_message();
                                
                                // Add error message to the chat
                                chat_ui.add_message(create_system_message(
                                    actual_recipient,
                                    &format!("Error sending message: {}", e)
                                ));
                                
                                // Log the error
                                error!("Failed to send message to {}: {}", actual_recipient, e);
                            }
                        }
                    } else {
                        info!("MAIN: OMEMO is disabled, sending plaintext to {}", actual_recipient);
                        // OMEMO is disabled, just send the message normally
                        match xmpp_client.send_message(actual_recipient, &content).await {
                            Ok(_) => {
                                info!("MAIN: Plaintext message sent successfully to {}", actual_recipient);
                                // Remove the "preparing message..." status
                                chat_ui.remove_last_message();
                                
                                // Message sent successfully, the UI already has this message displayed
                            },
                            Err(e) => {
                                error!("MAIN: Error sending plaintext message to {}: {}", actual_recipient, e);
                                // Remove the "preparing message..." status
                                chat_ui.remove_last_message();
                                
                                // Add error message to the chat
                                chat_ui.add_message(create_system_message(
                                    actual_recipient,
                                    &format!("Error sending message: {}", e)
                                ));
                                
                                // Log the error
                                error!("Failed to send message to {}: {}", actual_recipient, e);
                            }
                        }
                    }
                } else if content == "__TOGGLE_OMEMO_TRUST__" {
                    // ... existing toggle OMEMO trust code ...
                    // Handle OMEMO key trust toggle
                    info!("Toggling OMEMO trust for {}", recipient);
                    
                    // Show a status message in the UI
                    chat_ui.add_message(create_system_message(
                        &recipient,
                        "Toggling trust status for all OMEMO devices..."
                    ));
                    
                    // Render UI to show the status message
                    terminal.draw(|f| chat_ui.draw(f))?;
                    
                    // Toggle trust for all devices
                    match xmpp_client.toggle_omemo_trust(&recipient).await {
                        Ok(is_now_trusted) => {
                            // Success - report the new status
                            let status_msg = if is_now_trusted {
                                format!("All OMEMO devices for {} are now TRUSTED", recipient)
                            } else {
                                format!("All OMEMO devices for {} are now UNTRUSTED", recipient)
                            };
                            
                            // Remove the "toggling" message
                            chat_ui.remove_last_message();
                            
                            // Add the success message
                            chat_ui.add_message(create_system_message(
                                &recipient,
                                &status_msg
                            ));
                        },
                        Err(e) => {
                            // Error - report the failure
                            error!("Failed to toggle OMEMO trust: {}", e);
                            
                            // Remove the "toggling" message
                            chat_ui.remove_last_message();
                            
                            // Add the error message
                            chat_ui.add_message(create_system_message(
                                &recipient,
                                &format!("Failed to toggle OMEMO trust: {}", e)
                            ));
                        }
                    }
                } else if content == "__SHOW_ADD_CONTACT__" {
                    // ... existing show add contact code ...
                    // Show the add contact dialog with the current server domain
                    // Extract server domain from saved credentials
                    if let Ok(Some(creds)) = load_credentials() {
                        info!("Showing add contact dialog with server: {}", creds.server);
                        chat_ui.show_add_contact_dialog(&creds.server);
                    } else {
                        // If we can't get the server from credentials, try to extract it from connection
                        if let Some(server) = xmpp_client.get_server_domain().await {
                            info!("Showing add contact dialog with server from connection: {}", server);
                            chat_ui.show_add_contact_dialog(&server);
                        } else {
                            // Fallback to a default message if we can't determine the server
                            chat_ui.add_message(create_system_message(
                                "me",
                                "Could not determine server domain for adding contacts. Please use a full JID."
                            ));
                        }
                    }
                } else if content == "__ADD_CONTACT__" {
                    // ... existing add contact code ...
                    // Handle adding a new contact
                    info!("Adding new contact: {}", recipient);
                    
                    // Show status message in UI
                    chat_ui.add_message(create_system_message(
                        "me",
                        &format!("Adding contact {}...", recipient)
                    ));
                    
                    // Render UI to show the status message
                    terminal.draw(|f| chat_ui.draw(f))?;
                    
                    // Add the contact to roster
                    match xmpp_client.add_contact_to_roster(&recipient).await {
                        Ok(_) => {
                            // Success
                            info!("Successfully added contact {} to roster", recipient);
                            
                            // Remove the status message
                            chat_ui.remove_last_message();
                            
                            // Add success message
                            chat_ui.add_message(create_system_message(
                                "me",
                                &format!("Contact {} added successfully", recipient)
                            ));
                            
                            // Add the contact to the UI
                            chat_ui.add_contact(&recipient);
                            
                            // Switch to the contact in the UI
                            chat_ui.set_active_contact(&recipient);
                            
                            // Clear messages for this new contact
                            chat_ui.clear_messages();
                            
                            // Signal contact change for message history loading
                            chat_ui.add_message(create_system_message(
                                &recipient,
                                "Contact added. You can now start chatting."
                            ));
                        },
                        Err(e) => {
                            // Error
                            error!("Failed to add contact {}: {}", recipient, e);
                            
                            // Remove the status message
                            chat_ui.remove_last_message();
                            
                            // Add error message
                            chat_ui.add_message(create_system_message(
                                "me",
                                &format!("Failed to add contact {}: {}", recipient, e)
                            ));
                        }
                    }
                } else if content == "__REMOVE_CONTACT__" || content == "__REMOVE_CONTACT_CONFIRMED__" {
                    // ... existing remove contact code ...
                    if content == "__REMOVE_CONTACT__" {
                        // Handle removing a contact
                        info!("Preparing to remove contact: {}", recipient);
                        
                        // Show confirmation dialog instead of immediately removing
                        chat_ui.show_contact_remove_dialog(&recipient);
                        
                        // Render UI to show the confirmation dialog
                        terminal.draw(|f| chat_ui.draw(f))?;
                    } else { // __REMOVE_CONTACT_CONFIRMED__
                        // Handle removing a contact that was confirmed in the dialog
                        info!("Removing contact: {}", recipient);
                        
                        // Show status message in UI
                        chat_ui.add_message(create_system_message(
                            "me",
                            &format!("Removing contact {}...", recipient)
                        ));
                        
                        // Render UI to show the status message
                        terminal.draw(|f| chat_ui.draw(f))?;
                        
                        // Get the current contacts before removal for fallback
                        let current_contacts = chat_ui.contacts.clone();
                        let removed_contact = recipient.to_string();
                        
                        // Remove the contact from roster
                        match xmpp_client.remove_contact_from_roster(&recipient).await {
                            Ok(_) => {
                                // Success
                                info!("Successfully removed contact {} from roster", recipient);
                                
                                // Remove the status message
                                chat_ui.remove_last_message();
                                
                                // Add success message
                                chat_ui.add_message(create_system_message(
                                    "me",
                                    &format!("Contact {} removed successfully", recipient)
                                ));
                                
                                // Try to get updated roster with multiple attempts and delays
                                // This helps ensure we get the latest state after removal
                                info!("Fetching updated roster after contact removal");
                                let mut updated_contacts = Vec::new();
                                let mut success = false;
                                
                                for attempt in 1..=3 {
                                    info!("Roster fetch attempt {} after contact removal", attempt);
                                    match xmpp_client.get_roster().await {
                                        Ok(Some(contacts)) => {
                                            updated_contacts = contacts;
                                            success = true;
                                            info!("Successfully retrieved updated roster with {} contacts", updated_contacts.len());
                                            break;
                                        },
                                        Ok(None) => {
                                            warn!("Server returned empty roster on attempt {}", attempt);
                                            // Continue to retry
                                        },
                                        Err(e) => {
                                            error!("Failed to retrieve roster on attempt {}: {}", attempt, e);
                                            // Continue to retry
                                        }
                                    }
                                    
                                    // Wait a bit before retrying
                                    tokio::time::sleep(std::time::Duration::from_millis(300 * attempt)).await;
                                }
                                
                                // If we couldn't get an updated roster, use the current one without the removed contact
                                if !success || updated_contacts.is_empty() {
                                    warn!("Using fallback contact list after removal");
                                    updated_contacts = current_contacts.iter()
                                        .filter(|&c| c != &removed_contact)
                                        .cloned()
                                        .collect();
                                }
                                
                                // Clear and update the contacts list
                                chat_ui.contacts.clear();
                                
                                if updated_contacts.is_empty() {
                                    // No contacts in roster, add a placeholder
                                    chat_ui.add_contact("[No contacts found]");
                                    
                                    // Set placeholder as active and show message
                                    chat_ui.set_active_contact("[No contacts found]");
                                    chat_ui.clear_messages();
                                    chat_ui.add_message(create_system_message(
                                        "me",
                                        "No contacts in your roster. Use Ctrl+A to add a contact."
                                    ));
                                } else {
                                    // Add all contacts to the UI
                                    for contact in &updated_contacts {
                                        chat_ui.add_contact(contact);
                                    }
                                    
                                    // Set a new active contact
                                    let first_contact = updated_contacts[0].clone();
                                    chat_ui.set_active_contact(&first_contact);
                                    
                                    // Clear messages for this new contact
                                    chat_ui.clear_messages();
                                    
                                    // Load message history for the new active contact
                                    load_message_history_async(chat_ui, xmpp_client, &first_contact);
                                }
                            },
                            Err(e) => {
                                // Error
                                error!("Failed to remove contact {}: {}", recipient, e);
                                
                                // Remove the status message
                                chat_ui.remove_last_message();
                                
                                // Add error message
                                chat_ui.add_message(create_system_message(
                                    "me",
                                    &format!("Failed to remove contact {}: {}", recipient, e)
                                ));
                            }
                        }
                    }
                } else if content == "__CONTACT_CHANGED__" {
                    // ... existing contact changed code ...
                    // Special case for contact change
                    info!("Contact changed to: {}", recipient);
                    
                    // Reset typing state tracking
                    last_state_sent = None;
                    
                    // Clear existing messages
                    chat_ui.clear_messages();
                    
                    // Draw UI to show clear message area
                    terminal.draw(|f| chat_ui.draw(f))?;
                    
                    // Load message history for this contact asynchronously
                    load_message_history_async(chat_ui, xmpp_client, &recipient);
                    
                    // Redraw right away to show loading message
                    terminal.draw(|f| chat_ui.draw(f))?;
                } else if content == "__KEY_ACCEPTED__" || content == "__KEY_REJECTED__" {
                    // ... existing key verification code ...
                    // Handle key verification response
                    info!("Processing key verification response for {}", recipient);
                    
                    if let Err(e) = xmpp_client.handle_key_verification_response(&recipient, &content).await {
                        error!("Failed to process key verification response: {}", e);
                        // Add an error message to the UI
                        chat_ui.add_message(create_system_message(
                            &recipient,
                            &format!("Error processing key verification: {}", e)
                        ));
                    }
                } else if content == "__ENABLE_CARBONS__" {
                    // ... existing enable carbons code ...
                    // Handle enabling message carbons
                    info!("Enabling message carbons");
                    
                    // Show a status message in the UI
                    chat_ui.add_message(create_system_message(
                        "me",
                        "Enabling message carbons..."
                    ));
                    
                    // Render UI to show the status message
                    terminal.draw(|f| chat_ui.draw(f))?;
                    
                    // Enable message carbons
                    match xmpp_client.enable_carbons().await {
                        Ok(_) => {
                            // Success
                            info!("Successfully enabled message carbons");
                            
                            // Remove the status message
                            chat_ui.remove_last_message();
                            
                            // Add success message
                            chat_ui.add_message(create_system_message(
                                "me",
                                "Message carbons enabled successfully"
                            ));
                        },
                        Err(e) => {
                            // Error
                            error!("Failed to enable message carbons: {}", e);
                            
                            // Remove the status message
                            chat_ui.remove_last_message();
                            
                            // Add error message
                            chat_ui.add_message(create_system_message(
                                "me",
                                &format!("Failed to enable message carbons: {}", e)
                            ));
                        }
                    }
                } else if content == "__REFETCH_OMEMO__" {
                    // Handle Ctrl+R OMEMO device list re-fetch for the active contact
                    let jid = recipient.split('/').next().unwrap_or(&recipient);
                    chat_ui.add_message(create_system_message(
                        jid,
                        &format!("Forcing OMEMO device list re-fetch for {}...", jid)
                    ));
                    info!("DEBUG: Forcing OMEMO device list re-fetch for {} (Ctrl+R)", jid);
                    match xmpp_client.force_refresh_device_list(jid).await {
                        Ok(device_ids) if !device_ids.is_empty() => {
                            chat_ui.add_message(create_system_message(
                                jid,
                                &format!("Found {} OMEMO device(s): {:?}", device_ids.len(), device_ids)
                            ));
                            info!("DEBUG: OMEMO device IDs for {}: {:?}", jid, device_ids);
                            for device_id in device_ids {
                                match xmpp_client.get_device_fingerprint(jid, device_id).await {
                                    Ok(fingerprint) => {
                                        chat_ui.add_message(create_system_message(
                                            jid,
                                            &format!("Device {} fingerprint: {}", device_id, fingerprint)
                                        ));
                                        info!("DEBUG: OMEMO device {} fingerprint for {}: {}", device_id, jid, fingerprint);
                                    },
                                    Err(e) => {
                                        chat_ui.add_message(create_system_message(
                                            jid,
                                            &format!("Could not retrieve fingerprint for device {}: {}", device_id, e)
                                        ));
                                        warn!("DEBUG: Could not retrieve fingerprint for device {} of {}: {}", device_id, jid, e);
                                    }
                                }
                            }
                        },
                        Ok(_) => {
                            chat_ui.add_message(create_system_message(
                                jid,
                                "No OMEMO devices found."
                            ));
                            warn!("DEBUG: No OMEMO devices found for {}", jid);
                        },
                        Err(e) => {
                            chat_ui.add_message(create_system_message(
                                jid,
                                &format!("Failed to force OMEMO device list re-fetch: {}", e)
                            ));
                            error!("DEBUG: Failed to force OMEMO device list re-fetch for {}: {}", jid, e);
                        }
                    }
                } else if content == "__SHOW_DEVICE_FINGERPRINTS__" {
                    // Handle show device fingerprints command 
                    match xmpp_client.get_own_fingerprint().await {
                        Ok(fingerprint) => {
                            match xmpp_client.get_own_device_id().await {
                                Ok(current_device_id) => {
                                    // Show fingerprint dialog
                                    chat_ui.show_device_fingerprints_dialog(
                                        vec![(current_device_id.to_string(), fingerprint)], 
                                        Some(current_device_id.to_string())
                                    );
                                },
                                Err(e) => {
                                    chat_ui.add_message(create_system_message(
                                        "me",
                                        &format!("Could not get device ID: {}", e)
                                    ));
                                }
                            }
                        },
                        Err(e) => {
                            chat_ui.add_message(create_system_message(
                                "me",
                                &format!("No OMEMO device fingerprints available: {}", e)
                            ));
                        }
                    }
                } else if content == "__TEST_FRIEND_REQUEST__" {
                    // Test the friend request notification UI
                    info!("Testing friend request notification UI");
                    chat_ui.test_friend_request_notification();
                } else if recipient.is_empty() && content.is_empty() {
                    // Only quit when BOTH recipient AND content are empty
                    // This is a signal to quit
                    break;
                } else if !content.is_empty() {
                    // ... existing regular message code ...
                    // Regular message, show sending status in the UI
                    chat_ui.add_message(create_system_message(&recipient, "Sending message..."));
                    
                    // Reset typing state when sending a message
                    last_state_sent = None;
                    
                    // Send 'active' chat state to indicate we're no longer composing
                    if let Err(e) = xmpp_client.send_chat_state(&recipient, &TypingStatus::Active).await {
                        error!("Failed to send active state after message: {}", e);
                    }
                    
                    // Render UI to show the sending status
                    terminal.draw(|f| chat_ui.draw(f))?;
                    
                    // Send the message
                    let prepared_content = prepare_message_for_sending(chat_ui, &recipient, &content);
                    match xmpp_client.send_message(&recipient, &prepared_content).await {
                        Ok(_) => {
                            // Remove the "sending message..." status
                            chat_ui.remove_last_message();
                            
                            // Generate a unique ID for this message that will be used for all status updates
                            let message_id = uuid::Uuid::new_v4().to_string();
                            
                            // Message sent successfully, add it to the UI
                            chat_ui.add_message(Message {
                                id: message_id.clone(),
                                sender_id: "me".to_string(),
                                recipient_id: recipient.clone(),
                                content: content.clone(), // Show original message in UI, not encrypted version
                                timestamp: chrono::Utc::now().timestamp() as u64,
                                delivery_status: DeliveryStatus::Sent, // Initially mark as sent, updates will use same ID
                            });
                            
                            // Store the message ID for later status updates
                            if let Err(e) = xmpp_client.store_message_id(&recipient, &message_id).await {
                                error!("Failed to store message ID for tracking: {}", e);
                            }
                        },
                        Err(e) => {
                            // Remove the "sending message..." status
                            chat_ui.remove_last_message();
                            
                            // Add error message to the chat
                            chat_ui.add_message(create_system_message(
                                &recipient,
                                &format!("Error sending message: {}", e)
                            ));
                            
                            // Log the error
                            error!("Failed to send message to {}: {}", recipient, e);
                        }
                    }
                }
            },
            None => {
                // No input event to process, continue with the next iteration
                // This typically happens when the user hasn't pressed a key
            }
        }
    }
    
    Ok(())
}

// This would typically be added to your main.rs or xmpp client module
pub fn handle_new_omemo_key(ui: &mut ChatUI, contact: &str, fingerprint: &str, device_id: Option<&str>) {
    // Show the key confirmation dialog
    ui.show_key_confirmation(contact, fingerprint, device_id);
    
    // Note: The actual user response (accept/reject) will be handled in the UI's input handling code
    // and will return "__KEY_ACCEPTED__" or "__KEY_REJECTED__" through the handle_input method
}

pub fn prepare_message_for_sending(_ui: &ChatUI, _recipient: &str, message: &str) -> String {
    // In the future, this function could process the message based on recipient preferences
    // For now, it simply returns the message content as-is
    message.to_string()
}

/// Check for pending OMEMO key verifications and show popups
async fn check_pending_key_verifications(chat_ui: &mut ChatUI, xmpp_client: &XMPPClient) -> Result<()> {
    info!("Checking for pending OMEMO key verifications");
    
    // Only continue if OMEMO is enabled
    if !xmpp_client.is_omemo_enabled().await {
        info!("OMEMO is not enabled, skipping key verification check");
        return Ok(());
    }
    
    // Create storage instance to check database for pending verifications
    let storage = match chatterbox::omemo::storage::OmemoStorage::new_default() {
        Ok(storage) => storage,
        Err(e) => {
            error!("Failed to create OMEMO storage: {}", e);
            return Err(anyhow::anyhow!("Failed to create OMEMO storage: {}", e));
        }
    };
    
    // Get all contacts that might have pending verifications
    // Clone contacts to avoid borrowing issues
    let contacts = chat_ui.contacts.clone();
    
    for contact in contacts {
        // Skip special contacts
        if contact.starts_with('[') && contact.ends_with(']') {
            continue;
        }
        
        // Check if this contact has a pending verification
        match storage.get_pending_device_verification(&contact) {
            Ok(Some((device_id, fingerprint))) => {
                info!("Found pending key verification for {}:{} with fingerprint {}", 
                     contact, device_id, fingerprint);
                
                // Show the verification dialog
                handle_new_omemo_key(
                    chat_ui,
                    &contact,
                    &fingerprint,
                    Some(&device_id.to_string())
                );
                
                // Only show one verification at a time to avoid overwhelming the user
                break;
            },
            Ok(None) => {
                // No pending verification for this contact
                //debug!("No pending key verification for {}", contact);
            },
            Err(e) => {
                warn!("Error checking pending verification for {}: {}", contact, e);
            }
        }
    }
    
    Ok(())
}