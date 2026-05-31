// src/app.rs
//! Application logic: UI setup, event loop, and helper functions.
//! Extracted from main.rs to keep the entry point minimal.

use anyhow::Result;
use log::{error, info, warn};
use std::io;

use crate::{
    ui::ChatUI,
    credentials::load_credentials,
};
use chatterbox::{
    xmpp::{XMPPClient, chat_states::TypingStatus},
    models::Message,
    xmpp::message_archive::MAMQueryOptions,
    storage::MessageStore,
};

/// Creates a system message for display in the UI
pub fn create_system_message(to: &str, content: &str) -> Message {
    Message::system(to, content)
}

/// Run the full application after a successful XMPP connection.
/// This sets up the TUI, loads contacts/fingerprints, and enters the main event loop.
pub async fn run_app(
    mut xmpp_client: XMPPClient,
    mut msg_rx: tokio::sync::mpsc::Receiver<Message>,
    typing_rx: tokio::sync::mpsc::Receiver<(String, TypingStatus)>,
    disable_mam: bool,
) -> Result<()> {
    // Setup terminal UI
    let mut terminal = crate::ui::setup_terminal()?;
    let mut chat_ui = ChatUI::new();

    // Draw UI early
    terminal.draw(|f| chat_ui.draw(f))?;

    // Allow OMEMO initialization to complete fully
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    info!("Waiting for OMEMO initialization to complete...");

    // Open local message store
    let bare_jid = xmpp_client.get_jid().split('/').next().unwrap_or(xmpp_client.get_jid()).to_string();
    let store = match MessageStore::open(&bare_jid) {
        Ok(s) => {
            info!("Local message store opened for {}", bare_jid);
            Some(s)
        }
        Err(e) => {
            error!("Failed to open message store: {}. Messages won't be persisted locally.", e);
            None
        }
    };

    // Set up the contact list
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        setup_contacts(&mut chat_ui, &mut xmpp_client, disable_mam),
    )
    .await
    {
        Ok(_) => {
            info!("Contact setup completed successfully");
        }
        Err(_) => {
            error!("Contact setup timed out after 5 seconds");
            chat_ui.add_contact("[Error: Contact setup timed out]");
            chat_ui.add_message(create_system_message(
                "me",
                "Contact setup timed out. You can still chat by entering complete JIDs manually.",
            ));
        }
    }

    // Show OMEMO fingerprints for each contact as system messages
    show_omemo_fingerprints(&mut chat_ui, &xmpp_client).await;

    // Draw UI again with contact list and fingerprints
    terminal.draw(|f| chat_ui.draw(f))?;

    // Start message history loading in background if we have an active contact
    start_initial_history_load(&mut chat_ui, &xmpp_client, disable_mam, store.as_ref()).await;

    // Check for pending OMEMO key verifications
    check_pending_key_verifications(&mut chat_ui, &xmpp_client).await?;

    // Main event loop
    run_main_loop(
        &mut chat_ui,
        &mut terminal,
        &mut xmpp_client,
        &mut msg_rx,
        disable_mam,
        typing_rx,
        store.as_ref(),
    )
    .await?;

    // Restore terminal
    crate::ui::restore_terminal(terminal)?;

    println!("Chat session ended.");
    Ok(())
}

/// Show OMEMO fingerprints for all contacts
async fn show_omemo_fingerprints(chat_ui: &mut ChatUI, xmpp_client: &XMPPClient) {
    if !xmpp_client.is_omemo_enabled().await {
        return;
    }

    let contacts = chat_ui.contacts.clone();
    for contact in contacts {
        if contact.starts_with('[') && contact.ends_with(']') {
            continue;
        }
        let bare_jid = contact.split('/').next().unwrap_or(contact.as_str());

        let device_ids = if let Some(omemo_manager) = xmpp_client.get_omemo_manager() {
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                omemo_manager.lock().await.get_device_ids_for_test(bare_jid),
            )
            .await
            {
                Ok(Ok(ids)) => ids,
                Ok(Err(e)) => {
                    error!("Failed to refresh device list for {}: {}", bare_jid, e);
                    Vec::new()
                }
                Err(_) => {
                    error!("Timeout refreshing device list for {}", bare_jid);
                    Vec::new()
                }
            }
        } else {
            error!("OMEMO not initialized");
            Vec::new()
        };

        if !device_ids.is_empty() {
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
                    }
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
        } else {
            let msg = create_system_message(
                &contact,
                &format!("No OMEMO devices found for {}", bare_jid),
            );
            chat_ui.add_message(msg);
        }
    }
}

/// Start loading message history in background for the initial active contact.
/// Loads from local store first (instant), then does a MAM catch-up for newer messages.
async fn start_initial_history_load(
    chat_ui: &mut ChatUI,
    xmpp_client: &XMPPClient,
    disable_mam: bool,
    store: Option<&MessageStore>,
) {
    if !chat_ui.has_active_contact() {
        return;
    }
    if chat_ui.contacts.is_empty() {
        return;
    }

    let active_contact = chat_ui.contacts[0].clone();

    if disable_mam {
        chat_ui.add_message(create_system_message(
            &active_contact,
            "Message history disabled (--disable-mam flag)",
        ));
        return;
    }

    // Load from local store first (instant)
    let newest_ts = if let Some(s) = store {
        match s.load_messages(&active_contact, 100) {
            Ok(msgs) if !msgs.is_empty() => {
                let count = msgs.len();
                for msg in &msgs {
                    chat_ui.add_message(msg.clone());
                }
                chat_ui.add_message(create_system_message(
                    &active_contact,
                    &format!("Loaded {} messages from local history", count),
                ));
                s.newest_timestamp(&active_contact).ok().flatten()
            }
            Ok(_) => None,
            Err(e) => {
                error!("Failed to load local messages for {}: {}", active_contact, e);
                None
            }
        }
    } else {
        None
    };

    // MAM catch-up for messages newer than what we have locally
    load_message_history_with_catchup(chat_ui, xmpp_client, &active_contact, disable_mam, newest_ts);
}

/// Set up the contacts list from the XMPP server
async fn setup_contacts(chat_ui: &mut ChatUI, xmpp_client: &mut XMPPClient, _disable_mam: bool) {
    match xmpp_client.get_roster().await {
        Ok(Some(contacts)) if !contacts.is_empty() => {
            for contact in contacts {
                chat_ui.add_contact(&contact);
            }
            if !chat_ui.contacts.is_empty() {
                let first_contact = chat_ui.contacts[0].clone();
                chat_ui.set_active_contact(&first_contact);
            }
        }
        Ok(_) => {
            chat_ui.add_contact("[No contacts found]");
            chat_ui.add_message(create_system_message(
                "me",
                "No contacts found in your roster. You can still chat by entering a complete JID (e.g. user@domain.com)",
            ));
        }
        Err(e) => {
            error!("Error fetching roster: {}", e);
            chat_ui.add_contact("[Error loading contacts]");
            chat_ui.add_message(create_system_message(
                "me",
                &format!(
                    "Failed to load contacts: {}. You can still chat with contacts by entering their full JID.",
                    e
                ),
            ));
        }
    }

    if !chat_ui.has_active_contact() && !chat_ui.contacts.is_empty() {
        let first_contact = chat_ui.contacts[0].clone();
        chat_ui.set_active_contact(&first_contact);
    }
}

/// Loads message history for a contact in the background without blocking the UI
fn load_message_history_async(
    chat_ui: &mut ChatUI,
    xmpp_client: &XMPPClient,
    contact: &str,
    disable_mam: bool,
) {
    if contact.starts_with('[') && contact.ends_with(']') {
        return;
    }

    if disable_mam {
        chat_ui.add_message(create_system_message(
            contact,
            "Message history disabled (--disable-mam flag)",
        ));
        return;
    }

    chat_ui.add_message(create_system_message(
        contact,
        "Checking for message history in background...",
    ));

    let client_clone = xmpp_client.clone();
    let contact_clone = contact.to_string();
    let msg_tx = xmpp_client.get_message_sender();

    tokio::spawn(async move {
        let has_history = match client_clone.has_message_history(&contact_clone, 1).await {
            Ok(exists) => {
                if !exists {
                    if let Err(e) = msg_tx
                        .send(create_system_message(&contact_clone, "No message history found"))
                        .await
                    {
                        error!("Failed to send 'no history' message: {}", e);
                    }
                    return;
                }
                true
            }
            Err(e) => {
                error!("Failed to check for message history: {}", e);
                if let Err(send_err) = msg_tx
                    .send(create_system_message(
                        &contact_clone,
                        &format!("History check failed: {}. Attempting full retrieval...", e),
                    ))
                    .await
                {
                    error!("Failed to send history check error message: {}", send_err);
                }
                false
            }
        };

        if has_history {
            if let Err(e) = msg_tx
                .send(create_system_message(
                    &contact_clone,
                    "Fetching message history...",
                ))
                .await
            {
                error!("Failed to send history fetching message: {}", e);
            }
        }

        let options = MAMQueryOptions::new().with_jid(&contact_clone).with_limit(50);

        match client_clone.get_message_history_with_pagination(options).await {
            Ok(result) => {
                if result.messages.is_empty() {
                    if let Err(e) = msg_tx
                        .send(create_system_message(&contact_clone, "No message history found"))
                        .await
                    {
                        error!("Failed to send 'no history' message: {}", e);
                    }
                } else {
                    if let Err(e) = msg_tx
                        .send(create_system_message(
                            &contact_clone,
                            &format!("Loaded {} historical messages", result.messages.len()),
                        ))
                        .await
                    {
                        error!("Failed to send history success message: {}", e);
                    }

                    for message in &result.messages {
                        if let Err(e) = msg_tx.send(message.clone()).await {
                            error!("Failed to send historical message to UI: {}", e);
                            break;
                        }
                    }

                    if !result.complete && result.rsm_last.is_some() {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                        if let Err(e) = client_clone
                            .load_complete_message_history_in_background(
                                &contact_clone,
                                result,
                                msg_tx.clone(),
                                10,
                            )
                            .await
                        {
                            error!("Error in background history loading: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to retrieve message history for {}: {}",
                    contact_clone, e
                );
                if let Err(send_err) = msg_tx
                    .send(create_system_message(
                        &contact_clone,
                        &format!("Failed to load message history: {}", e),
                    ))
                    .await
                {
                    error!("Failed to send history error message: {}", send_err);
                }
            }
        }
    });
}

/// Loads message history from the server, starting after the given local timestamp.
/// If `since` is None, fetches the full history (same as load_message_history_async).
fn load_message_history_with_catchup(
    chat_ui: &mut ChatUI,
    xmpp_client: &XMPPClient,
    contact: &str,
    disable_mam: bool,
    since: Option<u64>,
) {
    if contact.starts_with('[') && contact.ends_with(']') {
        return;
    }

    if disable_mam {
        return;
    }

    let client_clone = xmpp_client.clone();
    let contact_clone = contact.to_string();
    let msg_tx = xmpp_client.get_message_sender();

    chat_ui.add_message(create_system_message(
        contact,
        "Checking server for new messages...",
    ));

    tokio::spawn(async move {
        let mut options = MAMQueryOptions::new().with_jid(&contact_clone).with_limit(50);

        // If we have local history, only fetch messages newer than what we have
        if let Some(ts) = since {
            let start_time = chrono::DateTime::from_timestamp(ts as i64 + 1, 0)
                .unwrap_or_else(|| chrono::Utc::now());
            options = options.with_start(start_time);
        }

        match client_clone.get_message_history_with_pagination(options).await {
            Ok(result) => {
                if result.messages.is_empty() {
                    if let Err(e) = msg_tx
                        .send(create_system_message(&contact_clone, "No new messages on server"))
                        .await
                    {
                        error!("Failed to send catchup status: {}", e);
                    }
                } else {
                    if let Err(e) = msg_tx
                        .send(create_system_message(
                            &contact_clone,
                            &format!("Fetched {} new messages from server", result.messages.len()),
                        ))
                        .await
                    {
                        error!("Failed to send catchup status: {}", e);
                    }

                    for message in &result.messages {
                        if let Err(e) = msg_tx.send(message.clone()).await {
                            error!("Failed to send historical message to UI: {}", e);
                            break;
                        }
                    }

                    if !result.complete && result.rsm_last.is_some() {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        if let Err(e) = client_clone
                            .load_complete_message_history_in_background(
                                &contact_clone,
                                result,
                                msg_tx.clone(),
                                10,
                            )
                            .await
                        {
                            error!("Error in background history catchup: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("MAM catch-up failed for {}: {}", contact_clone, e);
                if let Err(send_err) = msg_tx
                    .send(create_system_message(
                        &contact_clone,
                        &format!("Server history check failed: {}", e),
                    ))
                    .await
                {
                    error!("Failed to send catchup error: {}", send_err);
                }
            }
        }
    });
}

/// Run the main event loop
async fn run_main_loop(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    msg_rx: &mut tokio::sync::mpsc::Receiver<Message>,
    disable_mam: bool,
    mut typing_rx: tokio::sync::mpsc::Receiver<(String, TypingStatus)>,
    store: Option<&MessageStore>,
) -> Result<()> {
    let mut presence_rx = xmpp_client.subscribe_to_presence();
    let mut friend_req_rx = xmpp_client.subscribe_to_friend_requests();

    xmpp_client.resend_presence();
    chat_ui.set_connection_status(xmpp_client.is_client_accessible());

    let mut last_key_press = std::time::Instant::now();
    let mut last_state_sent = None::<TypingStatus>;
    let mut verified_contacts = std::collections::HashSet::new();
    let mut last_connection_check = std::time::Instant::now();
    let mut typing_failures: u32 = 0;
    let mut last_typing_check: Option<std::time::Instant> = None;

    loop {
        terminal.draw(|f| chat_ui.draw(f))?;

        chat_ui.clean_typing_states(30);
        chat_ui.clean_friend_request_notifications(5);

        let input_result = chat_ui.handle_input()?;

        // Check OMEMO keys for newly-selected contacts
        if chat_ui.has_active_contact() && chat_ui.is_omemo_enabled() {
            let active_contact = chat_ui.get_active_contact();
            if !verified_contacts.contains(&active_contact) {
                verified_contacts.insert(active_contact.clone());
                let client_clone = xmpp_client.clone();
                let contact_clone = active_contact.clone();
                tokio::spawn(async move {
                    if let Err(e) = client_clone.check_omemo_keys_for_contact(&contact_clone).await
                    {
                        error!("Failed to check OMEMO keys for {}: {}", contact_clone, e);
                    }
                });
            }
        }

        // Process incoming messages
        if let Ok(message) = msg_rx.try_recv() {
            if message.sender_id == "system"
                && message.content.starts_with("__OMEMO_KEY_VERIFY__:")
            {
                let parts: Vec<&str> = message.content.splitn(4, ':').collect();
                if parts.len() >= 3 {
                    let contact = parts[1];
                    let fingerprint = parts[2];
                    let device_id = if parts.len() > 3 { Some(parts[3]) } else { None };
                    handle_new_omemo_key(chat_ui, contact, fingerprint, device_id.as_deref());
                }
            } else {
                chat_ui.add_message(message.clone());
                // Persist non-system messages locally
                if message.sender_id != "system" {
                    if let Some(s) = store {
                        if let Err(e) = s.store_message(&message) {
                            error!("Failed to persist message: {}", e);
                        }
                    }
                }
                if message.sender_id != "me" && message.sender_id != "system" {
                    chat_ui.message_received_from(&message.sender_id);
                }
                if !chat_ui.contacts.contains(&message.sender_id)
                    && message.sender_id != "me"
                    && message.sender_id != "system"
                {
                    chat_ui.add_contact(&message.sender_id);
                }
            }
        }

        // Drain presence updates
        loop {
            match presence_rx.try_recv() {
                Ok(event) => {
                    if let Some((contact_id, status)) = event.to_contact_status() {
                        chat_ui.update_contact_status(&contact_id, status);
                    }
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!(
                        "Presence broadcast lagged by {} events, requesting refresh",
                        n
                    );
                    xmpp_client.resend_presence();
                }
                Err(_) => break,
            }
        }

        // Friend request notifications
        match friend_req_rx.try_recv() {
            Ok(contact_id) => {
                info!(
                    "Received auto-accepted friend request notification for {}",
                    contact_id
                );
                chat_ui.show_friend_request_notification(&contact_id);
                if !chat_ui.contacts.contains(&contact_id) {
                    chat_ui.add_contact(&contact_id);
                    info!("Added new contact {} to contacts list", contact_id);
                }
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                warn!("Friend request broadcast lagged by {} events", n);
            }
            Err(_) => {}
        }

        // Typing notifications from remote
        if let Ok((contact_id, typing_status)) = typing_rx.try_recv() {
            chat_ui.update_typing_status(&contact_id, typing_status);
        }

        // Periodic connection status check
        let now = std::time::Instant::now();
        if now.duration_since(last_connection_check) >= std::time::Duration::from_secs(5) {
            chat_ui.set_connection_status(xmpp_client.is_client_accessible());
            last_connection_check = now;
        }

        // Outbound typing state management
        if input_result.is_none() && chat_ui.has_active_contact() {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(last_key_press);
            let contact = chat_ui.get_active_contact();

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

            let should_send_typing = typing_failures < 3;

            if should_check_typing && should_send_typing {
                if elapsed < std::time::Duration::from_secs(5) {
                    if last_state_sent != Some(TypingStatus::Composing)
                        || elapsed > std::time::Duration::from_secs(10)
                    {
                        match xmpp_client
                            .send_chat_state(&contact, &TypingStatus::Composing)
                        {
                            Ok(_) => {
                                last_state_sent = Some(TypingStatus::Composing);
                                typing_failures = 0;
                            }
                            Err(e) => {
                                error!("Failed to send typing indicator: {}", e);
                                typing_failures += 1;
                            }
                        }
                    }
                } else if elapsed >= std::time::Duration::from_secs(5)
                    && elapsed < std::time::Duration::from_secs(30)
                    && last_state_sent != Some(TypingStatus::Paused)
                {
                    match xmpp_client
                        .send_chat_state(&contact, &TypingStatus::Paused)
                    {
                        Ok(_) => {
                            last_state_sent = Some(TypingStatus::Paused);
                            typing_failures = 0;
                        }
                        Err(e) => {
                            error!("Failed to send paused typing indicator: {}", e);
                            typing_failures += 1;
                        }
                    }
                } else if elapsed >= std::time::Duration::from_secs(30)
                    && last_state_sent != Some(TypingStatus::Active)
                {
                    match xmpp_client
                        .send_chat_state(&contact, &TypingStatus::Active)
                    {
                        Ok(_) => {
                            last_state_sent = Some(TypingStatus::Active);
                            typing_failures = 0;
                        }
                        Err(e) => {
                            error!("Failed to send active state: {}", e);
                            typing_failures += 1;
                        }
                    }
                }
            }
        } else if input_result.is_some() {
            last_key_press = std::time::Instant::now();
            typing_failures = 0;
        }

        match input_result {
            Some((recipient, content)) => {
                handle_user_command(
                    chat_ui,
                    terminal,
                    xmpp_client,
                    &recipient,
                    &content,
                    disable_mam,
                    &mut last_state_sent,
                    store,
                )
                .await?;

                // Quit signal: both empty
                if recipient.is_empty() && content.is_empty() {
                    break;
                }
            }
            None => {}
        }
    }

    Ok(())
}

/// Dispatch a user command/message from the input handler.
async fn handle_user_command(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    recipient: &str,
    content: &str,
    disable_mam: bool,
    last_state_sent: &mut Option<TypingStatus>,
    store: Option<&MessageStore>,
) -> Result<()> {
    if content.starts_with("/plain ") {
        let plain_content = content.trim_start_matches("/plain ");
        warn!("⚠️ SENDING UNENCRYPTED MESSAGE: {}", plain_content);
        match xmpp_client
            .send_message_with_receipt(recipient, plain_content)
            .await
        {
            Ok(_) => {
                chat_ui.add_message(Message::outgoing_plaintext(
                    uuid::Uuid::new_v4().to_string(),
                    recipient.to_string(),
                    plain_content.to_string(),
                ));
            }
            Err(e) => {
                error!("Failed to send plaintext message: {}", e);
            }
        }
        return Ok(());
    }

    if content == "__SHOW_DEVICE_FINGERPRINTS__" {
        handle_show_device_fingerprints(chat_ui, terminal, xmpp_client).await;
        return Ok(());
    }

    if recipient.starts_with("__VERIFY_KEYS__:") {
        let actual_recipient = recipient.trim_start_matches("__VERIFY_KEYS__:");
        handle_verify_keys_send(
            chat_ui,
            terminal,
            xmpp_client,
            actual_recipient,
            content,
            last_state_sent,
        )
        .await?;
        return Ok(());
    }

    if content == "__TOGGLE_OMEMO_TRUST__" {
        handle_toggle_omemo_trust(chat_ui, terminal, xmpp_client, recipient).await;
        return Ok(());
    }

    if content == "__SHOW_ADD_CONTACT__" {
        handle_show_add_contact(chat_ui, xmpp_client).await;
        return Ok(());
    }

    if content == "__ADD_CONTACT__" {
        handle_add_contact(chat_ui, terminal, xmpp_client, recipient).await;
        return Ok(());
    }

    if content == "__REMOVE_CONTACT__" || content == "__REMOVE_CONTACT_CONFIRMED__" {
        handle_remove_contact(chat_ui, terminal, xmpp_client, recipient, content, disable_mam)
            .await;
        return Ok(());
    }

    if content == "__CONTACT_CHANGED__" {
        info!("Contact changed to: {}", recipient);
        *last_state_sent = None;
        chat_ui.clear_messages();
        terminal.draw(|f| chat_ui.draw(f))?;

        // Load from local store first (instant)
        let local_count = if let Some(s) = store {
            match s.load_messages(recipient, 100) {
                Ok(msgs) if !msgs.is_empty() => {
                    let count = msgs.len();
                    for msg in msgs {
                        chat_ui.add_message(msg);
                    }
                    count
                }
                Ok(_) => 0,
                Err(e) => {
                    error!("Failed to load local messages for {}: {}", recipient, e);
                    0
                }
            }
        } else {
            0
        };

        if local_count > 0 {
            chat_ui.add_message(create_system_message(
                recipient,
                &format!("Loaded {} messages from local history", local_count),
            ));
        }

        // MAM catch-up for messages newer than what we have locally
        let newest_ts = store.and_then(|s| s.newest_timestamp(recipient).ok().flatten());
        load_message_history_with_catchup(chat_ui, xmpp_client, recipient, disable_mam, newest_ts);

        terminal.draw(|f| chat_ui.draw(f))?;
        return Ok(());
    }

    if content == "__KEY_ACCEPTED__" || content == "__KEY_REJECTED__" {
        info!("Processing key verification response for {}", recipient);
        if let Err(e) = xmpp_client
            .handle_key_verification_response(recipient, content)
            .await
        {
            error!("Failed to process key verification response: {}", e);
            chat_ui.add_message(create_system_message(
                recipient,
                &format!("Error processing key verification: {}", e),
            ));
        }
        return Ok(());
    }

    if content == "__ENABLE_CARBONS__" {
        handle_enable_carbons(chat_ui, terminal, xmpp_client).await;
        return Ok(());
    }

    if content == "__REFETCH_OMEMO__" {
        handle_refetch_omemo(chat_ui, xmpp_client, recipient).await;
        return Ok(());
    }

    if content == "__TEST_FRIEND_REQUEST__" {
        info!("Testing friend request notification UI");
        chat_ui.test_friend_request_notification();
        return Ok(());
    }

    // Quit signal
    if recipient.is_empty() && content.is_empty() {
        return Ok(());
    }

    // Regular message send
    if !content.is_empty() {
        handle_send_message(chat_ui, terminal, xmpp_client, recipient, content, last_state_sent, store)
            .await?;
    }

    Ok(())
}

async fn handle_show_device_fingerprints(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
) {
    info!("MAIN: Received request to show device fingerprints dialog (own devices)");
    chat_ui.reset_device_fingerprints_dialog();

    let my_jid = xmpp_client.get_jid();
    let bare_jid = my_jid.split('/').next().unwrap_or(my_jid);
    chat_ui.add_message(create_system_message(
        "me",
        &format!(
            "Retrieving device fingerprints for your account ({}).",
            bare_jid
        ),
    ));
    info!(
        "MAIN: Using JID {} to fetch own device fingerprints",
        bare_jid
    );
    let _ = terminal.draw(|f| chat_ui.draw(f));

    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        xmpp_client.get_device_ids_for_user(bare_jid),
    )
    .await
    {
        Ok(Ok(device_ids)) if !device_ids.is_empty() => {
            chat_ui.remove_last_message();
            let mut fingerprints = Vec::new();
            for device_id in &device_ids {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    xmpp_client.get_device_fingerprint(bare_jid, *device_id),
                )
                .await
                {
                    Ok(Ok(fingerprint)) => {
                        fingerprints.push((device_id.to_string(), fingerprint));
                    }
                    Ok(Err(e)) => {
                        fingerprints.push((device_id.to_string(), format!("Error: {}", e)));
                    }
                    Err(_) => {
                        fingerprints.push((
                            device_id.to_string(),
                            "Error: Timeout retrieving fingerprint".to_string(),
                        ));
                    }
                }
            }

            // Also fetch the active contact's fingerprints
            let active_contact = chat_ui.get_active_contact();
            let (contact_jid, contact_fingerprints) =
                if !active_contact.is_empty() && active_contact != bare_jid {
                    let contact_bare = active_contact.split('/').next().unwrap_or(&active_contact);
                    let mut cfps = Vec::new();
                    if let Ok(Ok(contact_device_ids)) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        xmpp_client.get_device_ids_for_user(contact_bare),
                    )
                    .await
                    {
                        for device_id in &contact_device_ids {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                xmpp_client.get_device_fingerprint(contact_bare, *device_id),
                            )
                            .await
                            {
                                Ok(Ok(fp)) => cfps.push((device_id.to_string(), fp)),
                                Ok(Err(e)) => {
                                    cfps.push((device_id.to_string(), format!("Error: {}", e)))
                                }
                                Err(_) => cfps.push((device_id.to_string(), "Timeout".to_string())),
                            }
                        }
                    }
                    (Some(contact_bare.to_string()), cfps)
                } else {
                    (None, Vec::new())
                };

            if fingerprints.is_empty() {
                chat_ui.add_message(create_system_message(
                    "me",
                    "No device fingerprints could be retrieved.",
                ));
            } else {
                let current_device_id = match xmpp_client.get_own_device_id().await {
                    Ok(id) => Some(id.to_string()),
                    Err(_) => None,
                };
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    chat_ui.show_device_fingerprints_dialog(
                        fingerprints.clone(),
                        current_device_id,
                        contact_jid.clone(),
                        contact_fingerprints.clone(),
                    );
                })) {
                    Ok(_) => {}
                    Err(_) => {
                        chat_ui.reset_device_fingerprints_dialog();
                        chat_ui.add_message(create_system_message(
                            "me",
                            "Failed to display fingerprints in dialog. Showing as messages instead:",
                        ));
                        for (device_id, fingerprint) in fingerprints {
                            chat_ui.add_message(create_system_message(
                                "me",
                                &format!("Device {}: {}", device_id, fingerprint),
                            ));
                        }
                    }
                }
            }
            if let Err(e) = terminal.draw(|f| chat_ui.draw(f)) {
                chat_ui.reset_device_fingerprints_dialog();
                chat_ui.add_message(create_system_message(
                    "me",
                    &format!("Error displaying device fingerprints dialog: {}", e),
                ));
            }
        }
        Ok(Ok(_)) => {
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                "No OMEMO devices found for your account.",
            ));
        }
        Ok(Err(e)) => {
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                &format!("Failed to retrieve device IDs: {}", e),
            ));
        }
        Err(_) => {
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                "Timed out while retrieving device IDs",
            ));
        }
    }
}

async fn handle_verify_keys_send(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    actual_recipient: &str,
    content: &str,
    last_state_sent: &mut Option<TypingStatus>,
) -> Result<()> {
    info!(
        "MAIN: Processing message with __VERIFY_KEYS__ prefix. Actual recipient: {}",
        actual_recipient
    );
    chat_ui.add_message(create_system_message(
        actual_recipient,
        "Preparing secure message...",
    ));
    *last_state_sent = None;

    if let Err(e) = xmpp_client
        .send_chat_state(actual_recipient, &TypingStatus::Active)
    {
        error!("Failed to send active state after message: {}", e);
    }
    terminal.draw(|f| chat_ui.draw(f))?;

    if chat_ui.is_omemo_enabled() {
        info!(
            "MAIN: UI OMEMO is enabled, attempting encrypted message to: {}",
            actual_recipient
        );

        if xmpp_client.is_omemo_enabled().await {
            if let Err(e) = xmpp_client
                .check_omemo_keys_for_contact(actual_recipient)
                .await
            {
                error!("Error checking OMEMO keys: {}", e);
                chat_ui.remove_last_message();
                chat_ui.add_message(create_system_message(
                    actual_recipient,
                    &format!("Error checking encryption keys: {}", e),
                ));
                return Ok(());
            }

            match xmpp_client
                .send_encrypted_message(actual_recipient, content)
                .await
            {
                Ok(_) => {
                    info!(
                        "MAIN: Encrypted message sent successfully to {}",
                        actual_recipient
                    );
                    chat_ui.remove_last_message();
                }
                Err(e) => {
                    error!(
                        "MAIN: Error sending encrypted message to {}: {}",
                        actual_recipient, e
                    );
                    chat_ui.remove_last_message();
                    chat_ui.add_message(create_system_message(
                        actual_recipient,
                        &format!("Error sending encrypted message: {}", e),
                    ));
                }
            }
        } else {
            warn!("MAIN: OMEMO requested but not available, falling back to plaintext");
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                actual_recipient,
                "OMEMO encryption requested but not available. Message not sent. Please initialize OMEMO or disable encryption.",
            ));
        }
    } else {
        info!(
            "MAIN: UI OMEMO is disabled, sending plaintext message to: {}",
            actual_recipient
        );
        match xmpp_client
            .send_message_with_receipt(actual_recipient, content)
            .await
        {
            Ok(_) => {
                info!(
                    "MAIN: Plaintext message sent successfully to {}",
                    actual_recipient
                );
                chat_ui.remove_last_message();
            }
            Err(e) => {
                error!(
                    "MAIN: Error sending plaintext message to {}: {}",
                    actual_recipient, e
                );
                chat_ui.remove_last_message();
                chat_ui.add_message(create_system_message(
                    actual_recipient,
                    &format!("Error sending message: {}", e),
                ));
            }
        }
    }
    Ok(())
}

async fn handle_toggle_omemo_trust(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    recipient: &str,
) {
    info!("Toggling OMEMO trust for {}", recipient);
    chat_ui.add_message(create_system_message(
        recipient,
        "Toggling trust status for all OMEMO devices...",
    ));
    let _ = terminal.draw(|f| chat_ui.draw(f));

    match xmpp_client.toggle_omemo_trust(recipient).await {
        Ok(is_now_trusted) => {
            let status_msg = if is_now_trusted {
                format!("All OMEMO devices for {} are now TRUSTED", recipient)
            } else {
                format!("All OMEMO devices for {} are now UNTRUSTED", recipient)
            };
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(recipient, &status_msg));
        }
        Err(e) => {
            error!("Failed to toggle OMEMO trust: {}", e);
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                recipient,
                &format!("Failed to toggle OMEMO trust: {}", e),
            ));
        }
    }
}

async fn handle_show_add_contact(chat_ui: &mut ChatUI, xmpp_client: &mut XMPPClient) {
    if let Ok(Some(creds)) = load_credentials() {
        info!("Showing add contact dialog with server: {}", creds.server);
        chat_ui.show_add_contact_dialog(&creds.server);
    } else if let Some(server) = xmpp_client.get_server_domain().await {
        info!(
            "Showing add contact dialog with server from connection: {}",
            server
        );
        chat_ui.show_add_contact_dialog(&server);
    } else {
        chat_ui.add_message(create_system_message(
            "me",
            "Could not determine server domain for adding contacts. Please use a full JID.",
        ));
    }
}

async fn handle_add_contact(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    recipient: &str,
) {
    info!("Adding new contact: {}", recipient);
    chat_ui.add_message(create_system_message(
        "me",
        &format!("Adding contact {}...", recipient),
    ));
    let _ = terminal.draw(|f| chat_ui.draw(f));

    match xmpp_client.add_contact_to_roster(recipient).await {
        Ok(_) => {
            info!("Successfully added contact {} to roster", recipient);
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                &format!("Contact {} added successfully", recipient),
            ));
            chat_ui.add_contact(recipient);
            chat_ui.set_active_contact(recipient);
            chat_ui.clear_messages();
            chat_ui.add_message(create_system_message(
                recipient,
                "Contact added. You can now start chatting.",
            ));
        }
        Err(e) => {
            error!("Failed to add contact {}: {}", recipient, e);
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                &format!("Failed to add contact {}: {}", recipient, e),
            ));
        }
    }
}

async fn handle_remove_contact(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    recipient: &str,
    content: &str,
    disable_mam: bool,
) {
    if content == "__REMOVE_CONTACT__" {
        info!("Preparing to remove contact: {}", recipient);
        chat_ui.show_contact_remove_dialog(recipient);
        let _ = terminal.draw(|f| chat_ui.draw(f));
        return;
    }

    // __REMOVE_CONTACT_CONFIRMED__
    info!("Removing contact: {}", recipient);
    chat_ui.add_message(create_system_message(
        "me",
        &format!("Removing contact {}...", recipient),
    ));
    let _ = terminal.draw(|f| chat_ui.draw(f));

    let current_contacts = chat_ui.contacts.clone();
    let removed_contact = recipient.to_string();

    match xmpp_client.remove_contact_from_roster(recipient).await {
        Ok(_) => {
            info!("Successfully removed contact {} from roster", recipient);
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                &format!("Contact {} removed successfully", recipient),
            ));

            let mut updated_contacts = Vec::new();
            let mut success = false;

            for attempt in 1..=3u64 {
                info!("Roster fetch attempt {} after contact removal", attempt);
                match xmpp_client.get_roster().await {
                    Ok(Some(contacts)) => {
                        updated_contacts = contacts;
                        success = true;
                        info!(
                            "Successfully retrieved updated roster with {} contacts",
                            updated_contacts.len()
                        );
                        break;
                    }
                    Ok(None) => {
                        warn!("Server returned empty roster on attempt {}", attempt);
                    }
                    Err(e) => {
                        error!("Failed to retrieve roster on attempt {}: {}", attempt, e);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(300 * attempt)).await;
            }

            if !success || updated_contacts.is_empty() {
                warn!("Using fallback contact list after removal");
                updated_contacts = current_contacts
                    .iter()
                    .filter(|&c| c != &removed_contact)
                    .cloned()
                    .collect();
            }

            chat_ui.contacts.clear();

            if updated_contacts.is_empty() {
                chat_ui.add_contact("[No contacts found]");
                chat_ui.set_active_contact("[No contacts found]");
                chat_ui.clear_messages();
                chat_ui.add_message(create_system_message(
                    "me",
                    "No contacts in your roster. Use Ctrl+A to add a contact.",
                ));
            } else {
                for contact in &updated_contacts {
                    chat_ui.add_contact(contact);
                }
                let first_contact = updated_contacts[0].clone();
                chat_ui.set_active_contact(&first_contact);
                chat_ui.clear_messages();
                load_message_history_async(chat_ui, xmpp_client, &first_contact, disable_mam);
                load_message_history_async(chat_ui, xmpp_client, &first_contact, disable_mam);
            }
        }
        Err(e) => {
            error!("Failed to remove contact {}: {}", recipient, e);
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                &format!("Failed to remove contact {}: {}", recipient, e),
            ));
        }
    }
}

async fn handle_enable_carbons(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
) {
    info!("Enabling message carbons");
    chat_ui.add_message(create_system_message("me", "Enabling message carbons..."));
    let _ = terminal.draw(|f| chat_ui.draw(f));

    match xmpp_client.enable_carbons().await {
        Ok(_) => {
            info!("Successfully enabled message carbons");
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                "Message carbons enabled successfully",
            ));
        }
        Err(e) => {
            error!("Failed to enable message carbons: {}", e);
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                "me",
                &format!("Failed to enable message carbons: {}", e),
            ));
        }
    }
}

async fn handle_refetch_omemo(chat_ui: &mut ChatUI, xmpp_client: &mut XMPPClient, recipient: &str) {
    let jid = recipient.split('/').next().unwrap_or(recipient);
    chat_ui.add_message(create_system_message(
        jid,
        &format!("Forcing OMEMO device list re-fetch for {}...", jid),
    ));
    info!(
        "DEBUG: Forcing OMEMO device list re-fetch for {} (Ctrl+R)",
        jid
    );

    if let Some(omemo_manager) = xmpp_client.get_omemo_manager() {
        match omemo_manager.lock().await.get_device_ids_for_test(jid).await {
            Ok(device_ids) if !device_ids.is_empty() => {
                chat_ui.add_message(create_system_message(
                    jid,
                    &format!(
                        "Found {} OMEMO device(s): {:?}",
                        device_ids.len(),
                        device_ids
                    ),
                ));
                info!("DEBUG: OMEMO device IDs for {}: {:?}", jid, device_ids);
                for device_id in device_ids {
                    match xmpp_client.get_device_fingerprint(jid, device_id).await {
                        Ok(fingerprint) => {
                            chat_ui.add_message(create_system_message(
                                jid,
                                &format!("Device {} fingerprint: {}", device_id, fingerprint),
                            ));
                        }
                        Err(e) => {
                            chat_ui.add_message(create_system_message(
                                jid,
                                &format!(
                                    "Could not retrieve fingerprint for device {}: {}",
                                    device_id, e
                                ),
                            ));
                            warn!(
                                "DEBUG: Could not retrieve fingerprint for device {} of {}: {}",
                                device_id, jid, e
                            );
                        }
                    }
                }
            }
            Ok(_) => {
                chat_ui.add_message(create_system_message(jid, "No OMEMO devices found."));
                warn!("DEBUG: No OMEMO devices found for {}", jid);
            }
            Err(e) => {
                chat_ui.add_message(create_system_message(
                    jid,
                    &format!("Failed to force OMEMO device list re-fetch: {}", e),
                ));
                error!(
                    "DEBUG: Failed to force OMEMO device list re-fetch for {}: {}",
                    jid, e
                );
            }
        }
    } else {
        chat_ui.add_message(create_system_message(jid, "OMEMO not initialized"));
    }
}

async fn handle_send_message(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    recipient: &str,
    content: &str,
    last_state_sent: &mut Option<TypingStatus>,
    store: Option<&MessageStore>,
) -> Result<()> {
    chat_ui.add_message(create_system_message(recipient, "Sending message..."));
    *last_state_sent = None;

    if let Err(e) = xmpp_client
        .send_chat_state(recipient, &TypingStatus::Active)
    {
        error!("Failed to send active state after message: {}", e);
    }
    terminal.draw(|f| chat_ui.draw(f))?;

    let prepared_content = prepare_message_for_sending(chat_ui, recipient, content);

    let send_result = if chat_ui.is_omemo_enabled() {
        xmpp_client.send_message(recipient, &prepared_content).await
    } else {
        xmpp_client
            .send_message_with_receipt(recipient, &prepared_content)
            .await
    };

    match send_result {
        Ok(_) => {
            chat_ui.remove_last_message();
            let message_id = uuid::Uuid::new_v4().to_string();
            let message = Message::outgoing_encrypted(message_id.clone(), recipient.to_string(), content.to_string());
            chat_ui.add_message(message.clone());
            // Persist outgoing message locally
            if let Some(s) = store {
                if let Err(e) = s.store_message(&message) {
                    error!("Failed to persist outgoing message: {}", e);
                }
            }
            if let Err(e) = xmpp_client.store_message_id(recipient, &message_id).await {
                error!("Failed to store message ID for tracking: {}", e);
            }
        }
        Err(e) => {
            chat_ui.remove_last_message();
            chat_ui.add_message(create_system_message(
                recipient,
                &format!("Error sending message: {}", e),
            ));
            error!("Failed to send message to {}: {}", recipient, e);
        }
    }
    Ok(())
}

pub fn handle_new_omemo_key(
    ui: &mut ChatUI,
    contact: &str,
    fingerprint: &str,
    device_id: Option<&str>,
) {
    ui.show_key_confirmation(contact, fingerprint, device_id);
}

pub fn prepare_message_for_sending(_ui: &ChatUI, _recipient: &str, message: &str) -> String {
    message.to_string()
}

/// Check for pending OMEMO key verifications and show popups
async fn check_pending_key_verifications(
    chat_ui: &mut ChatUI,
    xmpp_client: &XMPPClient,
) -> Result<()> {
    info!("Checking for pending OMEMO key verifications");

    if !xmpp_client.is_omemo_enabled().await {
        info!("OMEMO is not enabled, skipping key verification check");
        return Ok(());
    }

    let storage = match chatterbox::omemo::storage::OmemoStorage::new_default() {
        Ok(storage) => storage,
        Err(e) => {
            error!("Failed to create OMEMO storage: {}", e);
            return Err(anyhow::anyhow!("Failed to create OMEMO storage: {}", e));
        }
    };

    let contacts = chat_ui.contacts.clone();

    for contact in contacts {
        if contact.starts_with('[') && contact.ends_with(']') {
            continue;
        }

        match storage.get_pending_device_verification(&contact) {
            Ok(Some((device_id, fingerprint))) => {
                info!(
                    "Found pending key verification for {}:{} with fingerprint {}",
                    contact, device_id, fingerprint
                );
                handle_new_omemo_key(chat_ui, &contact, &fingerprint, Some(&device_id.to_string()));
                break;
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    "Error checking pending verification for {}: {}",
                    contact, e
                );
            }
        }
    }

    Ok(())
}
