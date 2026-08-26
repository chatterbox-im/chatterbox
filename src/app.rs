// src/app.rs
//! Application logic: UI setup, event loop, and helper functions.
//! Extracted from main.rs to keep the entry point minimal.

use anyhow::Result;
use log::{debug, error, info, warn};
use notify_rust::Notification;
use std::io;

use crate::{
    commands::UiCommand,
    credentials::{load_app_settings, load_credentials, save_app_settings, AppSettings},
    ui::ChatUI,
};
use chatterbox::{
    models::{AppEvent, Message, PresenceEvent},
    omemo::device_id::DeviceId,
    storage::MessageStore,
    xmpp::message_archive::MAMQueryOptions,
    xmpp::{chat_states::TypingStatus, XMPPClient},
};

/// Creates a system message for display in the UI
pub fn create_system_message(to: &str, content: &str) -> Message {
    Message::system(to, content)
}

/// Run the full application after a successful XMPP connection.
/// This sets up the TUI, loads contacts/fingerprints, and enters the main event loop.
pub async fn run_app(
    mut xmpp_client: XMPPClient,
    mut msg_rx: tokio::sync::mpsc::Receiver<AppEvent>,
    typing_rx: tokio::sync::mpsc::Receiver<(String, TypingStatus)>,
    disable_mam: bool,
) -> Result<()> {
    // Setup terminal UI
    let mut terminal = crate::ui::setup_terminal()?;
    let mut chat_ui = ChatUI::new();
    let mut app_settings = match load_app_settings() {
        Ok(settings) => settings,
        Err(e) => {
            warn!("Failed to load app settings: {}. Using defaults.", e);
            AppSettings::default()
        }
    };
    chat_ui.set_os_notifications_enabled(app_settings.os_notifications_enabled);

    // Draw UI early
    terminal.draw(|f| chat_ui.draw(f))?;

    // Allow OMEMO initialization to complete fully
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    info!("Waiting for OMEMO initialization to complete...");

    // Open local message store
    let bare_jid = xmpp_client
        .get_jid()
        .split('/')
        .next()
        .unwrap_or(xmpp_client.get_jid())
        .to_string();
    let store = match MessageStore::open(&bare_jid) {
        Ok(s) => {
            info!("Local message store opened for {}", bare_jid);
            Some(s)
        }
        Err(e) => {
            error!(
                "Failed to open message store: {}. Messages won't be persisted locally.",
                e
            );
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

    // Refresh OMEMO device lists without adding diagnostic data to the chat.
    show_omemo_fingerprints(&mut chat_ui, &xmpp_client).await;

    // Draw UI again with the contact list
    terminal.draw(|f| chat_ui.draw(f))?;

    // Start message history loading in background if we have an active contact
    chat_ui.begin_history_loading();
    terminal.draw(|f| chat_ui.draw(f))?;
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
        &mut app_settings,
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
                match xmpp_client
                    .get_device_fingerprint(bare_jid, device_id)
                    .await
                {
                    Ok(fingerprint) => {
                        debug!(
                            "Loaded OMEMO fingerprint for {} device {}: {}",
                            bare_jid, device_id, fingerprint
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Could not retrieve fingerprint for OMEMO device {}: {}",
                            device_id, e
                        );
                    }
                }
            }
        } else {
            debug!("No OMEMO devices found for {}", bare_jid);
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
        chat_ui.finish_local_history_loading();
        return;
    }

    let active_contact = chat_ui.get_active_contact();

    if disable_mam {
        chat_ui.finish_local_history_loading();
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
                chat_ui.show_toast(format!("Loaded {} messages from local history", count));
                s.newest_timestamp(&active_contact).ok().flatten()
            }
            Ok(_) => None,
            Err(e) => {
                error!(
                    "Failed to load local messages for {}: {}",
                    active_contact, e
                );
                None
            }
        }
    } else {
        None
    };

    chat_ui.finish_local_history_loading();

    // MAM catch-up for messages newer than what we have locally
    load_message_history_with_catchup(
        chat_ui,
        xmpp_client,
        &active_contact,
        disable_mam,
        newest_ts,
    );
}

/// Set up the contacts list from the XMPP server
async fn setup_contacts(chat_ui: &mut ChatUI, xmpp_client: &mut XMPPClient, _disable_mam: bool) {
    // Always add own JID as a contact (for messaging other devices on same account)
    let our_bare_jid = xmpp_client
        .get_jid()
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    if !our_bare_jid.is_empty() {
        chat_ui.add_contact(&our_bare_jid);
    }

    match xmpp_client.get_roster().await {
        Ok(Some(contacts)) if !contacts.is_empty() => {
            for contact in contacts {
                chat_ui.add_contact(&contact);
            }
        }
        Ok(_) => {
            if chat_ui.contacts.len() <= 1 {
                // Only own JID present, no real contacts
                chat_ui.add_message(create_system_message(
                    "me",
                    "No contacts found in your roster. Use Add Contact (Ctrl+A) to add someone.",
                ));
            }
        }
        Err(e) => {
            error!("Error fetching roster: {}", e);
            chat_ui.add_message(create_system_message(
                "me",
                &format!(
                    "Failed to load contacts: {}. You can still chat with contacts by entering their full JID.",
                    e
                ),
            ));
        }
    }

    if !chat_ui.has_active_contact() {
        // Skip own JID; select the first real roster contact
        if let Some(contact) = chat_ui.contacts.iter().find(|c| **c != our_bare_jid).cloned() {
            chat_ui.set_active_contact(&contact);
        }
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

    chat_ui.show_toast("Checking for message history in background...");

    let client_clone = xmpp_client.clone();
    let contact_clone = contact.to_string();
    let msg_tx = xmpp_client.get_message_sender();

    tokio::spawn(async move {
        let has_history = match client_clone.has_message_history(&contact_clone, 1).await {
            Ok(exists) => {
                if !exists {
                    if let Err(e) = msg_tx
                        .send(AppEvent::Toast("No message history found".to_string()))
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
                    .send(AppEvent::Toast(format!(
                        "History check failed: {}. Attempting full retrieval...",
                        e
                    )))
                    .await
                {
                    error!("Failed to send history check error message: {}", send_err);
                }
                false
            }
        };

        if has_history {
            if let Err(e) = msg_tx
                .send(AppEvent::Toast("Fetching message history...".to_string()))
                .await
            {
                error!("Failed to send history fetching message: {}", e);
            }
        }

        let options = MAMQueryOptions::new()
            .with_jid(&contact_clone)
            .with_limit(50);

        match client_clone
            .get_message_history_with_pagination(options)
            .await
        {
            Ok(result) => {
                if result.messages.is_empty() {
                    if let Err(e) = msg_tx
                        .send(AppEvent::Toast("No message history found".to_string()))
                        .await
                    {
                        error!("Failed to send 'no history' message: {}", e);
                    }
                } else {
                    if let Err(e) = msg_tx
                        .send(AppEvent::Toast(format!(
                            "Loaded {} historical messages",
                            result.messages.len()
                        )))
                        .await
                    {
                        error!("Failed to send history success message: {}", e);
                    }

                    for message in &result.messages {
                        if let Err(e) = msg_tx.send(AppEvent::Chat(message.clone())).await {
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
                    .send(AppEvent::Toast(format!("Failed to load message history: {}", e)))
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

    chat_ui.show_toast("Checking server for new messages...");

    tokio::spawn(async move {
        let mut options = MAMQueryOptions::new()
            .with_jid(&contact_clone)
            .with_limit(50);

        // If we have local history, only fetch messages newer than what we have
        if let Some(ts) = since {
            let start_time = chrono::DateTime::from_timestamp_millis(ts as i64)
                .unwrap_or_else(|| chrono::Utc::now());
            options = options.with_start(start_time);
        }

        match client_clone
            .get_message_history_with_pagination(options)
            .await
        {
            Ok(result) => {
                if result.messages.is_empty() {
                    if let Err(e) = msg_tx
                        .send(AppEvent::Toast("No new messages on server".to_string()))
                        .await
                    {
                        error!("Failed to send catchup status: {}", e);
                    }
                } else {
                    if let Err(e) = msg_tx
                        .send(AppEvent::Toast(format!(
                            "Fetched {} new messages from server",
                            result.messages.len()
                        )))
                        .await
                    {
                        error!("Failed to send catchup status: {}", e);
                    }

                    for message in &result.messages {
                        if let Err(e) = msg_tx.send(AppEvent::Chat(message.clone())).await {
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
                    .send(AppEvent::Chat(create_system_message(
                        &contact_clone,
                        &format!("Server history check failed: {}", e),
                    )))
                    .await
                {
                    error!("Failed to send catchup error: {}", send_err);
                }
            }
        }
    });
}

/// Fetch one older page when the user reaches the top of the loaded history.
fn load_older_message_history(
    chat_ui: &mut ChatUI,
    xmpp_client: &XMPPClient,
    contact: &str,
    store: Option<&MessageStore>,
) {
    let Some((oldest_id, oldest_timestamp)) = chat_ui.oldest_message_cursor(contact) else {
        chat_ui.finish_older_history_load(contact, false);
        return;
    };

    // The local store may contain messages older than the initial window. Load
    // them now so they are available if the server archive is exhausted.
    let local_older = store
        .and_then(|s| s.load_messages_before(contact, oldest_timestamp, 50).ok())
        .unwrap_or_default();

    let client_clone = xmpp_client.clone();
    let contact_clone = contact.to_string();
    let msg_tx = xmpp_client.get_message_sender();
    let end_time = chrono::DateTime::from_timestamp_millis(oldest_timestamp)
        .unwrap_or_else(|| chrono::Utc::now());

    tokio::spawn(async move {
        let options = MAMQueryOptions::new()
            .with_jid(&contact_clone)
            .with_end(end_time)
            .with_before(&oldest_id)
            .with_limit(50);

        match client_clone.get_message_history_with_pagination(options).await {
            Ok(result) => {
                let server_has_older = !result.complete && !result.messages.is_empty();
                let use_local_fallback = result.complete || result.messages.is_empty();
                let mut messages = result.messages;
                if use_local_fallback && !local_older.is_empty() {
                    messages.extend(local_older.clone());
                    messages.sort_by_key(|message| message.timestamp);
                }
                let has_older = server_has_older || local_older.len() == 50;

                if messages.is_empty() {
                    let _ = msg_tx
                        .send(AppEvent::Toast("No older messages on server".to_string()))
                        .await;
                } else {
                    let _ = msg_tx
                        .send(AppEvent::Toast(format!(
                            "Loaded {} older messages",
                            messages.len()
                        )))
                        .await;
                }

                if let Err(e) = msg_tx
                    .send(AppEvent::HistoryPage {
                        contact: contact_clone,
                        messages,
                        has_older,
                    })
                    .await
                {
                    error!("Failed to send older history page: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to load older message history: {}", e);
                let has_older = local_older.len() == 50;
                let _ = msg_tx
                    .send(AppEvent::Toast(format!(
                        "Server history unavailable; checking local history ({})",
                        e
                    )))
                    .await;
                let _ = msg_tx
                    .send(AppEvent::HistoryPage {
                        contact: contact_clone,
                        messages: local_older,
                        has_older,
                    })
                    .await;
            }
        }
    });
}

/// Run the main event loop
async fn run_main_loop(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    msg_rx: &mut tokio::sync::mpsc::Receiver<AppEvent>,
    disable_mam: bool,
    mut typing_rx: tokio::sync::mpsc::Receiver<(String, TypingStatus)>,
    store: Option<&MessageStore>,
    app_settings: &mut AppSettings,
) -> Result<()> {
    let mut presence_rx = xmpp_client.subscribe_to_presence();
    let mut friend_req_rx = xmpp_client.subscribe_to_friend_requests();
    let mut terminal_events = crate::ui::TerminalEventReader::new();

    xmpp_client.resend_presence();
    chat_ui.set_connection_status(xmpp_client.is_client_accessible());

    let mut last_key_press = std::time::Instant::now();
    let mut last_state_sent = None::<TypingStatus>;
    let mut verified_contacts = std::collections::HashSet::new();
    let mut typing_failures: u32 = 0;
    let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut connection_tick = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut typing_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut history_loading_tick = tokio::time::interval(std::time::Duration::from_millis(150));
    let mut render_tick = tokio::time::interval(std::time::Duration::from_millis(16));
    let mut render_needed = true;
    let mut terminal_events_closed = false;
    let mut presence_closed = false;
    let mut friend_req_closed = false;
    let mut typing_closed = false;
    let mut last_render = std::time::Instant::now() - std::time::Duration::from_secs(1);

    check_active_contact_omemo_keys(chat_ui, xmpp_client, &mut verified_contacts);

    loop {
        if render_needed && last_render.elapsed() >= std::time::Duration::from_millis(16) {
            terminal.draw(|f| chat_ui.draw(f))?;
            render_needed = false;
            last_render = std::time::Instant::now();
        }

        tokio::select! {
            terminal_event = terminal_events.recv(), if !terminal_events_closed => {
                match terminal_event {
                    Some(event) => {
                        let is_composing_key = matches!(
                            &event,
                            crossterm::event::Event::Key(key)
                                if key.kind == crossterm::event::KeyEventKind::Press
                                    && matches!(key.code, crossterm::event::KeyCode::Char(_))
                                    && !key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                                    && !key.modifiers.contains(crossterm::event::KeyModifiers::ALT)
                        );
                        let input_result = chat_ui.handle_terminal_event(event)?;

                        if is_composing_key && chat_ui.has_pending_input() {
                            last_key_press = std::time::Instant::now();
                            typing_failures = 0;
                        }

                        if let Some(cmd) = input_result {
                            let quit = matches!(cmd, UiCommand::Quit);
                            handle_user_command(
                                chat_ui,
                                terminal,
                                xmpp_client,
                                cmd,
                                disable_mam,
                                &mut last_state_sent,
                                store,
                                app_settings,
                            )
                            .await?;

                            if quit {
                                break;
                            }
                        }

                        check_active_contact_omemo_keys(chat_ui, xmpp_client, &mut verified_contacts);
                        render_needed = true;
                    }
                    None => {
                        terminal_events_closed = true;
                    }
                }
            }
            message = msg_rx.recv() => {
                match message {
                    Some(event) => {
                        process_incoming_message(chat_ui, event, store);
                        while let Ok(event) = msg_rx.try_recv() {
                            process_incoming_message(chat_ui, event, store);
                        }
                        render_needed = true;
                    }
                    None => {
                        warn!("Message channel closed; exiting UI loop");
                        break;
                    }
                }
            }
            presence = presence_rx.recv(), if !presence_closed => {
                match presence {
                    Ok(event) => {
                        let mut changed = process_presence_event(chat_ui, event);
                        loop {
                            match presence_rx.try_recv() {
                                Ok(event) => changed |= process_presence_event(chat_ui, event),
                                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                                    warn!("Presence broadcast lagged by {} events, requesting refresh", n);
                                    xmpp_client.resend_presence();
                                }
                                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                                    presence_closed = true;
                                    break;
                                }
                                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                            }
                        }
                        render_needed |= changed;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Presence broadcast lagged by {} events, requesting refresh", n);
                        xmpp_client.resend_presence();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        presence_closed = true;
                    }
                }
            }
            friend_req = friend_req_rx.recv(), if !friend_req_closed => {
                match friend_req {
                    Ok(contact_id) => {
                        process_friend_request(chat_ui, contact_id);
                        loop {
                            match friend_req_rx.try_recv() {
                                Ok(contact_id) => process_friend_request(chat_ui, contact_id),
                                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => warn!("Friend request broadcast lagged by {} events", n),
                                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                                    friend_req_closed = true;
                                    break;
                                }
                                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                            }
                        }
                        render_needed = true;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Friend request broadcast lagged by {} events", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        friend_req_closed = true;
                    }
                }
            }
            typing = typing_rx.recv(), if !typing_closed => {
                match typing {
                    Some((contact_id, typing_status)) => {
                        chat_ui.update_typing_status(&contact_id, typing_status);
                        while let Ok((contact_id, typing_status)) = typing_rx.try_recv() {
                            chat_ui.update_typing_status(&contact_id, typing_status);
                        }
                        render_needed = true;
                    }
                    None => {
                        typing_closed = true;
                    }
                }
            }
            _ = cleanup_tick.tick() => {
                let typing_changed = chat_ui.clean_typing_states(30);
                let friend_request_changed = chat_ui.clean_friend_request_notifications(5);
                let toast_changed = chat_ui.clean_toasts(5);
                render_needed |= typing_changed || friend_request_changed || toast_changed;
            }
            _ = connection_tick.tick() => {
                let connected = xmpp_client.is_client_accessible();
                if chat_ui.is_connected() != connected {
                    chat_ui.set_connection_status(connected);
                    render_needed = true;
                }
            }
            _ = typing_tick.tick() => {
                update_outbound_typing_state(
                    chat_ui,
                    xmpp_client,
                    last_key_press,
                    &mut last_state_sent,
                    &mut typing_failures,
                );
            }
            _ = history_loading_tick.tick() => {
                if chat_ui.is_history_loading() {
                    chat_ui.advance_history_loading_animation();
                    render_needed = true;
                }
            }
            _ = render_tick.tick() => {}
        }
    }

    Ok(())
}

fn process_incoming_message(chat_ui: &mut ChatUI, event: AppEvent, store: Option<&MessageStore>) {
    match event {
        AppEvent::Toast(message) => chat_ui.show_toast(message),
        AppEvent::HistoryPage {
            contact,
            messages,
            has_older,
        } => {
            if chat_ui.get_active_contact() == contact {
                chat_ui.finish_older_history_load(&contact, has_older);
                for message in messages {
                    process_incoming_message(chat_ui, AppEvent::Chat(message), store);
                }
                chat_ui.keep_scroll_at_top();
            }
        }
        AppEvent::KeyVerifyRequest { sender, fingerprint, device_id } => {
            handle_new_omemo_key(chat_ui, &sender, &fingerprint, device_id.as_ref().map(|id| id.to_string()).as_deref());
        }
        AppEvent::Chat(message) => {
            chat_ui.add_message(message.clone());
            if message.sender_id != "system" {
                if let Some(s) = store {
                    if let Err(e) = s.store_message(&message) {
                        error!("Failed to persist message: {}", e);
                    }
                }
            }
            if message.sender_id != "me" && message.sender_id != "system" {
                chat_ui.message_received_from(&message.sender_id);
                if chat_ui.os_notifications_enabled() && !chat_ui.is_terminal_focused() {
                    notify_incoming_message(&message);
                }
            }
            if !chat_ui.contacts.contains(&message.sender_id)
                && message.sender_id != "me"
                && message.sender_id != "system"
            {
                chat_ui.add_contact(&message.sender_id);
            }
        }
    }
}

fn process_presence_event(chat_ui: &mut ChatUI, event: PresenceEvent) -> bool {
    if let Some((contact_id, status)) = event.to_contact_status() {
        let changed = chat_ui.get_contact_status(&contact_id) != status;
        chat_ui.update_contact_status(&contact_id, status);
        if changed {
            let bare_contact = contact_id.split('/').next().unwrap_or(&contact_id);
            let status_message = match chat_ui.get_contact_status(&contact_id) {
                chatterbox::models::ContactStatus::Online => {
                    Some(format!("{} is now online", bare_contact))
                }
                chatterbox::models::ContactStatus::Offline => {
                    Some(format!("{} went offline", bare_contact))
                }
                chatterbox::models::ContactStatus::Away => None,
            };
            if let Some(message) = status_message {
                chat_ui.add_message(create_system_message(bare_contact, &message));
            }
        }
        changed
    } else {
        false
    }
}

fn process_friend_request(chat_ui: &mut ChatUI, contact_id: String) {
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

fn check_active_contact_omemo_keys(
    chat_ui: &ChatUI,
    xmpp_client: &XMPPClient,
    verified_contacts: &mut std::collections::HashSet<String>,
) {
    if chat_ui.has_active_contact() && chat_ui.is_omemo_enabled() {
        let active_contact = chat_ui.get_active_contact();
        if !verified_contacts.contains(&active_contact) {
            verified_contacts.insert(active_contact.clone());
            let client_clone = xmpp_client.clone();
            let contact_clone = active_contact.clone();
            tokio::spawn(async move {
                if let Err(e) = client_clone
                    .check_omemo_keys_for_contact(&contact_clone)
                    .await
                {
                    error!("Failed to check OMEMO keys for {}: {}", contact_clone, e);
                }
            });
        }
    }
}

fn update_outbound_typing_state(
    chat_ui: &ChatUI,
    xmpp_client: &mut XMPPClient,
    last_key_press: std::time::Instant,
    last_state_sent: &mut Option<TypingStatus>,
    typing_failures: &mut u32,
) {
    if !chat_ui.has_active_contact() || *typing_failures >= 3 {
        return;
    }

    let elapsed = std::time::Instant::now().duration_since(last_key_press);
    let contact = chat_ui.get_active_contact();
    let next_state = if elapsed < std::time::Duration::from_secs(5) {
        Some(TypingStatus::Composing)
    } else if elapsed < std::time::Duration::from_secs(30) {
        Some(TypingStatus::Paused)
    } else {
        Some(TypingStatus::Inactive)
    };

    if next_state == *last_state_sent {
        return;
    }

    let next_state = next_state.expect("typing state is always selected");
    match xmpp_client.send_chat_state(&contact, &next_state) {
        Ok(_) => {
            *last_state_sent = Some(next_state);
            *typing_failures = 0;
        }
        Err(e) => {
            error!("Failed to send typing state {:?}: {}", next_state, e);
            *typing_failures += 1;
        }
    }
}

fn notify_incoming_message(message: &Message) {
    let summary = format!("New message from {}", message.sender_id);
    if let Err(e) = Notification::new()
        .summary(&summary)
        .body(&message.content)
        .appname("Chatterbox")
        .show()
    {
        debug!("Failed to show OS notification: {}", e);
    }
}

/// Dispatch a typed UI command from the input handler.
async fn handle_user_command(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
    cmd: UiCommand,
    disable_mam: bool,
    last_state_sent: &mut Option<TypingStatus>,
    store: Option<&MessageStore>,
    app_settings: &mut AppSettings,
) -> Result<()> {
    match cmd {
        UiCommand::Quit => {}

        UiCommand::SendPlainMessage { to, body } => {
            warn!("⚠️ SENDING UNENCRYPTED MESSAGE to {} ({} bytes)", to, body.len());
            match xmpp_client.send_message_with_receipt(&to, &body).await {
                Ok(_) => {
                    chat_ui.add_message(Message::outgoing_plaintext(
                        uuid::Uuid::new_v4().to_string(),
                        to,
                        body,
                    ));
                }
                Err(e) => error!("Failed to send plaintext message: {}", e),
            }
        }

        UiCommand::SendMessage { to, body } => {
            handle_send_message(
                chat_ui, terminal, xmpp_client, &to, &body, last_state_sent, store,
            ).await?;
        }

        UiCommand::ShowDeviceFingerprints => {
            handle_show_device_fingerprints(chat_ui, terminal, xmpp_client).await;
        }

        UiCommand::ToggleOmemoTrust { contact } => {
            handle_toggle_omemo_trust(chat_ui, terminal, xmpp_client, &contact).await;
        }

        UiCommand::SetDeviceTrust { jid, device_id, level } => {
            if let Err(e) = xmpp_client
                .set_single_device_trust(&jid, DeviceId::from(device_id), level)
                .await
            {
                info!("MAIN: set_single_device_trust failed: {}", e);
            }
        }

        UiCommand::ShowAddContact => {
            handle_show_add_contact(chat_ui, xmpp_client).await;
        }

        UiCommand::AddContact { jid } => {
            handle_add_contact(chat_ui, terminal, xmpp_client, &jid).await;
        }

        UiCommand::RemoveContact { contact } => {
            handle_remove_contact(
                chat_ui, terminal, xmpp_client, &contact,
                "__REMOVE_CONTACT__", disable_mam,
            ).await;
        }

        UiCommand::RemoveContactConfirmed { contact } => {
            handle_remove_contact(
                chat_ui, terminal, xmpp_client, &contact,
                "__REMOVE_CONTACT_CONFIRMED__", disable_mam,
            ).await;
        }

        UiCommand::ContactChanged { contact } => {
            info!("Contact changed to: {}", contact);
            *last_state_sent = None;
            chat_ui.clear_messages();
            chat_ui.begin_history_loading();
            terminal.draw(|f| chat_ui.draw(f))?;

            let first_view = !chat_ui.history_loaded_contacts.contains(&contact);

            let local_count = if let Some(s) = store {
                match s.load_messages(&contact, 100) {
                    Ok(msgs) if !msgs.is_empty() => {
                        let count = msgs.len();
                        for msg in msgs { chat_ui.add_message(msg); }
                        count
                    }
                    Ok(_) => 0,
                    Err(e) => {
                        error!("Failed to load local messages for {}: {}", contact, e);
                        0
                    }
                }
            } else { 0 };

            let newest_ts = store.and_then(|s| {
                s.newest_timestamp(&contact).ok().flatten()
            });

            if local_count > 0 {
                chat_ui.history_loaded_contacts.insert(contact.clone());
                if first_view {
                    load_message_history_with_catchup(
                        chat_ui, xmpp_client, &contact, disable_mam, newest_ts,
                    );
                }
            } else {
                load_message_history_async(
                    chat_ui, xmpp_client, &contact, disable_mam,
                );
            }
            chat_ui.finish_local_history_loading();
            terminal.draw(|f| chat_ui.draw(f))?;
        }

        UiCommand::LoadOlderHistory { contact } => {
            load_older_message_history(chat_ui, xmpp_client, &contact, store);
        }

        UiCommand::KeyAccepted { contact } => {
            if let Err(e) = xmpp_client.handle_key_verification_response(&contact, chatterbox::omemo::storage::TrustLevel::Trusted).await {
                error!("Failed to process key acceptance: {}", e);
                chat_ui.add_message(create_system_message(
                    &contact,
                    &format!("Error processing key verification: {}", e),
                ));
            }
        }

        UiCommand::KeyRejected { contact } => {
            if let Err(e) = xmpp_client.handle_key_verification_response(&contact, chatterbox::omemo::storage::TrustLevel::Untrusted).await {
                error!("Failed to process key rejection: {}", e);
                chat_ui.add_message(create_system_message(
                    &contact,
                    &format!("Error processing key verification: {}", e),
                ));
            }
        }

        UiCommand::EnableCarbons => {
            handle_enable_carbons(chat_ui, terminal, xmpp_client).await;
        }

        UiCommand::RefetchOmemo { contact } => {
            handle_refetch_omemo(chat_ui, xmpp_client, &contact).await;
        }

        UiCommand::ToggleOsNotifications => {
            app_settings.os_notifications_enabled = chat_ui.os_notifications_enabled();
            if let Err(e) = save_app_settings(app_settings) {
                error!("Failed to save app settings: {}", e);
                chat_ui.add_message(create_system_message(
                    "me",
                    &format!("Failed to save notification setting: {}", e),
                ));
            }
        }
    }
    Ok(())
}

async fn handle_show_device_fingerprints(
    chat_ui: &mut ChatUI,
    terminal: &mut crate::ui::Terminal<crate::ui::CrosstermBackend<io::Stdout>>,
    xmpp_client: &mut XMPPClient,
) {
    use chatterbox::omemo::TrustLevel;

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

    // ── helper: fetch fingerprint + trust for one device ──────────────────────
    async fn fetch_fp_trust(
        client: &XMPPClient,
        jid: &str,
        device_id: DeviceId,
    ) -> (String, TrustLevel) {
        let fp = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.get_device_fingerprint(jid, device_id),
        )
        .await
        {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => format!("(error: {})", e),
            Err(_) => "(timeout)".to_string(),
        };
        let trust = match client.get_device_trust_level(jid, device_id).await {
            Ok(t) => t,
            Err(_) => TrustLevel::Undecided,
        };
        (fp, trust)
    }

    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        xmpp_client.get_device_ids_for_user(bare_jid),
    )
    .await
    {
        Ok(Ok(device_ids)) if !device_ids.is_empty() => {
            chat_ui.remove_last_message();

            // ── own devices ───────────────────────────────────────────────────
            let current_device_id = xmpp_client.get_own_device_id().await.ok();
            let mut own_rows: Vec<(String, String, TrustLevel, bool)> = Vec::new();
            for device_id in &device_ids {
                let (fp, trust) = fetch_fp_trust(xmpp_client, bare_jid, *device_id).await;
                let is_current = current_device_id.map_or(false, |id| id == device_id.get());
                own_rows.push((device_id.to_string(), fp, trust, is_current));
            }

            // ── contact devices ───────────────────────────────────────────────
            let active_contact = chat_ui.get_active_contact();
            let (contact_jid, contact_rows) =
                if !active_contact.is_empty() && active_contact != bare_jid {
                    let contact_bare = active_contact.split('/').next().unwrap_or(&active_contact);
                    let mut rows: Vec<(String, String, TrustLevel)> = Vec::new();
                    if let Ok(Ok(contact_device_ids)) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        xmpp_client.get_device_ids_for_user(contact_bare),
                    )
                    .await
                    {
                        for device_id in &contact_device_ids {
                            let (fp, trust) =
                                fetch_fp_trust(xmpp_client, contact_bare, *device_id).await;
                            rows.push((device_id.to_string(), fp, trust));
                        }
                    }
                    (Some(contact_bare.to_string()), rows)
                } else {
                    (None, Vec::new())
                };

            if own_rows.is_empty() && contact_rows.is_empty() {
                chat_ui.add_message(create_system_message(
                    "me",
                    "No device fingerprints could be retrieved.",
                ));
            } else {
                chat_ui.show_device_fingerprints_dialog(
                    bare_jid.to_string(),
                    own_rows,
                    contact_jid,
                    contact_rows,
                );
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
            // If it's our own JID, add locally anyway (server rejects self-roster adds)
            let our_bare_jid = xmpp_client.get_jid().split('/').next().unwrap_or("");
            if recipient == our_bare_jid || recipient.eq_ignore_ascii_case(our_bare_jid) {
                info!(
                    "Adding own JID {} as local contact (server rejected roster add)",
                    recipient
                );
                chat_ui.remove_last_message();
                chat_ui.add_contact(recipient);
                chat_ui.set_active_contact(recipient);
                chat_ui.clear_messages();
                chat_ui.add_message(create_system_message(
                    recipient,
                    "Added as local contact (own JID). You can send messages to your other devices.",
                ));
            } else {
                error!("Failed to add contact {}: {}", recipient, e);
                chat_ui.remove_last_message();
                chat_ui.add_message(create_system_message(
                    "me",
                    &format!("Failed to add contact {}: {}", recipient, e),
                ));
            }
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
        match omemo_manager
            .lock()
            .await
            .get_device_ids_for_test(jid)
            .await
        {
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

    if let Err(e) = xmpp_client.send_chat_state(recipient, &TypingStatus::Active) {
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
            let message = if chat_ui.is_omemo_enabled() {
                Message::outgoing_encrypted(message_id.clone(), recipient.to_string(), content.to_string())
            } else {
                Message::outgoing_plaintext(message_id.clone(), recipient.to_string(), content.to_string())
            };
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

        match storage.get_pending_device_verification(&chatterbox::jid::BareJid::parse(&contact).expect("expected valid JID")) {
            Ok(Some((device_id, fingerprint))) => {
                info!(
                    "Found pending key verification for {}:{} with fingerprint {}",
                    contact, device_id, fingerprint
                );
                handle_new_omemo_key(
                    chat_ui,
                    &contact,
                    &fingerprint,
                    Some(&device_id.to_string()),
                );
                break;
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Error checking pending verification for {}: {}", contact, e);
            }
        }
    }

    Ok(())
}
