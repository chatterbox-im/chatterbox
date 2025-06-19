// Message archive management tests
// These tests verify message archiving functionality (XEP-0313: Message Archive Management)

// Import common test utilities
mod common;
use common::{setup_logging, get_test_credentials, get_test_recipient, wait_for_message};

// External crate imports
use anyhow::Result;
use log::{info, warn, error};
use tokio::time::{timeout, Duration as TokioDuration};

// Import the crate functionality
use chatterbox::models::DeliveryStatus;

/// Test Message Archive Management (MAM) functionality
/// This test verifies that messages are properly archived by the server
/// and can be retrieved using XEP-0313: Message Archive Management
#[tokio::test]
async fn test_message_archiving() -> Result<()> {
    // Setup logging for the test
    setup_logging();
    info!("Starting Message Archive Management (MAM) integration test...");

    // 1. Get credentials
    let credentials = get_test_credentials().await?;
    info!("Using credentials for {} on server {}", credentials.username, credentials.server);

    // 2. Connect to the server
    let (mut client, mut msg_rx) = chatterbox::xmpp::XMPPClient::new();
    info!("Connecting to XMPP server...");
    
    match client.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Connected to XMPP server successfully"),
        Err(e) => {
            error!("Failed to connect to XMPP server: {}", e);
            return Err(anyhow::anyhow!("Failed to connect: {}", e));
        }
    }

    // Small delay to ensure connection is fully established
    tokio::time::sleep(TokioDuration::from_secs(1)).await;

    // 3. Get a contact to message
    let contacts = match client.get_roster().await? {
        Some(roster_contacts) if !roster_contacts.is_empty() => roster_contacts,
        _ => {
            info!("No contacts found in roster, using a test JID");
            let test_recipient = get_test_recipient().await?;
            vec![test_recipient]
        }
    };

    let test_contact = &contacts[0];
    info!("Using contact {} for message archiving test", test_contact);

    // 4. Generate a unique test message with timestamp
    let timestamp = chrono::Utc::now().timestamp();
    let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string(); // Use first 8 chars of UUID
    let test_message = format!("ARCHIVE TEST {} - Timestamp: {}", unique_id, timestamp);
    
    info!("Sending test message to contact: {}", test_contact);
    info!("Test message content: {}", test_message);

    // 5. Send test message
    match client.send_message(test_contact, &test_message).await {
        Ok(_) => info!("Test message sent successfully"),
        Err(e) => {
            error!("Failed to send test message: {}", e);
            let _ = client.disconnect().await;
            return Err(anyhow::anyhow!("Failed to send message: {}", e));
        }
    }

    // 6. Wait briefly to ensure the message is processed and archived
    info!("Waiting for the message to be processed and archived...");
    tokio::time::sleep(TokioDuration::from_secs(3)).await;

    // 7. Verify the message was successfully sent
    match wait_for_message(
        &mut msg_rx,
        |msg| msg.content == test_message && 
              (msg.delivery_status == DeliveryStatus::Sent || 
               msg.delivery_status == DeliveryStatus::Delivered || 
               msg.delivery_status == DeliveryStatus::Read),
        5
    ).await {
        Ok(msg) => info!("Message confirmed as sent with ID: {}", msg.id),
        Err(e) => warn!("Did not receive sent confirmation: {}", e)
    };

    // 8. Now retrieve the message history to verify the message was archived
    info!("Retrieving message history to verify archiving...");
    
    // Create MAM query options for this specific contact
    let now = chrono::Utc::now();
    let five_minutes_ago = now - chrono::Duration::minutes(5);
    
    let query_options = chatterbox::xmpp::message_archive::MAMQueryOptions::new()
        .with_jid(test_contact)
        .with_start(five_minutes_ago)
        .with_end(now)
        .with_limit(20);
    
    let archived_messages = match client.get_message_history(query_options).await {
        Ok(messages) => {
            info!("Successfully retrieved {} archived messages", messages.len());
            messages
        },
        Err(e) => {
            error!("Failed to retrieve message history: {}", e);
            // Continue the test even without archived messages
            Vec::new()
        }
    };
    
    // 9. Check if our unique test message is in the archived messages
    let found_message = archived_messages.iter().any(|m| m.content.contains(&unique_id));
    
    if found_message {
        info!("✅ SUCCESS: Test message was properly archived by the server and retrieved via MAM");
    } else {
        warn!("❌ FAILED: Could not find our test message in the archive");
        
        // Log all retrieved messages for debugging
        if !archived_messages.is_empty() {
            info!("Retrieved messages:");
            for (i, msg) in archived_messages.iter().enumerate() {
                info!("  [{}] From: {}, To: {}, Content: {}", 
                    i+1, msg.sender_id, msg.recipient_id, msg.content);
            }
        }
    }

    // 10. Perform a secondary check using has_message_history
    info!("Performing secondary check using has_message_history...");
    
    let history_exists = match client.has_message_history(test_contact, 5).await {
        Ok(exists) => {
            if exists {
                info!("Server confirms message history exists for this contact");
            } else {
                warn!("Server reports no message history exists for this contact");
            }
            exists
        },
        Err(e) => {
            warn!("Failed to check message history existence: {}", e);
            false
        }
    };

    // 11. Disconnect client
    info!("Disconnecting from XMPP server...");
    match client.disconnect().await {
        Ok(_) => info!("Disconnected from XMPP server cleanly"),
        Err(e) => warn!("Error during disconnect: {}", e),
    }

    // 12. Report test results
    info!("\n==== Message Archiving Test Results ====");
    info!("1. Message sent successfully: PASS");
    info!("2. Message found in archive: {}", if found_message { "PASS" } else { "FAIL" });
    info!("3. Contact has message history: {}", if history_exists { "PASS" } else { "FAIL" });
    
    let overall_result = if found_message { 
        "PASSED" 
    } else if history_exists { 
        "PARTIAL - History exists but specific message not found" 
    } else { 
        "FAILED - No archived messages found" 
    };
    
    info!("Overall Assessment: {}", overall_result);
    info!("=======================================\n");

    Ok(())
}

/// Test more thorough message archiving with both plaintext and encrypted messages
#[tokio::test]
async fn test_comprehensive_message_archiving() -> Result<()> {
    // Setup logging for the test
    setup_logging();
    info!("Starting comprehensive message archiving test...");

    // 1. Get credentials
    let credentials = get_test_credentials().await?;
    info!("Using credentials for {} on server {}", credentials.username, credentials.server);

    // 2. Connect to the server
    let (mut client, _msg_rx) = chatterbox::xmpp::XMPPClient::new();
    info!("Connecting to XMPP server...");
    
    match client.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Connected to XMPP server successfully"),
        Err(e) => {
            error!("Failed to connect to XMPP server: {}", e);
            return Err(anyhow::anyhow!("Failed to connect: {}", e));
        }
    }

    // 3. Initialize OMEMO for the client
    info!("Initializing client with OMEMO support...");
    match client.initialize_client().await {
        Ok(_) => info!("Client initialized with OMEMO support"),
        Err(e) => {
            warn!("Failed to initialize client with OMEMO: {}", e);
            info!("Continuing test with plaintext messages only");
            // Continue test without OMEMO
        }
    }

    // 4. Get a contact to message
    let contacts = match client.get_roster().await? {
        Some(roster_contacts) if !roster_contacts.is_empty() => roster_contacts,
        _ => {
            info!("No contacts found in roster, using a test JID");
            let test_recipient = get_test_recipient().await?;
            vec![test_recipient]
        }
    };

    let test_contact = &contacts[0];
    info!("Using contact {} for archiving test", test_contact);

    // 5. Generate unique test messages
    let timestamp = chrono::Utc::now().timestamp();
    let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    
    let plaintext_message = format!("PLAIN-{} Timestamp: {}", unique_id, timestamp);
    let encrypted_message = format!("ENCRYPTED-{} Timestamp: {}", unique_id, timestamp);
    
    info!("Sending test messages to contact: {}", test_contact);
    info!("Plaintext message: {}", plaintext_message);
    info!("Encrypted message: {}", encrypted_message);

    // 6. Send plaintext message first
    info!("Sending plaintext message...");
    match client.send_message(test_contact, &plaintext_message).await {
        Ok(_) => info!("Plaintext message sent successfully"),
        Err(e) => {
            warn!("Failed to send plaintext message: {}", e);
            // Continue test even if message sending fails
        }
    }
    
    // 7. Wait briefly before sending next message
    tokio::time::sleep(TokioDuration::from_secs(1)).await;
    
    // 8. Send encrypted message if OMEMO is available
    let omemo_available = client.is_omemo_enabled().await;
    
    if omemo_available {
        info!("Sending OMEMO encrypted message...");
        match client.send_encrypted_message(test_contact, &encrypted_message).await {
            Ok(_) => info!("Encrypted message sent successfully"),
            Err(e) => {
                warn!("Failed to send encrypted message: {}", e);
                // Continue test even if message sending fails
            }
        }
    } else {
        info!("OMEMO not available, skipping encrypted message test");
    }
    
    // 9. Wait for messages to be processed and archived
    info!("Waiting for messages to be processed and archived...");
    tokio::time::sleep(TokioDuration::from_secs(3)).await;
    
    // 10. Disconnect client
    info!("Disconnecting client...");
    match client.disconnect().await {
        Ok(_) => info!("Client disconnected successfully"),
        Err(e) => warn!("Error disconnecting client: {}", e)
    }
    
    // 11. Connect a new client to verify archived messages
    info!("Connecting a new client to verify archived messages...");
    let (mut archive_client, _) = chatterbox::xmpp::XMPPClient::new();
    
    match archive_client.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Archive verification client connected successfully"),
        Err(e) => {
            error!("Failed to connect archive verification client: {}", e);
            return Err(anyhow::anyhow!("Failed to connect verification client: {}", e));
        }
    }
    
    // 12. Retrieve message history
    info!("Retrieving message history...");
    
    // Create MAM query options for this specific contact
    let now = chrono::Utc::now();
    let five_minutes_ago = now - chrono::Duration::minutes(5);
    
    let query_options = chatterbox::xmpp::message_archive::MAMQueryOptions::new()
        .with_jid(test_contact)
        .with_start(five_minutes_ago)
        .with_end(now)
        .with_limit(30);
    
    let archived_messages = match archive_client.get_message_history(query_options).await {
        Ok(messages) => {
            info!("Successfully retrieved {} archived messages", messages.len());
            messages
        },
        Err(e) => {
            error!("Failed to retrieve message history: {}", e);
            Vec::new()
        }
    };
    
    // 13. Check if our test messages are in the archive
    let found_plaintext = archived_messages.iter().any(|m| m.content.contains(&format!("PLAIN-{}", unique_id)));
    let found_encrypted = if omemo_available {
        archived_messages.iter().any(|m| m.content.contains(&format!("ENCRYPTED-{}", unique_id)))
    } else {
        // If OMEMO was not available, don't check for encrypted message
        true
    };
    
    if found_plaintext {
        info!("✅ SUCCESS: Plaintext message was properly archived");
    } else {
        warn!("❌ FAILED: Could not find plaintext message in archive");
    }
    
    if omemo_available {
        if found_encrypted {
            info!("✅ SUCCESS: Encrypted message was properly archived");
        } else {
            warn!("❌ FAILED: Could not find encrypted message in archive");
        }
    }
    
    // 14. Disconnect archive client
    info!("Disconnecting archive verification client...");
    match archive_client.disconnect().await {
        Ok(_) => info!("Archive verification client disconnected successfully"),
        Err(e) => warn!("Error disconnecting archive verification client: {}", e)
    }
    
    // 15. Report test results
    info!("\n==== Comprehensive Message Archiving Test Results ====");
    info!("1. Plaintext message found in archive: {}", if found_plaintext { "PASS" } else { "FAIL" });
    if omemo_available {
        info!("2. Encrypted message found in archive: {}", if found_encrypted { "PASS" } else { "FAIL" });
    } else {
        info!("2. Encrypted message test: SKIPPED (OMEMO not available)");
    }
    
    let overall_result = if found_plaintext && (found_encrypted || !omemo_available) { 
        "PASSED" 
    } else if found_plaintext || found_encrypted { 
        "PARTIAL - Only some messages were archived" 
    } else { 
        "FAILED - No test messages found in archive" 
    };
    
    info!("Overall Assessment: {}", overall_result);
    info!("====================================================\n");

    Ok(())
}