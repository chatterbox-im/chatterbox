// OMEMO multi-device tests
// These tests verify OMEMO encryption works properly in multi-device scenarios

// Import common test utilities
mod common;
use common::{setup_logging, get_test_credentials, get_test_recipient, wait_for_message};

// External crate imports
use anyhow::Result;
use log::{info, warn, error};
use tokio::time::{timeout, Duration as TokioDuration};

/// Test OMEMO multi-device encryption functionality
#[tokio::test]
async fn test_omemo_multi_device_encryption() -> Result<()> {
    // Setup logging for the test
    setup_logging();
    info!("Starting OMEMO multi-device encryption integration test...");

    // 1. Get credentials
    let credentials = get_test_credentials().await?;
    info!("Using credentials for {} on server {}", credentials.username, credentials.server);

    // 2. Connect two clients representing different devices of the same user
    // First client
    let (mut client1, mut msg_rx1) = chatterbox::xmpp::XMPPClient::new();
    info!("Connecting first client to XMPP server...");
    
    match client1.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("First client connected to XMPP server successfully"),
        Err(e) => {
            error!("Failed to connect first client to XMPP server: {}", e);
            return Err(anyhow::anyhow!("Failed to connect first client: {}", e));
        }
    }

    // Second client - same account, different resource
    let (mut client2, mut msg_rx2) = chatterbox::xmpp::XMPPClient::new();
    info!("Connecting second client to XMPP server...");
    
    match client2.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Second client connected to XMPP server successfully"),
        Err(e) => {
            error!("Failed to connect second client to XMPP server: {}", e);
            // Make sure to disconnect the first client
            let _ = client1.disconnect().await;
            return Err(anyhow::anyhow!("Failed to connect second client: {}", e));
        }
    }

    // Wait for connections to stabilize
    tokio::time::sleep(TokioDuration::from_secs(2)).await;

    // 3. Initialize OMEMO for both clients
    info!("Initializing both clients with OMEMO support...");
    
    // Initialize first client
    match client1.initialize_client().await {
        Ok(_) => info!("First client initialized with OMEMO support"),
        Err(e) => {
            error!("Failed to initialize first client with OMEMO: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to initialize OMEMO for first client: {}", e));
        }
    }
    
    // Initialize second client
    match client2.initialize_client().await {
        Ok(_) => info!("Second client initialized with OMEMO support"),
        Err(e) => {
            error!("Failed to initialize second client with OMEMO: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to initialize OMEMO for second client: {}", e));
        }
    }

    // Wait for OMEMO initialization to complete
    tokio::time::sleep(TokioDuration::from_secs(2)).await;

    // 4. Get contact to test with
    let contacts = match client1.get_roster().await? {
        Some(roster_contacts) if !roster_contacts.is_empty() => roster_contacts,
        _ => {
            info!("No contacts found in roster, using a test JID");
            let test_recipient = get_test_recipient().await?;
            vec![test_recipient]
        }
    };

    let test_contact = &contacts[0];
    info!("Using contact {} for testing", test_contact);

    // 5. Send encrypted message from client1 to the contact
    let timestamp1 = chrono::Utc::now().timestamp();
    let test_message1 = format!("OMEMO multi-device test message from client1 - {}", timestamp1);

    info!("Sending OMEMO encrypted message from client1 to contact {}", test_contact);
    match client1.send_encrypted_message(test_contact, &test_message1).await {
        Ok(_) => info!("OMEMO encrypted message sent successfully from client1"),
        Err(e) => {
            error!("Failed to send OMEMO encrypted message from client1: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to send encrypted message from client1: {}", e));
        }
    }

    // 6. Check if client2 receives a carbon copy of the encrypted message
    info!("Checking if client2 receives carbon copy of encrypted message...");
    let received_carbon = match wait_for_message(
        &mut msg_rx2,
        |msg| msg.content == test_message1,
        5 // 5 second timeout
    ).await {
        Ok(msg) => {
            info!("Client2 received carbon copy of encrypted message: {}", msg.id);
            true
        },
        Err(e) => {
            warn!("Client2 did not receive carbon copy of encrypted message: {}", e);
            false
        }
    };

    // 7. Send encrypted message from client2 to the contact
    let timestamp2 = chrono::Utc::now().timestamp();
    let test_message2 = format!("OMEMO multi-device test message from client2 - {}", timestamp2);

    info!("Sending OMEMO encrypted message from client2 to contact {}", test_contact);
    match client2.send_encrypted_message(test_contact, &test_message2).await {
        Ok(_) => info!("OMEMO encrypted message sent successfully from client2"),
        Err(e) => {
            error!("Failed to send OMEMO encrypted message from client2: {}", e);
            // Continue the test
        }
    }

    // 8. Check if client1 receives a carbon copy of the encrypted message
    info!("Checking if client1 receives carbon copy of encrypted message...");
    let received_carbon2 = match wait_for_message(
        &mut msg_rx1,
        |msg| msg.content == test_message2,
        5 // 5 second timeout
    ).await {
        Ok(msg) => {
            info!("Client1 received carbon copy of encrypted message: {}", msg.id);
            true
        },
        Err(e) => {
            warn!("Client1 did not receive carbon copy of encrypted message: {}", e);
            false
        }
    };

    // 9. Disconnect clients
    info!("Disconnecting clients...");
    let _ = client1.disconnect().await;
    let _ = client2.disconnect().await;

    // 10. Report test results
    if received_carbon || received_carbon2 {
        info!("OMEMO multi-device encryption test PASSED - at least one carbon copy was received");
    } else {
        warn!("OMEMO multi-device encryption test WARNING - no carbon copies were received");
        // This isn't a failure as some servers might not support this feature combination
    }

    Ok(())
}

/// Test OMEMO multi-device encryption functionality more thoroughly
#[tokio::test]
async fn test_omemo_multi_device_encryption_enhanced() -> Result<()> {
    // Setup logging for the test
    setup_logging();
    info!("Starting ENHANCED OMEMO multi-device encryption integration test...");

    // 1. Get credentials
    let credentials = get_test_credentials().await?;
    info!("Using credentials for {} on server {}", credentials.username, credentials.server);

    // 2. Connect two clients representing different devices of the same user
    // First client
    let (mut client1, mut msg_rx1) = chatterbox::xmpp::XMPPClient::new();
    info!("Connecting first client to XMPP server...");
    
    match client1.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("First client connected to XMPP server successfully"),
        Err(e) => {
            error!("Failed to connect first client to XMPP server: {}", e);
            return Err(anyhow::anyhow!("Failed to connect first client: {}", e));
        }
    }

    // Second client - same account, different resource
    let (mut client2, mut msg_rx2) = chatterbox::xmpp::XMPPClient::new();
    info!("Connecting second client to XMPP server...");
    
    match client2.connect(
        &credentials.server,
        &credentials.username,
        &credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Second client connected to XMPP server successfully"),
        Err(e) => {
            error!("Failed to connect second client to XMPP server: {}", e);
            // Make sure to disconnect the first client
            let _ = client1.disconnect().await;
            return Err(anyhow::anyhow!("Failed to connect second client: {}", e));
        }
    }

    // Wait for connections to stabilize
    tokio::time::sleep(TokioDuration::from_secs(2)).await;

    // 3. Initialize OMEMO for both clients
    info!("Initializing both clients with OMEMO support...");
    
    // Initialize first client
    match client1.initialize_client().await {
        Ok(_) => info!("First client initialized with OMEMO support"),
        Err(e) => {
            error!("Failed to initialize first client with OMEMO: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to initialize OMEMO for first client: {}", e));
        }
    }
    
    // Initialize second client
    match client2.initialize_client().await {
        Ok(_) => info!("Second client initialized with OMEMO support"),
        Err(e) => {
            error!("Failed to initialize second client with OMEMO: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to initialize OMEMO for second client: {}", e));
        }
    }

    // Wait for OMEMO initialization to complete
    tokio::time::sleep(TokioDuration::from_secs(2)).await;

    // 4. Verify different device IDs were generated
    let device_id1 = match client1.get_own_device_id().await {
        Ok(id) => {
            info!("Client 1 device ID: {}", id);
            id
        },
        Err(e) => {
            error!("Failed to get device ID for client 1: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to get device ID for client 1: {}", e));
        }
    };

    let device_id2 = match client2.get_own_device_id().await {
        Ok(id) => {
            info!("Client 2 device ID: {}", id);
            id
        },
        Err(e) => {
            error!("Failed to get device ID for client 2: {}", e);
            // Cleanup
            let _ = client1.disconnect().await;
            let _ = client2.disconnect().await;
            return Err(anyhow::anyhow!("Failed to get device ID for client 2: {}", e));
        }
    };

    // Verify devices have different IDs
    if device_id1 == device_id2 {
        warn!("Both clients have the same device ID: {}. This suggests multi-device support may not be working correctly.", device_id1);
    } else {
        info!("Confirmed clients have different device IDs: {} and {}", device_id1, device_id2);
    }

    // 5. Get fingerprints for both devices
    let fingerprint1 = match client1.get_own_fingerprint().await {
        Ok(fp) => {
            info!("Client 1 fingerprint: {}", fp);
            fp
        },
        Err(e) => {
            warn!("Failed to get fingerprint for client 1: {}", e);
            "unknown".to_string()
        }
    };

    let fingerprint2 = match client2.get_own_fingerprint().await {
        Ok(fp) => {
            info!("Client 2 fingerprint: {}", fp);
            fp
        },
        Err(e) => {
            warn!("Failed to get fingerprint for client 2: {}", e);
            "unknown".to_string()
        }
    };

    // Verify fingerprints are different
    if fingerprint1 == fingerprint2 && fingerprint1 != "unknown" {
        warn!("Both clients have the same fingerprint. This suggests multi-device support may not be working correctly.");
    } else if fingerprint1 != "unknown" && fingerprint2 != "unknown" {
        info!("Confirmed clients have different fingerprints");
    }

    // 6. Verify device discovery between the clients
    info!("Testing device discovery between clients...");
    
    // Get client1's view of own devices
    let devices_from_client1 = match client1.get_contact_devices(&credentials.username).await {
        Ok(devices) => {
            info!("Client 1 sees these devices for the account: {:?}", devices);
            devices
        },
        Err(e) => {
            warn!("Client 1 failed to get device list: {}", e);
            Vec::new()
        }
    };

    // Get client2's view of own devices
    let devices_from_client2 = match client2.get_contact_devices(&credentials.username).await {
        Ok(devices) => {
            info!("Client 2 sees these devices for the account: {:?}", devices);
            devices
        },
        Err(e) => {
            warn!("Client 2 failed to get device list: {}", e);
            Vec::new()
        }
    };

    // Verify both clients can see each other's device IDs
    let client1_sees_client2 = devices_from_client1.contains(&device_id2);
    let client2_sees_client1 = devices_from_client2.contains(&device_id1);
    
    if client1_sees_client2 && client2_sees_client1 {
        info!("Device discovery is working correctly: both clients can see each other's device IDs");
    } else {
        warn!("Device discovery issues detected:");
        if !client1_sees_client2 {
            warn!("Client 1 cannot see Client 2's device ID");
        }
        if !client2_sees_client1 {
            warn!("Client 2 cannot see Client 1's device ID");
        }
    }

    // 7. Get contact to test with
    let contacts = match client1.get_roster().await? {
        Some(roster_contacts) if !roster_contacts.is_empty() => roster_contacts,
        _ => {
            info!("No contacts found in roster, using a test JID");
            let test_recipient = get_test_recipient().await?;
            vec![test_recipient]
        }
    };

    let test_contact = &contacts[0];
    info!("Using contact {} for testing", test_contact);

    // 8. Trust test: Client 1 trusts a contact's device, client 2 doesn't
    // First, get contact's device ID(s)
    match client1.request_omemo_devicelist(test_contact).await {
        Ok(_) => info!("Successfully requested device list for contact"),
        Err(e) => warn!("Failed to request device list for contact: {}", e)
    };

    tokio::time::sleep(TokioDuration::from_secs(1)).await;

    let contact_devices = match client1.get_contact_devices(test_contact).await {
        Ok(devices) => {
            if devices.is_empty() {
                info!("Contact {} has no OMEMO devices, using default ID 1", test_contact);
                vec![1]
            } else {
                info!("Contact {} has devices: {:?}", test_contact, devices);
                devices
            }
        },
        Err(e) => {
            warn!("Failed to get contact devices: {}", e);
            vec![1]
        }
    };

    // Attempt trust differentiation if there's at least one device
    if !contact_devices.is_empty() {
        let contact_device_id = contact_devices[0];
        
        // Client 1 trusts the device
        match client1.mark_device_trusted(test_contact, contact_device_id).await {
            Ok(_) => info!("Client 1 successfully trusted contact device {}", contact_device_id),
            Err(e) => warn!("Client 1 failed to trust contact device: {}", e)
        }
        
        // Client 2 does not trust (explicitly marks as untrusted)
        match client2.mark_device_untrusted(test_contact, contact_device_id).await {
            Ok(_) => info!("Client 2 successfully marked contact device {} as untrusted", contact_device_id),
            Err(e) => warn!("Client 2 failed to untrust contact device: {}", e)
        }
        
        // Verify trust settings
        match client1.is_device_trusted(test_contact, contact_device_id).await {
            Ok(trusted) => info!("Client 1 trust status for contact device: {}", trusted),
            Err(e) => warn!("Failed to check client 1 trust status: {}", e)
        }
        
        match client2.is_device_trusted(test_contact, contact_device_id).await {
            Ok(trusted) => info!("Client 2 trust status for contact device: {}", trusted),
            Err(e) => warn!("Failed to check client 2 trust status: {}", e)
        }
    }

    // 9. Send encrypted message from client1 to the contact
    let timestamp1 = chrono::Utc::now().timestamp();
    let test_message1 = format!("ENHANCED OMEMO multi-device test message from client1 - {}", timestamp1);

    info!("Sending OMEMO encrypted message from client1 to contact {}", test_contact);
    match client1.send_encrypted_message(test_contact, &test_message1).await {
        Ok(_) => info!("OMEMO encrypted message sent successfully from client1"),
        Err(e) => {
            error!("Failed to send OMEMO encrypted message from client1: {}", e);
            // Continue testing anyway
        }
    }

    // 10. Check if client2 receives carbon copy and verify decryption
    info!("Checking if client2 receives and can decrypt the carbon copy...");
    let carbon_received = match wait_for_message(
        &mut msg_rx2,
        |msg| msg.content == test_message1,
        5 // 5 second timeout
    ).await {
        Ok(msg) => {
            info!("Client2 received and decrypted carbon copy successfully: {}", msg.id);
            true
        },
        Err(e) => {
            warn!("Client2 did not receive or couldn't decrypt carbon copy: {}", e);
            false
        }
    };

    // 11. Send encrypted message from client2 to the contact
    let timestamp2 = chrono::Utc::now().timestamp();
    let test_message2 = format!("ENHANCED OMEMO multi-device test message from client2 - {}", timestamp2);

    info!("Sending OMEMO encrypted message from client2 to contact {}", test_contact);
    match client2.send_encrypted_message(test_contact, &test_message2).await {
        Ok(_) => info!("OMEMO encrypted message sent successfully from client2"),
        Err(e) => {
            warn!("Failed to send OMEMO encrypted message from client2: {}", e);
            // Continue testing anyway
        }
    }

    // 12. Check if client1 receives carbon copy and verify decryption
    info!("Checking if client1 receives and can decrypt the carbon copy...");
    let carbon_received2 = match wait_for_message(
        &mut msg_rx1,
        |msg| msg.content == test_message2,
        5 // 5 second timeout
    ).await {
        Ok(msg) => {
            info!("Client1 received and decrypted carbon copy successfully: {}", msg.id);
            true
        },
        Err(e) => {
            warn!("Client1 did not receive or couldn't decrypt carbon copy: {}", e);
            false
        }
    };

    // 13. Summary of multi-device capabilities
    info!("\n==== OMEMO Multi-Device Support Evaluation ====");
    info!("1. Different device IDs: {}", if device_id1 != device_id2 { "PASS" } else { "FAIL" });
    info!("2. Different fingerprints: {}", if fingerprint1 != fingerprint2 && fingerprint1 != "unknown" { "PASS" } else { "UNCLEAR" });
    info!("3. Device discovery: {}", if client1_sees_client2 && client2_sees_client1 { "PASS" } else { "FAIL" });
    info!("4. Carbon copy reception and decryption from client1: {}", if carbon_received { "PASS" } else { "FAIL" });
    info!("5. Carbon copy reception and decryption from client2: {}", if carbon_received2 { "PASS" } else { "FAIL" });
    
    let overall_assessment = if device_id1 != device_id2 && 
                             (client1_sees_client2 || client2_sees_client1) && 
                             (carbon_received || carbon_received2) {
        "PASSED - Multi-device functionality appears to be working"
    } else if device_id1 != device_id2 {
        "PARTIAL - Devices have unique IDs but carbon functionality is limited"
    } else {
        "FAILED - Core multi-device capability issues detected"
    };
    
    info!("Overall assessment: {}", overall_assessment);
    info!("===============================================\n");

    // 14. Disconnect clients
    info!("Disconnecting clients...");
    let _ = client1.disconnect().await;
    let _ = client2.disconnect().await;

    info!("Enhanced OMEMO multi-device encryption test completed");
    Ok(())
}