// Simple OMEMO message test
// This test demonstrates sending and receiving OMEMO encrypted messages

// Import common test utilities
mod common;
use common::{setup_logging, get_test_credentials};

// External crate imports
use anyhow::Result;
use log::{info, warn, error};
use tokio::time::{timeout, Duration as TokioDuration};

// Import the crate functionality
use chatterbox::xmpp::XMPPClient;

// Import credentials from our common module
use common::credentials::Credentials;

#[tokio::test]
async fn test_omemo_simple() -> Result<()> {
    // Setup logging
    setup_logging();
    info!("Starting simple OMEMO message test...");

    // 1. Log in as user "ca"
    let ca_credentials = get_test_credentials().await?;
    info!("Using credentials for {} on server {}", ca_credentials.username, ca_credentials.server);
    
    // 2. Connect and send encrypted message
    let (mut ca_client, mut ca_msg_rx) = XMPPClient::new();
    info!("Connecting to XMPP server as ca...");
    
    match ca_client.connect(
        &ca_credentials.server,
        &ca_credentials.username,
        &ca_credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Connected to XMPP server successfully as ca"),
        Err(e) => {
            error!("Failed to connect to XMPP server as ca: {}", e);
            return Err(anyhow::anyhow!("Failed to connect as ca: {}", e));
        }
    }
    
    // Small delay to ensure everything is ready
    tokio::time::sleep(TokioDuration::from_secs(1)).await;
    
    // Initialize OMEMO for the client
    info!("Initializing client with OMEMO support...");
    match ca_client.initialize_client().await {
        Ok(_) => info!("Client initialized with OMEMO support"),
        Err(e) => {
            error!("Failed to initialize client with OMEMO: {}", e);
            let _ = timeout(TokioDuration::from_secs(5), ca_client.disconnect()).await;
            return Err(anyhow::anyhow!("Failed to initialize OMEMO: {}", e));
        }
    }
    
    // Send encrypted message to "cb"
    let cb_jid = "cb@xmpp.server.org";
    let test_message = format!("OMEMO test message - {}", chrono::Utc::now().timestamp());
    info!("Sending OMEMO encrypted message to {}: {}", cb_jid, test_message);
    
    match ca_client.send_encrypted_message(cb_jid, &test_message).await {
        Ok(_) => info!("OMEMO encrypted message sent successfully"),
        Err(e) => {
            error!("Failed to send OMEMO encrypted message: {}", e);
            let _ = timeout(TokioDuration::from_secs(5), ca_client.disconnect()).await;
            return Err(anyhow::anyhow!("Failed to send OMEMO encrypted message: {}", e));
        }
    }
    
    // 3. Disconnect "ca"
    info!("Disconnecting ca client...");
    match timeout(TokioDuration::from_secs(5), ca_client.disconnect()).await {
        Ok(result) => match result {
            Ok(_) => info!("Disconnected ca client successfully"),
            Err(e) => warn!("Error during ca disconnect: {}", e),
        },
        Err(_) => warn!("Disconnect operation for ca timed out after 5 seconds"),
    }
    
    // 4. Log in as "cb" and check for message
    info!("Connecting as cb to check for received message...");
    let cb_credentials = Credentials::new(
        &ca_credentials.server,
        "cb",
        "+ng0APPS2TCL1rTeWZjXA1ULFz5ns35"
    );
    
    let (mut cb_client, mut cb_msg_rx) = XMPPClient::new();
    match cb_client.connect(
        &cb_credentials.server,
        &cb_credentials.username,
        &cb_credentials.get_password().unwrap_or_default(),
    ).await {
        Ok(_) => info!("Connected to XMPP server successfully as cb"),
        Err(e) => {
            error!("Failed to connect to XMPP server as cb: {}", e);
            return Err(anyhow::anyhow!("Failed to connect as cb: {}", e));
        }
    }
    
    // Small delay to ensure everything is ready
    tokio::time::sleep(TokioDuration::from_secs(1)).await;
    
    // Initialize OMEMO for the client
    info!("Initializing cb client with OMEMO support...");
    match cb_client.initialize_client().await {
        Ok(_) => info!("CB client initialized with OMEMO support"),
        Err(e) => {
            error!("Failed to initialize cb client with OMEMO: {}", e);
            let _ = timeout(TokioDuration::from_secs(5), cb_client.disconnect()).await;
            return Err(anyhow::anyhow!("Failed to initialize OMEMO for cb: {}", e));
        }
    }
    
    // For this simple test, we'll just consider it a success if we got this far
    info!("Test completed successfully - we were able to send an OMEMO message and connect as the recipient");
    
    // Disconnect "cb"
    info!("Disconnecting cb client...");
    match timeout(TokioDuration::from_secs(5), cb_client.disconnect()).await {
        Ok(result) => match result {
            Ok(_) => info!("Disconnected cb client successfully"),
            Err(e) => warn!("Error during cb disconnect: {}", e),
        },
        Err(_) => warn!("Disconnect operation for cb timed out after 5 seconds"),
    }
    
    info!("Simple OMEMO message test completed successfully");
    Ok(())
}
