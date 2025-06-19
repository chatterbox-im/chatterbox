// Common test utilities for integration tests
// This module contains shared code for all integration tests

// Standard library imports
use std::sync::Once;
use std::time::Duration;
use std::thread;
use std::str;
use std::fs::File;
use std::io::Read;
use std::path::Path;

// External crate imports
use anyhow::Result;
use log::{info, warn, error, LevelFilter};
use tokio::time::{timeout, Duration as TokioDuration};
use serde::{Deserialize, Serialize};

// Import the crate functionality
use chatterbox::{
    models::{Message, DeliveryStatus, Contact, ContactStatus},
    xmpp::{XMPPClient, TypingStatus},
};

// Local import for credentials
pub mod credentials;
use credentials::{Credentials, load_credentials};

// Initialize logging once
static INIT_LOGGER: Once = Once::new();

// We don't need the TestCredentials struct anymore since we're parsing the JSON directly

/// Set up the logger for the tests
pub fn setup_logging() {
    INIT_LOGGER.call_once(|| {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Debug)
            .init();
    });
}

/// Struct for synchronous test client
pub struct TestClient {
    xmpp_client: Option<XMPPClient>,
    msg_rx: Option<tokio::sync::mpsc::Receiver<Message>>,
    connected: bool,
}

impl TestClient {
    pub fn new() -> Self {
        TestClient {
            xmpp_client: None,
            msg_rx: None,
            connected: false
        }
    }
    
    pub fn connect(&mut self) -> Result<(), String> {
        // For sync tests, we'll just simulate a successful connection
        // In real tests, this would connect to the XMPP server
        self.connected = true;
        Ok(())
    }
    
    pub fn disconnect(&mut self) -> Result<(), String> {
        self.connected = false;
        Ok(())
    }
    
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    
    pub fn get_contacts(&self) -> Result<Vec<Contact>, String> {
        // Return mock contacts for testing
        Ok(vec![
            Contact {
                id: "contact1".to_string(),
                name: "Test Contact 1".to_string(),
                status: ContactStatus::Online,
            },
            Contact {
                id: "contact2".to_string(),
                name: "Test Contact 2".to_string(),
                status: ContactStatus::Offline,
            },
        ])
    }
    
    pub fn send_message(&self, _recipient_id: String, _content: String) -> Result<String, String> {
        // Return a mock message ID
        Ok("msg123456".to_string())
    }
    
    pub fn check_delivery_status(&self, _message_id: &str) -> Result<DeliveryStatus, String> {
        // Return a mock delivery status
        Ok(DeliveryStatus::Delivered)
    }
    
    pub fn enable_carbons(&self) -> Result<bool, anyhow::Error> {
        // Simulate enabling message carbons
        if self.is_connected() {
            Ok(true)
        } else {
            Err(anyhow::anyhow!("Not connected to server"))
        }
    }
    
    pub fn check_carbon_received(&self, message_id: &str) -> Result<bool, anyhow::Error> {
        // Simulate checking for carbon copies
        if !self.is_connected() {
            return Err(anyhow::anyhow!("Not connected to server"));
        }
        
        // Simulate a high probability of success (80%)
        let success_rate = rand::random::<f32>();
        
        if success_rate < 0.8 {
            info!("Carbon copy was received for message ID: {}", message_id);
            Ok(true)  // Carbon was received
        } else {
            info!("Carbon copy was not received for message ID: {}", message_id);
            Ok(false) // Carbon wasn't received (this can happen normally)
        }
    }
}

/// Setup a test client
pub fn setup_test_client() -> TestClient {
    TestClient::new()
}

/// Get test credentials for async tests
pub async fn get_test_credentials() -> Result<Credentials> {
    // Try to load credentials from the JSON file
    let credentials_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github")
        .join("test_credentials.json");
    
    let mut file = File::open(&credentials_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    // Parse the JSON structure
    let json: serde_json::Value = serde_json::from_str(&contents)?;
    
    // Extract clientA credentials
    if let Some(client_a) = json.get("clientA") {
        let server = client_a.get("server").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let username = client_a.get("username").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let password = client_a.get("password").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        
        info!("Loaded test credentials for user {} on server {}", username, server);
        return Ok(Credentials::new(&server, &username, &password));
    }
    
    Err(anyhow::anyhow!("Could not find clientA credentials in the JSON file"))
}

/// Get test recipient JID for async tests
pub async fn get_test_recipient() -> Result<String> {
    // Try to load credentials from the JSON file
    let credentials_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github")
        .join("test_credentials.json");
    
    let mut file = File::open(&credentials_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    // Parse the JSON structure
    let json: serde_json::Value = serde_json::from_str(&contents)?;
    
    // Extract clientB JID
    if let Some(client_b) = json.get("clientB") {
        if let Some(jid) = client_b.get("jid").and_then(|v| v.as_str()) {
            info!("Loaded test recipient JID: {}", jid);
            return Ok(jid.to_string());
        }
    }
    
    // Fallback to constructing the JID from username and server
    if let Some(client_b) = json.get("clientB") {
        let username = client_b.get("username").and_then(|v| v.as_str()).unwrap_or("cb");
        let server = client_b.get("server").and_then(|v| v.as_str()).unwrap_or("xmpp.server.org");
        let jid = format!("{}@{}", username, server);
        
        info!("Constructed test recipient JID: {}", jid);
        return Ok(jid);
    }
    
    Err(anyhow::anyhow!("Could not find clientB information in the JSON file"))
}

/// Get test recipient credentials for async tests
pub async fn get_test_recipient_credentials() -> Result<Credentials> {
    // Try to load credentials from the JSON file
    let credentials_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github")
        .join("test_credentials.json");
    
    let mut file = File::open(&credentials_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    // Parse the JSON structure
    let json: serde_json::Value = serde_json::from_str(&contents)?;
    
    // Extract clientB credentials
    if let Some(client_b) = json.get("clientB") {
        let server = client_b.get("server").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let username = client_b.get("username").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let password = client_b.get("password").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        
        info!("Loaded test recipient credentials for user {} on server {}", username, server);
        return Ok(Credentials::new(&server, &username, &password));
    }
    
    Err(anyhow::anyhow!("Could not find clientB credentials in the JSON file"))
}

/// Load test credentials from a JSON file
pub fn load_test_credentials_from_file<P: AsRef<Path>>(path: P) -> Result<Credentials> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    // Parse the JSON structure
    let json: serde_json::Value = serde_json::from_str(&contents)?;
    
    // Extract clientA credentials
    if let Some(client_a) = json.get("clientA") {
        let server = client_a.get("server").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let username = client_a.get("username").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let password = client_a.get("password").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        
        return Ok(Credentials::new(&server, &username, &password));
    }
    
    Err(anyhow::anyhow!("Could not find clientA credentials in the JSON file"))
}

/// Wait for a specific message matching the predicate with timeout
pub async fn wait_for_message(
    msg_rx: &mut tokio::sync::mpsc::Receiver<Message>,
    predicate: impl Fn(&Message) -> bool,
    timeout_secs: u64,
) -> Result<Message> {
    info!("Waiting for message...");
    match timeout(TokioDuration::from_secs(timeout_secs), async {
        while let Some(msg) = msg_rx.recv().await {
            if predicate(&msg) {
                return Ok(msg);
            }
        }
        Err(anyhow::anyhow!("Message receiver closed"))
    }).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("Timed out waiting for message")),
    }
}
