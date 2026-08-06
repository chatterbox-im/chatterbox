// Shared utilities for live-server diagnostic scripts (examples/smoke_*.rs).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Once;

use anyhow::Result;
use log::{info, LevelFilter};
use tokio::time::{timeout, Duration as TokioDuration};

use chatterbox::models::{AppEvent, Message};

pub mod credentials;
pub mod fake_server;
use credentials::Credentials;

static INIT_LOGGER: Once = Once::new();

#[allow(dead_code)]
pub fn setup_logging() {
    INIT_LOGGER.call_once(|| {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Debug)
            .init();
    });
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
        let server = client_a
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let username = client_a
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let password = client_a
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        info!(
            "Loaded test credentials for user {} on server {}",
            username, server
        );
        return Ok(Credentials::new(&server, &username, &password));
    }

    Err(anyhow::anyhow!(
        "Could not find clientA credentials in the JSON file"
    ))
}

/// Get test recipient JID for async tests
#[allow(dead_code)]
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
        let username = client_b
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("cb");
        let server = client_b
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("xmpp.server.org");
        let jid = format!("{}@{}", username, server);

        info!("Constructed test recipient JID: {}", jid);
        return Ok(jid);
    }

    Err(anyhow::anyhow!(
        "Could not find clientB information in the JSON file"
    ))
}

/// Get test recipient credentials for async tests
#[allow(dead_code)]
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
        let server = client_b
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let username = client_b
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let password = client_b
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        info!(
            "Loaded test recipient credentials for user {} on server {}",
            username, server
        );
        return Ok(Credentials::new(&server, &username, &password));
    }

    Err(anyhow::anyhow!(
        "Could not find clientB credentials in the JSON file"
    ))
}

/// Load test credentials from a JSON file
#[allow(dead_code)]
pub fn load_test_credentials_from_file<P: AsRef<Path>>(path: P) -> Result<Credentials> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse the JSON structure
    let json: serde_json::Value = serde_json::from_str(&contents)?;

    // Extract clientA credentials
    if let Some(client_a) = json.get("clientA") {
        let server = client_a
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let username = client_a
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let password = client_a
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        return Ok(Credentials::new(&server, &username, &password));
    }

    Err(anyhow::anyhow!(
        "Could not find clientA credentials in the JSON file"
    ))
}

/// Wait for a specific message matching the predicate with timeout
#[allow(dead_code)]
pub async fn wait_for_message(
    msg_rx: &mut tokio::sync::mpsc::Receiver<AppEvent>,
    predicate: impl Fn(&Message) -> bool,
    timeout_secs: u64,
) -> Result<Message> {
    info!("Waiting for message...");
    match timeout(TokioDuration::from_secs(timeout_secs), async {
        while let Some(event) = msg_rx.recv().await {
            if let AppEvent::Chat(msg) = event {
                if predicate(&msg) {
                    return Ok(msg);
                }
            }
        }
        Err(anyhow::anyhow!("Message receiver closed"))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("Timed out waiting for message")),
    }
}
