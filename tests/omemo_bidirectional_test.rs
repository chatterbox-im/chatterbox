// Full bidirectional OMEMO message exchange test
//
// Connects two clients (A and B) simultaneously, initializes OMEMO,
// sends encrypted messages both ways, and verifies decryption.
//
// Requires environment variables:
//   XMPP_SERVER, XMPP_USERNAME (account A), XMPP_PASSWORD (account A)
//   XMPP_USERNAME_B, XMPP_PASSWORD_B (account B)

use anyhow::Result;
use log::{info, error};
use tokio::time::{timeout, Duration};

use chatterbox::models::Message;
use chatterbox::xmpp::XMPPClient;

fn get_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("Environment variable {} must be set", name))
}

/// Wait for a message matching the predicate on the receiver channel
async fn wait_for_msg(
    rx: &mut tokio::sync::mpsc::Receiver<Message>,
    predicate: impl Fn(&Message) -> bool,
    timeout_secs: u64,
) -> Result<Message> {
    match timeout(Duration::from_secs(timeout_secs), async {
        while let Some(msg) = rx.recv().await {
            info!("  received msg: from={} content={:?} status={:?}",
                  msg.sender_id, msg.content, msg.delivery_status);
            if predicate(&msg) {
                return Ok(msg);
            }
        }
        Err(anyhow::anyhow!("channel closed"))
    }).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("timed out after {}s", timeout_secs)),
    }
}

#[tokio::test]
#[ignore = "requires live XMPP server with two accounts"]
async fn test_bidirectional_omemo_exchange() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .ok();

    let server = get_env("XMPP_SERVER");
    let user_a = get_env("XMPP_USERNAME");
    let pass_a = get_env("XMPP_PASSWORD");
    let user_b = get_env("XMPP_USERNAME_B");
    let pass_b = get_env("XMPP_PASSWORD_B");

    let jid_a = format!("{}@{}", user_a, server);
    let jid_b = format!("{}@{}", user_b, server);

    // --- Connect both clients ---
    info!("Connecting client A ({})...", user_a);
    let (mut client_a, mut rx_a) = XMPPClient::new();
    client_a.connect(&server, &user_a, &pass_a).await?;
    info!("Client A connected");

    info!("Connecting client B ({})...", user_b);
    let (mut client_b, mut rx_b) = XMPPClient::new();
    client_b.connect(&server, &user_b, &pass_b).await?;
    info!("Client B connected");

    // --- Initialize OMEMO on both ---
    info!("Initializing OMEMO on client A...");
    client_a.initialize_client().await?;
    info!("Client A OMEMO ready");

    info!("Initializing OMEMO on client B...");
    client_b.initialize_client().await?;
    info!("Client B OMEMO ready");

    // Allow time for device list publication and exchange
    info!("Waiting for OMEMO device list exchange...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // --- A sends to B ---
    let msg_a_to_b = format!("hello-from-a-{}", chrono::Utc::now().timestamp_millis());
    info!("Client A sending to {}: {}", jid_b, msg_a_to_b);
    client_a.send_encrypted_message(&jid_b, &msg_a_to_b).await?;
    info!("Client A: message sent");

    // --- Verify B received it ---
    info!("Waiting for client B to receive message...");
    let received_b = wait_for_msg(&mut rx_b, |m| m.content == msg_a_to_b, 30).await;
    match &received_b {
        Ok(m) => info!("Client B received: {:?}", m.content),
        Err(e) => error!("Client B did NOT receive the message: {}", e),
    }

    // --- B sends to A ---
    let msg_b_to_a = format!("hello-from-b-{}", chrono::Utc::now().timestamp_millis());
    info!("Client B sending to {}: {}", jid_a, msg_b_to_a);
    client_b.send_encrypted_message(&jid_a, &msg_b_to_a).await?;
    info!("Client B: message sent");

    // --- Verify A received it ---
    info!("Waiting for client A to receive message...");
    let received_a = wait_for_msg(&mut rx_a, |m| m.content == msg_b_to_a, 30).await;
    match &received_a {
        Ok(m) => info!("Client A received: {:?}", m.content),
        Err(e) => error!("Client A did NOT receive the message: {}", e),
    }

    // --- Disconnect ---
    info!("Disconnecting...");
    let _ = timeout(Duration::from_secs(5), client_a.disconnect()).await;
    let _ = timeout(Duration::from_secs(5), client_b.disconnect()).await;

    // --- Verdict ---
    let a_to_b_ok = received_b.is_ok();
    let b_to_a_ok = received_a.is_ok();

    if a_to_b_ok && b_to_a_ok {
        info!("PASSED ✅ — Bidirectional OMEMO exchange verified");
        Ok(())
    } else {
        let mut failures = Vec::new();
        if !a_to_b_ok { failures.push("A→B failed"); }
        if !b_to_a_ok { failures.push("B→A failed"); }
        Err(anyhow::anyhow!("OMEMO exchange failed: {}", failures.join(", ")))
    }
}
