//! E2E bidirectional OMEMO test against a real XMPP server.
//!
//! Marked `#[ignore]` so it only runs when explicitly requested:
//!   cargo test --test omemo_bidirectional_test -- --ignored --nocapture
//!
//! Required env vars: XMPP_SERVER, XMPP_USERNAME, XMPP_PASSWORD,
//!                    XMPP_USERNAME_B, XMPP_PASSWORD_B

use anyhow::Result;
use log::info;
use tempfile::TempDir;
use tokio::time::{timeout, Duration};

use chatterbox::models::AppEvent;
use chatterbox::xmpp::XMPPClient;

fn env_or_skip(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn wait_for_content(
    rx: &mut tokio::sync::mpsc::Receiver<AppEvent>,
    expected: &str,
    secs: u64,
) -> Result<()> {
    timeout(Duration::from_secs(secs), async {
        while let Some(event) = rx.recv().await {
            if let AppEvent::Chat(msg) = event {
                if msg.content == expected {
                    return Ok(());
                }
            }
        }
        Err(anyhow::anyhow!("channel closed before message arrived"))
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out after {}s waiting for {:?}", secs, expected))?
}

#[tokio::test]
#[ignore]
async fn bidirectional_omemo_exchange() {
    let (Some(server), Some(user_a), Some(pass_a), Some(user_b), Some(pass_b)) = (
        env_or_skip("XMPP_SERVER"),
        env_or_skip("XMPP_USERNAME"),
        env_or_skip("XMPP_PASSWORD"),
        env_or_skip("XMPP_USERNAME_B"),
        env_or_skip("XMPP_PASSWORD_B"),
    ) else {
        eprintln!("SKIPPED — required XMPP env vars not set");
        return;
    };

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .ok();

    let jid_a = format!("{}@{}", user_a, server);
    let jid_b = format!("{}@{}", user_b, server);

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let (mut client_a, mut rx_a) = XMPPClient::new();
    client_a.omemo_dir = Some(dir_a.path().to_path_buf());
    client_a.connect(&server, &user_a, &pass_a).await.expect("client A connect");
    client_a.initialize_client().await.expect("client A init");

    let (mut client_b, mut rx_b) = XMPPClient::new();
    client_b.omemo_dir = Some(dir_b.path().to_path_buf());
    client_b.connect(&server, &user_b, &pass_b).await.expect("client B connect");
    client_b.initialize_client().await.expect("client B init");

    // Let device lists propagate.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let msg_a_to_b = format!("hello-from-a-{}", ts);
    let msg_b_to_a = format!("hello-from-b-{}", ts);

    info!("A → B: {}", msg_a_to_b);
    client_a.send_encrypted_message(&jid_b, &msg_a_to_b).await.expect("A send");

    info!("B → A: {}", msg_b_to_a);
    client_b.send_encrypted_message(&jid_a, &msg_b_to_a).await.expect("B send");

    wait_for_content(&mut rx_b, &msg_a_to_b, 30).await.expect("B did not receive A's message");
    wait_for_content(&mut rx_a, &msg_b_to_a, 30).await.expect("A did not receive B's message");

    let _ = timeout(Duration::from_secs(5), client_a.disconnect()).await;
    let _ = timeout(Duration::from_secs(5), client_b.disconnect()).await;

    info!("PASSED — bidirectional OMEMO exchange verified");
}
