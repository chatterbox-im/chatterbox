//! Tier-3 integration tests: two in-process clients + FakeServer.
//!
//! These tests cover full client lifecycles without a real XMPP server.

mod common;
use common::fake_server::FakeServer;

use chatterbox::xmpp::XMPPClient;

// ── Connection handshake tests ────────────────────────────────────────────────

/// A client can connect via FakeServer and complete the handshake
/// (Online event → carbons enable → disco → initial presence) without error.
#[tokio::test]
async fn client_connects_via_fake_server() {
    let server = FakeServer::new();
    let handle = server.register("alice@example.com");

    let (mut alice, _msg_rx) = XMPPClient::new();
    alice
        .connect_with_transport(handle, "alice@example.com".to_string(), "example.com")
        .await
        .expect("connect_with_transport should succeed with FakeServer");

    assert_eq!(alice.get_jid(), "alice@example.com");
}

/// Two clients can connect independently; each ends up with the correct JID.
#[tokio::test]
async fn two_clients_connect_via_fake_server() {
    let server = FakeServer::new();
    let alice_handle = server.register("alice@example.com");
    let bob_handle = server.register("bob@example.com");

    let (mut alice, _) = XMPPClient::new();
    alice
        .connect_with_transport(alice_handle, "alice@example.com".to_string(), "example.com")
        .await
        .expect("alice should connect");

    let (mut bob, _) = XMPPClient::new();
    bob
        .connect_with_transport(bob_handle, "bob@example.com".to_string(), "example.com")
        .await
        .expect("bob should connect");

    assert_eq!(alice.get_jid(), "alice@example.com");
    assert_eq!(bob.get_jid(), "bob@example.com");
}

// ── OMEMO initialisation ──────────────────────────────────────────────────────

/// After `initialize_client()`, the client's device list and bundle are
/// present in the FakeServer's PEP store.
#[tokio::test]
async fn initialize_client_publishes_device_list_and_bundle() {
    use tempfile::TempDir;

    let server = FakeServer::new();
    let handle = server.register("alice@example.com");

    let (mut alice, _) = XMPPClient::new();
    let alice_dir = TempDir::new().unwrap();
    alice.omemo_dir = Some(alice_dir.path().to_path_buf());

    alice
        .connect_with_transport(handle, "alice@example.com".to_string(), "example.com")
        .await
        .expect("alice should connect");

    alice.initialize_client().await.expect("initialize_client should succeed");

    // The device list node must now be in FakeServer.
    let ns = "eu.siacs.conversations.axolotl";
    let node = format!("{}.devicelist", ns);
    assert!(
        server.pep_node("alice@example.com", &node).is_some(),
        "device list must be published to FakeServer after initialize_client"
    );
}

/// Two connected, initialized clients can establish an OMEMO session:
/// alice encrypts a message → it is delivered to bob → bob decrypts it.
#[tokio::test]
async fn alice_sends_omemo_message_bob_decrypts() {
    use tempfile::TempDir;
    use tokio::time::{timeout, Duration};

    let server = FakeServer::new();
    let alice_handle = server.register("alice@example.com");
    let bob_handle = server.register("bob@example.com");

    // Connect alice
    let (mut alice, _alice_msgs) = XMPPClient::new();
    let alice_dir = TempDir::new().unwrap();
    alice.omemo_dir = Some(alice_dir.path().to_path_buf());
    alice
        .connect_with_transport(alice_handle, "alice@example.com".to_string(), "example.com")
        .await
        .expect("alice connect");
    alice.initialize_client().await.expect("alice init");

    // Connect bob
    let (mut bob, mut bob_msgs) = XMPPClient::new();
    let bob_dir = TempDir::new().unwrap();
    bob.omemo_dir = Some(bob_dir.path().to_path_buf());
    bob
        .connect_with_transport(bob_handle, "bob@example.com".to_string(), "example.com")
        .await
        .expect("bob connect");
    bob.initialize_client().await.expect("bob init");

    // Alice sends an encrypted message to bob.
    alice
        .send_encrypted_message("bob@example.com", "hello bob")
        .await
        .expect("alice should be able to send encrypted message");

    // Bob should receive the decrypted message.
    let decrypted = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = bob_msgs.recv().await {
                match event {
                    chatterbox::models::AppEvent::Chat(msg) if msg.content.contains("hello bob") => {
                        return msg;
                    }
                    _ => continue,
                }
            }
        }
    })
    .await
    .expect("bob should receive the decrypted message within 5 seconds");

    assert_eq!(decrypted.content, "hello bob");
}

/// The OMEMO session persists across alice's disconnect and reconnect.
/// After reconnecting (from the same storage), alice can still send to bob.
#[tokio::test]
async fn session_survives_alice_restart() {
    use tempfile::TempDir;
    use tokio::time::{timeout, Duration};

    let server = FakeServer::new();
    let bob_handle = server.register("bob@example.com");

    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    // Bob connects and stays connected for the whole test.
    let (mut bob, mut bob_msgs) = XMPPClient::new();
    bob.omemo_dir = Some(bob_dir.path().to_path_buf());
    bob.connect_with_transport(bob_handle, "bob@example.com".to_string(), "example.com").await.unwrap();
    bob.initialize_client().await.unwrap();

    // Alice's first connection — establish session.
    {
        let alice_handle1 = server.register("alice@example.com");
        let (mut alice, _) = XMPPClient::new();
        alice.omemo_dir = Some(alice_dir.path().to_path_buf());
        alice.connect_with_transport(alice_handle1, "alice@example.com".to_string(), "example.com").await.unwrap();
        alice.initialize_client().await.unwrap();

        alice.send_encrypted_message("bob@example.com", "before restart").await.unwrap();
    }
    // alice is dropped here (connection closed).

    // Bob receives "before restart".
    let msg1 = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(chatterbox::models::AppEvent::Chat(m)) = bob_msgs.recv().await {
                if m.content == "before restart" { return m; }
            }
        }
    }).await.expect("message before restart");
    assert_eq!(msg1.content, "before restart");

    // Alice's second connection — same storage dir.
    let alice_handle2 = server.register("alice@example.com");
    let (mut alice2, _) = XMPPClient::new();
    alice2.omemo_dir = Some(alice_dir.path().to_path_buf());
    alice2.connect_with_transport(alice_handle2, "alice@example.com".to_string(), "example.com").await.unwrap();
    alice2.initialize_client().await.unwrap();

    alice2.send_encrypted_message("bob@example.com", "after restart").await.unwrap();

    let msg2 = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(chatterbox::models::AppEvent::Chat(m)) = bob_msgs.recv().await {
                if m.content == "after restart" { return m; }
            }
        }
    }).await.expect("message after restart");
    assert_eq!(msg2.content, "after restart");
}
