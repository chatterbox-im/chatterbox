#![forbid(unsafe_code)]

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

#[tokio::test]
async fn startup_fetches_published_keys_despite_cached_device_list() {
    use chatterbox::jid::BareJid;
    use chatterbox::omemo::device_id::DeviceId;
    use chatterbox::omemo::storage::{DeviceListEntry, OmemoStorage, TrustLevel};
    use tempfile::TempDir;
    use tokio::time::{sleep, timeout, Duration};

    let server = FakeServer::new();
    let peer_jid = BareJid::parse("bob@example.com").unwrap();
    let device_id = DeviceId::from(2u32);
    let bob_dir = TempDir::new().unwrap();
    OmemoStorage::new(Some(bob_dir.path().to_path_buf()))
        .unwrap()
        .store_device_id(device_id)
        .unwrap();
    let (mut bob, _bob_msgs) = XMPPClient::new();
    bob.omemo_dir = Some(bob_dir.path().to_path_buf());
    bob.connect_with_transport(
        server.register(peer_jid.as_str()),
        peer_jid.to_string(),
        "example.com",
    )
    .await
    .unwrap();
    bob.initialize_client().await.unwrap();

    let (mut cached_identity, expected_fingerprint) = {
        let manager = bob.get_omemo_manager().unwrap();
        let manager = manager.lock().await;
        let fingerprint = manager
            .get_device_fingerprint(peer_jid.as_str(), device_id)
            .await
            .unwrap();
        let item = server
            .pep_node(peer_jid.as_str(), &chatterbox::omemo::bundle_node(device_id))
            .unwrap();
        let identity = manager
            .parse_device_bundle_response(&format!("<items>{item}</items>"), device_id)
            .unwrap();
        (identity, fingerprint)
    };
    let expected_identity_key = cached_identity.identity_key.clone();
    cached_identity.identity_key[0] ^= 1;

    let alice_dir = TempDir::new().unwrap();
    let mut cache = OmemoStorage::new(Some(alice_dir.path().to_path_buf())).unwrap();
    cache
        .save_device_list(&DeviceListEntry {
            jid: peer_jid.to_string(),
            device_ids: vec![DeviceId::from(42u32)],
            last_update: 0,
        })
        .unwrap();
    cache
        .save_fetched_identity(&peer_jid, &cached_identity, "old fingerprint")
        .unwrap();
    cache
        .set_trust_level(&peer_jid, device_id, TrustLevel::Verified)
        .unwrap();
    server.set_roster("alice@example.com", &[peer_jid.as_str()]);

    let (mut alice, _alice_msgs) = XMPPClient::new();
    alice.omemo_dir = Some(alice_dir.path().to_path_buf());
    alice
        .connect_with_transport(
            server.register("alice@example.com"),
            "alice@example.com".to_string(),
            "example.com",
        )
        .await
        .unwrap();
    alice.initialize_client().await.unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            let devices = cache.load_device_list(&peer_jid).unwrap().device_ids;
            let identity = cache.load_device_identity(&peer_jid, device_id).unwrap();
            if devices == vec![device_id] && identity.identity_key == expected_identity_key {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("startup must refresh both cached device IDs and published keys");

    assert_eq!(
        cache.get_trust_level(&peer_jid, device_id).unwrap(),
        TrustLevel::Untrusted
    );
    assert_eq!(
        cache.get_pending_device_verification(&peer_jid).unwrap(),
        Some((device_id, expected_fingerprint))
    );
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
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
