//! Tier-3 integration tests: two in-process clients + FakeServer.
//!
//! These tests cover full client lifecycles without a real XMPP server.

mod common;
use common::fake_server::FakeServer;

use chatterbox::xmpp::XMPPClient;

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

/// Two clients can connect independently.
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
}
