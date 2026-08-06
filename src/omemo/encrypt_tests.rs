//! Direct tests for encrypt.rs: the device-fanout matrix.
//!
//! The key invariant: exactly the right set of device IDs ends up in
//! encrypted_keys.  Both positive (trusted device IS present) and negative
//! (untrusted / ignored device is ABSENT) assertions are required — a bug
//! that drops every device would pass a negative-only test.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::jid::BareJid;
    use crate::omemo::device_id::DeviceId;
    use crate::omemo::session::OmemoSessionState;
    use crate::omemo::storage::TrustLevel;
    use crate::omemo::{OmemoError, OmemoPubSub};
    use crate::omemo::test_support::{RecordingPubSub, make_manager, make_pair};

    fn bjid(s: &str) -> BareJid { BareJid::parse(s).unwrap() }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Set alice's trust level for bob's device in alice's storage.
    async fn set_trust(
        alice: &mut crate::omemo::OmemoManager,
        jid: &str,
        did: u32,
        level: TrustLevel,
    ) {
        alice.storage.lock().await
            .set_trust_level(&bjid(jid), DeviceId::from(did), level)
            .unwrap();
    }

    // ── Fanout matrix ─────────────────────────────────────────────────────────

    /// Trusted device is present; untrusted device on the same JID is absent.
    #[tokio::test]
    async fn trusted_present_untrusted_absent() {
        let alice_jid = "alice@example.com";
        let carol_jid = "carol@example.com";
        let ps = RecordingPubSub::new();
        let (mut alice, _ad)  = make_manager(alice_jid, 1, ps.clone()).await;
        let (carol_a, _ca)    = make_manager(carol_jid, 100, ps.clone()).await;
        let (carol_b, _cb)    = make_manager(carol_jid, 101, ps.clone()).await;

        ps.add_device_list(carol_jid, &[100, 101]).await;
        ps.add_bundle(carol_jid, 100, carol_a.key_bundle.as_ref().unwrap()).await;
        ps.add_bundle(carol_jid, 101, carol_b.key_bundle.as_ref().unwrap()).await;
        ps.add_device_list(alice_jid, &[1]).await;

        set_trust(&mut alice, carol_jid, 101, TrustLevel::Untrusted).await;

        let msg = alice.encrypt_message(carol_jid, "hello")
            .await.expect("must succeed — device 100 is trusted");

        assert!( msg.encrypted_keys.contains_key(&DeviceId::from(100u32)),
            "trusted device 100 must be present");
        assert!(!msg.encrypted_keys.contains_key(&DeviceId::from(101u32)),
            "untrusted device 101 must be absent");
    }

    /// When ALL recipient devices are untrusted, encrypt_message must return Err.
    #[tokio::test]
    async fn all_recipient_untrusted_returns_error() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let ps = RecordingPubSub::new();
        let (mut alice, _ad) = make_manager(alice_jid, 1, ps.clone()).await;
        let (bob, _bd)       = make_manager(bob_jid,   2, ps.clone()).await;

        ps.add_device_list(bob_jid, &[2]).await;
        ps.add_bundle(bob_jid, 2, bob.key_bundle.as_ref().unwrap()).await;
        ps.add_device_list(alice_jid, &[1]).await;

        set_trust(&mut alice, bob_jid, 2, TrustLevel::Untrusted).await;

        let err = alice.encrypt_message(bob_jid, "x").await.unwrap_err();
        assert!(
            matches!(err, OmemoError::NoDeviceError(_) | OmemoError::ProtocolError(_)),
            "expected an undeliverable-message error, got {:?}", err
        );
    }

    /// Own second device (trusted) must be in encrypted_keys for carbons.
    #[tokio::test]
    async fn own_second_device_trusted_is_present() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let ps = RecordingPubSub::new();
        let (mut alice,  _ad1) = make_manager(alice_jid, 1, ps.clone()).await;
        let (alice2, _ad2) = make_manager(alice_jid, 2, ps.clone()).await;
        let (bob, _bd)         = make_manager(bob_jid,   3, ps.clone()).await;

        ps.add_device_list(alice_jid, &[1, 2]).await;
        ps.add_bundle(alice_jid, 2, alice2.key_bundle.as_ref().unwrap()).await;
        ps.add_device_list(bob_jid, &[3]).await;
        ps.add_bundle(bob_jid, 3, bob.key_bundle.as_ref().unwrap()).await;

        let msg = alice.encrypt_message(bob_jid, "hello")
            .await.expect("must succeed");

        assert!(msg.encrypted_keys.contains_key(&DeviceId::from(2u32)),
            "own second device (2) must be present for carbons");
        assert!(!msg.encrypted_keys.contains_key(&DeviceId::from(1u32)),
            "own current device (1) must be absent from encrypted_keys");
    }

    /// Own second device (untrusted) must be absent from encrypted_keys.
    #[tokio::test]
    async fn own_second_device_untrusted_is_absent() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let ps = RecordingPubSub::new();
        let (mut alice, _ad1) = make_manager(alice_jid, 1, ps.clone()).await;
        let (alice2, _ad2)    = make_manager(alice_jid, 2, ps.clone()).await;
        let (bob, _bd)        = make_manager(bob_jid,   3, ps.clone()).await;

        ps.add_device_list(alice_jid, &[1, 2]).await;
        ps.add_bundle(alice_jid, 2, alice2.key_bundle.as_ref().unwrap()).await;
        ps.add_device_list(bob_jid, &[3]).await;
        ps.add_bundle(bob_jid, 3, bob.key_bundle.as_ref().unwrap()).await;

        set_trust(&mut alice, alice_jid, 2, TrustLevel::Untrusted).await;

        let msg = alice.encrypt_message(bob_jid, "hello")
            .await.expect("must succeed — bob device 3 is trusted");

        assert!(!msg.encrypted_keys.contains_key(&DeviceId::from(2u32)),
            "own untrusted device (2) must be absent");
        assert!(msg.encrypted_keys.contains_key(&DeviceId::from(3u32)),
            "recipient trusted device (3) must be present");
    }

    /// Own current device must never appear in encrypted_keys.
    #[tokio::test]
    async fn own_current_device_always_absent() {
        let (mut alice, _ad, _bob, _bd, _ps) =
            make_pair("alice@example.com", 1, "bob@example.com", 2).await;

        let msg = alice.encrypt_message("bob@example.com", "x").await.unwrap();
        assert!(!msg.encrypted_keys.contains_key(&DeviceId::from(1u32)),
            "alice's own device (1) must never be in encrypted_keys");
    }

    /// An ignored device with state RecoveryPreKeySent must be overridden and
    /// included (the recovery attempt requires reaching that device).
    #[tokio::test]
    async fn device_in_recovery_prekey_sent_is_present() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let (mut alice, _ad, bob, _bd, ps) =
            make_pair(alice_jid, 1, bob_jid, 2).await;

        // Simulate a recovery state for bob's device.
        alice.sessions.insert(
            (bjid(bob_jid), DeviceId::from(2u32)),
            OmemoSessionState::RecoveryPreKeySent { attempt: 1 },
        );

        let msg = alice.encrypt_message(bob_jid, "recovery")
            .await.expect("must succeed despite RecoveryPreKeySent");

        // The recovery message must reach bob's device.
        assert!(msg.encrypted_keys.contains_key(&DeviceId::from(2u32)),
            "device in RecoveryPreKeySent must receive encrypted key");
    }

    /// Duplicate device IDs in the server list must appear exactly once.
    #[tokio::test]
    async fn duplicate_device_id_in_list_appears_exactly_once() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let ps = RecordingPubSub::new();
        let (mut alice, _ad) = make_manager(alice_jid, 1, ps.clone()).await;
        let (bob, _bd)       = make_manager(bob_jid,   2, ps.clone()).await;

        // Duplicate device 2 in the server list.
        ps.add_device_list(bob_jid, &[2, 2, 2]).await;
        ps.add_bundle(bob_jid, 2, bob.key_bundle.as_ref().unwrap()).await;
        ps.add_device_list(alice_jid, &[1]).await;

        let msg = alice.encrypt_message(bob_jid, "x")
            .await.expect("must succeed");

        assert_eq!(
            msg.encrypted_keys.len(), 1,
            "device 2 must appear exactly once; got {:?}",
            msg.encrypted_keys.keys().collect::<Vec<_>>()
        );
    }
}
