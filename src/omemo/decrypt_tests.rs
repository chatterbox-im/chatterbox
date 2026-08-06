//! Direct tests for decrypt.rs: session-state transitions on failure paths.

#[cfg(test)]
mod tests {
    use crate::jid::BareJid;
    use crate::omemo::device_id::DeviceId;
    use crate::omemo::session::OmemoSessionState;
    use crate::omemo::test_support::make_pair;

    fn bjid(s: &str) -> BareJid { BareJid::parse(s).unwrap() }

    // ── Anti-DoS: replayed / stale PreKey must not destroy a live session ──────

    /// Feeding a bogus encrypted key to bob while a live session exists must
    /// not tear down that session — the session must still be usable afterwards.
    #[tokio::test]
    async fn failed_decrypt_does_not_destroy_active_session() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let alice_did = DeviceId::from(1u32);

        let (mut alice, _ad, mut bob, _bd, _ps) =
            make_pair(alice_jid, 1, bob_jid, 2).await;

        // Establish an active session via successful first exchange.
        let msg1 = alice.encrypt_message(bob_jid, "establish").await.unwrap();
        bob.decrypt_message(alice_jid, alice_did, &msg1).await.unwrap();

        let session_key = (bjid(alice_jid), alice_did);
        assert!(
            matches!(bob.sessions.get(&session_key), Some(OmemoSessionState::Active(_))),
            "session must be Active after establishment"
        );

        // Corrupt the encrypted key in a second message so decryption fails.
        let mut msg2 = alice.encrypt_message(bob_jid, "corrupt").await.unwrap();
        if let Some(v) = msg2.encrypted_keys.get_mut(&DeviceId::from(2u32)) {
            for b in v.iter_mut() { *b ^= 0xFF; }
        }

        let _ = bob.decrypt_message(alice_jid, alice_did, &msg2).await;

        // The session must not have been destroyed by the bad message.
        // Either Active (common path) or InitiatorAwaitingReply (also fine).
        let state = bob.sessions.get(&session_key);
        assert!(
            matches!(state, Some(OmemoSessionState::Active(_))),
            "corrupted message must not destroy Active session; got {:?}", state
        );

        // Normal traffic must still work.
        let msg3 = alice.encrypt_message(bob_jid, "still works").await.unwrap();
        let dec = bob.decrypt_message(alice_jid, alice_did, &msg3).await
            .expect("normal message must decrypt after failed attempt");
        assert_eq!(dec, "still works");
    }

    // ── AEAD failure increments recovery_attempt ──────────────────────────────

    /// handle_aead_decryption_failure increments the attempt counter each call.
    /// The ordering: prev_attempt is read BEFORE reset_session removes the
    /// sessions entry — this test enforces that ordering survives refactors.
    #[tokio::test]
    async fn aead_failure_increments_recovery_attempt() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let alice_did = DeviceId::from(1u32);

        let (_alice, _ad, mut bob, _bd, _ps) =
            make_pair(alice_jid, 1, bob_jid, 2).await;

        let key = (bjid(alice_jid), alice_did);

        for expected in 1u8..=6 {
            bob.handle_aead_decryption_failure(alice_jid, alice_did.get())
                .await
                .unwrap();
            let attempt = bob.sessions.get(&key)
                .and_then(|s| s.recovery_attempt())
                .unwrap_or(0);
            assert!(attempt >= expected,
                "attempt must be >= {expected} after {expected} AEAD failures; got {attempt}");
        }

        let state = bob.sessions.get(&key);
        assert!(
            matches!(state, Some(OmemoSessionState::RecoveryPreKeySent { .. })),
            "state must be RecoveryPreKeySent after max failures; got {:?}", state
        );
    }

    // ── PeerResetPending after stale SPK ──────────────────────────────────────

    /// A PreKey built against an SPK that has been rotated out of history must
    /// leave the session in PeerResetPending (covered more fully in lifecycle_tests,
    /// this confirms the session state, not just the error).
    #[tokio::test]
    async fn stale_spk_message_sets_peer_reset_pending() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let alice_did = DeviceId::from(1u32);

        let (mut alice, _ad, mut bob, _bd, _ps) =
            make_pair(alice_jid, 1, bob_jid, 2).await;

        // Alice encrypts before any rotation.
        let msg = alice.encrypt_message(bob_jid, "stale").await.unwrap();

        // Bob rotates the SPK past history depth so the message can no longer decrypt.
        bob.prekey_rotation_config.check_interval = 0;
        for _ in 0..8 {
            bob.prekey_rotation_config.last_rotation = 0;
            bob.check_and_rotate_prekeys().await.unwrap();
        }

        let _ = bob.decrypt_message(alice_jid, alice_did, &msg).await;

        let session_key = (bjid(alice_jid), alice_did);
        assert!(
            matches!(bob.sessions.get(&session_key), Some(OmemoSessionState::PeerResetPending)),
            "stale SPK must yield PeerResetPending; got {:?}",
            bob.sessions.get(&session_key)
        );
    }
}

