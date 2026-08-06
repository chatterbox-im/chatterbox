//! Direct tests for lifecycle.rs: SPK rotation, device-list publishing, ignore/expiry.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::jid::BareJid;
    use crate::omemo::device_id::DeviceId;
    use crate::omemo::session::OmemoSessionState;
    use crate::omemo::test_support::{RecordingPubSub, make_manager, make_pair};

    fn bjid(s: &str) -> BareJid { BareJid::parse(s).unwrap() }

    // ── SPK rotation ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rotation_advances_spk_id_and_stores_old_key_in_history() {
        let ps = RecordingPubSub::new();
        let (mut mgr, _d) = make_manager("alice@example.com", 1, ps).await;
        mgr.prekey_rotation_config.check_interval = 0;
        mgr.prekey_rotation_config.last_rotation  = 0;

        let before = mgr.key_bundle.clone().unwrap();
        assert!(mgr.check_and_rotate_prekeys().await.unwrap(), "rotation must fire");
        let after = mgr.key_bundle.as_ref().unwrap();

        assert_eq!(
            after.signed_pre_key_id,
            before.signed_pre_key_id + 1,
            "SPK id must increment"
        );
        assert_ne!(
            after.signed_pre_key_pair.public_key.as_raw(),
            before.signed_pre_key_pair.public_key.as_raw(),
            "rotation must produce a new SPK"
        );
        assert_eq!(
            after.signed_pre_key_history
                .get(&before.signed_pre_key_id)
                .expect("outgoing SPK must be in history")
                .public_key
                .as_raw(),
            before.signed_pre_key_pair.public_key.as_raw(),
        );
        assert_eq!(
            after.identity_key_pair.public_key.as_raw(),
            before.identity_key_pair.public_key.as_raw(),
            "rotation must never change the identity key"
        );
    }

    #[tokio::test]
    async fn history_trims_to_depth_5_keeping_newest() {
        let ps = RecordingPubSub::new();
        let (mut mgr, _d) = make_manager("alice@example.com", 2, ps).await;
        mgr.prekey_rotation_config.check_interval = 0;

        let mut ids = Vec::new();
        for _ in 0..8 {
            ids.push(mgr.key_bundle.as_ref().unwrap().signed_pre_key_id);
            mgr.prekey_rotation_config.last_rotation = 0;
            mgr.check_and_rotate_prekeys().await.unwrap();
        }

        let h = &mgr.key_bundle.as_ref().unwrap().signed_pre_key_history;
        assert_eq!(h.len(), 5, "history must be trimmed to SPK_HISTORY_DEPTH=5");
        for old in &ids[..3] {
            assert!(!h.contains_key(old), "SPK id {old} should have been evicted");
        }
        for keep in &ids[3..] {
            assert!(h.contains_key(keep), "SPK id {keep} must be retained");
        }
    }

    #[tokio::test]
    async fn no_rotation_when_interval_not_reached() {
        let ps = RecordingPubSub::new();
        let (mut mgr, _d) = make_manager("alice@example.com", 3, ps).await;
        mgr.prekey_rotation_config.check_interval = 86_400;
        mgr.prekey_rotation_config.last_rotation  = mgr.now_secs(); // just rotated

        let rotated = mgr.check_and_rotate_prekeys().await.unwrap();
        assert!(!rotated, "rotation must be skipped when interval not reached");
    }

    /// Future last_rotation (e.g. NTP step or restored backup) must not panic.
    /// Without saturating_sub, (now - future) wraps to a huge u64 in release.
    #[tokio::test]
    async fn rotation_survives_last_rotation_in_the_future() {
        let ps = RecordingPubSub::new();
        let (mut mgr, _d) = make_manager("alice@example.com", 4, ps).await;
        mgr.prekey_rotation_config.check_interval = 86_400;
        mgr.prekey_rotation_config.last_rotation  = mgr.now_secs() + 86_400;

        let r = mgr.check_and_rotate_prekeys().await;
        assert!(r.is_ok(), "future last_rotation must not panic; got: {:?}", r);
    }

    /// A message encrypted against a rotated SPK must still decrypt via history.
    #[tokio::test]
    async fn prekey_built_against_rotated_spk_still_decrypts() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let (mut alice, _ad, mut bob, _bd, ps) =
            make_pair(alice_jid, 10, bob_jid, 20).await;

        let msg = alice.encrypt_message(bob_jid, "in flight").await.unwrap();

        // Bob rotates before the message lands.
        bob.prekey_rotation_config.check_interval = 0;
        bob.prekey_rotation_config.last_rotation  = 0;
        bob.check_and_rotate_prekeys().await.unwrap();

        // Must still decrypt via signed_pre_key_history.
        let decrypted = bob
            .decrypt_message(alice_jid, DeviceId::from(10u32), &msg)
            .await
            .expect("should decrypt via history");
        assert_eq!(decrypted, "in flight");
    }

    /// A message built against an SPK that has fallen off the history tail must fail.
    #[tokio::test]
    async fn prekey_older_than_history_depth_is_rejected() {
        let alice_jid = "alice@example.com";
        let bob_jid   = "bob@example.com";
        let (mut alice, _ad, mut bob, _bd, _ps) =
            make_pair(alice_jid, 11, bob_jid, 21).await;

        let msg = alice.encrypt_message(bob_jid, "very stale").await.unwrap();

        // Rotate 8 times, pushing the original SPK off the end of the history.
        for _ in 0..8 {
            bob.prekey_rotation_config.check_interval = 0;
            bob.prekey_rotation_config.last_rotation  = 0;
            bob.check_and_rotate_prekeys().await.unwrap();
        }

        let r = bob.decrypt_message(alice_jid, DeviceId::from(11u32), &msg).await;
        assert!(r.is_err(), "stale SPK must be rejected");

        // After rejection, the session state must be PeerResetPending so the
        // next outbound message starts a fresh X3DH exchange.
        let key = (bjid(alice_jid), DeviceId::from(11u32));
        assert!(
            matches!(
                bob.sessions.get(&key),
                Some(OmemoSessionState::PeerResetPending)
            ),
            "expected PeerResetPending after stale-SPK rejection"
        );
    }

    // ── device-list publishing ─────────────────────────────────────────────────

    #[tokio::test]
    async fn own_device_appended_not_replacing_existing_list() {
        let ps = RecordingPubSub::new();
        let alice_jid = "alice@example.com";
        ps.add_device_list(alice_jid, &[7777, 8888]).await;

        let (mgr, _d) = make_manager(alice_jid, 999, ps.clone()).await;
        mgr.ensure_device_list_published().await.unwrap();

        let published = ps.log.lock().await.device_lists.last().cloned().unwrap();
        assert!(published.contains(&DeviceId::from(7777u32)), "must keep 7777");
        assert!(published.contains(&DeviceId::from(8888u32)), "must keep 8888");
        assert!(published.contains(&mgr.device_id), "must add own device");
    }

    #[tokio::test]
    async fn no_republish_when_already_listed() {
        let ps = RecordingPubSub::new();
        let alice_jid = "alice@example.com";

        let (mgr, _d) = make_manager(alice_jid, 555, ps.clone()).await;
        ps.add_device_list(alice_jid, &[mgr.device_id.get()]).await;

        mgr.ensure_device_list_published().await.unwrap();

        let log = ps.log.lock().await;
        assert!(
            log.device_lists.is_empty(),
            "must not republish when already present; log: {:?}",
            log.device_lists
        );
    }

    // ── ignore / expiry ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn three_failures_triggers_ignore_two_does_not() {
        let ps = RecordingPubSub::new();
        let (mut mgr, _d) = make_manager("alice@example.com", 1, ps).await;
        let peer = "bob@example.com";
        let did  = 999u32;

        for _ in 0..2 {
            mgr.track_undecryptable_message(peer, did).await.unwrap();
        }
        assert!(
            !mgr.is_device_ignored(&bjid(peer), did).await.unwrap(),
            "must not ignore before the 3rd failure"
        );

        mgr.track_undecryptable_message(peer, did).await.unwrap();
        assert!(
            mgr.is_device_ignored(&bjid(peer), did).await.unwrap(),
            "must ignore after 3rd failure"
        );
    }

    #[tokio::test]
    async fn ignore_expires_after_its_duration() {
        let ps = RecordingPubSub::new();
        let (mut mgr, _d) = make_manager("alice@example.com", 1, ps).await;
        let peer = bjid("bob@example.com");
        let did  = 42u32;

        mgr.ignore_device(&peer, did, std::time::Duration::from_secs(300))
            .await.unwrap();
        assert!(mgr.is_device_ignored(&peer, did).await.unwrap());

        // Advance the virtual clock past the expiry.
        mgr.now_override = Some(mgr.now_secs() + 301);
        assert!(!mgr.is_device_ignored(&peer, did).await.unwrap());
    }

    #[tokio::test]
    async fn reset_session_clears_all_flags_and_survives_restart() {
        use crate::omemo::storage::OmemoStorage;

        let ps = RecordingPubSub::new();
        let (mut mgr, dir) = make_manager("alice@example.com", 1, ps.clone()).await;
        let peer    = bjid("bob@example.com");
        let bob_did = DeviceId::from(77u32);

        // Set up flags that reset_session must clear.
        mgr.sessions.insert(
            (peer.clone(), bob_did),
            OmemoSessionState::PeerResetPending,
        );
        mgr.ignore_device(&peer, bob_did.get(), std::time::Duration::from_secs(600))
            .await.unwrap();

        mgr.reset_session(&peer, bob_did.get()).await.unwrap();

        assert!(mgr.sessions.get(&(peer.clone(), bob_did)).is_none(),
            "session must be removed");
        assert!(!mgr.is_device_ignored(&peer, bob_did.get()).await.unwrap(),
            "ignore flag must be cleared");
        assert_eq!(
            mgr.get_device_failure_count(&peer, bob_did.get()).await, 0,
            "failure count must be reset"
        );

        // Reload from the same storage directory — flags must be gone on disk.
        let storage2 = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        let rebuild_still_set = storage2
            .load_all_rebuild_pending()
            .iter()
            .any(|(jid, did)| jid == peer.as_str() && *did == bob_did);
        assert!(!rebuild_still_set, "rebuild flag must be cleared on disk");

        let prekey_still_set = storage2
            .load_all_prekey_pending()
            .iter()
            .any(|(jid, did)| jid == peer.as_str() && *did == bob_did);
        assert!(!prekey_still_set, "prekey-pending flag must be cleared on disk");
    }
}
