/// Property-based tests for OMEMO session convergence.
///
/// These tests generate arbitrary sequences of operations and assert that
/// Alice and Bob always converge on a working session — i.e., after any
/// sequence of sends, crashes, and restarts, each side can decrypt the
/// other's messages within a bounded number of additional exchanges.
///
/// The tests use the full `OmemoManager` stack (with `RecordingPubSub` and
/// filesystem-backed `OmemoStorage` in temp directories).  `proptest` is
/// synchronous, so each test case runs inside a `tokio` runtime created
/// inline.
#[cfg(test)]
mod proptest_session {
    use proptest::prelude::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    use crate::omemo::device_id::DeviceId;
    use crate::omemo::storage::OmemoStorage;
    use crate::omemo::{OmemoManager, OmemoPubSub};
    use crate::omemo::test_support::RecordingPubSub;

    // ── Test harness ──────────────────────────────────────────────────────────

    /// Reload a manager from the same dir, simulating a process restart.
    async fn make_manager(
        jid: &str,
        device_id: u32,
        dir: &TempDir,
        pubsub: Arc<dyn OmemoPubSub>,
    ) -> OmemoManager {
        let meta = dir.path().join("metadata");
        std::fs::create_dir_all(&meta).unwrap();
        std::fs::write(meta.join("device_id"), device_id.to_string()).unwrap();
        let storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
        OmemoManager::new(storage, jid.to_string(), None, pubsub)
            .await
            .expect("OmemoManager creation failed")
    }

    // ── Operation model ───────────────────────────────────────────────────────

    /// A single operation in a test sequence.
    #[derive(Debug, Clone)]
    enum Op {
        /// Alice sends a message to Bob.
        AliceToBob,
        /// Bob sends a message to Alice.
        BobToAlice,
        /// Restart Alice (reload from storage, preserving disk state).
        RestartAlice,
        /// Restart Bob (reload from storage, preserving disk state).
        RestartBob,
    }

    /// Strategy: sequences of 1..=20 operations.
    /// Sends are 7x more frequent than restarts so the ratchet actually advances.
    fn arb_ops() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(
            prop_oneof![
                7 => Just(Op::AliceToBob),
                7 => Just(Op::BobToAlice),
                1 => Just(Op::RestartAlice),
                1 => Just(Op::RestartBob),
            ],
            1..=20,
        )
    }

    // ── Property test ─────────────────────────────────────────────────────────

    // Core invariant: after any sequence of sends and restarts, Alice and Bob
    // must be able to decrypt each other's messages.  After a crash or failure
    // the next successful send re-establishes the session, so we allow one
    // "recovery send" on each side before declaring convergence achieved.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            ..Default::default()
        })]

        #[test]
        fn session_converges_after_arbitrary_operations(ops in arb_ops()) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let alice_jid = "alice@prop.test";
                let bob_jid   = "bob@prop.test";
                let alice_did = DeviceId::from(40001u32);
                let bob_did   = DeviceId::from(40002u32);

                let pubsub = RecordingPubSub::new();
                let alice_dir = TempDir::new().unwrap();
                let bob_dir   = TempDir::new().unwrap();

                let mut alice = make_manager(alice_jid, alice_did.get(), &alice_dir, pubsub.clone()).await;
                let mut bob   = make_manager(bob_jid,   bob_did.get(),   &bob_dir,   pubsub.clone()).await;

                // Publish both bundles
                pubsub.add_device_list(alice_jid, &[alice_did.get()]).await;
                pubsub.add_device_list(bob_jid,   &[bob_did.get()]).await;
                pubsub.add_bundle(alice_jid, alice_did.get(), alice.key_bundle.as_ref().unwrap()).await;
                pubsub.add_bundle(bob_jid,   bob_did.get(),   bob.key_bundle.as_ref().unwrap()).await;

                // Apply the generated sequence
                for op in &ops {
                    match op {
                        Op::AliceToBob => {
                            if let Ok(msg) = alice.encrypt_message(bob_jid, "ping").await {
                                let _ = bob.decrypt_message(alice_jid, alice_did, &msg).await;
                            }
                        }
                        Op::BobToAlice => {
                            if let Ok(msg) = bob.encrypt_message(alice_jid, "pong").await {
                                let _ = alice.decrypt_message(bob_jid, bob_did, &msg).await;
                            }
                        }
                        Op::RestartAlice => {
                            alice = make_manager(alice_jid, alice_did.get(), &alice_dir, pubsub.clone()).await;
                        }
                        Op::RestartBob => {
                            bob = make_manager(bob_jid, bob_did.get(), &bob_dir, pubsub.clone()).await;
                        }
                    }
                }

                // Convergence check: after the sequence, both sides must be
                // able to exchange a message in a single round-trip.
                // Allowing two attempts hides a real regression (a session that
                // reliably needs two round-trips to recover is broken).
                let converged = try_exchange(&mut alice, alice_jid, alice_did,
                                             &mut bob, bob_jid, bob_did).await;

                // Return the assertion as a Result so proptest can shrink failures
                if converged {
                    Ok::<(), proptest::test_runner::TestCaseError>(())
                } else {
                    Err(proptest::test_runner::TestCaseError::fail(
                        format!("session did not converge after {:?}", ops)
                    ))
                }
            })?
        }
    }

    /// Send one message in each direction and return true if both succeed.
    async fn try_exchange(
        alice: &mut OmemoManager,
        alice_jid: &str,
        alice_did: DeviceId,
        bob: &mut OmemoManager,
        bob_jid: &str,
        bob_did: DeviceId,
    ) -> bool {
        let Ok(msg_a) = alice
            .encrypt_message(bob_jid, "convergence-check-a2b")
            .await
        else {
            return false;
        };
        let Ok(dec_a) = bob.decrypt_message(alice_jid, alice_did, &msg_a).await else {
            return false;
        };
        if dec_a != "convergence-check-a2b" {
            return false;
        }
        let Ok(msg_b) = bob
            .encrypt_message(alice_jid, "convergence-check-b2a")
            .await
        else {
            return false;
        };
        let Ok(dec_b) = alice.decrypt_message(bob_jid, bob_did, &msg_b).await else {
            return false;
        };
        dec_b == "convergence-check-b2a"
    }
}
