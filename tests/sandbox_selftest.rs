//! Verifies the startup sandbox actually denies reads outside its allow-list.
//!
//! The sandbox is process-global and irreversible, so it can't be exercised
//! inside the (multithreaded) test runner. Instead we run the real binary in a
//! hidden self-test mode (`CHATTERBOX_SANDBOX_SELFTEST`): it applies the
//! production sandbox allowing only a temp dir, then checks from inside the
//! sandbox that a sibling file in `$HOME` (outside the allow-list) is unreadable
//! while the allowed dir stays read+writable.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::process::Command;

#[test]
fn sandbox_blocks_reads_outside_allowlist() {
    let exe = env!("CARGO_BIN_EXE_chatterbox");

    // Probe data lives under $HOME — a region the sandbox denies by default —
    // with an explicitly-allowed subdir and a sibling "secret" that must remain
    // unreadable once confined.
    let home = dirs::home_dir().expect("home dir");
    let base = home.join(format!(".chatterbox-sbtest-{}", std::process::id()));
    let allow = base.join("allowed");
    let secret = base.join("secret.txt");
    std::fs::create_dir_all(&allow).expect("create allow dir");
    std::fs::write(&secret, b"TOPSECRET").expect("write secret");

    let output = Command::new(exe)
        .env("CHATTERBOX_SANDBOX_SELFTEST", "1")
        .env("CHATTERBOX_ST_ALLOW", &allow)
        .env("CHATTERBOX_ST_DENIED", &secret)
        .output()
        .expect("run sandbox self-test");

    let _ = std::fs::remove_dir_all(&base);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // If the sandbox couldn't be installed here (e.g. a Linux kernel without
    // Landlock), the binary fails open — the test is inconclusive, not failed.
    // On macOS the sandbox (Seatbelt) is always available; treat unavailability
    // as a hard failure so CI on the primary platform never silently skips.
    if stderr.contains("could not enable sandbox") || stderr.contains("not supported") {
        #[cfg(target_os = "macos")]
        panic!("sandbox must be available on macOS: {}", stderr.trim());
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!(
                "SKIP: sandbox unavailable in this environment: {}",
                stderr.trim()
            );
            return;
        }
    }

    assert!(
        stdout.contains("DENIED_READ_BLOCKED=true"),
        "sandbox did NOT block a read outside its allow-list.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("ALLOWED_RW_OK=true"),
        "sandbox blocked its own allowed data dir.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        output.status.success(),
        "self-test probe exited nonzero.\nstdout: {stdout}\nstderr: {stderr}"
    );
}
