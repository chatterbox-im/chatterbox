//! Startup filesystem sandbox (best-effort).
//!
//! Restricts the process so it can only touch its own data directories, system
//! libraries, and the network. Everything else in the user's home — documents,
//! `~/.ssh`, other apps' data, browser profiles — becomes unreadable.
//!
//! Implemented with [`birdcage`], which maps to **Landlock + seccomp on Linux**
//! and **Seatbelt (`sandbox_init`) on macOS**. birdcage 0.8 has no in-process
//! "lock" call, so we use a re-exec pattern: the first invocation installs the
//! sandbox and execs a copy of itself (the "sandboxee") which runs the actual
//! application, fully confined.
//!
//! On macOS the base Seatbelt profile birdcage emits still allows mach/IPC, so
//! DNS (via `mDNSResponder`) and TLS trust evaluation (via `securityd`/`trustd`)
//! keep working — only filesystem access is locked down.
//!
//! Set `CHATTERBOX_NO_SANDBOX=1` to disable (e.g. to diagnose a denial).

use std::path::PathBuf;

/// Env var marking the already-sandboxed child process, so it doesn't re-exec.
const SANDBOX_MARKER: &str = "CHATTERBOX_SANDBOXED";

/// Env var to opt out of sandboxing entirely.
const DISABLE_VAR: &str = "CHATTERBOX_NO_SANDBOX";

/// Install the sandbox and re-exec the application inside it.
///
/// `allow_dirs` are the only user locations granted read+write; they **must
/// already exist** on disk, since the sandbox canonicalises them.
///
/// When this returns, the current process should continue running the app —
/// either because we are the sandboxed child, sandboxing is disabled, the
/// platform is unsupported, or setup failed (fail-open). On the first (parent)
/// invocation, when sandboxing succeeds, this spawns the sandboxed child, waits
/// for it, and **exits the process** with the child's status — it does not
/// return in that case.
pub fn install_and_reexec(allow_dirs: &[PathBuf]) {
    // Already inside the sandboxed child → just run the app.
    if std::env::var_os(SANDBOX_MARKER).is_some() {
        return;
    }
    // Explicitly disabled → run unconfined, but say so.
    if std::env::var_os(DISABLE_VAR).is_some() {
        eprintln!("chatterbox: sandbox disabled via {DISABLE_VAR}");
        return;
    }

    match try_reexec(allow_dirs) {
        // Child was spawned and finished — propagate its exit code.
        Ok(code) => std::process::exit(code),
        // Setup failed *before* a child was spawned. Fail open: a broken
        // sandbox must not make the client unusable.
        Err(e) => {
            eprintln!(
                "chatterbox: WARNING — could not enable sandbox ({e}); running \
                 WITHOUT filesystem isolation. Set {DISABLE_VAR}=1 to silence."
            );
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn try_reexec(allow_dirs: &[PathBuf]) -> anyhow::Result<i32> {
    use birdcage::process::Command;
    use birdcage::{Birdcage, Exception, Sandbox};
    use std::path::Path;

    let exe = std::env::current_exe()?;
    let mut cage = Birdcage::new();

    // Our own binary must be executable+readable from inside the sandbox, or the
    // confined parent cannot exec the sandboxee (and the loader cannot read it).
    cage.add_exception(Exception::ExecuteAndRead(exe.clone()))?;

    // Preserve the whole environment (HOME, TERM, XMPP_* credentials, …);
    // without this birdcage would scrub it from the child.
    cage.add_exception(Exception::FullEnvironment)?;

    // Network for the XMPP connection. On macOS, DNS + TLS additionally rely on
    // the base profile's mach/ipc allowances, which birdcage already grants.
    cage.add_exception(Exception::Networking)?;

    // System locations needed to load and run the binary + drive the terminal.
    // These are intentionally broad: the security goal is denying access to the
    // *user's* files, not to read-only system paths.
    for path in system_exec_paths() {
        let p = Path::new(path);
        if p.exists() {
            // ExecuteAndRead also covers read access for libraries/resources.
            let _ = cage.add_exception(Exception::ExecuteAndRead(p.to_path_buf()));
        }
    }
    for path in system_read_paths() {
        let p = Path::new(path);
        if p.exists() {
            let _ = cage.add_exception(Exception::Read(p.to_path_buf()));
        }
    }

    // Scratch space (sqlite temp files, TLS, etc.).
    let tmp = std::env::temp_dir();
    if tmp.exists() {
        cage.add_exception(Exception::WriteAndRead(tmp))?;
    }

    // The app's own data directories — the only writable user locations.
    for dir in allow_dirs {
        cage.add_exception(Exception::WriteAndRead(dir.clone()))?;
    }

    // Build the sandboxee: re-run ourselves with the same args. stdio is
    // inherited by default, so the child keeps the real TTY for the TUI.
    let mut cmd = Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    cmd.env(SANDBOX_MARKER, "1");

    // `spawn` installs the sandbox in THIS process and launches the child.
    // Any error here happens before the child exists, so it's safe to fall
    // through and run unconfined.
    let mut child = cage.spawn(cmd)?;

    // From here a sandboxed child is running; we must NOT also run the app in
    // this (now-confined) parent. Always terminate with the child's status.
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
    Ok(code)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn try_reexec(_allow_dirs: &[PathBuf]) -> anyhow::Result<i32> {
    anyhow::bail!("sandboxing is not supported on this platform")
}

/// Directories granted execute+read (loader, system binaries, libraries).
#[cfg(target_os = "macos")]
fn system_exec_paths() -> &'static [&'static str] {
    // birdcage's base profile imports `system.sb`, which already grants most
    // system reads; these are belt-and-suspenders for the loader and TUI.
    &["/usr/lib", "/usr/bin", "/bin", "/sbin", "/System"]
}

/// Directories granted read-only access (config, shared data, devices).
#[cfg(target_os = "macos")]
fn system_read_paths() -> &'static [&'static str] {
    &["/usr/share", "/private/etc", "/Library", "/dev"]
}

#[cfg(target_os = "linux")]
fn system_exec_paths() -> &'static [&'static str] {
    &[
        "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]
}

#[cfg(target_os = "linux")]
fn system_read_paths() -> &'static [&'static str] {
    &[
        "/usr/share",
        "/etc",
        "/proc",
        "/sys",
        "/run/systemd/resolve",
        "/dev/urandom",
        "/dev/null",
        "/dev/tty",
    ]
}
