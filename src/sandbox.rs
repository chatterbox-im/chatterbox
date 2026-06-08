//! Startup filesystem sandbox (best-effort).
//!
//! Confines the process so it can only touch its own data directories, system
//! libraries, and the network. Everything else in the user's home — documents,
//! `~/.ssh`, other apps' data under `~/Library/Application Support` — becomes
//! unreadable.
//!
//! Platforms:
//! - **macOS**: a hand-written Seatbelt profile applied in-process via
//!   `sandbox_init`. We roll our own (rather than use `birdcage`) because a TUI
//!   needs `file-ioctl` on the terminal for raw mode and `user-preference-read`
//!   for CoreFoundation/Security — neither of which birdcage's profile can
//!   express. The base profile keeps `mach`/`ipc` open, so DNS (`mDNSResponder`)
//!   and TLS trust evaluation (`securityd`/`trustd`) keep working.
//! - **Linux**: `birdcage` (Landlock + seccomp). birdcage has no in-process
//!   lock, so we re-exec a confined copy of ourselves as the sandboxee.
//!
//! Set `CHATTERBOX_NO_SANDBOX=1` to disable (e.g. to diagnose a denial via
//! `log show --last 2m --predicate 'sender == "Sandbox"' | grep deny`).

use std::path::PathBuf;

/// Env var to opt out of sandboxing entirely.
const DISABLE_VAR: &str = "CHATTERBOX_NO_SANDBOX";

/// Confine the current process to `allow_dirs` (read+write), system locations,
/// and the network. `allow_dirs` must already exist on disk.
///
/// On macOS this confines the process in place and returns. On Linux it re-execs
/// a sandboxed child and, on success, exits with the child's status (so it does
/// not return). On unsupported platforms, or on any setup failure, it warns and
/// returns so the app still runs (fail-open).
pub fn install_and_reexec(allow_dirs: &[PathBuf]) {
    if std::env::var_os(DISABLE_VAR).is_some() {
        eprintln!("chatterbox: sandbox disabled via {DISABLE_VAR}");
        return;
    }

    #[cfg(target_os = "macos")]
    macos::install(allow_dirs);

    #[cfg(target_os = "linux")]
    linux::install(allow_dirs);

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = allow_dirs;
        eprintln!("chatterbox: sandboxing not supported on this platform; continuing unconfined");
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString};
    use std::fmt::Write as _;
    use std::os::raw::c_char;
    use std::path::PathBuf;
    use std::ptr;

    extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    pub fn install(allow_dirs: &[PathBuf]) {
        match try_install(allow_dirs) {
            Ok(()) => log::info!("macOS Seatbelt sandbox active"),
            Err(e) => eprintln!(
                "chatterbox: WARNING — could not enable sandbox ({e}); running WITHOUT \
                 filesystem isolation. Set CHATTERBOX_NO_SANDBOX=1 to silence."
            ),
        }
    }

    fn try_install(allow_dirs: &[PathBuf]) -> anyhow::Result<()> {
        let profile = build_profile(allow_dirs);
        let c_profile = CString::new(profile)?;

        let mut err: *mut c_char = ptr::null_mut();
        // flags = 0: `profile` is a literal SBPL string (not a named profile).
        let rc = unsafe { sandbox_init(c_profile.as_ptr(), 0, &mut err) };
        if rc == 0 {
            return Ok(());
        }

        let msg = if err.is_null() {
            "sandbox_init failed".to_string()
        } else {
            let m = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
            unsafe { sandbox_free_error(err) };
            m
        };
        anyhow::bail!("{msg}")
    }

    /// Build the Seatbelt (SBPL) profile string.
    fn build_profile(allow_dirs: &[PathBuf]) -> String {
        // Base: import the system profile (system libraries, dyld cache), deny by
        // default, then re-open the operation classes a networked TUI needs.
        let mut p = String::from(
            "(version 1)\n\
             (import \"system.sb\")\n\
             (deny default)\n\
             (allow mach*)\n\
             (allow ipc*)\n\
             (allow signal (target others))\n\
             (allow process-fork)\n\
             (allow sysctl*)\n\
             (allow system*)\n\
             (allow file-read-metadata)\n\
             (allow file-ioctl (subpath \"/dev\"))\n\
             (allow user-preference-read)\n\
             (system-network)\n\
             (allow network*)\n",
        );

        // Read-only system locations (frameworks, DNS config in /private/var/run,
        // shared caches in /private/var/folders).
        p.push_str("(allow file-read*\n");
        for sp in [
            "/usr",
            "/System",
            "/Library",
            "/Applications",
            "/bin",
            "/sbin",
            "/opt",
            "/private/etc",
            "/private/var",
            "/dev",
        ] {
            let _ = writeln!(p, "  (subpath {})", quote(sp));
        }
        // The binary's own directory (the loader / backtrace may read it).
        if let Some(dir) = exe_dir() {
            let _ = writeln!(p, "  (subpath {})", quote(&dir));
        }
        p.push_str(")\n");

        // Read+write: our data directories, scratch space, and the terminal
        // devices (crossterm opens /dev/tty O_RDWR for raw mode).
        p.push_str("(allow file-read* file-write*\n");
        for dir in allow_dirs {
            if let Ok(canon) = std::fs::canonicalize(dir) {
                let _ = writeln!(p, "  (subpath {})", quote(&canon.to_string_lossy()));
            }
        }
        if let Ok(tmp) = std::fs::canonicalize(std::env::temp_dir()) {
            let _ = writeln!(p, "  (subpath {})", quote(&tmp.to_string_lossy()));
        }
        p.push_str("  (literal \"/dev/tty\")\n  (literal \"/dev/null\")\n)\n");

        p
    }

    fn exe_dir() -> Option<String> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        let canon = std::fs::canonicalize(dir).ok()?;
        Some(canon.to_string_lossy().into_owned())
    }

    /// Quote and escape a path for an SBPL string literal.
    fn quote(path: &str) -> String {
        let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use birdcage::process::Command;
    use birdcage::{Birdcage, Exception, Sandbox};
    use std::path::{Path, PathBuf};

    /// Marks the already-sandboxed child so it doesn't re-exec again.
    const SANDBOX_MARKER: &str = "CHATTERBOX_SANDBOXED";

    pub fn install(allow_dirs: &[PathBuf]) {
        if std::env::var_os(SANDBOX_MARKER).is_some() {
            return; // we are the sandboxed child — run the app
        }
        match try_reexec(allow_dirs) {
            Ok(code) => std::process::exit(code),
            Err(e) => eprintln!(
                "chatterbox: WARNING — could not enable sandbox ({e}); running WITHOUT \
                 filesystem isolation. Set CHATTERBOX_NO_SANDBOX=1 to silence."
            ),
        }
    }

    fn try_reexec(allow_dirs: &[PathBuf]) -> anyhow::Result<i32> {
        let exe = std::env::current_exe()?;
        let mut cage = Birdcage::new();

        // Our own binary must be executable+readable from inside the sandbox.
        cage.add_exception(Exception::ExecuteAndRead(exe.clone()))?;
        // Preserve the environment (HOME, TERM, XMPP_* credentials, …).
        cage.add_exception(Exception::FullEnvironment)?;
        cage.add_exception(Exception::Networking)?;

        for path in [
            "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
        ] {
            let p = Path::new(path);
            if p.exists() {
                let _ = cage.add_exception(Exception::ExecuteAndRead(p.to_path_buf()));
            }
        }
        for path in [
            "/usr/share",
            "/etc",
            "/proc",
            "/sys",
            "/run/systemd/resolve",
            "/dev/urandom",
        ] {
            let p = Path::new(path);
            if p.exists() {
                let _ = cage.add_exception(Exception::Read(p.to_path_buf()));
            }
        }
        // Terminal devices need read+write for crossterm's raw mode.
        for path in ["/dev/tty", "/dev/null"] {
            let p = Path::new(path);
            if p.exists() {
                let _ = cage.add_exception(Exception::WriteAndRead(p.to_path_buf()));
            }
        }

        let tmp = std::env::temp_dir();
        if tmp.exists() {
            cage.add_exception(Exception::WriteAndRead(tmp))?;
        }
        for dir in allow_dirs {
            cage.add_exception(Exception::WriteAndRead(dir.clone()))?;
        }

        // Re-run ourselves with the same args; stdio is inherited (keeps the TTY).
        let mut cmd = Command::new(exe);
        cmd.args(std::env::args_os().skip(1));
        cmd.env(SANDBOX_MARKER, "1");

        // `spawn` installs the sandbox in this process and launches the child.
        // Any error here is before the child exists, so it's safe to fall through.
        let mut child = cage.spawn(cmd)?;

        // A sandboxed child is now running; never fall back to running the app in
        // this (now-confined) parent. Always exit with the child's status.
        let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
        Ok(code)
    }
}
