//! Single-instance application lock.
//!
//! Prevents multiple Chatterbox instances from running concurrently against the
//! same data directory, avoiding OMEMO ratchet desynchronization, prekey bundle
//! conflicts, and SQLite database locking errors.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum InstanceLockError {
    #[error("Another instance of Chatterbox is already running{}", .pid.map(|p| format!(" (PID {})", p)).unwrap_or_default())]
    AlreadyRunning {
        pid: Option<u32>,
        path: PathBuf,
    },
    #[error("Failed to open or lock instance lockfile {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// An active single-instance lock.
///
/// Keeps an open file descriptor with an exclusive non-blocking advisory lock
/// (`flock`) for the lifetime of this struct. Dropping this struct closes the
/// file and automatically releases the lock.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Attempt to acquire an exclusive lock on the file at `path`.
    ///
    /// If another process already holds the lock, returns
    /// `Err(InstanceLockError::AlreadyRunning)`.
    pub fn acquire(path: &Path) -> Result<Self, InstanceLockError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| InstanceLockError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| InstanceLockError::Io {
                path: path.to_path_buf(),
                source,
            })?;

        #[cfg(unix)]
        {
            use rustix::fs::{flock, FlockOperation};
            if let Err(err) = flock(&file, FlockOperation::NonBlockingLockExclusive) {
                if err == rustix::io::Errno::WOULDBLOCK || err == rustix::io::Errno::AGAIN {
                    let pid = read_pid_from_file(&mut file);
                    return Err(InstanceLockError::AlreadyRunning {
                        pid,
                        path: path.to_path_buf(),
                    });
                }
                return Err(InstanceLockError::Io {
                    path: path.to_path_buf(),
                    source: err.into(),
                });
            }
        }

        // We acquired the lock. Record the current PID.
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = writeln!(file, "{}", std::process::id());
        let _ = file.flush();

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
        })
    }

    /// Returns the path to the lockfile.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn read_pid_from_file(file: &mut File) -> Option<u32> {
    let _ = file.seek(SeekFrom::Start(0));
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;
    contents.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_acquire_and_release() {
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

        let lock1 = InstanceLock::acquire(&lock_path).expect("first acquire succeeds");
        assert_eq!(lock1.path(), lock_path.as_path());

        // Second acquire on the same path must fail with AlreadyRunning
        match InstanceLock::acquire(&lock_path) {
            Err(InstanceLockError::AlreadyRunning { pid, .. }) => {
                assert_eq!(pid, Some(std::process::id()));
            }
            other => panic!("expected AlreadyRunning, got {:?}", other),
        }

        // Drop first lock
        drop(lock1);

        // Third acquire should now succeed
        let lock2 = InstanceLock::acquire(&lock_path).expect("acquire after drop succeeds");
        drop(lock2);
    }

    #[test]
    fn test_two_different_paths() {
        let dir = tempdir().expect("tempdir");
        let path1 = dir.path().join("app1.lock");
        let path2 = dir.path().join("app2.lock");

        let lock1 = InstanceLock::acquire(&path1).expect("acquire path1 succeeds");
        let lock2 = InstanceLock::acquire(&path2).expect("acquire path2 succeeds");

        drop(lock1);
        drop(lock2);
    }

    #[test]
    fn test_nested_dir_creation() {
        let dir = tempdir().expect("tempdir");
        let nested_lock_path = dir.path().join("sub").join("nested").join("test.lock");

        let lock = InstanceLock::acquire(&nested_lock_path).expect("nested acquire succeeds");
        assert!(nested_lock_path.exists());
        drop(lock);
    }

    #[test]
    fn test_stale_lockfile_recovery() {
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("stale.lock");

        // Simulate an old process writing a PID and exiting (releasing the kernel lock)
        std::fs::write(&lock_path, "99999\n").expect("write stale lock");

        // A new instance should be able to acquire the lock immediately
        let lock = InstanceLock::acquire(&lock_path).expect("acquire on stale file succeeds");

        // The file should now contain our current PID
        let content = std::fs::read_to_string(&lock_path).expect("read lockfile");
        assert_eq!(content.trim(), std::process::id().to_string());
        drop(lock);
    }
}
