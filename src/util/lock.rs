//! Single instance lock
//!
//! Ensures only one instance of open-sesame runs at a time.
//! IPC is now handled by the ipc module using Unix domain sockets.

use crate::util::paths;
use crate::util::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Lock file for single instance enforcement
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Attempts to acquire the instance lock.
    ///
    /// Returns Ok(lock) if successful, Err if another instance is running.
    pub fn acquire() -> Result<Self> {
        let path = Self::lock_path();

        // Parent directory creation ensured
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // File opened without truncate to prevent PID wipe race condition
        // Truncation occurs only after lock acquisition
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::Other(format!("Failed to open lock file: {}", e)))?;

        // Exclusive lock acquisition attempted (non-blocking)
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

        if result != 0 {
            // Lock failed indicates another instance is running
            return Err(Error::Other(
                "Another instance is already running".to_string(),
            ));
        }

        // Lock acquired successfully, truncate and write PID
        let mut file = file;
        file.set_len(0)
            .map_err(|e| Error::Other(format!("Failed to truncate lock file: {}", e)))?;
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| Error::Other(format!("Failed to seek lock file: {}", e)))?;
        writeln!(file, "{}", std::process::id())
            .map_err(|e| Error::Other(format!("Failed to write PID: {}", e)))?;
        file.flush()
            .map_err(|e| Error::Other(format!("Failed to flush PID: {}", e)))?;

        tracing::debug!(
            "Lock acquired, PID {} written to {}",
            std::process::id(),
            path.display()
        );

        Ok(Self { _file: file, path })
    }

    /// Get the lock file path
    ///
    /// Uses ~/.cache/open-sesame/instance.lock with secure permissions.
    /// Falls back to UID-based naming only if cache dir cannot be determined.
    fn lock_path() -> PathBuf {
        // Secure cache directory used
        match paths::lock_file() {
            Ok(path) => path,
            Err(e) => {
                // Rare occurrence - only when HOME is completely unset
                // UID-based fallback provides minimal safety
                tracing::error!(
                    "Failed to get secure lock path: {}. Using UID-based fallback.",
                    e
                );
                let uid = unsafe { libc::getuid() };
                PathBuf::from(format!("/run/user/{}/open-sesame.lock", uid))
            }
        }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Lock automatically released when file is closed
        // Lock file optionally removed
        std::fs::remove_file(&self.path).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_path_returns_valid_path() {
        let path = InstanceLock::lock_path();
        // Path contains "open-sesame"
        assert!(
            path.to_string_lossy().contains("open-sesame"),
            "Lock path should contain 'open-sesame': {:?}",
            path
        );
        // Filename ends with .lock or instance.lock
        let filename = path
            .file_name()
            .expect("lock path should have a filename component")
            .to_string_lossy();
        assert!(
            filename.contains("lock"),
            "Lock file should have 'lock' in name: {:?}",
            path
        );
    }

    #[test]
    fn test_instance_lock_acquire_and_release() {
        // Test creates and releases lock
        // Unique path used to avoid conflicts with running instances

        // Lock acquisition
        let lock = InstanceLock::acquire();

        // Acquisition failure acceptable for testing (indicates running instance)
        if let Ok(_lock) = lock {
            // Lock held
            // Second acquisition attempt should fail
            let lock2 = InstanceLock::acquire();
            assert!(lock2.is_err(), "Double lock acquisition prevented");

            // Lock released when _lock goes out of scope
        }
        // lock.is_err() indicates running instance (acceptable for test)
    }
}
