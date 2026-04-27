//! BLAKE3-chained JSONL audit log for daemon-network.
//!
//! Every security-relevant event (session established, TOFU pin/mismatch,
//! AEAD failure, rate limit, cookie challenge) is appended as a JSON line
//! with a BLAKE3 hash chain linking each entry to its predecessor.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Audit logger with BLAKE3 hash chain.
pub struct AuditLog {
    writer: Mutex<File>,
    prev_hash: Mutex<[u8; 32]>,
    seq: Mutex<u64>,
}

/// A single audit log entry.
#[derive(Serialize)]
struct AuditEntry<'a> {
    seq: u64,
    ts: &'a str,
    event: &'a str,
    detail: &'a str,
    chain: String,
}

impl AuditLog {
    /// Open or create the audit log file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn open(path: &PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        let genesis = *blake3::hash(b"opensesame:network:audit:genesis").as_bytes();

        Ok(Self {
            writer: Mutex::new(file),
            prev_hash: Mutex::new(genesis),
            seq: Mutex::new(0),
        })
    }

    /// Append an audit event.
    pub fn append(&self, event: &str, detail: &str) {
        let now = {
            use std::time::SystemTime;
            let d = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}Z", d.as_secs())
        };

        let mut seq = self.seq.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *seq += 1;
        let current_seq = *seq;

        let mut prev = self.prev_hash.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let chain_input = format!("{}{event}{detail}{now}", hex::encode(*prev));
        let this_hash = *blake3::hash(chain_input.as_bytes()).as_bytes();

        let entry = AuditEntry {
            seq: current_seq,
            ts: &now,
            event,
            detail,
            chain: hex::encode(this_hash),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            let mut writer = self.writer.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = writeln!(writer, "{json}");
            let _ = writer.flush();
        }

        *prev = this_hash;
    }
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}
