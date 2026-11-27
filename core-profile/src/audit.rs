//! Hash-chained audit logger for tamper-evident profile operations.
//!
//! Each entry includes the hash of the previous entry's serialized line,
//! forming an append-only chain. Tampering with any entry invalidates all
//! subsequent hashes. The hash algorithm is the configured
//! `[crypto] audit_hash` (BLAKE3 by default, SHA-256 for
//! governance-compatible deployments); a chain is only verifiable under
//! the algorithm it was written with.
//!
//! This module is the only reader and writer of the audit log file:
//! [`open_audit_log`] resumes the chain for appending, [`read_audit_log`]
//! reads it, and [`verify_audit_log`] replays it.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{AuditAction, AuditEntry};

/// The chain hash of one serialized entry line: the next entry's
/// `prev_hash`.
fn chain_hash(line: &str, algorithm: core_types::AuditHash) -> String {
    match algorithm {
        core_types::AuditHash::Blake3 => blake3::hash(line.as_bytes()).to_hex().to_string(),
        core_types::AuditHash::Sha256 => {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(line.as_bytes()))
        }
    }
}

/// The contents of the audit log at `path`, or `None` when no log exists.
///
/// # Errors
///
/// `core_types::Error::Profile` naming the path when the log exists but
/// cannot be read.
pub fn read_audit_log(path: &Path) -> core_types::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(core_types::Error::Profile(format!(
            "failed to read audit log {}: {e}",
            path.display()
        ))),
    }
}

/// Replay the hash chain of the audit log at `path` under `algorithm`:
/// the number of verified entries, or `None` when no log exists.
///
/// # Errors
///
/// The `read_audit_log` errors, and the `verify_chain` errors for a
/// tampered or unparseable log.
pub fn verify_audit_log(
    path: &Path,
    algorithm: core_types::AuditHash,
) -> core_types::Result<Option<u64>> {
    read_audit_log(path)?
        .map(|contents| verify_chain(&contents, algorithm))
        .transpose()
}

/// Open the audit log at `path` for appending, continuing its chain under
/// `algorithm`. The file is created when absent; on Unix it is restricted
/// to its owner (0600), including a pre-existing file.
///
/// # Errors
///
/// The `load_audit_state` errors, and `core_types::Error::Profile` naming
/// the path when the log cannot be opened or its permissions set.
pub fn open_audit_log(
    path: &Path,
    algorithm: core_types::AuditHash,
    default_agent_id: Option<core_types::AgentId>,
) -> core_types::Result<AuditLogger<BufWriter<File>>> {
    // The chain head is read before the append handle exists, so the
    // handle cannot observe a partially created file.
    let AuditState {
        last_hash,
        sequence,
    } = load_audit_state(path, algorithm)?;
    let io_error = |what: &str, e: std::io::Error| {
        core_types::Error::Profile(format!(
            "failed to {what} audit log {}: {e}",
            path.display()
        ))
    };
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(path).map_err(|e| io_error("open", e))?;
    // `mode` applies only at creation; a pre-existing log is restricted here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io_error("restrict permissions of", e))?;
    }
    Ok(AuditLogger::new(
        BufWriter::new(file),
        last_hash,
        sequence,
        algorithm,
        default_agent_id,
    ))
}

/// Chain head of an existing log: the hash of its last entry and that
/// entry's sequence. A fresh log has an empty hash and sequence 0.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditState {
    last_hash: String,
    sequence: u64,
}

/// Load the chain head from the log at `path` so a new `AuditLogger`
/// continues the chain.
///
/// A missing or empty log is a fresh chain.
///
/// # Errors
///
/// The `read_audit_log` errors, and `core_types::Error::Other` when its
/// last entry does not parse: starting a fresh chain there would break
/// `verify_chain` for every later entry.
fn load_audit_state(
    path: &Path,
    algorithm: core_types::AuditHash,
) -> core_types::Result<AuditState> {
    let Some(contents) = read_audit_log(path)? else {
        return Ok(AuditState {
            last_hash: String::new(),
            sequence: 0,
        });
    };
    let Some(last_line) = contents.lines().rev().find(|l| !l.trim().is_empty()) else {
        return Ok(AuditState {
            last_hash: String::new(),
            sequence: 0,
        });
    };
    let entry: AuditEntry = serde_json::from_str(last_line).map_err(|e| {
        core_types::Error::Other(format!(
            "corrupt last audit entry in {}: {e}; inspect with `sesame audit verify`",
            path.display()
        ))
    })?;
    Ok(AuditState {
        last_hash: chain_hash(last_line, algorithm),
        sequence: entry.sequence,
    })
}

/// Hash-chained audit logger.
///
/// Writes JSON-lines to a file (or any `Write` impl). Each entry's
/// `prev_hash` is the hash, under the logger's algorithm, of the previous
/// entry's serialized JSON.
pub struct AuditLogger<W: Write> {
    writer: W,
    last_hash: String,
    sequence: u64,
    hash_algorithm: core_types::AuditHash,
    default_agent_id: Option<core_types::AgentId>,
}

impl<W: Write> AuditLogger<W> {
    /// Create a new audit logger writing to the given sink.
    ///
    /// `last_hash` and `sequence` continue an existing chain, or are
    /// empty/0 for a fresh one. For the audit log file use
    /// [`open_audit_log`], which loads them from the file.
    pub fn new(
        writer: W,
        last_hash: String,
        sequence: u64,
        hash_algorithm: core_types::AuditHash,
        default_agent_id: Option<core_types::AgentId>,
    ) -> Self {
        Self {
            writer,
            last_hash,
            sequence,
            hash_algorithm,
            default_agent_id,
        }
    }

    /// Append an auditable action to the log.
    ///
    /// Hashes the serialized entry under the logger's algorithm and stores
    /// it for the next entry's `prev_hash` field.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is before the Unix epoch,
    /// serialization fails, or the underlying writer returns an I/O error.
    pub fn append(&mut self, action: AuditAction) -> core_types::Result<()> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
            core_types::Error::Other(format!("system clock before Unix epoch: {e}"))
        })?;
        let timestamp_ms = u64::try_from(elapsed.as_millis())
            .map_err(|e| core_types::Error::Other(format!("audit timestamp overflow: {e}")))?;

        let sequence = self.sequence + 1;
        let entry = AuditEntry {
            sequence,
            timestamp_ms,
            action,
            prev_hash: self.last_hash.clone(),
            agent_id: self.default_agent_id,
        };

        let json = serde_json::to_string(&entry)
            .map_err(|e| core_types::Error::Other(format!("audit serialization: {e}")))?;

        writeln!(self.writer, "{json}").map_err(core_types::Error::Io)?;
        self.writer.flush().map_err(core_types::Error::Io)?;

        // Advance the chain head only once the entry is written, so a failed
        // write leaves the logger consistent with the log.
        self.last_hash = chain_hash(&json, self.hash_algorithm);
        self.sequence = sequence;
        Ok(())
    }

    /// Current chain head hash.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Verify the integrity of an audit log by replaying the hash chain.
///
/// Returns `Ok(entry_count)` if the chain is valid, or an error
/// describing the first tampered entry.
///
/// # Errors
///
/// Returns an error if any entry fails to parse or if the hash chain is broken.
pub fn verify_chain(
    log_contents: &str,
    algorithm: core_types::AuditHash,
) -> core_types::Result<u64> {
    let mut expected_prev_hash = String::new();
    let mut count = 0u64;

    for (line_num, line) in log_contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(line).map_err(|e| {
            core_types::Error::Other(format!("audit parse error at line {}: {e}", line_num + 1))
        })?;

        if entry.prev_hash != expected_prev_hash {
            return Err(core_types::Error::Other(format!(
                "audit chain broken at sequence {}: expected prev_hash '{}', got '{}'",
                entry.sequence, expected_prev_hash, entry.prev_hash
            )));
        }

        expected_prev_hash = chain_hash(line, algorithm);
        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::ProfileId;
    use uuid::Uuid;

    fn pid(n: u128) -> ProfileId {
        ProfileId::from_uuid(Uuid::from_u128(n))
    }

    #[test]
    fn append_and_verify_chain() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );

        logger
            .append(AuditAction::ProfileActivated {
                target: pid(1),
                duration_ms: 42,
            })
            .unwrap();

        logger
            .append(AuditAction::SecretAccessed {
                profile_id: pid(2),
                secret_ref: "api-key".into(),
            })
            .unwrap();

        assert_eq!(logger.sequence(), 2);

        let log = String::from_utf8(buf).unwrap();
        let count = verify_chain(&log, core_types::AuditHash::Blake3).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn tampered_entry_detected() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );

        logger
            .append(AuditAction::ProfileActivated {
                target: pid(1),
                duration_ms: 10,
            })
            .unwrap();

        logger
            .append(AuditAction::ProfileActivated {
                target: pid(2),
                duration_ms: 20,
            })
            .unwrap();

        let mut log = String::from_utf8(buf).unwrap();

        // Tamper with the first line
        log = log.replacen("10", "99", 1);

        let result = verify_chain(&log, core_types::AuditHash::Blake3);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("chain broken"));
    }

    #[test]
    fn empty_log_verifies() {
        let count = verify_chain("", core_types::AuditHash::Blake3).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn chain_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Session 1: write 3 entries
        {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            let mut logger = AuditLogger::new(
                std::io::BufWriter::new(file),
                String::new(),
                0,
                core_types::AuditHash::Blake3,
                None,
            );

            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(1),
                    duration_ms: 10,
                })
                .unwrap();
            logger
                .append(AuditAction::SecretAccessed {
                    profile_id: pid(1),
                    secret_ref: "k1".into(),
                })
                .unwrap();
            logger
                .append(AuditAction::ProfileDeactivated {
                    target: pid(1),
                    duration_ms: 5,
                })
                .unwrap();
            assert_eq!(logger.sequence(), 3);
        }

        // Simulate restart: load state from disk
        let AuditState {
            last_hash,
            sequence: seq,
        } = load_audit_state(&path, core_types::AuditHash::Blake3).unwrap();
        assert_eq!(seq, 3);
        assert!(!last_hash.is_empty());

        // Session 2: continue from loaded state
        {
            let file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            let mut logger = AuditLogger::new(
                std::io::BufWriter::new(file),
                last_hash,
                seq,
                core_types::AuditHash::Blake3,
                None,
            );

            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(2),
                    duration_ms: 20,
                })
                .unwrap();
            logger
                .append(AuditAction::SecretAccessed {
                    profile_id: pid(2),
                    secret_ref: "k2".into(),
                })
                .unwrap();
            assert_eq!(logger.sequence(), 5);
        }

        // Verify the entire 5-entry chain is intact across the restart boundary
        let contents = std::fs::read_to_string(&path).unwrap();
        let count = verify_chain(&contents, core_types::AuditHash::Blake3).unwrap();
        assert_eq!(count, 5, "chain must have 5 entries spanning 2 sessions");

        // Verify sequences are monotonic 1..=5
        let entries: Vec<AuditEntry> = contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence, (i + 1) as u64);
        }
    }

    #[test]
    fn open_audit_log_resumes_chain_under_its_algorithm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        for expected in 1..=2 {
            let mut logger = open_audit_log(&path, core_types::AuditHash::Sha256, None).unwrap();
            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(1),
                    duration_ms: 1,
                })
                .unwrap();
            assert_eq!(logger.sequence(), expected);
        }
        assert_eq!(
            verify_audit_log(&path, core_types::AuditHash::Sha256).unwrap(),
            Some(2)
        );
        assert!(verify_audit_log(&path, core_types::AuditHash::Blake3).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn open_audit_log_restricts_existing_file_to_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        open_audit_log(&path, core_types::AuditHash::Blake3, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn missing_audit_log_reads_and_verifies_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        assert_eq!(read_audit_log(&path).unwrap(), None);
        assert_eq!(
            verify_audit_log(&path, core_types::AuditHash::Blake3).unwrap(),
            None
        );
    }

    #[test]
    fn unreadable_audit_log_is_an_error_naming_it() {
        // A directory at the log path exists but cannot be read as a file.
        let dir = tempfile::tempdir().unwrap();
        let err = read_audit_log(dir.path()).unwrap_err().to_string();
        assert!(err.contains(&dir.path().display().to_string()), "{err}");
    }

    #[test]
    fn chain_starts_fresh_when_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.jsonl");
        let state = load_audit_state(&path, core_types::AuditHash::Blake3).unwrap();
        assert_eq!(state.sequence, 0);
        assert!(state.last_hash.is_empty());
    }

    #[test]
    fn sha256_chain_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let algo = core_types::AuditHash::Sha256;
        for _ in 0..2 {
            let state = load_audit_state(&path, algo).unwrap();
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            let mut logger = AuditLogger::new(
                std::io::BufWriter::new(file),
                state.last_hash,
                state.sequence,
                core_types::AuditHash::Sha256,
                None,
            );
            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(1),
                    duration_ms: 1,
                })
                .unwrap();
        }
        // The resumed entry's prev_hash must use the chain's own algorithm.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(verify_chain(&contents, algo).unwrap(), 2);
    }

    #[test]
    fn failed_write_does_not_advance_chain() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut logger = AuditLogger::new(
            Broken,
            String::new(),
            7,
            core_types::AuditHash::Blake3,
            None,
        );
        assert!(
            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(1),
                    duration_ms: 1,
                })
                .is_err()
        );
        assert_eq!(logger.sequence(), 7);
        assert!(logger.last_hash().is_empty());
    }

    #[test]
    fn corrupt_last_entry_is_an_error() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write one valid entry
        {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            let mut logger = AuditLogger::new(
                std::io::BufWriter::new(file),
                String::new(),
                0,
                core_types::AuditHash::Blake3,
                None,
            );
            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(1),
                    duration_ms: 1,
                })
                .unwrap();
        }

        // Append garbage
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{{broken json").unwrap();

        // A fresh chain here would fork the log; loading must refuse.
        let err = load_audit_state(&path, core_types::AuditHash::Blake3).unwrap_err();
        assert!(
            err.to_string().contains("corrupt last audit entry"),
            "{err}"
        );
    }

    // ===== Audit Chain Integrity (Deleted/Reordered Entries) =====

    #[test]
    fn audit_chain_detects_deleted_entry() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );

        for i in 1..=5 {
            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(i),
                    duration_ms: 10,
                })
                .unwrap();
        }

        let log = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 5);

        // Delete the middle entry (index 2 = sequence 3)
        let mut tampered_lines = lines.clone();
        tampered_lines.remove(2);
        let tampered_log = tampered_lines.join("\n");

        let result = verify_chain(&tampered_log, core_types::AuditHash::Blake3);
        assert!(
            result.is_err(),
            "deleted entry must break chain verification"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("chain broken") || err.contains("parse error"),
            "error should mention chain break, got: {err}"
        );
    }

    #[test]
    fn audit_chain_detects_reordered_entries() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );

        for i in 1..=4 {
            logger
                .append(AuditAction::ProfileActivated {
                    target: pid(i),
                    duration_ms: 10,
                })
                .unwrap();
        }

        let log = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 4);

        // Swap entries 2 and 3
        let mut reordered_lines = lines.clone();
        reordered_lines.swap(1, 2);
        let reordered_log = reordered_lines.join("\n");

        let result = verify_chain(&reordered_log, core_types::AuditHash::Blake3);
        assert!(
            result.is_err(),
            "reordered entries must break chain verification"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("chain broken"),
            "error should mention chain break, got: {err}"
        );
    }

    #[test]
    fn single_entry_chain() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );

        logger
            .append(AuditAction::IsolationViolationAttempt {
                from_profile: core_types::TrustProfileName::try_from("work").unwrap(),
                resource: crate::IsolatedResource::Clipboard,
            })
            .unwrap();

        let log = String::from_utf8(buf).unwrap();
        assert_eq!(
            verify_chain(&log, core_types::AuditHash::Blake3).unwrap(),
            1
        );
    }

    #[test]
    fn sha256_append_and_verify_chain() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Sha256,
            None,
        );

        logger
            .append(AuditAction::ProfileActivated {
                target: pid(1),
                duration_ms: 42,
            })
            .unwrap();

        logger
            .append(AuditAction::SecretAccessed {
                profile_id: pid(2),
                secret_ref: "api-key".into(),
            })
            .unwrap();

        assert_eq!(logger.sequence(), 2);

        let log = String::from_utf8(buf).unwrap();
        let count = verify_chain(&log, core_types::AuditHash::Sha256).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn sha256_tampered_entry_detected() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Sha256,
            None,
        );

        logger
            .append(AuditAction::ProfileActivated {
                target: pid(1),
                duration_ms: 10,
            })
            .unwrap();

        logger
            .append(AuditAction::ProfileActivated {
                target: pid(2),
                duration_ms: 20,
            })
            .unwrap();

        let mut log = String::from_utf8(buf).unwrap();
        log = log.replacen("10", "99", 1);

        let result = verify_chain(&log, core_types::AuditHash::Sha256);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chain broken"));
    }

    #[test]
    fn sha256_and_blake3_produce_different_hashes() {
        let mut buf_b3 = Vec::new();
        let mut logger_b3 = AuditLogger::new(
            &mut buf_b3,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );
        logger_b3
            .append(AuditAction::ProfileActivated {
                target: pid(1),
                duration_ms: 1,
            })
            .unwrap();

        let mut buf_sha = Vec::new();
        let mut logger_sha = AuditLogger::new(
            &mut buf_sha,
            String::new(),
            0,
            core_types::AuditHash::Sha256,
            None,
        );
        logger_sha
            .append(AuditAction::ProfileActivated {
                target: pid(1),
                duration_ms: 1,
            })
            .unwrap();

        // The prev_hash in subsequent entries would differ, but since these are first entries
        // with empty prev_hash, the JSON is the same. The internal last_hash should differ.
        assert_ne!(logger_b3.last_hash(), logger_sha.last_hash());
    }

    #[test]
    fn all_new_audit_action_variants_chain_correctly() {
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(
            &mut buf,
            String::new(),
            0,
            core_types::AuditHash::Blake3,
            None,
        );

        let agent = core_types::AgentId::from_uuid(Uuid::from_u128(100));
        let installation = core_types::InstallationId {
            id: Uuid::from_u128(200),
            org_ns: None,
            namespace: Uuid::from_u128(300),
            machine_binding: None,
        };
        let req_id = Uuid::from_u128(500);
        let deleg_id = Uuid::from_u128(600);
        let session_id = Uuid::from_u128(700);

        let actions: Vec<AuditAction> = vec![
            AuditAction::AgentConnected {
                agent_id: agent,
                agent_type: core_types::AgentType::Human,
            },
            AuditAction::AgentDisconnected {
                agent_id: agent,
                reason: "shutdown".into(),
            },
            AuditAction::InstallationCreated {
                id: installation.clone(),
                org: Some("acme".into()),
                machine_binding_present: true,
            },
            AuditAction::AuthorizationRequired {
                request_id: req_id,
                operation: "secret.read".into(),
            },
            AuditAction::AuthorizationGranted {
                request_id: req_id,
                delegator: agent,
                scope: "SecretRead".into(),
            },
            AuditAction::AuthorizationDenied {
                request_id: req_id,
                reason: "insufficient attestation".into(),
            },
            AuditAction::AuthorizationTimeout { request_id: req_id },
            AuditAction::DelegationRevoked {
                delegation_id: deleg_id,
                revoker: agent,
                reason: "expired".into(),
            },
            AuditAction::HeartbeatRenewed {
                delegation_id: deleg_id,
                renewal_source: agent,
            },
            AuditAction::FederationSessionEstablished {
                session_id,
                remote_installation: installation,
            },
            AuditAction::FederationSessionTerminated {
                session_id,
                reason: "peer disconnected".into(),
            },
            AuditAction::PostureEvaluated {
                composite_score: 0.85,
            },
        ];

        for action in actions {
            logger.append(action).unwrap();
        }

        assert_eq!(logger.sequence(), 12);

        let log = String::from_utf8(buf).unwrap();
        let count = verify_chain(&log, core_types::AuditHash::Blake3).unwrap();
        assert_eq!(count, 12, "every audit action variant chains");
    }
}
