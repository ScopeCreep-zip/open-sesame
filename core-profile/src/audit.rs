//! Hash-chained audit logger for tamper-evident profile operations.
//!
//! Each entry includes a BLAKE3 hash of the previous entry, forming
//! an append-only chain. Tampering with any entry invalidates all
//! subsequent hashes.
//!
//! Uses BLAKE3 instead of SHA-256 for consistency with the rest of
//! the crypto stack and for its superior performance.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{AuditAction, AuditEntry};

/// Hash-chained audit logger.
///
/// Writes JSON-lines to a file (or any `Write` impl). Each entry's
/// `prev_hash` is the BLAKE3 hash of the previous entry's serialized JSON.
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
    /// `last_hash` and `sequence` should be loaded from the last entry
    /// in an existing log file, or empty/0 for a fresh log.
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
    /// Computes the BLAKE3 hash of the serialized entry and stores it
    /// for the next entry's `prev_hash` field.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the underlying writer returns an I/O error.
    pub fn append(&mut self, action: AuditAction) -> core_types::Result<()> {
        self.sequence += 1;

        #[allow(clippy::cast_possible_truncation)]
        // timestamp millis won't exceed u64 until year 584M+
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = AuditEntry {
            sequence: self.sequence,
            timestamp_ms,
            action,
            prev_hash: self.last_hash.clone(),
            agent_id: self.default_agent_id,
        };

        let json = serde_json::to_string(&entry)
            .map_err(|e| core_types::Error::Other(format!("audit serialization: {e}")))?;

        // Hash the entire JSON line for chain integrity
        let hash_hex = match self.hash_algorithm {
            core_types::AuditHash::Blake3 => blake3::hash(json.as_bytes()).to_hex().to_string(),
            core_types::AuditHash::Sha256 => {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(json.as_bytes()))
            }
        };
        self.last_hash = hash_hex;

        writeln!(self.writer, "{json}").map_err(core_types::Error::Io)?;

        self.writer.flush().map_err(core_types::Error::Io)?;

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
    algorithm: &core_types::AuditHash,
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

        let hash_hex = match algorithm {
            core_types::AuditHash::Blake3 => blake3::hash(line.as_bytes()).to_hex().to_string(),
            core_types::AuditHash::Sha256 => {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(line.as_bytes()))
            }
        };
        expected_prev_hash = hash_hex;
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
        let count = verify_chain(&log, &core_types::AuditHash::Blake3).unwrap();
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

        let result = verify_chain(&log, &core_types::AuditHash::Blake3);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("chain broken"));
    }

    #[test]
    fn empty_log_verifies() {
        let count = verify_chain("", &core_types::AuditHash::Blake3).unwrap();
        assert_eq!(count, 0);
    }

    /// Simulate daemon restart: read last entry from a log file on disk,
    /// extract its hash and sequence, then continue appending.
    fn load_audit_state(path: &std::path::Path) -> (String, u64) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return (String::new(), 0);
        };
        let Some(last_line) = contents.lines().rev().find(|l| !l.trim().is_empty()) else {
            return (String::new(), 0);
        };
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(last_line) {
            let hash = blake3::hash(last_line.as_bytes());
            (hash.to_hex().to_string(), entry.sequence)
        } else {
            (String::new(), 0)
        }
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
        let (last_hash, seq) = load_audit_state(&path);
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
        let count = verify_chain(&contents, &core_types::AuditHash::Blake3).unwrap();
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
    fn chain_starts_fresh_when_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.jsonl");
        let (hash, seq) = load_audit_state(&path);
        assert_eq!(seq, 0);
        assert!(hash.is_empty());
    }

    #[test]
    fn chain_recovers_from_corrupt_last_entry() {
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

        // Should fall back to fresh chain
        let (hash, seq) = load_audit_state(&path);
        assert_eq!(seq, 0);
        assert!(hash.is_empty());
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

        let result = verify_chain(&tampered_log, &core_types::AuditHash::Blake3);
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

        let result = verify_chain(&reordered_log, &core_types::AuditHash::Blake3);
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
            verify_chain(&log, &core_types::AuditHash::Blake3).unwrap(),
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
        let count = verify_chain(&log, &core_types::AuditHash::Sha256).unwrap();
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

        let result = verify_chain(&log, &core_types::AuditHash::Sha256);
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
        let profile_name = core_types::TrustProfileName::try_from("work").unwrap();
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
            AuditAction::ProfileIdMigrated {
                name: profile_name,
                old_id: pid(1),
                new_id: pid(2),
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

        assert_eq!(logger.sequence(), 13);

        let log = String::from_utf8(buf).unwrap();
        let count = verify_chain(&log, &core_types::AuditHash::Blake3).unwrap();
        assert_eq!(
            count, 13,
            "all 13 new audit action variants must chain correctly"
        );
    }
}
