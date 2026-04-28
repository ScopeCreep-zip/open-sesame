//! Vault operation log database for M3 replication.
//!
//! Creates and manages `vault-log.db` alongside the per-profile `vault.db` files.
//! Contains two tables:
//! - `vault_log`: append-only operation log entries with HLC timestamps
//! - `hlc_state`: single-row local HLC clock state, persisted across restarts
//! - `replication_watermarks`: per-peer sync progress tracking
//!
//! The vault log is the ground truth for M3 replication. `vault.db` is the
//! materialised fold of the log. If `vault.db` is lost, it can be reconstructed
//! from the log.

use core_types::{HlcTimestamp, TrustProfileName, VaultLogOp};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

/// Vault log database handle.
pub struct VaultLog {
    conn: Mutex<Connection>,
    /// Local HLC clock state.
    hlc: Mutex<HlcTimestamp>,
}

impl VaultLog {
    /// Open or create the vault log database at the given path.
    ///
    /// Creates tables if absent, restores HLC state from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or schema creation fails.
    pub fn open(path: &Path) -> Result<Self, VaultLogError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(VaultLogError::Io)?;
        }

        let conn = Connection::open(path).map_err(VaultLogError::Sqlite)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(VaultLogError::Sqlite)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_log (
                id                      TEXT PRIMARY KEY NOT NULL,
                hlc_wall_secs           INTEGER NOT NULL,
                hlc_counter             INTEGER NOT NULL,
                hlc_node_id             TEXT NOT NULL,
                author_installation_id  TEXT NOT NULL,
                author_signing_pubkey   TEXT NOT NULL,
                profile_id              TEXT NOT NULL,
                operation_type          TEXT NOT NULL,
                operation_json          TEXT NOT NULL,
                prev_by_author_hash     TEXT,
                signature               TEXT NOT NULL,
                received_at             TEXT NOT NULL,
                locally_applied         INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_log_profile_hlc
                ON vault_log (profile_id, hlc_wall_secs, hlc_counter, hlc_node_id);
            CREATE INDEX IF NOT EXISTS idx_log_not_applied
                ON vault_log (locally_applied, received_at)
                WHERE locally_applied = 0;

            CREATE TABLE IF NOT EXISTS replication_watermarks (
                peer_installation_id    TEXT NOT NULL,
                profile_id              TEXT NOT NULL,
                watermark_wall_secs     INTEGER NOT NULL,
                watermark_counter       INTEGER NOT NULL,
                watermark_node_id       TEXT NOT NULL,
                last_sync_at            TEXT NOT NULL,
                PRIMARY KEY (peer_installation_id, profile_id)
            );

            CREATE TABLE IF NOT EXISTS hlc_state (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                wall_secs   INTEGER NOT NULL,
                counter     INTEGER NOT NULL,
                node_id     TEXT NOT NULL
            );",
        )
        .map_err(VaultLogError::Sqlite)?;

        // Restore HLC state from disk or initialise to zero.
        let hlc = Self::load_hlc(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            hlc: Mutex::new(hlc),
        })
    }

    /// Get the current local HLC timestamp (for read-only queries).
    #[must_use]
    #[allow(dead_code)] // Used by tests; called by M3 replication protocol
    pub fn current_hlc(&self) -> HlcTimestamp {
        *self.hlc.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Tick the local HLC for a new local event and persist.
    pub fn tick(&self) -> Result<HlcTimestamp, VaultLogError> {
        let wall_now = wall_secs_now();
        let mut hlc = self.hlc.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ts = HlcTimestamp::tick(&mut hlc, wall_now);
        self.persist_hlc(&ts)?;
        Ok(ts)
    }

    /// Update the local HLC on receiving a remote timestamp and persist.
    pub fn receive(&self, remote: &HlcTimestamp) -> Result<HlcTimestamp, VaultLogError> {
        let wall_now = wall_secs_now();
        let mut hlc = self.hlc.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ts = HlcTimestamp::receive(&mut hlc, remote, wall_now);
        self.persist_hlc(&ts)?;
        Ok(ts)
    }

    /// Write a local vault operation to the log.
    ///
    /// Called by `vault_log_hook` in `crud.rs` after every successful
    /// `SecretSet` or `SecretDelete`.
    pub fn write_local_entry(
        &self,
        profile: &TrustProfileName,
        operation: VaultLogOp,
        key: &str,
        installation_id: &str,
    ) -> Result<(), VaultLogError> {
        let ts = self.tick()?;
        let entry_id = uuid::Uuid::now_v7();
        let op_type = match operation {
            VaultLogOp::Set => "set",
            VaultLogOp::Delete => "delete",
            VaultLogOp::AclUpdate => "acl_update",
            _ => "unknown",
        };

        // Minimal operation JSON — M3 will add encrypted_values and full structure.
        let operation_json = serde_json::json!({
            "op": op_type,
            "key": key,
        })
        .to_string();

        let now = now_iso8601();
        let node_id_hex = hex::encode(ts.node_id);

        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "INSERT INTO vault_log
             (id, hlc_wall_secs, hlc_counter, hlc_node_id, author_installation_id,
              author_signing_pubkey, profile_id, operation_type, operation_json,
              prev_by_author_hash, signature, received_at, locally_applied)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
            params![
                entry_id.to_string(),
                ts.wall_secs,
                ts.counter,
                node_id_hex,
                installation_id,
                "",  // signing pubkey — populated when M2 init ceremony runs
                profile.to_string(),
                op_type,
                operation_json,
                Option::<String>::None,  // prev_by_author_hash — M3 computes chain
                "",  // signature — M3 signs with Ed25519
                now,
            ],
        )
        .map_err(VaultLogError::Sqlite)?;

        tracing::debug!(
            entry = %entry_id,
            profile = %profile,
            op = op_type,
            key = key,
            "vault log entry written"
        );

        Ok(())
    }

    /// Validate a vault log entry's structural integrity.
    ///
    /// Checks that the signature field is exactly 64 bytes (Ed25519).
    /// Content verification (actual signature check) is deferred to M3.
    pub fn validate_entry_structure(entry_json: &str) -> Result<(), VaultLogError> {
        let v: serde_json::Value =
            serde_json::from_str(entry_json).map_err(VaultLogError::Json)?;
        if let Some(sig) = v["signature"].as_str()
            && !sig.is_empty()
        {
            let sig_bytes = hex::decode(sig).unwrap_or_default();
            if sig_bytes.len() != 64 {
                return Err(VaultLogError::InvalidSignature(format!(
                    "expected 64-byte Ed25519 signature, got {} bytes",
                    sig_bytes.len()
                )));
            }
        }
        Ok(())
    }

    /// Query log entries since a given HLC watermark for replication serving.
    ///
    /// Returns entries as a JSON array string. Used by the
    /// `VaultReplicationPullRequest` handler in dispatch.rs.
    pub fn query_entries_since(
        &self,
        profile_id: &str,
        since_watermark_json: Option<&str>,
        max_entries: u32,
    ) -> Result<String, VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (wall_secs, counter): (i64, i64) = if let Some(wm) = since_watermark_json {
            let v: serde_json::Value = serde_json::from_str(wm).unwrap_or_default();
            (
                v["wall_secs"].as_i64().unwrap_or(0),
                v["counter"].as_i64().unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        let mut stmt = conn.prepare(
            "SELECT operation_json FROM vault_log
             WHERE profile_id = ?1
               AND (hlc_wall_secs > ?2 OR (hlc_wall_secs = ?2 AND hlc_counter > ?3))
             ORDER BY hlc_wall_secs, hlc_counter, hlc_node_id
             LIMIT ?4"
        ).map_err(VaultLogError::Sqlite)?;

        let entries: Vec<String> = stmt
            .query_map(
                params![profile_id, wall_secs, counter, max_entries],
                |row| row.get(0),
            )
            .map_err(VaultLogError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(VaultLogError::Sqlite)?;

        Ok(serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into()))
    }

    /// Insert a received replication entry into the log (from a remote peer).
    ///
    /// Validates entry structure before insertion. The entry is stored with
    /// `locally_applied = 0` for later fold application.
    pub fn insert_received_entry(&self, entry_json: &str) -> Result<(), VaultLogError> {
        Self::validate_entry_structure(entry_json)?;

        // Parse minimal fields from the JSON.
        let v: serde_json::Value =
            serde_json::from_str(entry_json).map_err(VaultLogError::Json)?;

        let id = v["id"].as_str().unwrap_or_default();
        let wall_secs = v["timestamp"]["wall_secs"].as_u64().unwrap_or(0);
        let counter = v["timestamp"]["counter"].as_u64().unwrap_or(0);
        let node_id = v["timestamp"]["node_id"].as_str().unwrap_or("");
        let author = v["author_installation_uuid"].as_str().unwrap_or("");
        let profile_id = v["profile_id"].as_str().unwrap_or("");
        let op_type = v["operation"]["op"].as_str().unwrap_or("unknown");
        let signature = v["signature"].as_str().unwrap_or("");
        let prev_hash = v["prev_by_author"].as_str();

        let now = now_iso8601();

        // Scope the conn lock so it's released before self.receive() which
        // also acquires conn internally via persist_hlc.
        {
            let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            conn.execute(
                "INSERT OR IGNORE INTO vault_log
                 (id, hlc_wall_secs, hlc_counter, hlc_node_id, author_installation_id,
                  author_signing_pubkey, profile_id, operation_type, operation_json,
                  prev_by_author_hash, signature, received_at, locally_applied)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0)",
                params![
                    id,
                    wall_secs as i64,
                    counter as i64,
                    node_id,
                    author,
                    "",  // signing pubkey extracted in M3
                    profile_id,
                    op_type,
                    entry_json,
                    prev_hash,
                    signature,
                    now,
                ],
            )
            .map_err(VaultLogError::Sqlite)?;
        } // conn lock released here

        // Update local HLC on receive (acquires conn internally).
        #[allow(clippy::cast_possible_truncation)]
        let remote_ts = HlcTimestamp {
            wall_secs: wall_secs as u32,
            counter: counter as u32,
            node_id: {
                let bytes = hex::decode(node_id).unwrap_or_default();
                let mut nid = [0u8; 8];
                let len = bytes.len().min(8);
                nid[..len].copy_from_slice(&bytes[..len]);
                nid
            },
        };
        self.receive(&remote_ts)?;

        tracing::debug!(entry = id, "received vault log entry stored");
        Ok(())
    }

    /// Count of entries in the vault log.
    #[allow(dead_code)] // Used by tests; called by M3 compaction threshold check
    pub fn entry_count(&self) -> Result<u64, VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault_log", [], |row| row.get(0))
            .map_err(VaultLogError::Sqlite)?;
        #[allow(clippy::cast_sign_loss)]
        Ok(count as u64)
    }

    fn load_hlc(conn: &Connection) -> Result<HlcTimestamp, VaultLogError> {
        let result = conn.query_row(
            "SELECT wall_secs, counter, node_id FROM hlc_state WHERE id = 1",
            [],
            |row| {
                let wall_secs: i64 = row.get(0)?;
                let counter: i64 = row.get(1)?;
                let node_id_hex: String = row.get(2)?;
                Ok((wall_secs, counter, node_id_hex))
            },
        );

        match result {
            Ok((wall_secs, counter, node_id_hex)) => {
                let bytes = hex::decode(&node_id_hex).unwrap_or_default();
                let mut node_id = [0u8; 8];
                let len = bytes.len().min(8);
                node_id[..len].copy_from_slice(&bytes[..len]);
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok(HlcTimestamp {
                    wall_secs: wall_secs as u32,
                    counter: counter as u32,
                    node_id,
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(HlcTimestamp::zero()),
            Err(e) => Err(VaultLogError::Sqlite(e)),
        }
    }

    fn persist_hlc(&self, ts: &HlcTimestamp) -> Result<(), VaultLogError> {
        let node_id_hex = hex::encode(ts.node_id);
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "INSERT INTO hlc_state (id, wall_secs, counter, node_id)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET wall_secs=?1, counter=?2, node_id=?3",
            params![ts.wall_secs as i64, ts.counter as i64, node_id_hex],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }
}

fn wall_secs_now() -> u32 {
    use std::time::SystemTime;
    #[allow(clippy::cast_possible_truncation)]
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    secs
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
}

/// Errors from the vault log.
#[derive(Debug, thiserror::Error)]
pub enum VaultLogError {
    #[error("`SQLite` error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

impl std::fmt::Debug for VaultLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultLog").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> (VaultLog, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-log.db");
        let log = VaultLog::open(&path).unwrap();
        (log, dir)
    }

    #[test]
    fn open_creates_tables() {
        let (log, _dir) = temp_log();
        assert_eq!(log.entry_count().unwrap(), 0);
    }

    #[test]
    fn hlc_starts_at_zero() {
        let (log, _dir) = temp_log();
        let hlc = log.current_hlc();
        assert_eq!(hlc, HlcTimestamp::zero());
    }

    #[test]
    fn tick_advances_hlc() {
        let (log, _dir) = temp_log();
        let t1 = log.tick().unwrap();
        let t2 = log.tick().unwrap();
        assert!(t2 > t1);
    }

    #[test]
    fn hlc_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-log.db");

        let t1 = {
            let log = VaultLog::open(&path).unwrap();
            log.tick().unwrap();
            log.tick().unwrap()
        };

        let log2 = VaultLog::open(&path).unwrap();
        let restored = log2.current_hlc();
        assert_eq!(restored, t1, "HLC must persist across reopen");

        let t3 = log2.tick().unwrap();
        assert!(t3 > t1, "HLC must advance after reopen");
    }

    #[test]
    fn write_local_entry_inserts() {
        let (log, _dir) = temp_log();
        let profile = TrustProfileName::try_from("work").unwrap();
        log.write_local_entry(&profile, VaultLogOp::Set, "api-key", "install-uuid")
            .unwrap();
        assert_eq!(log.entry_count().unwrap(), 1);

        log.write_local_entry(&profile, VaultLogOp::Delete, "api-key", "install-uuid")
            .unwrap();
        assert_eq!(log.entry_count().unwrap(), 2);
    }

    #[test]
    fn insert_received_entry_deduplicates() {
        let (log, _dir) = temp_log();
        let entry = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "timestamp": { "wall_secs": 1000, "counter": 0, "node_id": "aa" },
            "author_installation_uuid": "test-install",
            "profile_id": "test-profile",
            "operation": { "op": "set", "key": "k" },
            "signature": "",
        })
        .to_string();

        log.insert_received_entry(&entry).unwrap();
        assert_eq!(log.entry_count().unwrap(), 1);

        // Duplicate insert should be ignored (INSERT OR IGNORE).
        log.insert_received_entry(&entry).unwrap();
        assert_eq!(log.entry_count().unwrap(), 1);
    }

    #[test]
    fn receive_updates_hlc() {
        let (log, _dir) = temp_log();
        let remote = HlcTimestamp {
            wall_secs: 999_999,
            counter: 42,
            node_id: [0xFF; 8],
        };
        let ts = log.receive(&remote).unwrap();
        assert!(ts > remote);
    }
}
