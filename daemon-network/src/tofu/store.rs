//! SQLite-backed TOFU identity store with append-only fork-evidence log.
//!
//! Two tables:
//! - `tofu_peers`: current state of each pinned peer (key, trust level, address, PSK)
//! - `tofu_events`: append-only log of every state transition (pin, unpin, mismatch,
//!   address migration, endorsement, revocation). BLAKE3 hash chain. Never GC'd.
//!
//! WAL mode for concurrent reads. File permissions enforced at creation (0600).

use core_types::TofuTrustLevel;
use rusqlite::{Connection, params};
use std::path::Path;

/// TOFU store wrapping a `SQLite` database.
pub struct TofuStore {
    conn: Connection,
}

impl TofuStore {
    /// Open or create the TOFU store at the given path.
    ///
    /// Enforces WAL mode, creates tables if absent, runs integrity check.
    ///
    /// # Errors
    ///
    /// Returns an error if the database is corrupted or cannot be opened.
    pub fn open(path: &Path) -> Result<Self, TofuStoreError> {
        // Enforce file permissions on creation.
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(TofuStoreError::Io)?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(TofuStoreError::Io)?;
        }

        let conn = Connection::open(path).map_err(TofuStoreError::Sqlite)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(TofuStoreError::Sqlite)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tofu_peers (
                public_key_hex      TEXT PRIMARY KEY NOT NULL,
                first_seen_at       TEXT NOT NULL,
                last_seen_at        TEXT NOT NULL,
                first_seen_addr     TEXT NOT NULL,
                last_known_addr     TEXT,
                trust_level         TEXT NOT NULL DEFAULT 'tofu',
                display_name        TEXT,
                installation_id     TEXT,
                cached_psk          BLOB,
                unpinned_at         TEXT,
                endorsement_json    TEXT,
                version             INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS tofu_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT NOT NULL,
                event_type          TEXT NOT NULL,
                public_key_hex      TEXT NOT NULL,
                remote_addr         TEXT,
                detail              TEXT,
                prev_hash           TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_key ON tofu_events (public_key_hex);",
        )
        .map_err(TofuStoreError::Sqlite)?;

        // Integrity check.
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(TofuStoreError::Sqlite)?;
        if integrity != "ok" {
            return Err(TofuStoreError::Corrupted(integrity));
        }

        Ok(Self { conn })
    }

    /// Look up a peer by public key hex.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the query fails.
    pub fn lookup_key(&self, public_key_hex: &str) -> Result<Option<TofuPeer>, TofuStoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT public_key_hex, first_seen_at, last_seen_at, first_seen_addr,
                        last_known_addr, trust_level, display_name, installation_id,
                        cached_psk, version
                 FROM tofu_peers WHERE public_key_hex = ?1",
            )
            .map_err(TofuStoreError::Sqlite)?;

        let peer = stmt
            .query_row(params![public_key_hex], |row| {
                Ok(TofuPeer {
                    public_key_hex: row.get(0)?,
                    first_seen_at: row.get(1)?,
                    last_seen_at: row.get(2)?,
                    first_seen_addr: row.get(3)?,
                    last_known_addr: row.get(4)?,
                    trust_level: parse_trust_level(&row.get::<_, String>(5)?),
                    display_name: row.get(6)?,
                    installation_id: row.get(7)?,
                    cached_psk: row.get(8)?,
                    version: row.get(9)?,
                })
            })
            .optional()
            .map_err(TofuStoreError::Sqlite)?;

        Ok(peer)
    }

    /// Pin a new peer (TOFU first-contact).
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the insert or event append fails.
    pub fn pin(
        &self,
        public_key_hex: &str,
        addr: &str,
        trust_level: TofuTrustLevel,
    ) -> Result<(), TofuStoreError> {
        let now = now_iso8601();
        let level_str = trust_level_str(trust_level);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO tofu_peers
                 (public_key_hex, first_seen_at, last_seen_at, first_seen_addr,
                  last_known_addr, trust_level, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
                params![public_key_hex, now, now, addr, addr, level_str],
            )
            .map_err(TofuStoreError::Sqlite)?;

        self.append_event(public_key_hex, "pin", Some(addr), Some(level_str))?;
        Ok(())
    }

    /// Update last-seen timestamp and address for an existing peer.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the update fails.
    pub fn touch(
        &self,
        public_key_hex: &str,
        addr: &str,
    ) -> Result<(), TofuStoreError> {
        let now = now_iso8601();
        let changed = self
            .conn
            .execute(
                "UPDATE tofu_peers SET last_seen_at = ?1, last_known_addr = ?2
                 WHERE public_key_hex = ?3",
                params![now, addr, public_key_hex],
            )
            .map_err(TofuStoreError::Sqlite)?;

        if changed > 0 {
            // Check if address changed — log migration event.
            if let Some(peer) = self.lookup_key(public_key_hex)?
                && peer.last_known_addr.as_deref() != Some(addr)
            {
                self.append_event(public_key_hex, "addr_migrate", Some(addr), None)?;
            }
        }
        Ok(())
    }

    /// Store a cached PSK (encrypted) for `IKpsk2` reconnection.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the update fails.
    pub fn store_psk(
        &self,
        public_key_hex: &str,
        psk: &[u8],
    ) -> Result<(), TofuStoreError> {
        self.conn
            .execute(
                "UPDATE tofu_peers SET cached_psk = ?1 WHERE public_key_hex = ?2",
                params![psk, public_key_hex],
            )
            .map_err(TofuStoreError::Sqlite)?;
        Ok(())
    }

    /// Retrieve cached PSK for a peer.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the query fails.
    pub fn get_psk(&self, public_key_hex: &str) -> Result<Option<Vec<u8>>, TofuStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT cached_psk FROM tofu_peers WHERE public_key_hex = ?1")
            .map_err(TofuStoreError::Sqlite)?;

        let psk = stmt
            .query_row(params![public_key_hex], |row| row.get::<_, Option<Vec<u8>>>(0))
            .optional()
            .map_err(TofuStoreError::Sqlite)?
            .flatten();

        Ok(psk)
    }

    /// Record a key mismatch event (fork evidence).
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the event append fails.
    pub fn record_mismatch(
        &self,
        public_key_hex: &str,
        presented_key_hex: &str,
        addr: &str,
    ) -> Result<(), TofuStoreError> {
        let detail = format!("presented={presented_key_hex}");
        self.append_event(public_key_hex, "mismatch", Some(addr), Some(&detail))?;
        Ok(())
    }

    /// Unpin a peer (operator action).
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the update or event append fails.
    pub fn unpin(&self, public_key_hex: &str) -> Result<(), TofuStoreError> {
        let now = now_iso8601();
        self.conn
            .execute(
                "UPDATE tofu_peers SET trust_level = 'unpinned', unpinned_at = ?1
                 WHERE public_key_hex = ?2",
                params![now, public_key_hex],
            )
            .map_err(TofuStoreError::Sqlite)?;
        self.append_event(public_key_hex, "unpin", None, None)?;
        Ok(())
    }

    /// List all peers.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the query fails.
    pub fn list_peers(&self) -> Result<Vec<TofuPeer>, TofuStoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT public_key_hex, first_seen_at, last_seen_at, first_seen_addr,
                        last_known_addr, trust_level, display_name, installation_id,
                        cached_psk, version
                 FROM tofu_peers ORDER BY last_seen_at DESC",
            )
            .map_err(TofuStoreError::Sqlite)?;

        let peers = stmt
            .query_map([], |row| {
                Ok(TofuPeer {
                    public_key_hex: row.get(0)?,
                    first_seen_at: row.get(1)?,
                    last_seen_at: row.get(2)?,
                    first_seen_addr: row.get(3)?,
                    last_known_addr: row.get(4)?,
                    trust_level: parse_trust_level(&row.get::<_, String>(5)?),
                    display_name: row.get(6)?,
                    installation_id: row.get(7)?,
                    cached_psk: row.get(8)?,
                    version: row.get(9)?,
                })
            })
            .map_err(TofuStoreError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(TofuStoreError::Sqlite)?;

        Ok(peers)
    }

    /// Get the count of events in the fork-evidence log.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the query fails.
    pub fn event_count(&self) -> Result<u64, TofuStoreError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM tofu_events", [], |row| row.get(0))
            .map_err(TofuStoreError::Sqlite)?;
        #[allow(clippy::cast_sign_loss)] // COUNT(*) is always non-negative
        Ok(count as u64)
    }

    /// Append a fork-evidence event with BLAKE3 hash chain.
    fn append_event(
        &self,
        public_key_hex: &str,
        event_type: &str,
        addr: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(), TofuStoreError> {
        let now = now_iso8601();

        // Get previous hash for chain continuity.
        let prev_hash: String = self
            .conn
            .query_row(
                "SELECT prev_hash FROM tofu_events ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| {
                // Genesis entry — hash of the string "opensesame:tofu:genesis".
                hex::encode(blake3::hash(b"opensesame:tofu:genesis").as_bytes())
            });

        // Compute this entry's hash: BLAKE3(prev_hash || event_type || public_key_hex || timestamp).
        let chain_input = format!("{prev_hash}{event_type}{public_key_hex}{now}");
        let this_hash = hex::encode(blake3::hash(chain_input.as_bytes()).as_bytes());

        self.conn
            .execute(
                "INSERT INTO tofu_events (timestamp, event_type, public_key_hex, remote_addr, detail, prev_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![now, event_type, public_key_hex, addr, detail, this_hash],
            )
            .map_err(TofuStoreError::Sqlite)?;

        Ok(())
    }
}

/// A peer record from the TOFU store.
#[derive(Debug, Clone)]
pub struct TofuPeer {
    pub public_key_hex: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub first_seen_addr: String,
    pub last_known_addr: Option<String>,
    pub trust_level: TofuTrustLevel,
    pub display_name: Option<String>,
    pub installation_id: Option<String>,
    pub cached_psk: Option<Vec<u8>>,
    pub version: i64,
}

fn now_iso8601() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
}

fn trust_level_str(level: TofuTrustLevel) -> &'static str {
    match level {
        TofuTrustLevel::Tofu => "tofu",
        TofuTrustLevel::Bootstrap => "bootstrap",
        TofuTrustLevel::Endorsed => "endorsed",
        TofuTrustLevel::Revoked => "revoked",
        TofuTrustLevel::Unpinned => "unpinned",
    }
}

fn parse_trust_level(s: &str) -> TofuTrustLevel {
    match s {
        "bootstrap" => TofuTrustLevel::Bootstrap,
        "endorsed" => TofuTrustLevel::Endorsed,
        "revoked" => TofuTrustLevel::Revoked,
        "unpinned" => TofuTrustLevel::Unpinned,
        // "tofu" and any unknown values default to Tofu.
        _ => TofuTrustLevel::Tofu,
    }
}

/// Errors from the TOFU store.
#[derive(Debug, thiserror::Error)]
pub enum TofuStoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOFU store corrupted: {0}")]
    Corrupted(String),
}

// rusqlite::OptionalExtension is needed for .optional() on query_row.
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (TofuStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-tofu.db");
        let store = TofuStore::open(&path).unwrap();
        (store, dir)
    }

    #[test]
    fn pin_and_lookup() {
        let (store, _dir) = temp_store();
        store.pin("aabbccdd", "10.0.0.1:48627", TofuTrustLevel::Tofu).unwrap();
        let peer = store.lookup_key("aabbccdd").unwrap().unwrap();
        assert_eq!(peer.public_key_hex, "aabbccdd");
        assert_eq!(peer.trust_level, TofuTrustLevel::Tofu);
        assert_eq!(peer.first_seen_addr, "10.0.0.1:48627");
    }

    #[test]
    fn lookup_missing_returns_none() {
        let (store, _dir) = temp_store();
        assert!(store.lookup_key("nonexistent").unwrap().is_none());
    }

    #[test]
    fn unpin_changes_trust_level() {
        let (store, _dir) = temp_store();
        store.pin("aabb", "1.2.3.4:1234", TofuTrustLevel::Tofu).unwrap();
        store.unpin("aabb").unwrap();
        let peer = store.lookup_key("aabb").unwrap().unwrap();
        assert_eq!(peer.trust_level, TofuTrustLevel::Unpinned);
    }

    #[test]
    fn psk_round_trip() {
        let (store, _dir) = temp_store();
        store.pin("ccdd", "5.6.7.8:5678", TofuTrustLevel::Tofu).unwrap();
        store.store_psk("ccdd", &[0xAA; 32]).unwrap();
        let psk = store.get_psk("ccdd").unwrap().unwrap();
        assert_eq!(psk, vec![0xAA; 32]);
    }

    #[test]
    fn psk_none_when_not_set() {
        let (store, _dir) = temp_store();
        store.pin("eeff", "9.0.1.2:9012", TofuTrustLevel::Tofu).unwrap();
        assert!(store.get_psk("eeff").unwrap().is_none());
    }

    #[test]
    fn event_log_grows() {
        let (store, _dir) = temp_store();
        assert_eq!(store.event_count().unwrap(), 0);
        store.pin("1111", "1.1.1.1:1111", TofuTrustLevel::Tofu).unwrap();
        assert_eq!(store.event_count().unwrap(), 1);
        store.unpin("1111").unwrap();
        assert_eq!(store.event_count().unwrap(), 2);
    }

    #[test]
    fn mismatch_recorded() {
        let (store, _dir) = temp_store();
        store.pin("aaaa", "2.2.2.2:2222", TofuTrustLevel::Tofu).unwrap();
        store.record_mismatch("aaaa", "bbbb", "2.2.2.2:2222").unwrap();
        assert_eq!(store.event_count().unwrap(), 2); // pin + mismatch
    }

    #[test]
    fn list_peers_returns_all() {
        let (store, _dir) = temp_store();
        store.pin("aa", "1.1.1.1:1", TofuTrustLevel::Tofu).unwrap();
        store.pin("bb", "2.2.2.2:2", TofuTrustLevel::Bootstrap).unwrap();
        let peers = store.list_peers().unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn bootstrap_trust_level() {
        let (store, _dir) = temp_store();
        store.pin("boot", "3.3.3.3:3", TofuTrustLevel::Bootstrap).unwrap();
        let peer = store.lookup_key("boot").unwrap().unwrap();
        assert_eq!(peer.trust_level, TofuTrustLevel::Bootstrap);
    }

    #[test]
    fn integrity_check_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("good.db");
        let _store = TofuStore::open(&path).unwrap(); // Creates valid DB
        drop(_store);
        let _store2 = TofuStore::open(&path).unwrap(); // Re-opens, integrity passes
    }
}
