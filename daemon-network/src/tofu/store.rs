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
    /// Installation ID for scoping the genesis hash chain.
    installation_id: String,
}

impl TofuStore {
    /// Open or create the TOFU store at the given path.
    ///
    /// The `installation_id` scopes the genesis hash so two installations
    /// on the same filesystem produce distinct event chains.
    ///
    /// Enforces WAL mode, creates tables if absent, runs integrity check.
    ///
    /// # Errors
    ///
    /// Returns an error if the database is corrupted or cannot be opened.
    pub fn open(path: &Path, installation_id: &str) -> Result<Self, TofuStoreError> {
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
                pin_expires_at      TEXT,
                pin_ttl_secs        INTEGER,
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

            CREATE INDEX IF NOT EXISTS idx_events_key ON tofu_events (public_key_hex);
            CREATE INDEX IF NOT EXISTS idx_peers_addr ON tofu_peers (last_known_addr);",
        )
        .map_err(TofuStoreError::Sqlite)?;

        // Integrity check.
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(TofuStoreError::Sqlite)?;
        if integrity != "ok" {
            return Err(TofuStoreError::Corrupted(integrity));
        }

        Ok(Self { conn, installation_id: installation_id.to_string() })
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

    /// Reverse lookup: find a peer by their last known network address.
    ///
    /// Used for `IKpsk2` reconnection — when an inbound connection arrives
    /// from a known address, look up the cached static key and PSK without
    /// requiring the initiator to identify itself first.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the query fails.
    pub fn lookup_addr(&self, addr: &str) -> Result<Option<TofuPeer>, TofuStoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT public_key_hex, first_seen_at, last_seen_at, first_seen_addr,
                        last_known_addr, trust_level, display_name, installation_id,
                        cached_psk, version
                 FROM tofu_peers WHERE last_known_addr = ?1",
            )
            .map_err(TofuStoreError::Sqlite)?;

        let peer = stmt
            .query_row(params![addr], |row| {
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
    /// `ttl_secs`: if `Some`, the pin expires after this many seconds unless
    /// refreshed by a successful handshake (`touch()`). If `None`, the pin
    /// never expires. `Bootstrap` and `Endorsed` pins should use `None`.
    /// `Tofu` pins from unauthenticated discovery (mDNS, BEP-44) should use
    /// a TTL (e.g., 86400 for 24h) so stale pins from transient networks
    /// auto-expire.
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
        self.pin_with_ttl(public_key_hex, addr, trust_level, None)
    }

    /// Pin a new peer with an optional expiry TTL.
    ///
    /// See [`pin`] for details.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the insert or event append fails.
    pub fn pin_with_ttl(
        &self,
        public_key_hex: &str,
        addr: &str,
        trust_level: TofuTrustLevel,
        ttl_secs: Option<u64>,
    ) -> Result<(), TofuStoreError> {
        let now = now_iso8601();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let level_str = trust_level_str(trust_level);
        let expires_at = ttl_secs.map(|ttl| format!("{}Z", now_secs + ttl));
        // Store the TTL value itself so touch() can compute refresh windows
        // without parsing first_seen_at (which is ISO 8601, not epoch).
        #[allow(clippy::cast_possible_wrap)]
        let ttl_val = ttl_secs.map(|t| t as i64);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO tofu_peers
                 (public_key_hex, first_seen_at, last_seen_at, first_seen_addr,
                  last_known_addr, trust_level, pin_expires_at, pin_ttl_secs, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                params![public_key_hex, now, now, addr, addr, level_str, expires_at, ttl_val],
            )
            .map_err(TofuStoreError::Sqlite)?;

        self.append_event(public_key_hex, "pin", Some(addr), Some(level_str))?;
        Ok(())
    }

    /// Update last-seen timestamp, address, and conditionally refresh pin expiry.
    ///
    /// Pin expiry is only refreshed when the peer is within the last 25% of
    /// its TTL window. This prevents an attacker from keeping a stale pin
    /// alive indefinitely by reconnecting early in the window. A 24h TTL pin
    /// only refreshes after 18h have passed.
    ///
    /// `Bootstrap` and `Endorsed` pins (no `pin_expires_at`) are unaffected.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the update fails.
    pub fn touch(
        &self,
        public_key_hex: &str,
        addr: &str,
    ) -> Result<(), TofuStoreError> {
        // Read old address, current expiry, and original TTL BEFORE updating.
        let row: Option<(Option<String>, Option<String>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT last_known_addr, pin_expires_at, pin_ttl_secs FROM tofu_peers WHERE public_key_hex = ?1",
                params![public_key_hex],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(TofuStoreError::Sqlite)?;

        let Some((old_addr, current_expires, pin_ttl)) = row else {
            return Ok(()); // Peer not found — nothing to touch.
        };

        let now = now_iso8601();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Conditionally refresh pin_expires_at if within last 25% of TTL.
        // Uses the stored pin_ttl_secs (not derived from first_seen_at which
        // is ISO 8601 and cannot be parsed as epoch seconds).
        let new_expires = match (&current_expires, pin_ttl) {
            (Some(expires_str), Some(ttl)) if ttl > 0 => {
                let expires_secs: u64 = expires_str
                    .trim_end_matches('Z')
                    .parse()
                    .unwrap_or(0);
                #[allow(clippy::cast_sign_loss)]
                let ttl_u64 = ttl as u64;
                let remaining = expires_secs.saturating_sub(now_secs);
                let threshold = ttl_u64 / 4; // Last 25% of the window.

                if remaining <= threshold {
                    // Within the last 25% — refresh by adding one full TTL.
                    Some(format!("{}Z", now_secs + ttl_u64))
                } else {
                    // Not yet in the refresh window — keep current expiry.
                    current_expires.clone()
                }
            }
            _ => {
                // No expiry (Bootstrap/Endorsed) or no TTL stored — leave as-is.
                current_expires.clone()
            }
        };

        self.conn
            .execute(
                "UPDATE tofu_peers SET last_seen_at = ?1, last_known_addr = ?2, pin_expires_at = ?3
                 WHERE public_key_hex = ?4",
                params![now, addr, new_expires, public_key_hex],
            )
            .map_err(TofuStoreError::Sqlite)?;

        // Log address migration if the address actually changed.
        if let Some(ref old) = old_addr
            && old != addr
        {
            let detail = format!("from={old}");
            self.append_event(public_key_hex, "addr_migrate", Some(addr), Some(&detail))?;
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

    /// List all pinned peer public key hex strings for BEP-44 resolution targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` query fails.
    pub fn pinned_pubkeys(&self) -> Result<Vec<String>, TofuStoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT public_key_hex FROM tofu_peers
                 WHERE trust_level IN ('tofu', 'bootstrap', 'endorsed')"
            )
            .map_err(TofuStoreError::Sqlite)?;

        let keys = stmt
            .query_map([], |row| row.get(0))
            .map_err(TofuStoreError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(TofuStoreError::Sqlite)?;

        Ok(keys)
    }

    /// Store the installation identity received via `HandshakeAck`.
    ///
    /// Called after a verified `HandshakeAck` exchange to persist the peer's
    /// `installation_id` and `display_name` in the TOFU store. These fields
    /// are advisory — they enrich `sesame network peers` output and support
    /// M3 replication routing, but are not part of the TOFU trust decision.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the update fails.
    pub fn set_installation_identity(
        &self,
        public_key_hex: &str,
        installation_id: &str,
        display_name: Option<&str>,
    ) -> Result<(), TofuStoreError> {
        // Cap display_name at 256 bytes to prevent memory amplification from
        // a malicious peer sending a multi-KB name that gets cloned into the
        // TOFU store, audit log, and IPC events.
        let capped_name = display_name.map(|n| {
            if n.len() <= 256 { return n; }
            // Truncate at a char boundary to avoid splitting multi-byte UTF-8.
            let mut end = 256;
            while end > 0 && !n.is_char_boundary(end) { end -= 1; }
            &n[..end]
        });
        self.conn
            .execute(
                "UPDATE tofu_peers SET installation_id = ?1, display_name = ?2
                 WHERE public_key_hex = ?3",
                params![installation_id, capped_name, public_key_hex],
            )
            .map_err(TofuStoreError::Sqlite)?;
        Ok(())
    }

    /// Expire TOFU pins whose `pin_expires_at` has passed.
    ///
    /// Sets expired peers to `Unpinned` and logs an event. Called from the
    /// maintenance sweep. Only affects `Tofu`-level pins — `Bootstrap` and
    /// `Endorsed` pins have no expiry (`pin_expires_at` is NULL).
    ///
    /// Returns the number of pins expired.
    ///
    /// # Errors
    ///
    /// Returns `TofuStoreError::Sqlite` if the query or update fails.
    pub fn expire_stale_pins(&self) -> Result<u32, TofuStoreError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let now_str = format!("{now_secs}Z");

        // Find all expired tofu pins.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT public_key_hex FROM tofu_peers
                 WHERE pin_expires_at IS NOT NULL
                   AND pin_expires_at <= ?1
                   AND trust_level = 'tofu'"
            )
            .map_err(TofuStoreError::Sqlite)?;

        let expired_keys: Vec<String> = stmt
            .query_map(params![now_str], |row| row.get(0))
            .map_err(TofuStoreError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(TofuStoreError::Sqlite)?;

        let now = now_iso8601();
        for key in &expired_keys {
            self.conn
                .execute(
                    "UPDATE tofu_peers SET trust_level = 'unpinned', unpinned_at = ?1
                     WHERE public_key_hex = ?2",
                    params![now, key],
                )
                .map_err(TofuStoreError::Sqlite)?;
            self.append_event(key, "pin_expired", None, Some("ttl"))?;
        }

        #[allow(clippy::cast_possible_truncation)]
        Ok(expired_keys.len() as u32)
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
                // Genesis entry — scoped by installation ID.
                let genesis = format!("opensesame:tofu:genesis:{}", self.installation_id);
                hex::encode(blake3::hash(genesis.as_bytes()).as_bytes())
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
#[allow(dead_code)] // Fields read by CLI (sesame network peers) and integration tests.
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
        let store = TofuStore::open(&path, "test-install").unwrap();
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
        let _store = TofuStore::open(&path, "test-install").unwrap(); // Creates valid DB
        drop(_store);
        let _store2 = TofuStore::open(&path, "test-install").unwrap(); // Re-opens, integrity passes
    }

    #[test]
    fn lookup_addr_finds_peer() {
        let (store, _dir) = temp_store();
        store.pin("aabbccdd", "10.0.0.1:48627", TofuTrustLevel::Tofu).unwrap();
        let peer = store.lookup_addr("10.0.0.1:48627").unwrap().unwrap();
        assert_eq!(peer.public_key_hex, "aabbccdd");
        assert_eq!(peer.trust_level, TofuTrustLevel::Tofu);
    }

    #[test]
    fn lookup_addr_returns_none_for_unknown() {
        let (store, _dir) = temp_store();
        assert!(store.lookup_addr("99.99.99.99:1234").unwrap().is_none());
    }

    #[test]
    fn lookup_addr_with_psk_for_ikpsk2() {
        let (store, _dir) = temp_store();
        store.pin("eeff0011", "10.0.0.5:48627", TofuTrustLevel::Tofu).unwrap();
        store.store_psk("eeff0011", &[0xBB; 32]).unwrap();
        let peer = store.lookup_addr("10.0.0.5:48627").unwrap().unwrap();
        assert_eq!(peer.public_key_hex, "eeff0011");
        assert_eq!(peer.cached_psk.unwrap(), vec![0xBB; 32]);
    }

    #[test]
    fn set_installation_identity_persists() {
        let (store, _dir) = temp_store();
        store.pin("aabb", "10.0.0.1:48627", TofuTrustLevel::Tofu).unwrap();

        // Before write-back: installation_id is None.
        let peer = store.lookup_key("aabb").unwrap().unwrap();
        assert!(peer.installation_id.is_none());
        assert!(peer.display_name.is_none());

        // Write-back.
        store.set_installation_identity("aabb", "550e8400-uuid", Some("peer-laptop")).unwrap();

        // After write-back.
        let peer = store.lookup_key("aabb").unwrap().unwrap();
        assert_eq!(peer.installation_id.as_deref(), Some("550e8400-uuid"));
        assert_eq!(peer.display_name.as_deref(), Some("peer-laptop"));
    }

    #[test]
    fn set_installation_identity_no_op_for_missing_peer() {
        let (store, _dir) = temp_store();
        // No peer pinned — update affects zero rows, no error.
        store.set_installation_identity("nonexistent", "uuid", None).unwrap();
    }

    #[test]
    fn pin_with_ttl_sets_expiry() {
        let (store, _dir) = temp_store();
        store.pin_with_ttl("aabb", "10.0.0.1:1", TofuTrustLevel::Tofu, Some(3600)).unwrap();
        let peer = store.lookup_key("aabb").unwrap().unwrap();
        assert_eq!(peer.trust_level, TofuTrustLevel::Tofu);
        // pin_expires_at is set (we can't check the exact value since it's
        // wall-clock-dependent, but we can verify it's non-null via the DB).
        let conn = rusqlite::Connection::open_with_flags(
            &_dir.path().join("test-tofu.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let expires: Option<String> = conn.query_row(
            "SELECT pin_expires_at FROM tofu_peers WHERE public_key_hex = 'aabb'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(expires.is_some(), "pin_with_ttl must set pin_expires_at");
    }

    #[test]
    fn pin_without_ttl_has_no_expiry() {
        let (store, _dir) = temp_store();
        store.pin("ccdd", "10.0.0.2:2", TofuTrustLevel::Bootstrap).unwrap();
        let conn = rusqlite::Connection::open_with_flags(
            &_dir.path().join("test-tofu.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let expires: Option<String> = conn.query_row(
            "SELECT pin_expires_at FROM tofu_peers WHERE public_key_hex = 'ccdd'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(expires.is_none(), "pin() without TTL must have NULL pin_expires_at");
    }

    #[test]
    fn expire_stale_pins_transitions_to_unpinned() {
        let (store, _dir) = temp_store();
        // Pin with a 0-second TTL (already expired).
        store.pin_with_ttl("dead", "10.0.0.1:1", TofuTrustLevel::Tofu, Some(0)).unwrap();
        // Brief sleep to ensure wall clock passes the expiry.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let expired = store.expire_stale_pins().unwrap();
        assert_eq!(expired, 1, "one pin must expire");
        let peer = store.lookup_key("dead").unwrap().unwrap();
        assert_eq!(peer.trust_level, TofuTrustLevel::Unpinned);
    }

    #[test]
    fn expire_stale_pins_ignores_bootstrap() {
        let (store, _dir) = temp_store();
        // Bootstrap pin with no TTL — must not expire.
        store.pin("boot", "10.0.0.1:1", TofuTrustLevel::Bootstrap).unwrap();
        let expired = store.expire_stale_pins().unwrap();
        assert_eq!(expired, 0);
        let peer = store.lookup_key("boot").unwrap().unwrap();
        assert_eq!(peer.trust_level, TofuTrustLevel::Bootstrap);
    }

    #[test]
    fn touch_does_not_refresh_expiry_early_in_window() {
        let (store, _dir) = temp_store();
        // Pin with 100s TTL.
        store.pin_with_ttl("peer", "10.0.0.1:1", TofuTrustLevel::Tofu, Some(100)).unwrap();

        // Read the initial expiry.
        let conn = rusqlite::Connection::open_with_flags(
            &_dir.path().join("test-tofu.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let expires_before: String = conn.query_row(
            "SELECT pin_expires_at FROM tofu_peers WHERE public_key_hex = 'peer'",
            [], |row| row.get(0),
        ).unwrap();

        // Touch immediately (well within the first 75% of the window).
        store.touch("peer", "10.0.0.1:1").unwrap();

        let expires_after: String = conn.query_row(
            "SELECT pin_expires_at FROM tofu_peers WHERE public_key_hex = 'peer'",
            [], |row| row.get(0),
        ).unwrap();

        assert_eq!(
            expires_before, expires_after,
            "touch early in TTL window must NOT refresh expiry"
        );
    }

    #[test]
    fn touch_refreshes_expiry_near_end_of_window() {
        let (store, _dir) = temp_store();
        // Pin with 1s TTL — expires almost immediately.
        store.pin_with_ttl("peer", "10.0.0.1:1", TofuTrustLevel::Tofu, Some(1)).unwrap();

        // Wait 1.1s so the pin is past expiry (well into the last 25%).
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let conn = rusqlite::Connection::open_with_flags(
            &_dir.path().join("test-tofu.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let expires_before: String = conn.query_row(
            "SELECT pin_expires_at FROM tofu_peers WHERE public_key_hex = 'peer'",
            [], |row| row.get(0),
        ).unwrap();

        store.touch("peer", "10.0.0.1:1").unwrap();

        let expires_after: String = conn.query_row(
            "SELECT pin_expires_at FROM tofu_peers WHERE public_key_hex = 'peer'",
            [], |row| row.get(0),
        ).unwrap();

        assert_ne!(
            expires_before, expires_after,
            "touch near end of TTL window must refresh expiry"
        );
    }

    #[test]
    fn pin_ttl_secs_stored_in_db() {
        let (store, _dir) = temp_store();
        store.pin_with_ttl("peer", "10.0.0.1:1", TofuTrustLevel::Tofu, Some(86400)).unwrap();
        let conn = rusqlite::Connection::open_with_flags(
            &_dir.path().join("test-tofu.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let ttl: i64 = conn.query_row(
            "SELECT pin_ttl_secs FROM tofu_peers WHERE public_key_hex = 'peer'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(ttl, 86400);
    }
}
