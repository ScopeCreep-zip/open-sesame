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
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

/// Canonical signing payload — stable binary encoding used by both
/// `write_local_entry` (signer) and `validate_entry_structure` (verifier).
///
/// Fields are length-prefixed and emitted in fixed alphabetical order.
/// This encoding is independent of any JSON serializer and immune to
/// key-ordering changes across library versions.
///
/// The profile_id is appended as a domain separator after the structured
/// fields (matching the original signing scheme's `|| profile_id` suffix).
#[allow(clippy::too_many_arguments)]
fn canonical_sign_payload(
    id: &str,
    hlc_wall_secs: u64,
    hlc_counter: u64,
    hlc_node_id: &str,
    author_installation_id: &str,
    profile_id: &str,
    operation_type: &str,
    operation_json: &str,
    prev_by_author_hash: Option<&str>,
    value_hash: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    // Fixed field order (alphabetical by field name):
    write_field(&mut buf, b"author_installation_id", author_installation_id.as_bytes());
    write_field(&mut buf, b"hlc_counter", &hlc_counter.to_le_bytes());
    write_field(&mut buf, b"hlc_node_id", hlc_node_id.as_bytes());
    write_field(&mut buf, b"hlc_wall_secs", &hlc_wall_secs.to_le_bytes());
    write_field(&mut buf, b"id", id.as_bytes());
    write_field(&mut buf, b"operation_json", operation_json.as_bytes());
    write_field(&mut buf, b"operation_type", operation_type.as_bytes());
    write_field(
        &mut buf,
        b"prev_by_author_hash",
        prev_by_author_hash.unwrap_or("").as_bytes(),
    );
    write_field(&mut buf, b"profile_id", profile_id.as_bytes());
    // value_hash: BLAKE3 of the secret value at write time. Binds the
    // signature to the specific value, preventing history fabrication
    // when the sender attaches a different (current) value during pull.
    // Empty string for delete operations (no value).
    write_field(&mut buf, b"value_hash", value_hash.as_bytes());
    // Domain separator: profile_id appended raw (matches original scheme).
    buf.extend_from_slice(profile_id.as_bytes());
    buf
}

fn write_field(buf: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

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

        // Schema versioning: refuse to run on mismatched versions.
        // No silent data destruction. Operator must intervene manually.
        const SCHEMA_VERSION: i64 = 2;
        let current_version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);
        if current_version != 0 && current_version != SCHEMA_VERSION {
            let direction = if current_version > SCHEMA_VERSION { "newer" } else { "older" };
            return Err(VaultLogError::InvalidSignature(format!(
                "vault-log.db schema version {current_version} is {direction} than expected {SCHEMA_VERSION}. \
                 Back up and delete {} to recreate, or upgrade the daemon binary.",
                path.display()
            )));
        }

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
                received_at             INTEGER NOT NULL,
                locally_applied         INTEGER NOT NULL DEFAULT 0,
                deferred_until          INTEGER,
                deferred_count          INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_log_profile_hlc
                ON vault_log (profile_id, hlc_wall_secs, hlc_counter, hlc_node_id);
            CREATE INDEX IF NOT EXISTS idx_log_not_applied
                ON vault_log (locally_applied, received_at)
                WHERE locally_applied = 0;

            -- Pull progress: keyed on (source_peer, profile). Tracks where
            -- we left off pulling from each peer. The source_peer is the relay
            -- that delivered entries, not necessarily the original author.
            CREATE TABLE IF NOT EXISTS pull_progress (
                source_peer_id          TEXT NOT NULL,
                profile_id              TEXT NOT NULL,
                watermark_wall_secs     INTEGER NOT NULL,
                watermark_counter       INTEGER NOT NULL,
                last_sync_at            INTEGER NOT NULL,
                PRIMARY KEY (source_peer_id, profile_id)
            );

            -- Replay HWM: keyed on (author, profile). Prevents replay of
            -- entries we've already processed from a specific author. The
            -- author is the original writer, which may differ from the relay
            -- peer in mesh topologies.
            CREATE TABLE IF NOT EXISTS entry_replay_hwm (
                author_installation_id  TEXT NOT NULL,
                profile_id              TEXT NOT NULL,
                hwm_wall_secs           INTEGER NOT NULL,
                hwm_counter             INTEGER NOT NULL,
                PRIMARY KEY (author_installation_id, profile_id)
            );

            CREATE TABLE IF NOT EXISTS hlc_state (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                wall_secs   INTEGER NOT NULL,
                counter     INTEGER NOT NULL,
                node_id     TEXT NOT NULL
            );",
        )
        .map_err(VaultLogError::Sqlite)?;

        // Set schema version.
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
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

    /// Write a local vault operation to the log with Ed25519 signature.
    ///
    /// Called by `vault_log_hook` in `crud.rs` after every successful
    /// `SecretSet` or `SecretDelete`. If a signing seed is available
    /// (via `crud::with_signing_seed()`), the entry is signed and chained
    /// to the previous entry by this author. If no seed is available
    /// (vault locked, pre-init-ceremony), the entry is written unsigned.
    /// `value_bytes`: the secret value for `Set` operations (used to compute
    /// `value_hash`). Pass `&[]` for `Delete` and other non-value operations.
    pub fn write_local_entry(
        &self,
        profile: &TrustProfileName,
        operation: VaultLogOp,
        key: &str,
        installation_id: &str,
        value_bytes: &[u8],
    ) -> Result<(), VaultLogError> {
        let ts = self.tick()?;
        let entry_id = uuid::Uuid::now_v7();
        let op_type = match operation {
            VaultLogOp::Set => "set",
            VaultLogOp::Delete => "delete",
            VaultLogOp::AclUpdate => "acl_update",
            _ => "unknown",
        };

        // Compute value_hash: BLAKE3 of the secret value at write time.
        // Binds the signature to the specific value so receivers can detect
        // when a pull response attaches a different (current) value than
        // what was originally written.
        // H-06: Set operations ALWAYS have a value_hash, even for empty values.
        // This prevents an attacker from exploiting empty-hash entries to
        // inject arbitrary values. Delete/other operations have empty hash.
        let value_hash = if matches!(operation, VaultLogOp::Set) {
            hex::encode(blake3::hash(value_bytes).as_bytes())
        } else {
            String::new()
        };

        let operation_json = serde_json::json!({
            "op": op_type,
            "key": key,
            "value_hash": value_hash,
        })
        .to_string();

        let now = now_epoch_secs();
        let node_id_hex = hex::encode(ts.node_id);

        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // Compute prev_by_author_hash: BLAKE3 of the previous entry's ID by
        // this author for this profile OR compaction snapshots (profile_id = "").
        // Including compaction snapshots ensures the hash chain is continuous
        // across compaction boundaries — without this, a compaction creates a
        // gap that looks like tampering to chain auditors.
        let prev_hash: Option<String> = conn
            .query_row(
                "SELECT id FROM vault_log
                 WHERE author_installation_id = ?1
                   AND (profile_id = ?2 OR profile_id = '')
                 ORDER BY hlc_wall_secs DESC, hlc_counter DESC
                 LIMIT 1",
                params![installation_id, profile.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(VaultLogError::Sqlite)?
            .map(|prev_id| hex::encode(blake3::hash(prev_id.as_bytes()).as_bytes()));

        // Sign the entry. Refuse to write unsigned entries.
        // The closure API keeps the seed inside the RwLock scope — no stack copies.
        let install_uuid = uuid::Uuid::parse_str(installation_id)
            .expect("installation_id validated as non-nil UUID at daemon startup (set_vault_log)");
        let entry_id_str = entry_id.to_string();
        let profile_str = profile.to_string();
        let (signing_pubkey_hex, signature_hex) = crate::crud::with_signing_seed(|seed| {
            let seed_secure = core_crypto::SecureBytes::from_slice(seed);
            match core_crypto::network::derive_signing_keypair(&seed_secure, &install_uuid) {
                Ok(signing_key) => {
                    let pubkey = signing_key.public_key();
                    let payload_bytes = canonical_sign_payload(
                        &entry_id_str,
                        ts.wall_secs,
                        ts.counter,
                        &node_id_hex,
                        installation_id,
                        &profile_str,
                        op_type,
                        &operation_json,
                        prev_hash.as_deref(),
                        &value_hash,
                    );
                    let sig = core_crypto::network::ed25519_sign(&signing_key, &payload_bytes);
                    Ok((hex::encode(pubkey), hex::encode(sig)))
                }
                Err(e) => Err(VaultLogError::InvalidSignature(
                    format!("signing keypair derivation failed: {e}"),
                )),
            }
        })
        .ok_or(VaultLogError::InvalidSignature(
            "signing seed not available — cannot write unsigned vault log entry".into(),
        ))??;

        conn.execute(
            "INSERT INTO vault_log
             (id, hlc_wall_secs, hlc_counter, hlc_node_id, author_installation_id,
              author_signing_pubkey, profile_id, operation_type, operation_json,
              prev_by_author_hash, signature, received_at, locally_applied)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
            params![
                entry_id.to_string(),
                ts.wall_secs as i64,
                ts.counter as i64,
                node_id_hex,
                installation_id,
                signing_pubkey_hex,
                profile.to_string(),
                op_type,
                operation_json,
                prev_hash,
                signature_hex,
                now,
            ],
        )
        .map_err(VaultLogError::Sqlite)?;

        tracing::debug!(
            entry = %entry_id,
            profile = %profile,
            op = op_type,
            key = key,
            signed = !signature_hex.is_empty(),
            "vault log entry written"
        );

        Ok(())
    }

    /// Validate a vault log entry's structural integrity and Ed25519 signature.
    ///
    /// All entries MUST be signed. Unsigned entries (empty `signature` field)
    /// are rejected — there is no backward-compatibility path for pre-signing
    /// installations. If the entry has a valid `signature` and `author_signing_pubkey`,
    /// verifies the Ed25519 signature against the canonical binary-encoded payload.
    pub fn validate_entry_structure(entry_json: &str) -> Result<(), VaultLogError> {
        // M-05: reject oversized entries before parsing to prevent OOM from hostile peers.
        const MAX_ENTRY_BYTES: usize = 64 * 1024;
        if entry_json.len() > MAX_ENTRY_BYTES {
            return Err(VaultLogError::InvalidSignature(format!(
                "entry too large: {} > {} bytes",
                entry_json.len(),
                MAX_ENTRY_BYTES
            )));
        }

        let v: serde_json::Value =
            serde_json::from_str(entry_json).map_err(VaultLogError::Json)?;

        // Signature verification FIRST — all field-content decisions must
        // happen after the entry is proven authentic (S-02/H-02).
        let sig_hex = v["signature"].as_str().unwrap_or("");
        let pubkey_hex = v["author_signing_pubkey"].as_str().unwrap_or("");

        if sig_hex.is_empty() {
            return Err(VaultLogError::InvalidSignature(
                "unsigned entry rejected — all entries must be Ed25519 signed".into(),
            ));
        }

        let sig_bytes = hex::decode(sig_hex).unwrap_or_default();
        if sig_bytes.len() != 64 {
            return Err(VaultLogError::InvalidSignature(format!(
                "expected 64-byte Ed25519 signature, got {} bytes",
                sig_bytes.len()
            )));
        }

        if pubkey_hex.is_empty() {
            return Err(VaultLogError::InvalidSignature(
                "signature present but author_signing_pubkey is empty".into(),
            ));
        }

        let pubkey_bytes = hex::decode(pubkey_hex).unwrap_or_default();
        if pubkey_bytes.len() != 32 {
            return Err(VaultLogError::InvalidSignature(format!(
                "expected 32-byte Ed25519 public key, got {} bytes",
                pubkey_bytes.len()
            )));
        }

        // Reconstruct the signed payload using the same canonical binary
        // encoding that write_local_entry uses. The wire format carries
        // operation as a JSON object; we serialize it back to a string to
        // match what write_local_entry signs (the operation_json column value).
        let operation_json_str = serde_json::to_string(&v["operation"]).unwrap_or_default();
        let payload_bytes = canonical_sign_payload(
            v["id"].as_str().unwrap_or(""),
            v["timestamp"]["wall_secs"].as_u64().unwrap_or(0),
            v["timestamp"]["counter"].as_u64().unwrap_or(0),
            v["timestamp"]["node_id"].as_str().unwrap_or(""),
            v["author_installation_uuid"].as_str().unwrap_or(""),
            v["profile_id"].as_str().unwrap_or(""),
            v["operation"]["op"].as_str().unwrap_or(""),
            &operation_json_str,
            v["prev_by_author"].as_str(),
            v["operation"]["value_hash"].as_str().unwrap_or(""),
        );

        let mut pubkey_array = [0u8; 32];
        pubkey_array.copy_from_slice(&pubkey_bytes);
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);

        if !core_crypto::network::ed25519_verify(&pubkey_array, &payload_bytes, &sig_array) {
            return Err(VaultLogError::InvalidSignature(
                "Ed25519 signature verification failed".into(),
            ));
        }

        // Content checks AFTER signature — fields are now authenticated.
        // System keys cannot be replicated (defense-in-depth).
        if let Some(key) = v["operation"]["key"].as_str()
            && key.starts_with('_')
        {
            return Err(VaultLogError::RejectedEntry(format!(
                "entry targets system key '{key}' — system keys cannot be replicated",
            )));
        }

        // Set operations MUST have a non-empty value_hash. This prevents an
        // attacker from crafting entries with empty value_hash that would bypass
        // the receiver's BLAKE3 value-binding check (any value would "match"
        // an empty expected hash if the receiver defaulted to accepting it).
        // Compaction snapshots and deletes legitimately have empty value_hash.
        let op_type = v["operation"]["op"].as_str().unwrap_or("");
        if op_type == "set" {
            let vh = v["operation"]["value_hash"].as_str().unwrap_or("");
            if vh.is_empty() {
                return Err(VaultLogError::RejectedEntry(
                    "set operation missing value_hash — all set entries must include BLAKE3 value binding".into(),
                ));
            }
        }

        Ok(())
    }

    /// Query log entries since a given HLC watermark for replication serving.
    ///
    /// Returns a `QueryResult` containing:
    /// - `entries_json`: JSON array of full wire-format entries (all signed
    ///   fields included so the receiver can validate). Does NOT include
    ///   `received_at` or `locally_applied` (local-only columns).
    /// - `last_hlc_json`: HLC of the last returned entry as JSON, for the
    ///   caller to cache as the next pull's watermark. `None` if no entries.
    ///
    /// The entries do NOT contain secret values — the caller (dispatch handler)
    /// reads values from the vault and attaches them separately.
    pub fn query_entries_since(
        &self,
        profile_id: &str,
        since_watermark_json: Option<&str>,
        max_entries: u32,
    ) -> Result<QueryResult, VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (wall_secs, counter): (i64, i64) = if let Some(wm) = since_watermark_json {
            let v: serde_json::Value = serde_json::from_str(wm)
                .map_err(VaultLogError::Json)?;
            let wall = v["wall_secs"].as_i64()
                .ok_or(VaultLogError::InvalidWatermark("missing or non-integer wall_secs"))?;
            let ctr = v["counter"].as_i64()
                .ok_or(VaultLogError::InvalidWatermark("missing or non-integer counter"))?;
            (wall, ctr)
        } else {
            (0, 0)
        };

        let mut stmt = conn.prepare(
            "SELECT id, hlc_wall_secs, hlc_counter, hlc_node_id,
                    author_installation_id, author_signing_pubkey, profile_id,
                    operation_type, operation_json, prev_by_author_hash, signature
             FROM vault_log
             WHERE profile_id = ?1
               AND (hlc_wall_secs > ?2 OR (hlc_wall_secs = ?2 AND hlc_counter > ?3))
             ORDER BY hlc_wall_secs, hlc_counter, hlc_node_id
             LIMIT ?4"
        ).map_err(VaultLogError::Sqlite)?;

        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, i64, i64, String, String, String, String, String, String, Option<String>, String)> = stmt
            .query_map(
                params![profile_id, wall_secs, counter, max_entries],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                    row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                    row.get(8)?, row.get(9)?, row.get(10)?,
                )),
            )
            .map_err(VaultLogError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(VaultLogError::Sqlite)?;

        let mut last_hlc: Option<(i64, i64)> = None;
        let mut entries = Vec::with_capacity(rows.len());
        for (id, ws, ctr, node_id, author, signing_pk, prof, op_type, op_json, prev_hash, sig) in &rows {
            last_hlc = Some((*ws, *ctr));
            let operation: serde_json::Value = serde_json::from_str(op_json)
                .unwrap_or(serde_json::Value::Null);
            entries.push(serde_json::json!({
                "id": id,
                "timestamp": {
                    "wall_secs": *ws as u64,
                    "counter": *ctr as u64,
                    "node_id": node_id,
                },
                "author_installation_uuid": author,
                "author_signing_pubkey": signing_pk,
                "profile_id": prof,
                "operation_type": op_type,
                "operation": operation,
                "prev_by_author": prev_hash,
                "signature": sig,
            }));
        }

        let entries_json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into());
        let last_hlc_json = last_hlc.map(|(ws, ctr)| {
            serde_json::json!({"wall_secs": ws, "counter": ctr}).to_string()
        });

        Ok(QueryResult { entries_json, last_hlc_json })
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
        let signing_pubkey = v["author_signing_pubkey"].as_str().unwrap_or("");
        let profile_id = v["profile_id"].as_str().unwrap_or("");
        let op_type = v["operation"]["op"].as_str().unwrap_or("unknown");
        let signature = v["signature"].as_str().unwrap_or("");
        let prev_hash = v["prev_by_author"].as_str();

        // F-17: reject invalid-length node_id instead of silent truncation.
        let node_id_bytes = hex::decode(node_id).unwrap_or_default();
        if node_id_bytes.len() != 8 {
            return Err(VaultLogError::InvalidSignature(format!(
                "node_id hex '{}' decodes to {} bytes, expected 8",
                node_id,
                node_id_bytes.len()
            )));
        }

        let now = now_epoch_secs();

        // M-01: Normalize operation_json to store only the inner operation
        // object {"op","key","value_hash"}, matching the format write_local_entry
        // uses. This eliminates the dual-shape parsing in apply_deferred_entries.
        let normalized_op = serde_json::to_string(&v["operation"]).unwrap_or_default();

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
                    signing_pubkey,
                    profile_id,
                    op_type,
                    normalized_op,
                    prev_hash,
                    signature,
                    now,
                ],
            )
            .map_err(VaultLogError::Sqlite)?;
            // Explicitly drop conn lock before self.receive() which acquires
            // it via persist_hlc(). Removing this drop causes a deadlock.
            drop(conn);
        }

        // Update local HLC on receive (acquires conn internally).
        let remote_ts = HlcTimestamp {
            wall_secs,
            counter,
            node_id: {
                let mut nid = [0u8; 8];
                nid.copy_from_slice(&node_id_bytes);
                nid
            },
        };
        self.receive(&remote_ts)?;

        tracing::debug!(entry = id, "received vault log entry stored");
        Ok(())
    }

    /// Query unapplied entries ordered by HLC for fold application.
    ///
    /// Returns entries where `locally_applied = 0`, ordered by causal
    /// timestamp. The caller decrypts `ReEncryptedValue` payloads and
    /// applies operations to the local vault, then calls
    /// [`mark_applied`] for each entry ID.
    pub fn unapplied_entries(&self, max_entries: u32) -> Result<Vec<UnappliedEntry>, VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, operation_type, operation_json,
                    hlc_wall_secs, hlc_counter, author_installation_id
             FROM vault_log
             WHERE locally_applied = 0
               AND (deferred_until IS NULL OR deferred_until <= ?1)
             ORDER BY hlc_wall_secs, hlc_counter, hlc_node_id
             LIMIT ?2"
        ).map_err(VaultLogError::Sqlite)?;

        let entries = stmt
            .query_map(params![now_epoch, max_entries], |row| {
                Ok(UnappliedEntry {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    operation_type: row.get(2)?,
                    operation_json: row.get(3)?,
                    hlc_wall_secs: row.get(4)?,
                    hlc_counter: row.get(5)?,
                    author_installation_id: row.get(6)?,
                })
            })
            .map_err(VaultLogError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(VaultLogError::Sqlite)?;

        Ok(entries)
    }

    /// Defer an entry for later retry. Sets `deferred_until` to `now + retry_secs`
    /// as an INTEGER epoch (seconds since Unix epoch) and increments `deferred_count`.
    pub fn defer_entry(&self, entry_id: &str, retry_secs: u64) -> Result<(), VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + retry_secs;
        conn.execute(
            "UPDATE vault_log SET deferred_until = ?1, deferred_count = deferred_count + 1 WHERE id = ?2",
            params![until as i64, entry_id],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }

    /// Defer an entry with exponential backoff computed from its current
    /// `deferred_count`. Reads the count and updates in a single lock
    /// acquisition — no TOCTOU between reading the count and computing
    /// the backoff interval.
    ///
    /// Backoff schedule: 0→30s, 1-3→60s, 4-10→300s, 11+→3600s.
    pub fn defer_entry_with_backoff(&self, entry_id: &str) -> Result<(), VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let count: i64 = conn
            .query_row(
                "SELECT deferred_count FROM vault_log WHERE id = ?1",
                params![entry_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let retry_secs: u64 = match count {
            0 => 30,
            1..=3 => 60,
            4..=10 => 300,
            _ => 3600,
        };
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + retry_secs;
        conn.execute(
            "UPDATE vault_log SET deferred_until = ?1, deferred_count = deferred_count + 1 WHERE id = ?2",
            params![until as i64, entry_id],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }

    /// Read the deferred count for an entry.
    #[allow(dead_code)] // Available for future retry-budget logic if needed.
    pub fn deferred_count(&self, entry_id: &str) -> Result<u32, VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let count: i64 = conn
            .query_row(
                "SELECT deferred_count FROM vault_log WHERE id = ?1",
                params![entry_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(count as u32)
    }

    /// Update the replay HWM for an entry author after successful fold.
    ///
    /// Keyed on `(author_installation_id, profile_id)`. Prevents replay of
    /// entries from this author that we've already processed. The author is
    /// the original writer, which may differ from the relay peer in mesh.
    pub fn update_replay_hwm(
        &self,
        author_install_id: &str,
        profile_id: &str,
        wall_secs: i64,
        counter: i64,
    ) -> Result<(), VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "INSERT INTO entry_replay_hwm
             (author_installation_id, profile_id, hwm_wall_secs, hwm_counter)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(author_installation_id, profile_id) DO UPDATE SET
                hwm_wall_secs = CASE
                    WHEN excluded.hwm_wall_secs > hwm_wall_secs THEN excluded.hwm_wall_secs
                    WHEN excluded.hwm_wall_secs = hwm_wall_secs
                         AND excluded.hwm_counter > hwm_counter THEN excluded.hwm_wall_secs
                    ELSE hwm_wall_secs
                END,
                hwm_counter = CASE
                    WHEN excluded.hwm_wall_secs > hwm_wall_secs THEN excluded.hwm_counter
                    WHEN excluded.hwm_wall_secs = hwm_wall_secs
                         AND excluded.hwm_counter > hwm_counter THEN excluded.hwm_counter
                    ELSE hwm_counter
                END",
            params![author_install_id, profile_id, wall_secs, counter],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }

    /// Update pull progress for a source peer after successful fold.
    ///
    /// Keyed on `(source_peer_id, profile_id)`. Tracks where we left off
    /// pulling from this peer. The source peer is the relay that delivered
    /// entries, not necessarily the original author. Used by daemon-network
    /// to set `since_watermark_json` on the next pull request.
    pub fn update_pull_progress(
        &self,
        source_peer_id: &str,
        profile_id: &str,
        wall_secs: i64,
        counter: i64,
    ) -> Result<(), VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = now_epoch_secs();
        conn.execute(
            "INSERT INTO pull_progress
             (source_peer_id, profile_id, watermark_wall_secs, watermark_counter, last_sync_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(source_peer_id, profile_id) DO UPDATE SET
                watermark_wall_secs = CASE
                    WHEN excluded.watermark_wall_secs > watermark_wall_secs THEN excluded.watermark_wall_secs
                    WHEN excluded.watermark_wall_secs = watermark_wall_secs
                         AND excluded.watermark_counter > watermark_counter THEN excluded.watermark_wall_secs
                    ELSE watermark_wall_secs
                END,
                watermark_counter = CASE
                    WHEN excluded.watermark_wall_secs > watermark_wall_secs THEN excluded.watermark_counter
                    WHEN excluded.watermark_wall_secs = watermark_wall_secs
                         AND excluded.watermark_counter > watermark_counter THEN excluded.watermark_counter
                    ELSE watermark_counter
                END,
                last_sync_at = excluded.last_sync_at",
            params![source_peer_id, profile_id, wall_secs, counter, now],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }

    /// Check if an entry's HLC is strictly newer than the stored replay HWM
    /// for this author+profile. Returns `true` if the entry should be accepted.
    ///
    /// Compares `(wall_secs, counter)` only — node_id is ignored within an
    /// author scope. Returns `true` if no HWM exists (first entry from author).
    pub fn check_hwm(
        &self,
        author_install_id: &str,
        profile_id: &str,
        entry_wall_secs: i64,
        entry_counter: i64,
    ) -> Result<bool, VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stored: Option<(i64, i64)> = conn
            .query_row(
                "SELECT hwm_wall_secs, hwm_counter
                 FROM entry_replay_hwm
                 WHERE author_installation_id = ?1 AND profile_id = ?2",
                params![author_install_id, profile_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(VaultLogError::Sqlite)?;

        match stored {
            None => Ok(true),
            Some((ws, ctr)) => {
                Ok(entry_wall_secs > ws || (entry_wall_secs == ws && entry_counter > ctr))
            }
        }
    }

    /// Remove pull progress and replay HWM for a peer. Called when a peer is
    /// unpinned from TOFU to prevent orphaned records from blocking compaction.
    #[allow(dead_code)] // Wired when NetworkUnpinRequest handler calls through to vault_log.
    pub fn cleanup_peer_state(&self, peer_install_id: &str) -> Result<(), VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "DELETE FROM pull_progress WHERE source_peer_id = ?1",
            params![peer_install_id],
        )
        .map_err(VaultLogError::Sqlite)?;
        // Also clean HWM if this peer was an author (same ID).
        conn.execute(
            "DELETE FROM entry_replay_hwm WHERE author_installation_id = ?1",
            params![peer_install_id],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }

    /// Mark an entry as locally applied after successful fold.
    pub fn mark_applied(&self, entry_id: &str) -> Result<(), VaultLogError> {
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute(
            "UPDATE vault_log SET locally_applied = 1 WHERE id = ?1",
            params![entry_id],
        )
        .map_err(VaultLogError::Sqlite)?;
        Ok(())
    }

    /// Compact the vault log by removing applied entries older than the
    /// oldest peer watermark.
    ///
    /// # Transactional safety (C1-NEW)
    ///
    /// The DELETE and snapshot INSERT are wrapped in a single SQLite
    /// transaction. If signing fails (seed disappeared between the
    /// pre-check and the transaction), ROLLBACK ensures no entries are
    /// lost. The signing key is derived BEFORE the transaction begins —
    /// once we hold the derived key, the seed's lifecycle cannot affect us.
    ///
    /// # Watermark semantics
    ///
    /// Only deletes entries that ALL active peers have already received
    /// (their watermarks are past the entry's HLC). Stale peers (no sync
    /// for 2x retention) are excluded from watermark calculation to prevent
    /// orphaned records from blocking compaction indefinitely.
    ///
    /// Inserts a signed `CompactionSnapshot` marker at the compaction
    /// boundary for local audit. Snapshots have `profile_id = ""` so they
    /// are NOT included in profile-scoped pull responses.
    ///
    /// Returns the number of entries deleted.
    pub fn compact(&self, compaction_threshold: u64, retention_secs: i64) -> Result<u32, VaultLogError> {
        // Phase 0: Quick count check before expensive signing key derivation.
        // Avoids wasting a tick + key derivation on the common no-op case.
        {
            let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM vault_log", [], |row| row.get(0))
                .map_err(VaultLogError::Sqlite)?;
            #[allow(clippy::cast_sign_loss)]
            if (count as u64) < compaction_threshold {
                return Ok(0);
            }
        }

        // Phase 1: Pre-acquire signing material. The derived signing key is
        // captured BEFORE any database mutation. If the seed disappears after
        // this point (vault lock event), we already have the derived key and
        // can complete the operation. If the seed is unavailable NOW, we fail
        // before any DELETE — no data loss possible.
        let install_id = crate::crud::INSTALL_ID.get().map_or("", |s| s.as_str());
        let install_uuid = uuid::Uuid::parse_str(install_id)
            .expect("installation_id validated as non-nil UUID at daemon startup (set_vault_log)");
        let signing_key = crate::crud::with_signing_seed(|seed| {
            let seed_secure = core_crypto::SecureBytes::from_slice(seed);
            core_crypto::network::derive_signing_keypair(&seed_secure, &install_uuid)
        })
        .ok_or(VaultLogError::InvalidSignature(
            "cannot compact without signing seed".into(),
        ))?
        .map_err(|e| VaultLogError::InvalidSignature(
            format!("compaction signing key derivation failed: {e}"),
        ))?;

        // Phase 2: Tick the HLC for the snapshot timestamp. This acquires and
        // releases conn internally via persist_hlc, so it MUST happen BEFORE
        // we hold the conn lock for the transaction.
        let ts = self.tick()?;

        // Phase 3: Single conn lock wrapping a SQLite transaction for the
        // entire recheck→watermark→DELETE→sign→INSERT sequence. ROLLBACK on
        // any failure ensures entries are never deleted without a snapshot.
        let conn = self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute_batch("BEGIN IMMEDIATE").map_err(VaultLogError::Sqlite)?;

        let result: Result<u32, VaultLogError> = (|| {
            // Recheck count inside the transaction — entries may have been
            // inserted between the phase 0 check and now.
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM vault_log", [], |row| row.get(0))
                .map_err(VaultLogError::Sqlite)?;
            #[allow(clippy::cast_sign_loss)]
            if (count as u64) < compaction_threshold {
                return Ok(0);
            }

            let stale_cutoff = now_epoch_secs().saturating_sub(2 * retention_secs);
            let active_peer_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pull_progress WHERE last_sync_at >= ?1",
                    params![stale_cutoff],
                    |row| row.get(0),
                )
                .unwrap_or(0);

            let min_watermark: (i64, i64) = if active_peer_count > 0 {
                conn.query_row(
                    "SELECT MIN(watermark_wall_secs), MIN(watermark_counter)
                     FROM pull_progress WHERE last_sync_at >= ?1",
                    params![stale_cutoff],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap_or((0, 0))
            } else {
                // No active peers: retain a rolling window for forensic / rejoin.
                (now_epoch_secs().saturating_sub(retention_secs), i64::MAX)
            };

            let deleted = conn
                .execute(
                    "DELETE FROM vault_log
                     WHERE locally_applied = 1
                       AND operation_type != 'compaction_snapshot'
                       AND (hlc_wall_secs < ?1 OR (hlc_wall_secs = ?1 AND hlc_counter < ?2))",
                    params![min_watermark.0, min_watermark.1],
                )
                .map_err(VaultLogError::Sqlite)?;

            if deleted == 0 {
                return Ok(0);
            }

            // Sign and insert compaction snapshot using the pre-acquired key.
            let node_id_hex = hex::encode(ts.node_id);
            let snapshot_id = uuid::Uuid::now_v7();
            let now = now_epoch_secs();
            let snapshot_json = serde_json::json!({
                "op": "compaction_snapshot",
                "key": "",
                "value_hash": "",
                "watermark_wall_secs": min_watermark.0,
                "watermark_counter": min_watermark.1,
                "entries_deleted": deleted,
            })
            .to_string();

            // Chain to previous entry by this author (maintain hash chain
            // continuity across compaction snapshots).
            let prev_hash: Option<String> = conn
                .query_row(
                    "SELECT id FROM vault_log
                     WHERE author_installation_id = ?1
                     ORDER BY hlc_wall_secs DESC, hlc_counter DESC
                     LIMIT 1",
                    params![install_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(VaultLogError::Sqlite)?
                .map(|prev_id| hex::encode(blake3::hash(prev_id.as_bytes()).as_bytes()));

            let snapshot_id_str = snapshot_id.to_string();
            let pubkey = signing_key.public_key();
            let payload_bytes = canonical_sign_payload(
                &snapshot_id_str,
                ts.wall_secs,
                ts.counter,
                &node_id_hex,
                install_id,
                "",
                "compaction_snapshot",
                &snapshot_json,
                prev_hash.as_deref(),
                "",
            );
            let sig = core_crypto::network::ed25519_sign(&signing_key, &payload_bytes);

            conn.execute(
                "INSERT INTO vault_log
                 (id, hlc_wall_secs, hlc_counter, hlc_node_id, author_installation_id,
                  author_signing_pubkey, profile_id, operation_type, operation_json,
                  prev_by_author_hash, signature, received_at, locally_applied)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
                params![
                    snapshot_id_str,
                    ts.wall_secs as i64,
                    ts.counter as i64,
                    node_id_hex,
                    install_id,
                    hex::encode(pubkey),
                    "",
                    "compaction_snapshot",
                    snapshot_json,
                    prev_hash,
                    hex::encode(sig),
                    now,
                ],
            )
            .map_err(VaultLogError::Sqlite)?;

            tracing::info!(
                deleted,
                watermark_wall = min_watermark.0,
                watermark_counter = min_watermark.1,
                "vault log compacted"
            );

            #[allow(clippy::cast_possible_truncation)]
            Ok(deleted as u32)
        })();

        match &result {
            Ok(0) => { conn.execute_batch("ROLLBACK").ok(); }
            Ok(_) => { conn.execute_batch("COMMIT").map_err(VaultLogError::Sqlite)?; }
            Err(_) => { conn.execute_batch("ROLLBACK").ok(); }
        }

        result
    }

    /// Count of entries in the vault log. Used by tests and compaction threshold.
    #[allow(dead_code)]
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
                #[allow(clippy::cast_sign_loss)]
                Ok(HlcTimestamp {
                    wall_secs: wall_secs as u64,
                    counter: counter as u64,
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

fn wall_secs_now() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current epoch seconds as i64 for INTEGER timestamp columns.
fn now_epoch_secs() -> i64 {
    use std::time::SystemTime;
    #[allow(clippy::cast_possible_wrap)]
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    secs
}

/// A vault log entry pending local application (fold).
#[derive(Debug)]
pub struct UnappliedEntry {
    /// Entry UUID.
    pub id: String,
    /// Profile this entry belongs to.
    pub profile_id: String,
    /// Operation type: "set", "delete", "acl_update".
    pub operation_type: String,
    /// Operation JSON containing the key and (for set) the value.
    pub operation_json: String,
    /// HLC wall seconds — needed for watermark update after fold.
    pub hlc_wall_secs: i64,
    /// HLC counter — needed for watermark update after fold.
    pub hlc_counter: i64,
    /// Author installation ID — needed for watermark scoping.
    pub author_installation_id: String,
}

/// Result from `query_entries_since`.
#[derive(Debug)]
#[allow(dead_code)] // Fields read by daemon-network via IPC response and by tests.
pub struct QueryResult {
    /// JSON array of full wire-format signed entries (no secret values).
    pub entries_json: String,
    /// HLC of the last returned entry as JSON `{"wall_secs":N,"counter":N}`.
    /// `None` if no entries matched. Used by daemon-network to cache the
    /// watermark for the next pull request.
    pub last_hlc_json: Option<String>,
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
    #[error("rejected entry: {0}")]
    #[allow(dead_code)] // Used by validate_entry_structure for system-key rejection.
    RejectedEntry(String),
    #[error("invalid watermark: {0}")]
    InvalidWatermark(&'static str),
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
        // Set signing seed (RwLock — re-settable across tests).
        crate::crud::set_signing_seed(Some(zeroize::Zeroizing::new([0xDD; 32])));
        // Installation ID (OnceLock — first test wins, subsequent calls are no-ops).
        let _ = crate::crud::INSTALL_ID.set("00000000-0000-0000-0000-000000000042".to_string());
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
        log.write_local_entry(&profile, VaultLogOp::Set, "api-key", "00000000-0000-0000-0000-000000000042", b"test-value")
            .unwrap();
        assert_eq!(log.entry_count().unwrap(), 1);

        log.write_local_entry(&profile, VaultLogOp::Delete, "api-key", "00000000-0000-0000-0000-000000000042", &[])
            .unwrap();
        assert_eq!(log.entry_count().unwrap(), 2);
    }

    /// Read the Nth entry (0-indexed) from a VaultLog and reconstruct
    /// wire-format JSON suitable for `validate_entry_structure` and
    /// `insert_received_entry`. This is the canonical "sender side" of
    /// the replication pipeline for tests.
    fn read_entry_as_wire_json(log: &VaultLog, offset: usize) -> String {
        let conn = log.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, hlc_wall_secs, hlc_counter, hlc_node_id,
                        author_installation_id, author_signing_pubkey, profile_id,
                        operation_type, operation_json, prev_by_author_hash, signature
                 FROM vault_log
                 ORDER BY hlc_wall_secs, hlc_counter
                 LIMIT 1 OFFSET ?1",
            )
            .unwrap();
        let (id, wall_secs, counter, node_id, author, signing_pubkey, profile_id,
         _op_type, operation_json, prev_hash, signature): (
            String, i64, i64, String, String, String, String,
            String, String, Option<String>, String,
        ) = stmt
            .query_row(params![offset as i64], |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                    row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                    row.get(8)?, row.get(9)?, row.get(10)?,
                ))
            })
            .unwrap();
        drop(stmt);
        drop(conn);

        let operation: serde_json::Value = serde_json::from_str(&operation_json).unwrap();
        serde_json::json!({
            "id": id,
            "timestamp": {
                "wall_secs": wall_secs as u64,
                "counter": counter as u64,
                "node_id": node_id,
            },
            "author_installation_uuid": author,
            "author_signing_pubkey": signing_pubkey,
            "profile_id": profile_id,
            "operation": operation,
            "prev_by_author": prev_hash,
            "signature": signature,
        })
        .to_string()
    }

    #[test]
    fn insert_received_entry_deduplicates() {
        // Sender writes an entry via write_local_entry.
        let (sender_log, _sender_dir) = temp_log();
        let profile = TrustProfileName::try_from("work").unwrap();
        sender_log
            .write_local_entry(&profile, VaultLogOp::Set, "k", "00000000-0000-0000-0000-000000000042", b"test-val")
            .unwrap();

        // Read back as wire-format JSON (what a peer would receive).
        let wire_entry = read_entry_as_wire_json(&sender_log, 0);

        // Receiver inserts the wire entry.
        let (receiver_log, _receiver_dir) = temp_log();
        receiver_log.insert_received_entry(&wire_entry).unwrap();
        assert_eq!(receiver_log.entry_count().unwrap(), 1);

        // Duplicate insert should be ignored (INSERT OR IGNORE).
        receiver_log.insert_received_entry(&wire_entry).unwrap();
        assert_eq!(receiver_log.entry_count().unwrap(), 1);
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

    #[test]
    fn query_entries_since_returns_matching() {
        let (log, _dir) = temp_log();
        let profile = core_types::TrustProfileName::try_from("work").unwrap();
        log.write_local_entry(&profile, core_types::VaultLogOp::Set, "key-1", "00000000-0000-0000-0000-000000000001", b"val-1").unwrap();
        log.write_local_entry(&profile, core_types::VaultLogOp::Set, "key-2", "00000000-0000-0000-0000-000000000001", b"val-2").unwrap();
        log.write_local_entry(&profile, core_types::VaultLogOp::Delete, "key-1", "00000000-0000-0000-0000-000000000001", &[]).unwrap();

        let result = log.query_entries_since("work", None, 100).unwrap();
        let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();
        assert_eq!(entries.len(), 3);
        // Full wire entries should have all signed fields.
        assert!(entries[0]["id"].is_string());
        assert!(entries[0]["timestamp"]["wall_secs"].is_u64());
        assert!(entries[0]["signature"].is_string());
        assert!(result.last_hlc_json.is_some());

        let wm = r#"{"wall_secs":0,"counter":0}"#;
        let result2 = log.query_entries_since("work", Some(wm), 100).unwrap();
        let entries2: Vec<serde_json::Value> = serde_json::from_str(&result2.entries_json).unwrap();
        assert_eq!(entries2.len(), 3);

        let result3 = log.query_entries_since("work", None, 2).unwrap();
        let entries3: Vec<serde_json::Value> = serde_json::from_str(&result3.entries_json).unwrap();
        assert_eq!(entries3.len(), 2);

        let result4 = log.query_entries_since("personal", None, 100).unwrap();
        let entries4: Vec<serde_json::Value> = serde_json::from_str(&result4.entries_json).unwrap();
        assert!(entries4.is_empty());
        assert!(result4.last_hlc_json.is_none());
    }

    #[test]
    fn query_entries_since_rejects_malformed_watermark() {
        let (log, _dir) = temp_log();
        // Malformed JSON.
        let result = log.query_entries_since("work", Some("not-json"), 100);
        assert!(result.is_err(), "malformed JSON watermark must error");

        // Valid JSON but missing required fields.
        let result = log.query_entries_since("work", Some(r#"{"foo":"bar"}"#), 100);
        assert!(result.is_err(), "watermark without wall_secs must error");

        // Valid JSON with wall_secs but missing counter.
        let result = log.query_entries_since("work", Some(r#"{"wall_secs":1}"#), 100);
        assert!(result.is_err(), "watermark without counter must error");
    }

    #[test]
    fn validate_rejects_wrong_length_signature() {
        // 32-byte signature (should be 64).
        let entry = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "signature": hex::encode([0xAA; 32]),
        }).to_string();
        let result = VaultLog::validate_entry_structure(&entry);
        assert!(result.is_err(), "32-byte signature must be rejected");
    }

    #[test]
    fn validate_rejects_signature_without_pubkey() {
        // 64-byte signature present but no author_signing_pubkey — rejected.
        let entry = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "signature": hex::encode([0xAA; 64]),
            "author_signing_pubkey": "",
        }).to_string();
        let result = VaultLog::validate_entry_structure(&entry);
        assert!(result.is_err(), "signature without pubkey must be rejected");
    }

    #[test]
    fn validate_verifies_valid_ed25519_signature() {
        // Uses the real write_local_entry → read-back round-trip, not
        // independent construction. This is the definitive test that the
        // signer and verifier agree.
        let (log, _dir) = temp_log();
        let profile = TrustProfileName::try_from("work").unwrap();
        log.write_local_entry(&profile, VaultLogOp::Set, "k", "00000000-0000-0000-0000-000000000042", b"test-val")
            .unwrap();
        let wire_entry = read_entry_as_wire_json(&log, 0);
        let result = VaultLog::validate_entry_structure(&wire_entry);
        assert!(result.is_ok(), "valid Ed25519 signature must be accepted: {result:?}");
    }

    /// 8-byte node_id hex for tampered-signature test construction.
    const TEST_NODE_ID: &str = "aa00000000000000";

    #[test]
    fn validate_rejects_tampered_signature() {
        // Must construct independently to tamper the signature — can't get
        // write_local_entry to produce a bad sig. Uses canonical_sign_payload
        // directly, which is acceptable for a negative test.
        let master = core_crypto::SecureBytes::from_slice(&[0xDD; 32]);
        let install_id = uuid::Uuid::from_u128(99);
        let signing_key = core_crypto::network::derive_signing_keypair(&master, &install_id).unwrap();
        let pubkey = signing_key.public_key();

        let test_value_hash = hex::encode(blake3::hash(b"test-val").as_bytes());
        let operation_obj = serde_json::json!({"key": "k", "op": "set", "value_hash": test_value_hash});
        let operation_json_str = serde_json::to_string(&operation_obj).unwrap();
        let payload_bytes = canonical_sign_payload(
            "00000000-0000-0000-0000-000000000001",
            1000, 0, TEST_NODE_ID,
            &install_id.to_string(), "work", "set",
            &operation_json_str, None,
            &test_value_hash,
        );
        let mut sig = core_crypto::network::ed25519_sign(&signing_key, &payload_bytes);
        sig[0] ^= 0xFF; // Tamper.

        let entry = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "timestamp": { "wall_secs": 1000, "counter": 0, "node_id": TEST_NODE_ID },
            "author_installation_uuid": install_id.to_string(),
            "author_signing_pubkey": hex::encode(pubkey),
            "profile_id": "work",
            "operation": operation_obj,
            "prev_by_author": null,
            "signature": hex::encode(sig),
        }).to_string();
        let result = VaultLog::validate_entry_structure(&entry);
        assert!(result.is_err(), "tampered signature must be rejected");
    }

    #[test]
    fn validate_rejects_unsigned_entry() {
        let entry = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "signature": "",
        }).to_string();
        let result = VaultLog::validate_entry_structure(&entry);
        assert!(result.is_err(), "unsigned entry must be rejected");
    }

    /// F-06 round-trip: write_local_entry → read back → validate_entry_structure.
    /// This is the critical test that would have caught the original signer/verifier
    /// field name mismatch. The writer produces DB-format entries; the validator
    /// consumes wire-format entries. This test verifies they agree on the signed bytes.
    #[test]
    fn write_then_validate_roundtrip() {
        let (log, _dir) = temp_log();
        let profile = TrustProfileName::try_from("work").unwrap();
        log.write_local_entry(&profile, VaultLogOp::Set, "roundtrip-key", "00000000-0000-0000-0000-000000000042", b"roundtrip-val")
            .unwrap();

        let wire_entry = read_entry_as_wire_json(&log, 0);
        let result = VaultLog::validate_entry_structure(&wire_entry);
        assert!(
            result.is_ok(),
            "round-trip: entry written by write_local_entry must pass validate_entry_structure: {result:?}"
        );
    }

    /// Full sender→receiver round-trip: write on sender, read back as wire
    /// format, insert on receiver, verify receiver validates and stores it.
    #[test]
    fn full_sender_receiver_roundtrip() {
        let (sender_log, _sd) = temp_log();
        let profile = TrustProfileName::try_from("work").unwrap();

        // Sender writes two entries.
        sender_log
            .write_local_entry(&profile, VaultLogOp::Set, "secret-a", "00000000-0000-0000-0000-000000000042", b"val-a")
            .unwrap();
        sender_log
            .write_local_entry(&profile, VaultLogOp::Delete, "secret-b", "00000000-0000-0000-0000-000000000042", &[])
            .unwrap();
        assert_eq!(sender_log.entry_count().unwrap(), 2);

        // Read both as wire JSON.
        let wire_0 = read_entry_as_wire_json(&sender_log, 0);
        let wire_1 = read_entry_as_wire_json(&sender_log, 1);

        // Receiver validates and inserts both.
        let (receiver_log, _rd) = temp_log();
        receiver_log.insert_received_entry(&wire_0).unwrap();
        receiver_log.insert_received_entry(&wire_1).unwrap();
        assert_eq!(receiver_log.entry_count().unwrap(), 2);

        // Receiver's entries should be unapplied.
        let unapplied = receiver_log.unapplied_entries(100).unwrap();
        assert_eq!(unapplied.len(), 2);
        assert_eq!(unapplied[0].operation_type, "set");
        assert_eq!(unapplied[1].operation_type, "delete");
    }
}
