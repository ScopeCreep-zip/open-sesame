//! SQLCipher-backed encrypted secret storage.
//!
//! Double encryption with cryptographic key separation:
//! - SQLCipher page-level AES-256-CBC using the vault key (PRAGMA key)
//! - Per-entry AES-256-GCM using a BLAKE3-derived entry key (independent
//!   from the page encryption key via domain separation)
//! - Random 12-byte nonces per encryption (prepended to ciphertext)
//!
//! This provides defense-in-depth: even if SQLCipher's page encryption is
//! somehow bypassed, individual values remain encrypted with a
//! cryptographically independent key and unique random nonces.

use core_crypto::{EncryptionKey, SecureBytes};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::store::{BoxFuture, SecretsStore};

/// Encrypted secret storage backed by SQLCipher.
pub struct SqlCipherStore {
    /// Synchronous rusqlite connection wrapped in a Mutex for async compatibility.
    /// SQLCipher is single-writer; Mutex serializes access.
    conn: Mutex<Connection>,
    /// Per-entry AES-256-GCM key, derived from vault_key via BLAKE3.
    /// Cryptographically independent from the SQLCipher page encryption key.
    entry_key: SecureBytes,
    /// DB file path (for diagnostics).
    db_path: PathBuf,
    /// Tracks whether pragma_rekey_clear() has already been called,
    /// preventing redundant PRAGMA rekey in Drop.
    cleared: AtomicBool,
}

impl SqlCipherStore {
    /// Open (or create) an encrypted SQLCipher database.
    ///
    /// The `vault_key` is a 32-byte BLAKE3-derived per-profile key used as the
    /// SQLCipher page encryption key (via `PRAGMA key`). A separate per-entry
    /// AES-256-GCM key is derived from the vault key via BLAKE3 with domain
    /// separation, ensuring cryptographic independence between page-level and
    /// entry-level encryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, the key is rejected,
    /// or schema migration fails.
    pub fn open(db_path: &Path, vault_key: &SecureBytes) -> core_types::Result<Self> {
        if vault_key.len() != 32 {
            return Err(core_types::Error::Crypto(format!(
                "vault key must be 32 bytes, got {}",
                vault_key.len()
            )));
        }

        let conn = Connection::open(db_path).map_err(|e| {
            core_types::Error::Secrets(format!(
                "failed to open database {}: {e}",
                db_path.display()
            ))
        })?;

        // Set the encryption key in raw hex mode.
        use zeroize::Zeroize;
        let mut hex_key = hex_encode(vault_key.as_bytes());
        let mut pragma_sql = format!("PRAGMA key = \"x'{hex_key}'\";");
        conn.execute_batch(&pragma_sql).map_err(|e| {
            hex_key.zeroize();
            pragma_sql.zeroize();
            core_types::Error::Secrets(format!("PRAGMA key failed: {e}"))
        })?;
        hex_key.zeroize();
        pragma_sql.zeroize();

        // SQLCipher configuration — must be set before any table access.
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA cipher_hmac_algorithm = HMAC_SHA256;
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA256;
             PRAGMA kdf_iter = 256000;
             PRAGMA journal_mode = WAL;",
        )
        .map_err(|e| {
            core_types::Error::Secrets(format!("SQLCipher PRAGMA configuration failed: {e}"))
        })?;

        // Schema migration (idempotent).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| core_types::Error::Secrets(format!("schema migration failed: {e}")))?;

        // Verify the key works by reading the schema.
        conn.execute_batch("SELECT count(*) FROM sqlite_master;")
            .map_err(|_| {
                core_types::Error::Secrets(
                    "database key verification failed: wrong key or corrupt database".into(),
                )
            })?;

        // Derive a separate key for per-entry AES-256-GCM encryption.
        // Domain-separated via BLAKE3 so it is cryptographically independent
        // from the SQLCipher page encryption key (same vault_key input, different context).
        let mut entry_key_bytes =
            blake3::derive_key("pds v2 entry-encryption-key", vault_key.as_bytes());
        let entry_key = SecureBytes::new(entry_key_bytes.to_vec());
        entry_key_bytes.zeroize();

        tracing::info!(path = %db_path.display(), "SQLCipher store opened");

        Ok(Self {
            conn: Mutex::new(conn),
            entry_key,
            db_path: db_path.to_owned(),
            cleared: AtomicBool::new(false),
        })
    }

    /// Encrypt a value with per-entry AES-256-GCM using a random nonce.
    ///
    /// Output wire format: `[12-byte random nonce][ciphertext + 16-byte GCM tag]`
    ///
    /// Every call generates a fresh random nonce via getrandom, preventing
    /// the catastrophic nonce reuse that occurs with deterministic derivation.
    fn encrypt_value(&self, plaintext: &[u8]) -> core_types::Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| core_types::Error::Crypto(format!("nonce generation failed: {e}")))?;
        let enc_key = EncryptionKey::from_bytes(
            self.entry_key
                .as_bytes()
                .try_into()
                .map_err(|_| core_types::Error::Crypto("entry key is not 32 bytes".into()))?,
        )?;
        let ciphertext = enc_key.encrypt(&nonce, plaintext)?;
        let mut wire = Vec::with_capacity(12 + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend(ciphertext);
        Ok(wire)
    }

    /// Decrypt a value with per-entry AES-256-GCM.
    ///
    /// Expected wire format: `[12-byte nonce][ciphertext + 16-byte GCM tag]`
    fn decrypt_value(&self, wire: &[u8]) -> core_types::Result<SecureBytes> {
        if wire.len() < 12 + 16 {
            return Err(core_types::Error::Crypto(
                "encrypted value too short (missing nonce or tag)".into(),
            ));
        }
        let nonce: [u8; 12] = wire[..12].try_into().unwrap();
        let ciphertext = &wire[12..];
        let enc_key = EncryptionKey::from_bytes(
            self.entry_key
                .as_bytes()
                .try_into()
                .map_err(|_| core_types::Error::Crypto("entry key is not 32 bytes".into()))?,
        )?;
        enc_key.decrypt(&nonce, ciphertext)
    }

    /// Clear SQLCipher's internal C-level key buffer via `PRAGMA rekey = '';`.
    ///
    /// Defense-in-depth: the Rust-side `entry_key: SecureBytes` already zeroizes
    /// on drop, but this ensures the SQLCipher C library's internal copy of the
    /// page encryption key is also scrubbed before the connection is closed.
    ///
    /// Called from all vault-closing paths: deactivation, lock, and shutdown.
    /// Logs a warning on failure but does not panic — zeroization is best-effort
    /// because the connection may already be in a broken state.
    pub fn pragma_rekey_clear(&self) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = conn.execute_batch("PRAGMA rekey = '';") {
            tracing::warn!(
                path = %self.db_path.display(),
                error = %e,
                "PRAGMA rekey clear failed — C-level key buffer may not be zeroized"
            );
        }
        // Mark as cleared so Drop does not fire redundantly.
        self.cleared.store(true, Ordering::Release);
    }

    /// Current Unix timestamp in seconds.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

impl SecretsStore for SqlCipherStore {
    fn get(&self, key: &str) -> BoxFuture<'_, core_types::Result<SecureBytes>> {
        let key = key.to_owned();
        Box::pin(async move {
            let conn = self
                .conn
                .lock()
                .map_err(|e| core_types::Error::Secrets(format!("lock poisoned: {e}")))?;

            let mut stmt = conn
                .prepare("SELECT value FROM secrets WHERE key = ?1")
                .map_err(|e| core_types::Error::Secrets(format!("prepare failed: {e}")))?;

            let ciphertext: Vec<u8> = stmt
                .query_row(rusqlite::params![key], |row| row.get(0))
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        core_types::Error::NotFound(format!("secret key: {key}"))
                    }
                    other => core_types::Error::Secrets(format!("query failed: {other}")),
                })?;

            self.decrypt_value(&ciphertext)
        })
    }

    fn set(&self, key: &str, value: &[u8]) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        let mut value = value.to_vec();
        Box::pin(async move {
            use zeroize::Zeroize;
            let ciphertext = self.encrypt_value(&value);
            value.zeroize();
            let ciphertext = ciphertext?;
            let now = Self::now_secs();

            let conn = self
                .conn
                .lock()
                .map_err(|e| core_types::Error::Secrets(format!("lock poisoned: {e}")))?;

            conn.execute(
                "INSERT INTO secrets (key, value, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                rusqlite::params![key, ciphertext, now],
            )
            .map_err(|e| core_types::Error::Secrets(format!("insert failed: {e}")))?;

            Ok(())
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        Box::pin(async move {
            let conn = self
                .conn
                .lock()
                .map_err(|e| core_types::Error::Secrets(format!("lock poisoned: {e}")))?;

            let rows = conn
                .execute("DELETE FROM secrets WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| core_types::Error::Secrets(format!("delete failed: {e}")))?;

            if rows == 0 {
                Err(core_types::Error::NotFound(format!("secret key: {key}")))
            } else {
                Ok(())
            }
        })
    }

    fn list_keys(&self) -> BoxFuture<'_, core_types::Result<Vec<String>>> {
        Box::pin(async move {
            let conn = self
                .conn
                .lock()
                .map_err(|e| core_types::Error::Secrets(format!("lock poisoned: {e}")))?;

            let mut stmt = conn
                .prepare("SELECT key FROM secrets ORDER BY key")
                .map_err(|e| core_types::Error::Secrets(format!("prepare failed: {e}")))?;

            let keys: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .map_err(|e| core_types::Error::Secrets(format!("query failed: {e}")))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(keys)
        })
    }
}

impl std::fmt::Debug for SqlCipherStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlCipherStore")
            .field("db_path", &self.db_path)
            .field("vault_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SqlCipherStore {
    fn drop(&mut self) {
        // Skip if pragma_rekey_clear() was already called explicitly.
        if self.cleared.load(Ordering::Acquire) {
            return;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = conn.execute_batch("PRAGMA rekey = '';") {
            let _ = e;
        }
    }
}

/// Hex-encode bytes (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::compliance_tests;

    fn test_vault_key() -> SecureBytes {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        SecureBytes::new(key.to_vec())
    }

    fn open_test_store(dir: &Path) -> SqlCipherStore {
        let db = dir.join("test.db");
        let key = test_vault_key();
        SqlCipherStore::open(&db, &key).unwrap()
    }

    #[tokio::test]
    async fn sqlcipher_passes_compliance() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        compliance_tests(&store).await;
    }

    #[tokio::test]
    async fn db_file_contains_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());

        let secret_value = b"THIS_IS_A_VERY_UNIQUE_SECRET_VALUE_12345";
        store.set("plaintext-check", secret_value).await.unwrap();

        // Force flush by dropping the store.
        drop(store);

        // Read raw DB bytes and verify no plaintext.
        let db_bytes = std::fs::read(dir.path().join("test.db")).unwrap();
        let db_str = String::from_utf8_lossy(&db_bytes);
        assert!(
            !db_str.contains("THIS_IS_A_VERY_UNIQUE_SECRET_VALUE_12345"),
            "plaintext secret found in encrypted DB file"
        );
        assert!(
            !db_str.contains("plaintext-check"),
            "plaintext key name found in encrypted DB file"
        );
    }

    #[tokio::test]
    async fn different_vault_keys_cannot_access() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cross-key.db");

        let key1 = test_vault_key();
        let store1 = SqlCipherStore::open(&db, &key1).unwrap();
        store1.set("secret", b"hidden").await.unwrap();
        drop(store1);

        // Open with a different key — should fail to verify.
        let mut key2_bytes = [0u8; 32];
        key2_bytes[0] = 0xFF;
        let key2 = SecureBytes::new(key2_bytes.to_vec());
        let result = SqlCipherStore::open(&db, &key2);
        assert!(result.is_err(), "different vault key should be rejected");
    }

    #[tokio::test]
    async fn schema_migration_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("migrate.db");
        let key = test_vault_key();

        // Open twice — schema migration should not fail.
        let store1 = SqlCipherStore::open(&db, &key).unwrap();
        store1.set("k", b"v").await.unwrap();
        drop(store1);

        let store2 = SqlCipherStore::open(&db, &key).unwrap();
        let val = store2.get("k").await.unwrap();
        assert_eq!(val.as_bytes(), b"v");
    }

    // ===== Cross-Profile Vault Isolation =====

    #[tokio::test]
    async fn cross_profile_keys_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cross-profile.db");

        let master_key = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i * 11) as u8;
            }
            SecureBytes::new(k.to_vec())
        };

        // Derive vault key for "work" profile
        let vault_key_work = core_crypto::derive_vault_key(master_key.as_bytes(), "work");

        // Open vault with work key and store a secret
        let store_work = SqlCipherStore::open(&db_path, &vault_key_work).unwrap();
        store_work.set("api-key", b"secret-value").await.unwrap();
        drop(store_work);

        // Derive vault key for "personal" profile (same master key, different profile)
        let vault_key_personal = core_crypto::derive_vault_key(master_key.as_bytes(), "personal");

        // BLAKE3 domain separation must produce distinct vault keys
        assert_ne!(vault_key_work.as_bytes(), vault_key_personal.as_bytes());

        // Attempt to open the same vault DB with the personal key — must fail
        let result = SqlCipherStore::open(&db_path, &vault_key_personal);
        assert!(
            result.is_err(),
            "opening vault encrypted with key A using key B must fail"
        );
    }

    #[tokio::test]
    async fn cross_profile_secret_access_returns_error() {
        let dir = tempfile::tempdir().unwrap();

        let master_key = {
            let mut k = [0u8; 32];
            k[0] = 0x42;
            SecureBytes::new(k.to_vec())
        };

        // Vault A for "work" profile
        let vault_key_a = core_crypto::derive_vault_key(master_key.as_bytes(), "work");
        let db_a = dir.path().join("vault-a.db");
        let store_a = SqlCipherStore::open(&db_a, &vault_key_a).unwrap();
        store_a.set("shared-key", b"work-secret").await.unwrap();

        // Vault B for "personal" profile (separate DB file)
        let vault_key_b = core_crypto::derive_vault_key(master_key.as_bytes(), "personal");
        let db_b = dir.path().join("vault-b.db");
        let store_b = SqlCipherStore::open(&db_b, &vault_key_b).unwrap();

        // Attempt to read the same key name from vault B — must be NotFound
        let result = store_b.get("shared-key").await;
        assert!(result.is_err(), "cross-profile access must return error");
        assert!(
            matches!(result, Err(core_types::Error::NotFound(_))),
            "expected NotFound error, got: {result:?}"
        );
    }

    #[test]
    fn vault_key_derivation_domain_separation() {
        let master_key = {
            let mut k = [0u8; 32];
            k[0] = 0xFF;
            SecureBytes::new(k.to_vec())
        };

        let profile = "test-profile";

        // Derive vault key (used for SQLCipher page encryption)
        let vault_key = core_crypto::derive_vault_key(master_key.as_bytes(), profile);

        // Derive entry key (same derivation as SqlCipherStore::open internally)
        let entry_key_bytes =
            blake3::derive_key("pds v2 entry-encryption-key", vault_key.as_bytes());

        // Vault key and entry key must be cryptographically independent
        assert_ne!(
            vault_key.as_bytes(),
            &entry_key_bytes,
            "vault key and entry key must differ via BLAKE3 domain separation"
        );
    }

    // ===== Encrypted DB Contains No Plaintext Key Names =====

    #[tokio::test]
    async fn db_file_contains_no_key_names_in_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());

        let key_names = [
            "very-unique-key-alpha",
            "very-unique-key-beta",
            "very-unique-key-gamma",
            "very-unique-key-delta",
            "very-unique-key-epsilon",
        ];

        for key in &key_names {
            store.set(key, b"secret-value").await.unwrap();
        }

        drop(store);

        let db_bytes = std::fs::read(dir.path().join("test.db")).unwrap();
        let db_str = String::from_utf8_lossy(&db_bytes);

        for key in &key_names {
            assert!(
                !db_str.contains(key),
                "encrypted DB must not contain plaintext key name: {key}"
            );
        }
    }

    // ===== Nonce Uniqueness =====

    #[tokio::test]
    async fn encrypt_same_value_produces_different_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());

        let plaintext = b"deterministic-plaintext-value";
        let mut nonces = std::collections::HashSet::new();

        for i in 0..100 {
            let key = format!("nonce-test-{i}");
            store.set(&key, plaintext).await.unwrap();

            // Read raw ciphertext from the DB
            let conn = store.conn.lock().unwrap();
            let ciphertext: Vec<u8> = conn
                .prepare("SELECT value FROM secrets WHERE key = ?1")
                .unwrap()
                .query_row(rusqlite::params![key], |row| row.get(0))
                .unwrap();

            assert!(
                ciphertext.len() >= 12,
                "ciphertext must include 12-byte nonce prefix"
            );

            let nonce: [u8; 12] = ciphertext[..12].try_into().unwrap();
            nonces.insert(nonce);
        }

        assert_eq!(
            nonces.len(),
            100,
            "all 100 nonces must be unique (random generation)"
        );
    }

    // ===== Existing tests =====

    #[tokio::test]
    async fn reopen_persists_data() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("persist.db");
        let key = test_vault_key();

        let store = SqlCipherStore::open(&db, &key).unwrap();
        store.set("persist/key", b"survives-restart").await.unwrap();
        drop(store);

        let store = SqlCipherStore::open(&db, &key).unwrap();
        let val = store.get("persist/key").await.unwrap();
        assert_eq!(val.as_bytes(), b"survives-restart");
    }

    #[tokio::test]
    async fn pragma_rekey_clear_does_not_remove_encryption() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rekey-test.db");
        let key = test_vault_key();

        // Open, write a secret, call pragma_rekey_clear, close.
        let store = SqlCipherStore::open(&db, &key).unwrap();
        store.set("rekey-check", b"secret-payload").await.unwrap();
        store.pragma_rekey_clear();
        drop(store);

        // Reopen with the ORIGINAL key -- must succeed if encryption preserved.
        let store2 = SqlCipherStore::open(&db, &key).unwrap();
        let val = store2.get("rekey-check").await.unwrap();
        assert_eq!(
            val.as_bytes(),
            b"secret-payload",
            "database must still be readable with original key after pragma_rekey_clear"
        );
        drop(store2);

        // Attempt to open with NO key (empty Connection::open, no PRAGMA key).
        // If PRAGMA rekey='' removed encryption, this would succeed.
        let conn = rusqlite::Connection::open(&db).unwrap();
        let result = conn.execute_batch("SELECT count(*) FROM sqlite_master;");
        assert!(
            result.is_err(),
            "database must NOT be readable without a key after pragma_rekey_clear -- \
             PRAGMA rekey='' may have removed encryption!"
        );
    }
}
