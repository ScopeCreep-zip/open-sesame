//! `SQLCipher`-backed encrypted secret storage.
//!
//! Double encryption with cryptographic key separation:
//! - `SQLCipher` page-level AES-256-CBC using the vault key (PRAGMA key)
//! - Per-entry AES-256-GCM using an entry key derived from the vault key
//!   under the vault's `hkdf` (`KeyContext::SqlCipherEntry`), independent
//!   from the page encryption key via domain separation
//! - A fresh random 12-byte nonce per encryption, prepended to the
//!   ciphertext (`core_crypto::EncryptionKey::seal_wire`)
//!
//! This provides defense-in-depth: even if `SQLCipher`'s page encryption
//! is somehow bypassed, individual values remain encrypted with a
//! cryptographically independent key and unique random nonces.

use core_crypto::{EncryptionKey, KeyContext, SecureBytes};
use core_types::{BoxFuture, HkdfAlgorithm};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use crate::store::{SecretsStore, not_found};

/// Encrypted secret storage backed by `SQLCipher`.
///
/// Dropping the store closes the connection; `SQLCipher`'s codec teardown
/// (`sqlcipher_codec_ctx_free`) then overwrites its copies of the page
/// key, HMAC key, and passphrase, held in its mlock'd private heap.
pub struct SqlCipherStore {
    /// Synchronous rusqlite connection wrapped in a Mutex for async compatibility.
    /// `SQLCipher` is single-writer; Mutex serializes access.
    conn: Mutex<Connection>,
    /// Per-entry AES-256-GCM key (zeroized on drop), cryptographically
    /// independent from the `SQLCipher` page encryption key.
    entry_key: EncryptionKey,
    /// DB file path (for diagnostics).
    db_path: PathBuf,
}

impl SqlCipherStore {
    /// Open (or create) an encrypted `SQLCipher` database.
    ///
    /// The `vault_key` is the profile's 32-byte vault key, used as the
    /// `SQLCipher` page encryption key (via `PRAGMA key`). The per-entry
    /// AES-256-GCM key is derived from it under the vault's `hkdf` with
    /// domain separation, ensuring cryptographic independence between
    /// page-level and entry-level encryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, the key is rejected,
    /// or schema migration fails.
    pub fn open(
        db_path: &Path,
        vault_key: &SecureBytes,
        hkdf: HkdfAlgorithm,
    ) -> core_types::Result<Self> {
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

        // Set the encryption key in raw hex mode; both strings zeroize on
        // drop, on every path.
        let hex_key = Zeroizing::new(hex::encode(vault_key.as_bytes()));
        let pragma_sql = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", *hex_key));
        conn.execute_batch(&pragma_sql)
            .map_err(|e| core_types::Error::Secrets(format!("PRAGMA key failed: {e}")))?;

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

        // The per-entry key: same vault_key input, different context.
        let entry_key = core_crypto::derive_encryption_key(
            hkdf,
            &KeyContext::SqlCipherEntry,
            vault_key.as_bytes(),
        );

        tracing::info!(path = %db_path.display(), "SQLCipher store opened");

        Ok(Self {
            conn: Mutex::new(conn),
            entry_key,
            db_path: db_path.to_owned(),
        })
    }

    /// The connection, for a store operation. A poisoned lock is an error:
    /// a writer panicked mid-statement.
    fn conn(&self) -> core_types::Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| core_types::Error::Secrets(format!("lock poisoned: {e}")))
    }

    /// Current Unix timestamp in seconds, recorded as the entry's
    /// creation and update time.
    ///
    /// # Errors
    ///
    /// A system clock before the Unix epoch or beyond `i64` seconds.
    fn now_secs() -> core_types::Result<i64> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                core_types::Error::Secrets(format!("system clock is before the Unix epoch: {e}"))
            })?
            .as_secs();
        i64::try_from(secs).map_err(|_| {
            core_types::Error::Secrets(format!("system clock {secs}s exceeds the i64 range"))
        })
    }
}

impl SecretsStore for SqlCipherStore {
    fn get(&self, key: &str) -> BoxFuture<'_, core_types::Result<SecureBytes>> {
        let key = key.to_owned();
        Box::pin(async move {
            let conn = self.conn()?;
            let mut stmt = conn
                .prepare("SELECT value FROM secrets WHERE key = ?1")
                .map_err(|e| core_types::Error::Secrets(format!("prepare failed: {e}")))?;

            let ciphertext: Vec<u8> = stmt
                .query_row(rusqlite::params![key], |row| row.get(0))
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => not_found(&key),
                    other => core_types::Error::Secrets(format!("query failed: {other}")),
                })?;

            self.entry_key.open_wire(&ciphertext)
        })
    }

    fn set(&self, key: &str, value: &[u8]) -> BoxFuture<'_, core_types::Result<()>> {
        let key = key.to_owned();
        let value = Zeroizing::new(value.to_vec());
        Box::pin(async move {
            let ciphertext = self.entry_key.seal_wire(&value)?;
            drop(value);
            let now = Self::now_secs()?;

            self.conn()?
                .execute(
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
            let rows = self
                .conn()?
                .execute("DELETE FROM secrets WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| core_types::Error::Secrets(format!("delete failed: {e}")))?;

            if rows == 0 {
                Err(not_found(&key))
            } else {
                Ok(())
            }
        })
    }

    fn list_keys(&self) -> BoxFuture<'_, core_types::Result<Vec<String>>> {
        Box::pin(async move {
            let conn = self.conn()?;
            let mut stmt = conn
                .prepare("SELECT key FROM secrets ORDER BY key")
                .map_err(|e| core_types::Error::Secrets(format!("prepare failed: {e}")))?;

            stmt.query_map([], |row| row.get(0))
                .map_err(|e| core_types::Error::Secrets(format!("query failed: {e}")))?
                .collect::<Result<Vec<String>, _>>()
                .map_err(|e| core_types::Error::Secrets(format!("row read failed: {e}")))
        })
    }
}

impl std::fmt::Debug for SqlCipherStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection and keys are not shown.
        f.debug_struct("SqlCipherStore")
            .field("db_path", &self.db_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::compliance_tests;
    use core_types::TrustProfileName;

    const HKDF: HkdfAlgorithm = HkdfAlgorithm::Blake3;

    fn test_vault_key() -> SecureBytes {
        let key: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        SecureBytes::new(key)
    }

    fn open(db: &Path, key: &SecureBytes) -> core_types::Result<SqlCipherStore> {
        SqlCipherStore::open(db, key, HKDF)
    }

    fn open_test_store(dir: &Path) -> SqlCipherStore {
        open(&dir.join("test.db"), &test_vault_key()).unwrap()
    }

    fn vault_key(master_key: &SecureBytes, profile: &str) -> SecureBytes {
        let profile = TrustProfileName::try_from(profile).unwrap();
        core_crypto::derive_key(HKDF, &KeyContext::Vault(&profile), master_key.as_bytes())
    }

    /// Read the stored ciphertext of `key`.
    fn stored(store: &SqlCipherStore, key: &str) -> Vec<u8> {
        store
            .conn
            .lock()
            .unwrap()
            .prepare("SELECT value FROM secrets WHERE key = ?1")
            .unwrap()
            .query_row(rusqlite::params![key], |row| row.get(0))
            .unwrap()
    }

    #[tokio::test]
    async fn entries_are_sealed_under_the_vaults_entry_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_vault_key();
        for hkdf in [HkdfAlgorithm::Blake3, HkdfAlgorithm::HkdfSha256] {
            let db = dir.path().join(format!("{hkdf:?}.db"));
            let store = SqlCipherStore::open(&db, &key, hkdf).unwrap();
            store.set("k", b"v").await.unwrap();
            let entry_key =
                core_crypto::derive_key(hkdf, &KeyContext::SqlCipherEntry, key.as_bytes());
            let expected = EncryptionKey::from_bytes(entry_key.as_bytes().try_into().unwrap());
            assert_eq!(
                expected.open_wire(&stored(&store, "k")).unwrap().as_bytes(),
                b"v"
            );
        }
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

        let store1 = open(&db, &test_vault_key()).unwrap();
        store1.set("secret", b"hidden").await.unwrap();
        drop(store1);

        // Open with a different key — should fail to verify.
        let mut key2_bytes = [0u8; 32];
        key2_bytes[0] = 0xFF;
        let result = open(&db, &SecureBytes::from_slice(&key2_bytes));
        assert!(result.is_err(), "different vault key should be rejected");
    }

    #[tokio::test]
    async fn schema_migration_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("migrate.db");
        let key = test_vault_key();

        // Open twice — schema migration should not fail.
        let store1 = open(&db, &key).unwrap();
        store1.set("k", b"v").await.unwrap();
        drop(store1);

        let store2 = open(&db, &key).unwrap();
        let val = store2.get("k").await.unwrap();
        assert_eq!(val.as_bytes(), b"v");
    }

    // ===== Cross-Profile Vault Isolation =====

    #[tokio::test]
    async fn cross_profile_keys_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cross-profile.db");

        let master_key = SecureBytes::new((0..32u8).map(|i| i.wrapping_mul(11)).collect());

        // Open vault with work key and store a secret
        let vault_key_work = vault_key(&master_key, "work");
        let store_work = open(&db_path, &vault_key_work).unwrap();
        store_work.set("api-key", b"secret-value").await.unwrap();
        drop(store_work);

        // Same master key, different profile: a distinct vault key.
        let vault_key_personal = vault_key(&master_key, "personal");
        assert_ne!(vault_key_work.as_bytes(), vault_key_personal.as_bytes());

        // Attempt to open the same vault DB with the personal key — must fail
        let result = open(&db_path, &vault_key_personal);
        assert!(
            result.is_err(),
            "opening vault encrypted with key A using key B must fail"
        );
    }

    #[tokio::test]
    async fn cross_profile_secret_access_returns_error() {
        let dir = tempfile::tempdir().unwrap();

        let mut master_key = [0u8; 32];
        master_key[0] = 0x42;
        let master_key = SecureBytes::from_slice(&master_key);

        // Vault A for "work" profile
        let store_a = open(
            &dir.path().join("vault-a.db"),
            &vault_key(&master_key, "work"),
        )
        .unwrap();
        store_a.set("shared-key", b"work-secret").await.unwrap();

        // Vault B for "personal" profile (separate DB file)
        let store_b = open(
            &dir.path().join("vault-b.db"),
            &vault_key(&master_key, "personal"),
        )
        .unwrap();

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
        let mut master_key = [0u8; 32];
        master_key[0] = 0xFF;
        let vault_key = vault_key(&SecureBytes::from_slice(&master_key), "test-profile");
        let entry_key =
            core_crypto::derive_key(HKDF, &KeyContext::SqlCipherEntry, vault_key.as_bytes());
        assert_ne!(
            vault_key.as_bytes(),
            entry_key.as_bytes(),
            "vault key and entry key must differ via domain separation"
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
            let ciphertext = stored(&store, &key);

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

        let store = open(&db, &key).unwrap();
        store.set("persist/key", b"survives-restart").await.unwrap();
        drop(store);

        let store = open(&db, &key).unwrap();
        let val = store.get("persist/key").await.unwrap();
        assert_eq!(val.as_bytes(), b"survives-restart");
    }

    #[tokio::test]
    async fn a_closed_vault_stays_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("closed.db");
        let key = test_vault_key();
        let store = open(&db, &key).unwrap();
        store.set("k", b"secret-payload").await.unwrap();
        drop(store);
        let conn = rusqlite::Connection::open(&db).unwrap();
        assert!(
            conn.execute_batch("SELECT count(*) FROM sqlite_master;")
                .is_err(),
            "a closed vault must not be readable without its key"
        );
    }
}
