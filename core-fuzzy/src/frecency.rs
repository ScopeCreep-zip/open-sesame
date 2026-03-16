//! Frecency scoring with SQLite persistence.
//!
//! Mozilla-style double-exponential decay model:
//! score = sum(frequency_i * 0.5^((now - timestamp_i) / half_life))
//!
//! Half-life: 30 days (configurable). Each launch records a timestamp.
//! The score decays exponentially so frequently-used recent apps rank highest.
//!
//! Frecency data is plaintext SQLite (ADR-LNC-002: usage patterns are not
//! secrets — which apps you launch frequently is not sensitive enough to
//! warrant SQLCipher overhead). Per-profile isolation via separate DB files.

use rusqlite::{Connection, params};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Half-life for frecency decay in milliseconds (30 days).
const HALF_LIFE_MS: f64 = 30.0 * 24.0 * 3600.0 * 1000.0;

/// SQLite-backed frecency index for a single profile.
pub struct FrecencyDb {
    conn: Connection,
}

impl FrecencyDb {
    /// Open or create a frecency database at the given path.
    ///
    /// Creates the schema on first open. Uses WAL mode for concurrent reads.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrated.
    pub fn open(path: &Path) -> core_types::Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| core_types::Error::Platform(format!("frecency DB open failed: {e}")))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| core_types::Error::Platform(format!("frecency WAL mode failed: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS frecency (
                entry_id    TEXT NOT NULL,
                profile_id  TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                action      TEXT NOT NULL DEFAULT 'launch',
                PRIMARY KEY (entry_id, profile_id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_frecency_profile
                ON frecency (profile_id, entry_id);",
        )
        .map_err(|e| {
            core_types::Error::Platform(format!("frecency schema migration failed: {e}"))
        })?;

        Ok(Self { conn })
    }

    /// Open an in-memory frecency database (for testing).
    pub fn open_in_memory() -> core_types::Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            core_types::Error::Platform(format!("frecency in-memory open failed: {e}"))
        })?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS frecency (
                entry_id    TEXT NOT NULL,
                profile_id  TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                action      TEXT NOT NULL DEFAULT 'launch',
                PRIMARY KEY (entry_id, profile_id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_frecency_profile
                ON frecency (profile_id, entry_id);",
        )
        .map_err(|e| core_types::Error::Platform(format!("frecency schema failed: {e}")))?;

        Ok(Self { conn })
    }

    /// Record a launch event for the given entry in the given profile.
    pub fn record_launch(&self, entry_id: &str, profile_id: &str) -> core_types::Result<()> {
        let now = now_unix();
        self.conn
            .execute(
                "INSERT INTO frecency (entry_id, profile_id, timestamp, action) VALUES (?1, ?2, ?3, 'launch')",
                params![entry_id, profile_id, now],
            )
            .map_err(|e| {
                core_types::Error::Platform(format!("frecency record failed: {e}"))
            })?;
        Ok(())
    }

    /// Compute frecency scores for all entries in the given profile.
    ///
    /// Returns `(entry_id, score)` pairs sorted by score descending.
    pub fn scores(&self, profile_id: &str) -> core_types::Result<Vec<(String, f64)>> {
        let now = now_unix();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT entry_id, timestamp FROM frecency WHERE profile_id = ?1 ORDER BY entry_id",
            )
            .map_err(|e| core_types::Error::Platform(format!("frecency query failed: {e}")))?;

        let rows = stmt
            .query_map(params![profile_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| core_types::Error::Platform(format!("frecency query_map failed: {e}")))?;

        // Accumulate scores per entry.
        let mut scores: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

        for row in rows {
            let (entry_id, timestamp) = row.map_err(|e| {
                core_types::Error::Platform(format!("frecency row read failed: {e}"))
            })?;

            let age_secs = (now - timestamp) as f64;
            let decay = 0.5_f64.powf(age_secs / HALF_LIFE_MS);
            *scores.entry(entry_id).or_default() += decay;
        }

        let mut result: Vec<(String, f64)> = scores.into_iter().collect();
        result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Ok(result)
    }

    /// Get the frecency score for a single entry in a profile.
    pub fn score_for(&self, entry_id: &str, profile_id: &str) -> core_types::Result<f64> {
        let now = now_unix();
        let mut stmt = self
            .conn
            .prepare("SELECT timestamp FROM frecency WHERE entry_id = ?1 AND profile_id = ?2")
            .map_err(|e| core_types::Error::Platform(format!("frecency query failed: {e}")))?;

        let timestamps: Vec<i64> = stmt
            .query_map(params![entry_id, profile_id], |row| row.get(0))
            .map_err(|e| core_types::Error::Platform(format!("frecency query_map failed: {e}")))?
            .filter_map(|r| r.ok())
            .collect();

        let mut score = 0.0;
        for ts in timestamps {
            let age_secs = (now - ts) as f64;
            let decay = 0.5_f64.powf(age_secs / HALF_LIFE_MS);
            score += decay;
        }

        Ok(score)
    }

    /// Prune entries older than the given number of days.
    pub fn prune(&self, max_age_days: u32) -> core_types::Result<u64> {
        let cutoff = now_unix() - i64::from(max_age_days) * 86_400_000;
        let deleted = self
            .conn
            .execute("DELETE FROM frecency WHERE timestamp < ?1", params![cutoff])
            .map_err(|e| core_types::Error::Platform(format!("frecency prune failed: {e}")))?;
        Ok(deleted as u64)
    }
}

/// Returns current time as milliseconds since epoch (for sub-second uniqueness).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve_score() {
        let db = FrecencyDb::open_in_memory().unwrap();
        db.record_launch("firefox.desktop", "work").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        db.record_launch("firefox.desktop", "work").unwrap();

        let score = db.score_for("firefox.desktop", "work").unwrap();
        // Two very recent launches: each ~1.0 decay, so score ~2.0
        assert!(score > 1.9 && score < 2.1, "score was {score}");
    }

    #[test]
    fn profile_isolation() {
        let db = FrecencyDb::open_in_memory().unwrap();
        db.record_launch("firefox.desktop", "work").unwrap();

        let work_score = db.score_for("firefox.desktop", "work").unwrap();
        let personal_score = db.score_for("firefox.desktop", "personal").unwrap();

        assert!(work_score > 0.0);
        assert_eq!(personal_score, 0.0);
    }

    #[test]
    fn scores_sorted_descending() {
        let db = FrecencyDb::open_in_memory().unwrap();
        // Firefox launched 3 times, code launched 1 time
        db.record_launch("firefox.desktop", "work").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        db.record_launch("firefox.desktop", "work").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        db.record_launch("firefox.desktop", "work").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        db.record_launch("code.desktop", "work").unwrap();

        let scores = db.scores("work").unwrap();
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0].0, "firefox.desktop");
        assert_eq!(scores[1].0, "code.desktop");
        assert!(scores[0].1 > scores[1].1);
    }

    #[test]
    fn prune_removes_old_entries() {
        let db = FrecencyDb::open_in_memory().unwrap();
        // Insert an entry with an old timestamp directly.
        db.conn
            .execute(
                "INSERT INTO frecency (entry_id, profile_id, timestamp, action) VALUES ('old.desktop', 'work', 1000, 'launch')",
                [],
            )
            .unwrap();
        db.record_launch("new.desktop", "work").unwrap();

        let deleted = db.prune(1).unwrap(); // prune entries older than 1 day
        assert_eq!(deleted, 1);

        let scores = db.scores("work").unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].0, "new.desktop");
    }

    #[test]
    fn empty_profile_returns_empty() {
        let db = FrecencyDb::open_in_memory().unwrap();
        let scores = db.scores("nonexistent").unwrap();
        assert!(scores.is_empty());
    }
}
