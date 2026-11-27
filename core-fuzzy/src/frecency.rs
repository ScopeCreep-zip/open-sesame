//! Frecency scoring with `SQLite` persistence.
//!
//! Exponential decay: an entry's score is the sum, over its launches, of
//! `0.5^(age / HALF_LIFE)`, so frequently and recently launched entries
//! rank highest. A launch older than [`RETENTION`] contributes under 0.1%
//! and is deleted when the database opens.
//!
//! Frecency data is plaintext `SQLite` (ADR-LNC-002: usage patterns are not
//! secrets — which apps you launch frequently is not sensitive enough to
//! warrant `SQLCipher` overhead). Each profile has its own database file
//! (`core_layout::Layout::frecency_db`).

use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The age at which a launch counts half: 30 days.
const HALF_LIFE: Duration = Duration::from_hours(30 * 24);

/// The age after which a launch is deleted: ten half-lives.
const RETENTION: Duration = Duration::from_hours(10 * 30 * 24);

/// The schema: one row per launch, timestamped in milliseconds since the
/// Unix epoch (distinct launches within a second stay distinct rows).
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS launches (
    entry_id  TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (entry_id, timestamp)
);";

/// `SQLite`-backed frecency index of one profile.
pub struct FrecencyDb {
    conn: Connection,
}

/// A frecency failure: the operation and the `SQLite` error.
fn failed(operation: &str, e: impl std::fmt::Display) -> core_types::Error {
    core_types::Error::Platform(format!("frecency {operation} failed: {e}"))
}

impl FrecencyDb {
    /// Open or create the frecency database at `path` (WAL mode), creating
    /// the schema and deleting launches older than `RETENTION`.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the database cannot be opened,
    /// migrated, or pruned, or the system clock is unreadable.
    pub fn open(path: &Path) -> core_types::Result<Self> {
        let conn = Connection::open(path).map_err(|e| failed("open", e))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| failed("WAL mode", e))?;
        Self::init(conn)
    }

    #[cfg(test)]
    fn open_in_memory() -> core_types::Result<Self> {
        Self::init(Connection::open_in_memory().map_err(|e| failed("open", e))?)
    }

    fn init(conn: Connection) -> core_types::Result<Self> {
        conn.execute_batch(SCHEMA)
            .map_err(|e| failed("schema migration", e))?;
        let db = Self { conn };
        let cutoff = millis(SystemTime::now() - RETENTION)?;
        db.conn
            .execute("DELETE FROM launches WHERE timestamp < ?1", params![cutoff])
            .map_err(|e| failed("prune", e))?;
        Ok(db)
    }

    /// Record a launch of `entry_id` now.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the insert fails or the system
    /// clock is unreadable.
    pub fn record_launch(&self, entry_id: &str) -> core_types::Result<()> {
        self.conn
            .execute(
                "INSERT INTO launches (entry_id, timestamp) VALUES (?1, ?2)",
                params![entry_id, millis(SystemTime::now())?],
            )
            .map_err(|e| failed("record", e))?;
        Ok(())
    }

    /// The frecency score of every entry, highest first.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the query or a row read fails,
    /// or the system clock is unreadable.
    pub fn scores(&self) -> core_types::Result<Vec<(String, f64)>> {
        let now = millis(SystemTime::now())?;
        let mut stmt = self
            .conn
            .prepare("SELECT entry_id, timestamp FROM launches")
            .map_err(|e| failed("query", e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| failed("query", e))?;

        let mut scores: HashMap<String, f64> = HashMap::new();
        for row in rows {
            let (entry_id, timestamp) = row.map_err(|e| failed("row read", e))?;
            *scores.entry(entry_id).or_default() += decay(now, timestamp);
        }
        let mut ranked: Vec<(String, f64)> = scores.into_iter().collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(ranked)
    }
}

/// The weight of a launch at `timestamp` seen at `now` (both milliseconds
/// since the epoch). A launch timestamped after `now` (the clock stepped
/// back) has age zero.
fn decay(now: i64, timestamp: i64) -> f64 {
    let age = Duration::from_millis(u64::try_from(now - timestamp).unwrap_or(0));
    0.5_f64.powf(age.as_secs_f64() / HALF_LIFE.as_secs_f64())
}

/// `time` in milliseconds since the Unix epoch.
fn millis(time: SystemTime) -> core_types::Result<i64> {
    let since = time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| failed("clock read", e))?;
    i64::try_from(since.as_millis()).map_err(|e| failed("clock read", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(db: &FrecencyDb, entry_id: &str, timestamp: i64) {
        db.conn
            .execute(
                "INSERT INTO launches (entry_id, timestamp) VALUES (?1, ?2)",
                params![entry_id, timestamp],
            )
            .unwrap();
    }

    #[test]
    fn recent_launches_each_count_about_one() {
        let db = FrecencyDb::open_in_memory().unwrap();
        db.record_launch("firefox.desktop").unwrap();
        std::thread::sleep(Duration::from_millis(1));
        db.record_launch("firefox.desktop").unwrap();

        let scores = db.scores().unwrap();
        assert_eq!(scores.len(), 1);
        assert!(scores[0].1 > 1.9 && scores[0].1 <= 2.0, "{scores:?}");
    }

    #[test]
    fn a_launch_one_half_life_old_counts_half() {
        let now = millis(SystemTime::now()).unwrap();
        let half_life = i64::try_from(HALF_LIFE.as_millis()).unwrap();
        assert!((decay(now, now - half_life) - 0.5).abs() < 1e-9);
        assert!((decay(now, now) - 1.0).abs() < f64::EPSILON);
        assert!((decay(now, now + 1_000) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scores_sorted_descending() {
        let db = FrecencyDb::open_in_memory().unwrap();
        for _ in 0..3 {
            db.record_launch("firefox.desktop").unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        db.record_launch("code.desktop").unwrap();

        let scores = db.scores().unwrap();
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0].0, "firefox.desktop");
        assert_eq!(scores[1].0, "code.desktop");
        assert!(scores[0].1 > scores[1].1);
    }

    #[test]
    fn opening_deletes_launches_past_retention() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.frecency.db");
        let db = FrecencyDb::open(&path).unwrap();
        let retention = i64::try_from(RETENTION.as_millis()).unwrap();
        let now = millis(SystemTime::now()).unwrap();
        insert(&db, "old.desktop", now - retention - 1_000);
        insert(&db, "kept.desktop", now - retention + 60_000);
        drop(db);

        let names: Vec<String> = FrecencyDb::open(&path)
            .unwrap()
            .scores()
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["kept.desktop"]);
    }

    #[test]
    fn empty_database_has_no_scores() {
        let db = FrecencyDb::open_in_memory().unwrap();
        assert!(db.scores().unwrap().is_empty());
    }
}
